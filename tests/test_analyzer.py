import io
import zipfile
from email.message import EmailMessage

import pytest

from phishanalyzer.analyzers.urls import unwrap_url
from phishanalyzer.config import load_config
from phishanalyzer.intel import Intel
from phishanalyzer.pipeline import analyze_bytes, analyze_report_bytes, save_case
from phishanalyzer.store import CaseStore
from phishanalyzer.utils import defang_url, lookalike_of

PASS_AUTH = ("mx.contoso.com; spf=pass smtp.mailfrom=contoso.com; dkim=pass header.d=contoso.com; "
             "dmarc=pass action=none header.from=contoso.com")
FAIL_AUTH = ("spf=fail (sender IP is 45.33.32.156) smtp.mailfrom=micros0ft-secure.com; dkim=none; "
             "dmarc=fail action=none header.from=micros0ft-secure.com; compauth=fail reason=000")


@pytest.fixture
def cfg(tmp_path):
    c = load_config(tmp_path / "no-config.yaml")
    c["_base_dir"] = str(tmp_path)
    c["network"]["dns_checks"] = False
    c["heuristics"]["internal_domains"] = ["contoso.com"]
    return c


@pytest.fixture
def intel(cfg):
    return Intel(cfg, offline=True)


def build(from_="IT Team <it@contoso.com>", subject="Team lunch", text="Lunch is at 1pm on Thursday.",
          html=None, auth=PASS_AUTH, headers=None, attachments=()):
    m = EmailMessage()
    m["Received"] = ("from mail.contoso.com (mail.contoso.com [52.1.2.3]) by mx.contoso.com; "
                     "Mon, 12 Oct 2026 10:00:01 +0000")
    if auth:
        m["Authentication-Results"] = auth
    m["From"] = from_
    m["To"] = "user@contoso.com"
    m["Subject"] = subject
    m["Date"] = "Mon, 12 Oct 2026 10:00:00 +0000"
    m["Message-ID"] = f"<{abs(hash(subject + text))}@mail.example>"
    for k, v in (headers or {}).items():
        m[k] = v
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    for name, data in attachments:
        m.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return m


PHISH_HTML = """<html><body><p>Your password expires today. Verify your account immediately to keep your Microsoft 365 mailbox.</p>
<a href="https://micros0ft-secure.com/login.php">https://login.microsoftonline.com</a></body></html>"""


def phish(**kw):
    defaults = dict(from_="Microsoft 365 <no-reply@micros0ft-secure.com>", subject="Password expiry notice",
                    text="Your password expires today. Verify your account immediately.", html=PHISH_HTML, auth=FAIL_AUTH,
                    headers={"Reply-To": "helpdesk.ms365@gmail.com"})
    defaults.update(kw)
    return build(**defaults)


def test_clean_internal_email(cfg, intel):
    r = analyze_bytes(build().as_bytes(), "clean.eml", cfg, intel)
    assert r.verdict == "CLEAN", [(f.title, f.points) for f in r.findings]
    assert r.auth["dmarc"] == "pass"


def test_credential_phish_with_lookalike_is_malicious(cfg, intel):
    r = analyze_bytes(phish().as_bytes(), "phish.eml", cfg, intel)
    titles = {f.title for f in r.findings}
    assert r.verdict == "MALICIOUS"
    assert "DMARC failed" in titles
    assert "Reply-To goes to a free email provider" in titles
    assert any("looks like microsoft.com" in t for t in titles)
    assert "Link text shows a different address than the real link" in titles
    assert r.originating_ip["ip"] == "45.33.32.156"
    assert "45.33.32.156" in r.iocs["ips"]
    assert "https://micros0ft-secure.com/login.php" in r.iocs["urls"]


def test_safelinks_and_urldefense_unwrap():
    wrapped = "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Flogin&data=x"
    assert unwrap_url(wrapped) == "https://evil.example/login"
    assert unwrap_url("https://urldefense.com/v3/__https://evil.example/a__;!!abc$") == "https://evil.example/a"


def test_link_carrying_victim_email_is_detected():
    from phishanalyzer.analyzers.urls import _carries_email
    assert _carries_email("https://evil-cdn.example/asc/?email=dXNlckBjb250b3NvLmNvbQ==")
    assert _carries_email("https://evil.example/login#user@contoso.com")
    assert not _carries_email("https://www.example.com/products/item-12345?ref=newsletter")


def test_authenticated_vendor_with_low_vt_domain_and_file_share_is_only_suspicious(cfg, intel):
    """Regression: a real vendor email was called MALICIOUS on 2/92 VirusTotal engines for its domain."""
    class LowVT(FakeVT):
        def domain(self, domain):
            return {"found": True, "malicious": 2, "suspicious": 0, "harmless": 54, "undetected": 36, "link": ""}

        def url(self, url):
            return {"found": False}
    intel.vt = LowVT()
    html = ("<p>Please find our company profile.</p>"
            "<a href='https://vendorco-my.sharepoint.com/personal/m_x/_layouts/15/guestaccess.aspx?share=abc'>Profile</a>"
            "<a href='https://we.tl/t-mznERRQ1HqFPHfix'>Catalogue</a>"
            "<img src='https://res.public.onecdn.static.microsoft/assets/item-types/24_1.5x/pdf.png'>")
    auth = "spf=pass smtp.mailfrom=vendor.example; dkim=pass header.d=vendor.example; dmarc=pass action=none header.from=vendor.example"
    r = analyze_bytes(build(from_="Sales <sales@vendor.example>", subject="Company profile", text="Profile attached",
                            html=html, auth=auth).as_bytes(), "x.eml", cfg, intel)
    assert r.verdict == "SUSPICIOUS", [(f.title, f.points, f.hard_verdict) for f in r.findings]
    assert not any(f.hard_verdict for f in r.findings)
    assert "file_share" in r.tags
    assert not any("imitates" in f.title for f in r.findings)    # static.microsoft is genuine Microsoft


def test_lookalike_detection():
    assert lookalike_of("paypa1.com", ["paypal.com"]) == "paypal.com"
    assert lookalike_of("rnicrosoft.com", ["microsoft.com"]) == "microsoft.com"
    assert lookalike_of("microsoft.com.secure-login.xyz", ["microsoft.com"]) == "microsoft.com"
    assert lookalike_of("login.microsoftonline.com", ["microsoft.com"], ["microsoftonline.com"]) is None
    assert lookalike_of("example.org", ["microsoft.com"]) is None


def test_double_extension_executable_is_malicious(cfg, intel):
    m = build(from_="Billing <billing@vendor.example>", subject="Invoice", text="See invoice.", auth=None,
              attachments=[("invoice.pdf.exe", b"MZ\x90\x00" + b"\x00" * 200)])
    r = analyze_bytes(m.as_bytes(), "x.eml", cfg, intel)
    assert r.verdict == "MALICIOUS"
    assert r.attachments[0]["true_type"] == "exe"
    assert len(r.attachments[0]["sha256"]) == 64


def test_exe_disguised_as_pdf(cfg, intel):
    m = build(from_="a@vendor.example", auth=None, attachments=[("report.pdf", b"MZ" + b"\x00" * 100)])
    r = analyze_bytes(m.as_bytes(), "x.eml", cfg, intel)
    assert any(f.title == "Executable disguised with a different extension" for f in r.findings)
    assert r.verdict == "MALICIOUS"


def test_zip_containing_script(cfg, intel):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("scan_0042.js", "var x = 1;")
    m = build(from_="a@vendor.example", auth=None, attachments=[("scan.zip", buf.getvalue())])
    r = analyze_bytes(m.as_bytes(), "x.eml", cfg, intel)
    assert r.verdict == "MALICIOUS"
    assert any(a["name"] == "scan.zip/scan_0042.js" for a in r.attachments)


def test_html_attachment_with_login_form(cfg, intel):
    page = b"<html><body><form action='https://collect.example/p'><input type='password'></form></body></html>"
    m = build(from_="Docs <share@files.example>", auth=None, text="Please review the shared document.",
              attachments=[("Document.html", page)])
    r = analyze_bytes(m.as_bytes(), "x.eml", cfg, intel)
    titles = {f.title for f in r.findings}
    assert "HTML attachment is a login page (password field)" in titles
    assert any(u["url"] == "https://collect.example/p" for u in r.urls)
    assert r.verdict == "MALICIOUS"          # a phishing login page delivered as a file = malicious attachment


class FakeVT:
    def file(self, sha256):
        return {"found": True, "malicious": 41, "suspicious": 0, "label": "trojan.agent", "link": ""}

    def url(self, url):
        return {"found": True, "malicious": 0, "suspicious": 0, "link": ""}

    def domain(self, domain):
        return {"found": True, "malicious": 0, "suspicious": 0, "link": ""}

    def ip(self, ip):
        return {"found": True, "malicious": 0, "suspicious": 0, "country": "US", "link": ""}


def test_virustotal_malicious_hash_is_malicious(cfg, intel):
    intel.vt = FakeVT()
    m = build(from_="a@vendor.example", auth=None, attachments=[("notes.txt", b"plain text notes")])
    r = analyze_bytes(m.as_bytes(), "x.eml", cfg, intel)
    assert r.verdict == "MALICIOUS"
    assert r.attachments[0]["virustotal"]["malicious"] == 41


def test_simulation_header(cfg, intel):
    r = analyze_bytes(phish(headers={"X-PHISHTEST": "KnowBe4"}).as_bytes(), "sim.eml", cfg, intel)
    assert r.verdict == "SIMULATION"


def test_simulation_header_from_unexpected_ip_is_not_trusted(cfg, intel):
    cfg["heuristics"]["simulation_sender_ips"] = ["23.21.109.197"]
    r = analyze_bytes(phish(headers={"X-PHISHTEST": "KnowBe4"}).as_bytes(), "sim.eml", cfg, intel)
    assert r.verdict == "MALICIOUS"


def test_report_without_attachment_is_unanalyzable(cfg, intel):
    wrapper = build(from_="user@contoso.com", subject="FW: weird email", text="Forwarded inline")
    results = analyze_report_bytes(wrapper.as_bytes(), "report.eml", cfg, intel)
    assert [r.verdict for r in results] == ["UNANALYZABLE"]


def test_report_with_attached_email(cfg, intel):
    wrapper = build(from_="user@contoso.com", subject="Phishing report", text="Reported via PAB")
    wrapper.add_attachment(phish())
    results = analyze_report_bytes(wrapper.as_bytes(), "report.eml", cfg, intel)
    assert len(results) == 1
    assert results[0].original["subject"] == "Password expiry notice"
    assert results[0].verdict == "MALICIOUS"


def test_reports_are_written_and_defanged(cfg, intel, tmp_path):
    r = analyze_bytes(phish().as_bytes(), "phish.eml", cfg, intel)
    store = CaseStore(tmp_path / "data" / "cases.sqlite")
    paths = save_case(r, cfg, store)
    html = paths["html"].read_text(encoding="utf-8")
    assert "MALICIOUS" in html
    assert defang_url("https://micros0ft-secure.com/login.php") in html
    assert "https://micros0ft-secure.com" not in html
    assert paths["json"].exists() and paths["iocs"].exists()
    # Same email again is linked to the first case.
    r2 = analyze_bytes(phish().as_bytes(), "phish.eml", cfg, intel)
    r2.case_id += "-2"
    save_case(r2, cfg, store)
    assert r2.duplicate_of == r.case_id
