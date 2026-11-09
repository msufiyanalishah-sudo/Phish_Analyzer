from phishanalyzer.daily_report import build_remediation, group_entries, render_email, report_attachments
from phishanalyzer.pipeline import analyze_bytes

from test_analyzer import build, cfg, intel, phish  # noqa: F401  (pytest fixtures)


def test_remediation_blocks_attacker_but_not_shared_providers(cfg, intel):
    r = analyze_bytes(phish().as_bytes(), "phish.eml", cfg, intel)
    rem = build_remediation(r, cfg)
    block = " ".join(rem["block"])
    keep = " ".join(rem["do_not_block"])
    assert "no-reply[@]micros0ft-secure[.]com" in block
    assert "Sender domain: micros0ft-secure[.]com" in block
    assert "helpdesk[.]ms365[@]gmail[.]com" in block          # block the Gmail address...
    assert "gmail[.]com: public/shared provider" in keep         # ...but never gmail.com itself
    assert "microsoftonline" not in block
    assert any("Entra ID sign-in" in a for a in rem["actions"])


def salary_campaign(sender):
    inner = build(from_="HR <hr@contoso-hr.example>", subject="Salary increase notice", auth=None,
                  text="Scan the code to view your salary increase.",
                  attachments=[("ATT00001.jpg", b"\xff\xd8\xff" + b"\x11" * 4000)])
    outer = build(from_=sender, subject="October 20, 2026", auth=None, text="See attached.")
    outer.add_attachment(inner, filename="Contoso SALARY INCREASE NOTICE.eml")
    return outer


def test_company_name_salary_lure_without_confirmed_evidence_is_high_risk_suspicious(cfg, intel):
    """No VirusTotal hit, no malicious attachment, no login page: strong pattern, but an analyst decides."""
    entries = []
    for i, sender in enumerate(("info@hacked-site1.example", "admin@hacked-site2.example")):
        r = analyze_bytes(salary_campaign(sender).as_bytes(), "x.eml", cfg, intel, reported_by=f"u{i}@contoso.com")
        assert r.verdict == "SUSPICIOUS" and r.confidence == "High", [(f.title, f.points) for f in r.findings]
        assert {"internal_impersonation", "hr_lure"} <= r.tags
        entries.append({"result": r, "raw": b"x", "name": "x.eml", "entry_id": str(i), "report": ""})
    groups = group_entries(entries)
    assert len(groups) == 1 and len(groups[0]["entry_ids"]) == 2


def test_sent_email_never_contains_a_live_url(cfg, intel, monkeypatch):
    """Regression: a raw QR-code URL in the body got the 21 Oct daily report quarantined."""
    import sys
    import types
    from phishanalyzer import daily_report
    from phishanalyzer.utils import defang_text
    assert defang_text("QR: https://evil-cdn.example/asc/?email=x and http://a.b/c") == \
        "QR: hxxps://evil-cdn[.]example/asc/?email=x and hxxp://a[.]b/c"

    sent = {}

    class FakeMail:
        Attachments = types.SimpleNamespace(Add=lambda path: None)

        def Send(self):
            sent.update(subject=self.Subject, body=self.HTMLBody)

    fake_client = types.SimpleNamespace(Dispatch=lambda name: types.SimpleNamespace(CreateItem=lambda kind: FakeMail()))
    monkeypatch.setitem(sys.modules, "win32com", types.SimpleNamespace(client=fake_client))
    monkeypatch.setitem(sys.modules, "win32com.client", fake_client)
    daily_report.send_mail("a@b.c", "Phish via https://evil.example/x", "<p>see https://evil.example/login</p>", [],
                           __import__("pathlib").Path(cfg["_base_dir"]))
    assert "https://" not in sent["body"] and "https://" not in sent["subject"]
    assert "hxxps://evil[.]example/login" in sent["body"]


def test_newsletter_mentioning_brands_is_not_impersonation(cfg, intel):
    m = build(from_="news@vendor.example", subject="Our monthly update", auth=None,
              text="We now integrate with Microsoft Teams and SharePoint. Win an Amazon voucher!")
    r = analyze_bytes(m.as_bytes(), "x.eml", cfg, intel)
    assert "brand_impersonation" not in r.tags
    assert r.verdict == "CLEAN"


def test_daily_email_groups_duplicate_reports_and_attaches_malicious(cfg, intel):
    raw = phish().as_bytes()
    entries = []
    for reporter in ("a@contoso.com", "b@contoso.com"):
        r = analyze_bytes(raw, "phish.eml", cfg, intel, reported_by=reporter)
        entries.append({"result": r, "raw": raw, "name": "phish.eml", "entry_id": reporter, "report": "x"})
    clean = analyze_bytes(build().as_bytes(), "clean.eml", cfg, intel, reported_by="c@contoso.com")
    entries.append({"result": clean, "raw": b"", "name": "", "entry_id": "c", "report": "y"})

    groups = group_entries(entries)
    assert [g["result"].verdict for g in groups] == ["MALICIOUS", "CLEAN"]
    assert groups[0]["reporters"] == ["a@contoso.com", "b@contoso.com"]

    subject, html = render_email(groups, 24, cfg, [])
    assert "1 Malicious" in subject and "1 Clean" in subject and "3 reports" in subject
    assert "Do NOT block" in html and "Password expiry notice" in html
    assert "https://micros0ft" not in html

    files = report_attachments(groups, cfg)          # default: no phishing samples attached
    assert [n for n, _ in files][0].startswith("iocs_")
    csv_text = files[-1][1].decode("utf-8-sig")
    assert "hxxps://micros0ft-secure[.]com/login.php" in csv_text
    assert "https://micros0ft-secure.com" not in csv_text   # live URLs get the email quarantined

    cfg["daily_report"]["attach_malicious"] = True
    names = [n for n, _ in report_attachments(groups, cfg)]
    assert names[0].startswith("MALICIOUS_01_Password expiry notice") and names[0].endswith(".eml")
