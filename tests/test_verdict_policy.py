"""MALICIOUS only on confirmed evidence: a link flagged by 3+ VirusTotal vendors, a malicious attachment,
or a link to a login page on a non-legitimate site. Everything else is at most SUSPICIOUS."""
from phishanalyzer.pipeline import analyze_bytes

from test_analyzer import build, cfg, intel  # noqa: F401  (pytest fixtures)

VENDOR_AUTH = ("spf=pass smtp.mailfrom=vendor.example; dkim=pass header.d=vendor.example; "
               "dmarc=pass action=none header.from=vendor.example")


class VT:
    """Fake VirusTotal: url_reports maps a URL to its report; anything else is unknown."""
    def __init__(self, url_reports=None, domain_malicious=0):
        self.url_reports = url_reports or {}
        self.domain_malicious = domain_malicious

    def url(self, url):
        return self.url_reports.get(url, {"found": False})

    def domain(self, domain):
        return {"found": True, "malicious": self.domain_malicious, "suspicious": 0, "harmless": 60, "undetected": 20}

    def file(self, sha256):
        return {"found": False}

    def ip(self, ip):
        return {"found": False}


def _email(url, sender="Sales <sales@vendor.example>", auth=VENDOR_AUTH, text="Please see the document."):
    return build(from_=sender, subject="Document", text=text, auth=auth,
                 html=f"<p>{text}</p><a href='{url}'>Open document</a>").as_bytes()


def _report(malicious, title="", final_url="", categories=()):
    return {"found": True, "malicious": malicious, "suspicious": 0, "harmless": 60, "undetected": 20,
            "title": title, "final_url": final_url, "categories": list(categories)}


def test_link_flagged_by_3_vendors_is_malicious_but_2_is_not(cfg, intel):
    url = "https://docs-share.example/view/123"
    intel.vt = VT({url: _report(3)})
    assert analyze_bytes(_email(url), "x.eml", cfg, intel).verdict == "MALICIOUS"
    intel.vt = VT({url: _report(2)})
    r = analyze_bytes(_email(url), "x.eml", cfg, intel)
    assert r.verdict != "MALICIOUS" and not any(f.hard_verdict for f in r.findings)


def test_link_to_login_page_seen_by_virustotal_is_malicious(cfg, intel):
    url = "https://docs-share.example/view/123"
    intel.vt = VT({url: _report(0, title="Sign in to your account")})
    r = analyze_bytes(_email(url, sender="Docs <share@other.example>", auth=None), "x.eml", cfg, intel)
    assert r.verdict == "MALICIOUS" and "login_page" in r.tags


def test_link_redirecting_to_login_path_is_malicious(cfg, intel):
    url = "https://short.example/abc"
    intel.vt = VT({url: _report(0, final_url="https://evil-cdn.example/owa/auth/logon.aspx")})
    r = analyze_bytes(_email(url, sender="IT <it@other.example>", auth=None), "x.eml", cfg, intel)
    assert r.verdict == "MALICIOUS"


def test_login_path_without_virustotal_is_malicious(cfg, intel):
    r = analyze_bytes(_email("https://evil-cdn.example/secure/login.php", sender="IT <it@other.example>", auth=None),
                      "x.eml", cfg, intel)
    assert r.verdict == "MALICIOUS"


def test_genuine_microsoft_login_link_is_not_malicious(cfg, intel):
    r = analyze_bytes(_email("https://login.microsoftonline.com/common/oauth2/authorize"), "x.eml", cfg, intel)
    assert r.verdict != "MALICIOUS"


def test_authenticated_vendor_linking_to_its_own_portal_is_not_malicious(cfg, intel):
    r = analyze_bytes(_email("https://portal.vendor.example/login"), "x.eml", cfg, intel)
    assert r.verdict != "MALICIOUS"
    assert any("own login portal" in f.title for f in r.findings)


def test_bad_domain_reputation_alone_is_not_malicious(cfg, intel):
    intel.vt = VT(domain_malicious=12)          # URL unknown to VirusTotal, domain heavily flagged
    r = analyze_bytes(_email("https://docs-share.example/view/123"), "x.eml", cfg, intel)
    assert r.verdict != "MALICIOUS"
    assert any("domain flagged by many" in f.title for f in r.findings)


def test_high_score_without_evidence_is_high_confidence_suspicious(cfg, intel):
    text = "URGENT: your password expires today. Verify your account immediately or it will be suspended."
    m = build(from_="Microsoft 365 <alert@micros0ft-team.example>", subject="Password expiry", text=text, auth=
              "spf=fail smtp.mailfrom=micros0ft-team.example; dkim=none; dmarc=fail action=none header.from=micros0ft-team.example",
              headers={"Reply-To": "helpdesk.365@gmail.com"})
    r = analyze_bytes(m.as_bytes(), "x.eml", cfg, intel)     # no links, no attachments
    assert r.score >= 60
    assert r.verdict == "SUSPICIOUS" and r.confidence == "High"


def test_social_media_login_wall_is_not_a_phishing_login_page(cfg, intel):
    """Regression: an Instagram link in a signature redirects signed-out visitors to /accounts/login."""
    url = "https://instagram.com/vendorco?igshid=abc"
    intel.vt = VT({url: _report(0, title="Instagram",
                               final_url="https://www.instagram.com/accounts/login/?next=%2Fvendorco")})
    r = analyze_bytes(_email(url), "x.eml", cfg, intel)
    assert r.verdict != "MALICIOUS" and "login_page" not in r.tags


def test_compromised_vendor_account_linking_to_fake_onedrive_is_malicious(cfg, intel):
    """Regression ('RFP Proposal Invitation'): authenticated real sender, link to a fake OneDrive page elsewhere."""
    url = "https://hacked-shop.example/kposrfp/2233441793630971334.html"
    intel.vt = VT({url: _report(1, title="OneDrive")})
    r = analyze_bytes(_email(url, text="Official RFP proposal invitation, please review the documents."),
                      "x.eml", cfg, intel)
    assert r.verdict == "MALICIOUS"


def test_authenticated_hr_vendor_mentioning_our_company_is_not_high_risk(cfg, intel):
    """Regression: a meeting-notes service sent 'Teams Interview with Contoso' (DMARC pass)."""
    m = build(from_="Assistant <assistant@notes-vendor.example>", subject="Teams Interview with Contoso on Nov 7",
              text="Summary of your interview and performance review discussion.",
              auth="spf=pass smtp.mailfrom=notes-vendor.example; dkim=pass header.d=notes-vendor.example; "
                   "dmarc=pass action=none header.from=notes-vendor.example")
    r = analyze_bytes(m.as_bytes(), "x.eml", cfg, intel)
    assert "high_risk_pattern" not in r.tags and r.verdict != "MALICIOUS"


def test_help_center_article_about_logging_in_is_not_a_login_page(cfg, intel):
    """Regression ('Your Flocknote code'): help-centre article titled 'How do I log in? - ... Help Center'."""
    url = "https://help.vendor-two.example/article/50-how-do-i-setup-a-login"
    intel.vt = VT({url: _report(0, title="How do I log in? - Vendor Help Center", final_url=url)})
    r = analyze_bytes(_email(url, sender="App <mail@vendor-two.example>", auth=None), "x.eml", cfg, intel)
    assert r.verdict != "MALICIOUS" and "login_page" not in r.tags


def test_help_page_flagged_as_phishing_by_virustotal_is_still_malicious(cfg, intel):
    url = "https://help.evil-cdn.example/article/login"
    intel.vt = VT({url: _report(0, title="Help Center", categories=["phishing"])})
    r = analyze_bytes(_email(url, sender="IT <it@other.example>", auth=None), "x.eml", cfg, intel)
    assert r.verdict == "MALICIOUS"
