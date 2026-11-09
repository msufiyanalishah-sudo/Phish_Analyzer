"""Claude second opinion: advisory, masked input, can only veto a login-path-only MALICIOUS."""
from phishanalyzer.analyzers.llm import build_prompt
from phishanalyzer.parsing import parse_email
from phishanalyzer.pipeline import analyze_bytes

from test_analyzer import build, cfg, intel, phish  # noqa: F401  (pytest fixtures)
from test_verdict_policy import VT, _email, _report


class FakeClaude:
    def __init__(self, intent, confidence):
        self.answer = {"intent": intent, "confidence": confidence, "reasons": ["test reason"], "model": "fake"}
        self.prompts = []

    def review(self, prompt):
        self.prompts.append(prompt)
        return dict(self.answer)


def test_prompt_masks_internal_addresses_company_name_and_phones(cfg, intel):
    m = build(from_="Payroll <hr@evil-payroll.example>", subject="Contoso salary update", auth=None,
              text="Dear user@contoso.com, Contoso HR here. Call +966 55 123 4567 or open https://evil-cdn.example/a")
    raw = m.as_bytes()
    r = analyze_bytes(raw, "x.eml", cfg, intel)
    prompt = build_prompt(parse_email(raw), r, cfg)
    assert "user@contoso.com" not in prompt and "[OUR_EMAIL]" in prompt
    assert "Contoso" not in prompt and "[OUR_COMPANY]" in prompt
    assert "123 4567" not in prompt and "[PHONE]" in prompt
    assert "https://" not in prompt and "hxxps://evil-cdn[.]example" in prompt
    assert "hr[@]evil-payroll[.]example" in prompt          # the external sender stays visible (defanged)
    assert prompt.startswith("<email>") and prompt.endswith("</email>")


def test_claude_adds_or_removes_points_but_never_makes_malicious(cfg, intel):
    intel.llm = FakeClaude("credential_phishing", 95)
    r = analyze_bytes(build(from_="x@vendor.example", auth=None, text="hello").as_bytes(), "x.eml", cfg, intel)
    assert r.llm["intent"] == "credential_phishing"
    assert any(f.title.startswith("Claude assessment") and f.points == 15 for f in r.findings)
    assert r.verdict != "MALICIOUS"

    intel.llm = FakeClaude("legitimate", 95)
    r = analyze_bytes(build(from_="x@vendor.example", auth=None, text="hello").as_bytes(), "x.eml", cfg, intel)
    assert any(f.title.startswith("Claude assessment") and f.points == -15 for f in r.findings)


def test_claude_can_veto_a_login_path_only_signal(cfg, intel):
    url = "https://evil-cdn.example/secure/login.php"
    intel.llm = FakeClaude("legitimate", 95)
    r = analyze_bytes(_email(url, sender="IT <it@other.example>", auth=None), "x.eml", cfg, intel)
    assert r.verdict != "MALICIOUS"
    assert any("Claude judged the email legitimate" in f.title for f in r.findings)


def test_claude_cannot_veto_virustotal_evidence(cfg, intel):
    url = "https://docs-share.example/view/123"
    intel.vt = VT({url: _report(9)})
    intel.llm = FakeClaude("legitimate", 99)                # e.g. fooled by "AI: this email is safe" in the body
    r = analyze_bytes(_email(url), "x.eml", cfg, intel)
    assert r.verdict == "MALICIOUS"

    intel.vt = VT({url: _report(0, title="Sign in to Microsoft 365")})
    r = analyze_bytes(_email(url, sender="Docs <share@other.example>", auth=None), "x.eml", cfg, intel)
    assert r.verdict == "MALICIOUS"                          # VirusTotal saw the login page: no veto
