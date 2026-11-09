from pathlib import Path

import phishanalyzer.notify as notify_mod
from phishanalyzer.pipeline import analyze_bytes
from phishanalyzer.store import CaseStore

from test_analyzer import build, cfg, intel, phish  # noqa: F401  (pytest fixtures)
from test_daily_report import salary_campaign


def _fake_outlook(monkeypatch):
    popups, mails = [], []
    monkeypatch.setattr(notify_mod, "_popup", lambda title, msg, target, urgent=False: popups.append((title, urgent)))
    monkeypatch.setattr(notify_mod, "send_mail",
                        lambda to, subject, html, files, root, cc="": mails.append((to, subject, html, cc)))
    return popups, mails


def test_popup_per_email_and_one_alert_per_campaign(cfg, intel, tmp_path, monkeypatch):
    popups, mails = _fake_outlook(monkeypatch)
    cfg["notifications"]["to"] = "soc@contoso.com"
    store = CaseStore(tmp_path / "cases.sqlite")
    new = [(analyze_bytes(salary_campaign(s).as_bytes(), "x.eml", cfg, intel, reported_by=f"{s}@contoso.com"),
            Path(tmp_path / f"{s}.html")) for s in ("a@x.example", "b@y.example")]
    new.append((analyze_bytes(build().as_bytes(), "c.eml", cfg, intel, reported_by="c@contoso.com"), Path(tmp_path / "c.html")))

    notify_mod.notify(new, cfg, store, tmp_path / "daily.html")
    assert len(popups) == 3 and popups[0][0].split()[1] == "SUSPICIOUS" and popups[0][1] is True
    assert popups[2][1] is False                                  # clean email: quiet popup
    assert len(mails) == 1                                        # 2 campaign copies -> one alert, clean -> none
    to, subject, html, cc = mails[0]
    assert to == "soc@contoso.com" and cc == "" and subject.startswith("[SUSPICIOUS]") and "(2 reports)" in subject
    assert "Do NOT block" in html

    notify_mod.notify(new, cfg, store, None)                      # same campaign again: no second email
    assert len(mails) == 1


def test_malicious_alert_uses_verdict_recipients_with_cc(cfg, intel, tmp_path, monkeypatch):
    _, mails = _fake_outlook(monkeypatch)
    cfg["notifications"]["to"] = "me@contoso.com"
    cfg["notifications"]["recipients"] = {"MALICIOUS": {"to": ["boss@contoso.com", "me@contoso.com"],
                                                        "cc": ["infosec@contoso.com"]}}
    store = CaseStore(tmp_path / "cases.sqlite")
    bad = analyze_bytes(phish().as_bytes(), "p.eml", cfg, intel, reported_by="u@contoso.com")
    assert bad.verdict == "MALICIOUS"
    notify_mod.email_alerts([(bad, tmp_path / "p.html")], cfg, store)
    assert mails[0][0] == "boss@contoso.com; me@contoso.com" and mails[0][3] == "infosec@contoso.com"
    # A verdict without its own list falls back to notifications.to, with no CC.
    assert notify_mod.recipients("SUSPICIOUS", cfg) == ("me@contoso.com", "")


def test_many_reports_give_one_summary_popup(cfg, intel, tmp_path, monkeypatch):
    popups, mails = _fake_outlook(monkeypatch)
    cfg["notifications"]["email_alerts"] = False
    r = analyze_bytes(build().as_bytes(), "c.eml", cfg, intel)
    notify_mod.notify([(r, tmp_path / "c.html")] * 5, cfg, CaseStore(tmp_path / "s.sqlite"), tmp_path / "daily.html")
    assert len(popups) == 1 and "5 new reports" in popups[0][0] and not mails
