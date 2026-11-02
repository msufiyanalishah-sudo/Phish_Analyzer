from openpyxl import load_workbook

from phishanalyzer.pipeline import analyze_bytes, save_case
from phishanalyzer.shared_log import append_cases, publish_case, refresh_daily, shared_paths
from phishanalyzer.store import CaseStore

from test_analyzer import build, cfg, intel, phish  # noqa: F401  (pytest fixtures)


def test_cases_are_appended_to_shared_workbook_and_daily_summary(cfg, intel, tmp_path):
    cfg["shared_report"]["folder"] = str(tmp_path / "shared")
    store = CaseStore(tmp_path / "data" / "cases.sqlite")
    logged = []
    for raw in (phish().as_bytes(), build().as_bytes()):
        r = analyze_bytes(raw, "x.eml", cfg, intel, reported_by="user@contoso.com")
        paths = save_case(r, cfg, store)
        shared_html = publish_case(paths["html"], cfg)
        append_cases([(r, shared_html)], cfg)          # one save per case, like the watcher
        logged.append((str(paths["json"]), str(shared_html)))

    wb = load_workbook(shared_paths(cfg)["workbook"])
    rows = list(wb["Log"].iter_rows(min_row=2, values_only=True))
    header = [c.value for c in wb["Log"][1]]
    assert [row[header.index("Verdict")] for row in rows] == ["MALICIOUS", "CLEAN"]
    assert "micros0ft-secure[.]com" in rows[0][header.index("Sender")]
    assert rows[0][header.index("DMARC")] == "fail"
    assert "micros0ft" not in str(rows[1])
    link = wb["Log"].cell(row=2, column=header.index("Case Report") + 1).hyperlink.target
    assert link.startswith("Cases")
    ioc_values = [row[5] for row in wb["IOCs"].iter_rows(min_row=2, values_only=True)]
    assert "https://micros0ft-secure.com/login.php" in ioc_values     # raw value for blocking tools

    daily = refresh_daily(cfg, logged)
    text = daily.read_text(encoding="utf-8")
    assert "Password expiry notice" in text and "Do NOT block" in text
