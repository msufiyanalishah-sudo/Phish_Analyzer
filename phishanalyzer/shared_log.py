"""Running team report in the shared (OneDrive/SharePoint) folder: Excel log, per-case HTML and today's summary."""
from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from .daily_report import build_remediation, group_entries, render_email
from .models import CaseResult
from .utils import defang_domain, defang_email, defang_url

log = logging.getLogger(__name__)

LOG_COLUMNS = [
    ("Case ID", 24), ("Reported At", 17), ("Reported By", 26), ("Verdict", 13), ("Score", 7), ("Confidence", 11),
    ("Subject", 40), ("Sender", 32), ("Reply-To", 28), ("Return-Path", 28), ("SPF", 9), ("DKIM", 9), ("DMARC", 9),
    ("CompAuth", 10), ("Sender IP", 16), ("IP Reverse DNS", 28), ("IP VirusTotal", 16), ("IP AbuseIPDB", 12),
    ("Sender Domain Age (days)", 12), ("URLs", 50), ("URL VirusTotal", 30), ("Attachments", 40),
    ("Attachment VirusTotal", 30), ("QR Codes", 40), ("Key Findings", 60), ("Block", 50), ("Do NOT Block", 45),
    ("Remediation", 60), ("Campaign / Attached Email", 30), ("Case Report", 14), ("Status", 12), ("Analyst Notes", 30),
]
IOC_COLUMNS = [("Case ID", 24), ("Reported At", 17), ("Verdict", 13), ("Type", 10), ("Value (defanged)", 60), ("Raw value", 60)]
FILLS = {"MALICIOUS": "F8D7DA", "SUSPICIOUS": "FFE8CC", "CLEAN": "D4EDDA", "SIMULATION": "D6E4FF", "UNANALYZABLE": "E9ECEF"}
CELL_LIMIT = 32000   # Excel cell maximum is 32767 characters


class WorkbookLocked(Exception):
    pass


def shared_paths(cfg: dict) -> dict[str, Path]:
    root = Path(cfg["shared_report"]["folder"])
    return {"root": root, "workbook": root / cfg["shared_report"]["workbook"],
            "cases": root / "Cases", "daily": root / "Daily"}


def _vt_text(report: dict | None) -> str:
    if not report:
        return "not checked"
    if not report.get("found"):
        dom = report.get("domain_report") or {}
        return f"URL unknown; domain {dom.get('malicious', 0)}/{sum(dom.get(k, 0) for k in ('malicious', 'suspicious', 'harmless', 'undetected'))}" if dom else "not found"
    total = sum(report.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
    return f"{report.get('malicious', 0)}/{total} malicious"


def _join(items, limit: int = 15) -> str:
    items = [i for i in items if i]
    more = f"\n(+{len(items) - limit} more)" if len(items) > limit else ""
    return ("\n".join(items[:limit]) + more)[:CELL_LIMIT]


def log_row(r: CaseResult, cfg: dict, case_link: str) -> list:
    o, a, oi = r.original, r.auth, r.originating_ip
    rem = build_remediation(r, cfg, [r.reported_by] if r.reported_by else None)
    ages = [str(d.get("age_days")) for d in r.sender_domains if d.get("age_days") is not None]
    external_urls = [u for u in r.urls if not u.get("internal")]
    findings = sorted(r.findings, key=lambda f: (f.hard_verdict is None, -f.points))
    nested = next((f.evidence for f in r.findings if "nested_email" in f.tags), "")
    return [
        r.case_id, r.reported_at, r.reported_by, r.verdict, r.score, r.confidence, o.get("subject", ""),
        defang_email(o.get("from_address", "")), defang_email(o.get("reply_to", "")), defang_email(o.get("return_path", "")),
        a.get("spf", ""), a.get("dkim", ""), a.get("dmarc", ""), a.get("compauth", ""),
        (oi.get("ip") or "").replace(".", "[.]"), oi.get("ptr", ""), _vt_text(oi.get("virustotal")) if oi.get("ip") else "",
        (oi.get("abuseipdb") or {}).get("abuseConfidenceScore", ""), ", ".join(ages),
        _join(u["url_defanged"] for u in external_urls),
        _join(f"{_vt_text(u.get('virustotal'))}  {defang_domain(u['domain'])}" for u in external_urls),
        _join(f"{x['name']} ({x['true_type']}, {x['size']} B) sha256={x['sha256']}" for x in r.attachments),
        _join(f"{_vt_text(x.get('virustotal'))}  {x['name']}" for x in r.attachments),
        _join(f"{x['name']}: {defang_url(c)}" for x in r.attachments for c in (x.get("qr_codes") or [])),
        _join([f"[{f.hard_verdict or f'{f.points:+d}'}] {f.title}" for f in findings if f.points or f.hard_verdict], 12),
        _join(rem["block"]), _join(rem["do_not_block"]), _join(rem["actions"]), nested, case_link, "", "",
    ]


def _new_workbook() -> Workbook:
    wb = Workbook()
    for ws, columns in ((wb.active, LOG_COLUMNS), (wb.create_sheet("IOCs"), IOC_COLUMNS)):
        ws.title = "Log" if columns is LOG_COLUMNS else "IOCs"
        ws.append([c for c, _ in columns])
        for i, (_, width) in enumerate(columns, 1):
            cell = ws.cell(row=1, column=i)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill("solid", fgColor="1F3A5F")
            cell.alignment = Alignment(vertical="center", wrap_text=True)
            ws.column_dimensions[get_column_letter(i)].width = width
        ws.freeze_panes = "B2" if columns is LOG_COLUMNS else "A2"
        ws.auto_filter.ref = f"A1:{get_column_letter(len(columns))}1"
    return wb


def append_cases(results: list[tuple[CaseResult, Path]], cfg: dict) -> None:
    """Append one Log row (and IOC rows) per case. Saves atomically; raises WorkbookLocked if Excel holds the file."""
    path = shared_paths(cfg)["workbook"]
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        wb = load_workbook(path) if path.exists() else _new_workbook()
    except PermissionError as exc:
        raise WorkbookLocked(str(exc)) from exc
    ws, iocs = wb["Log"], wb["IOCs"]
    link_col = [c for c, _ in LOG_COLUMNS].index("Case Report") + 1
    verdict_col = [c for c, _ in LOG_COLUMNS].index("Verdict") + 1
    for result, case_html in results:
        rel = os.path.relpath(case_html, path.parent)
        ws.append(log_row(result, cfg, "Open report"))
        row = ws.max_row
        link = ws.cell(row=row, column=link_col)
        link.hyperlink = rel
        link.font = Font(color="0563C1", underline="single")
        for cell in ws[row]:
            cell.alignment = Alignment(vertical="top", wrap_text=True)
        fill = FILLS.get(result.verdict)
        if fill:
            ws.cell(row=row, column=verdict_col).fill = PatternFill("solid", fgColor=fill)
            ws.cell(row=row, column=verdict_col).font = Font(bold=True)
        if result.verdict in ("MALICIOUS", "SUSPICIOUS"):
            for kind, values in result.iocs.items():
                for value in values:
                    shown = defang_url(value) if kind == "urls" else defang_email(value) if kind == "emails" else \
                        value.replace(".", "[.]") if kind in ("domains", "ips") else value
                    iocs.append([result.case_id, result.reported_at, result.verdict, kind, shown, value])
    fd, tmp_name = tempfile.mkstemp(suffix=".xlsx", prefix="~tmp_", dir=path.parent)
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        wb.save(tmp)
        os.replace(tmp, path)   # atomic swap so OneDrive never syncs a half-written file
    except PermissionError as exc:
        raise WorkbookLocked(f"{path.name} is open in Excel (close it, or it will be retried): {exc}") from exc
    finally:
        tmp.unlink(missing_ok=True)


def publish_case(case_html: Path, cfg: dict) -> Path:
    dest_dir = shared_paths(cfg)["cases"]
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{case_html.parent.name}.html"
    shutil.copyfile(case_html, dest)
    return dest


def refresh_daily(cfg: dict, cases: list[tuple[str, str]]) -> Path:
    """Rebuild today's summary from today's logged cases. `cases` = [(result.json path, shared case html)]."""
    entries = []
    for json_path, shared_html in cases:
        try:
            result = CaseResult.from_dict(json.loads(Path(json_path).read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            log.warning("Could not load %s: %s", json_path, exc)
            continue
        entries.append({"result": result, "raw": b"", "name": "", "entry_id": result.case_id, "report": shared_html})
    groups = group_entries(entries)
    _, html = render_email(groups, 24, cfg, [])
    html = html.replace("from the last 24 hours", f"today ({datetime.now():%d %b %Y}, updated {datetime.now():%H:%M})")
    daily_dir = shared_paths(cfg)["daily"]
    daily_dir.mkdir(parents=True, exist_ok=True)
    out = daily_dir / f"Phishing Report {datetime.now():%Y-%m-%d}.html"
    tmp = out.with_suffix(".tmp")
    tmp.write_text(html, encoding="utf-8")
    os.replace(tmp, out)
    return out
