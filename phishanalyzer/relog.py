"""Re-analyze emails already in the shared Excel log (e.g. after a rule fix) and update their rows in place.
Team-edited columns (Status, Analyst Notes) are kept."""
from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import tempfile
from datetime import date, datetime, timedelta
from pathlib import Path

from openpyxl import load_workbook
from openpyxl.styles import Alignment, Font, PatternFill

from .config import resolve_path
from .intel import Intel
from .models import CaseResult
from .outlook_com import OL_MAIL_ITEM, _reporter, analyze_item, connect, find_folder, is_user_report, received_time
from .pipeline import save_case
from .shared_log import FILLS, LOG_COLUMNS, WorkbookLocked, log_row, publish_case, refresh_daily, shared_paths
from .store import CaseStore
from .utils import defang_email, defang_url

log = logging.getLogger(__name__)
KEEP_COLUMNS = {"Status", "Analyst Notes"}


def _quota_error(message: str) -> bool:
    low = message.lower()
    return "quota" in low or "429" in low or "401" in low or "rate limit reached" in low


def _key(reporter, reported_at) -> tuple[str, str]:
    return (str(reporter or "").strip().lower(), str(reported_at or "").strip())


def relog(cfg: dict, intel: Intel, store: CaseStore, start: datetime | None = None,
          end: datetime | None = None) -> dict[str, int]:
    """Re-analyze rows whose 'Reported At' is between start and end (all rows when both are None).
    A row is left unchanged when a threat-intel quota ran out during its analysis, so a partial result never
    overwrites a complete one; re-run later to finish."""
    paths = shared_paths(cfg)
    wb_path = paths["workbook"]
    backup_dir = resolve_path(cfg, cfg["outputs"]["data_dir"]) / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_dir / f"Phishing Alert Log {datetime.now():%Y%m%d-%H%M%S}.xlsx"
    shutil.copyfile(wb_path, backup)
    log.info("Backup saved: %s", backup)

    wb = load_workbook(wb_path)
    ws = wb["Log"]
    header = [c.value for c in ws[1]]
    col = {name: header.index(name) + 1 for name in header}
    rows: dict[tuple[str, str], list[int]] = {}
    oldest = datetime.now()
    in_range = 0
    for r in range(2, ws.max_row + 1):
        key = _key(ws.cell(r, col["Reported By"]).value, ws.cell(r, col["Reported At"]).value)
        try:
            when = datetime.fromisoformat(key[1])
        except ValueError:
            continue
        if (start and when < start) or (end and when > end):
            continue
        rows.setdefault(key, []).append(r)
        oldest = min(oldest, when)
        in_range += 1

    ns = connect()
    folder = find_folder(ns, cfg["mailbox"].get("store", ""), cfg["mailbox"]["source_folder"])
    items = folder.Items
    items.Sort("[ReceivedTime]", True)
    cutoff = oldest - timedelta(minutes=5)
    workroot = resolve_path(cfg, cfg["outputs"]["quarantine_dir"])
    stats = {"rows": in_range, "updated": 0, "changed_verdict": 0, "skipped_quota": 0}
    updated: dict[int, CaseResult] = {}
    case_moves: list[tuple[str, str, str, str]] = []   # old case id, new case id, json, shared html

    for i in range(1, items.Count + 1):
        item = items.Item(i)
        if item.Class != OL_MAIL_ITEM:
            continue
        received = received_time(item)
        if received < cutoff:
            break
        if end and received > end + timedelta(minutes=5):
            continue
        if not is_user_report(item, cfg):
            continue
        # Don't spend lookups on reports that aren't rows in range.
        if _key(_reporter(item), received.isoformat(sep=" ", timespec="minutes")) not in rows:
            continue
        workdir = Path(tempfile.mkdtemp(prefix="relog_", dir=workroot))
        try:
            analyzed = analyze_item(item, cfg, intel, workdir)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        quota_hit = False
        for result, raw, _ in analyzed:
            targets = [r for r in rows.get(_key(result.reported_by, result.reported_at), []) if r not in updated]
            if not targets:
                continue
            if any(_quota_error(e) for e in result.errors):
                stats["skipped_quota"] += 1
                quota_hit = True
                log.warning("Quota reached; row left unchanged: %s", result.original.get("subject", ""))
                continue
            row = targets[0]
            saved = save_case(result, cfg, store, raw or None)
            shared_html = publish_case(saved["html"], cfg)
            old_id = ws.cell(row, col["Case ID"]).value
            old_verdict = ws.cell(row, col["Verdict"]).value
            values = log_row(result, cfg, "Open report")
            for name, value in zip([c for c, _ in LOG_COLUMNS], values):
                if name in KEEP_COLUMNS or name not in col:
                    continue
                cell = ws.cell(row, col[name])
                cell.value = value
                cell.alignment = Alignment(vertical="top", wrap_text=True)
            link = ws.cell(row, col["Case Report"])
            link.hyperlink = os.path.relpath(shared_html, wb_path.parent)
            link.font = Font(color="0563C1", underline="single")
            verdict_cell = ws.cell(row, col["Verdict"])
            verdict_cell.fill = PatternFill("solid", fgColor=FILLS.get(result.verdict, "FFFFFF"))
            verdict_cell.font = Font(bold=True)
            updated[row] = result
            case_moves.append((old_id, result.case_id, str(saved["json"]), str(shared_html)))
            stats["updated"] += 1
            if old_verdict != result.verdict:
                stats["changed_verdict"] += 1
                log.info("Row %d: %s -> %s  %s", row, old_verdict, result.verdict, result.original.get("subject", ""))
        if quota_hit:
            log.warning("Stopping: a threat-intel quota ran out. Run relog again later for the remaining rows.")
            break

    # Rebuild the IOC sheet: fresh IOCs for updated cases, existing rows for cases not re-analyzed.
    iocs = wb["IOCs"]
    replaced = {old for old, _, _, _ in case_moves}
    kept = [list(r) for r in iocs.iter_rows(min_row=2, values_only=True) if r[0] not in replaced]
    iocs.delete_rows(2, iocs.max_row)
    for row in kept:
        iocs.append(row)
    for result in updated.values():
        if result.verdict not in ("MALICIOUS", "SUSPICIOUS"):
            continue
        for kind, values in result.iocs.items():
            for value in values:
                shown = defang_url(value) if kind == "urls" else defang_email(value) if kind == "emails" else \
                    value.replace(".", "[.]") if kind in ("domains", "ips") else value
                iocs.append([result.case_id, result.reported_at, result.verdict, kind, shown, value])

    fd, tmp_name = tempfile.mkstemp(suffix=".xlsx", prefix="~tmp_", dir=wb_path.parent)
    os.close(fd)
    try:
        wb.save(tmp_name)
        os.replace(tmp_name, wb_path)
    except PermissionError as exc:
        raise WorkbookLocked(f"{wb_path.name} is open in Excel; close it and run relog again: {exc}") from exc
    finally:
        Path(tmp_name).unlink(missing_ok=True)

    # Point today's summary at the new results.
    db: sqlite3.Connection = store.db
    for old_id, new_id, json_path, html in case_moves:
        day = db.execute("SELECT day FROM logged_cases WHERE case_id = ?", (old_id,)).fetchone()
        db.execute("DELETE FROM logged_cases WHERE case_id = ?", (old_id,))
        db.execute("INSERT OR REPLACE INTO logged_cases VALUES (?, ?, ?, ?)",
                   (new_id, day[0] if day else date.today().isoformat(), json_path, html))
    db.commit()
    refresh_daily(cfg, store.logged_cases_for(date.today().isoformat()))
    stats["backup"] = str(backup)
    return stats
