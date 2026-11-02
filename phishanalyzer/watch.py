"""Continuous mode: pick up each new report as it lands in Outlook and add it to the shared team report."""
from __future__ import annotations

import logging
import shutil
import tempfile
import time
from datetime import date, datetime, timedelta
from pathlib import Path

from .config import resolve_path
from .intel import Intel
from .outlook_com import (OL_MAIL_ITEM, FolderNotFound, analyze_item, connect, find_folder, is_user_report,
                          print_summary, received_time)
from .notify import notify
from .pipeline import save_case
from .shared_log import WorkbookLocked, append_cases, publish_case, refresh_daily
from .store import CaseStore

log = logging.getLogger(__name__)


def watch_once(cfg: dict, intel: Intel, store: CaseStore) -> int:
    """Analyze reports not yet in the shared log (looking back `backfill_hours`). Returns how many were added."""
    ns = connect()
    folder = find_folder(ns, cfg["mailbox"].get("store", ""), cfg["mailbox"]["source_folder"])
    items = folder.Items
    items.Sort("[ReceivedTime]", True)
    cutoff = datetime.now() - timedelta(hours=cfg["watch"]["backfill_hours"])
    workroot = resolve_path(cfg, cfg["outputs"]["quarantine_dir"])
    workroot.mkdir(parents=True, exist_ok=True)

    pending = []   # items newest first; we log them oldest first
    for i in range(1, items.Count + 1):
        item = items.Item(i)
        if item.Class != OL_MAIL_ITEM:
            continue
        if received_time(item) < cutoff:
            break
        if is_user_report(item, cfg) and not store.is_logged(item.EntryID):
            pending.append(item)

    added = 0
    new = []   # (result, shared case html) analyzed in this cycle, for notifications
    for item in reversed(pending):
        entry_id = item.EntryID
        workdir = Path(tempfile.mkdtemp(prefix="watch_", dir=workroot))
        try:
            analyzed = analyze_item(item, cfg, intel, workdir)
        except Exception:
            log.exception("Could not analyze '%s'", item.Subject)
            continue
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        rows, cases = [], []
        for result, raw, _ in analyzed:
            paths = save_case(result, cfg, store, raw or None)
            shared_html = publish_case(paths["html"], cfg)
            rows.append((result, shared_html))
            cases.append((result.case_id, str(paths["json"]), str(shared_html)))
            print_summary(result, shared_html)
        try:
            append_cases(rows, cfg)
        except WorkbookLocked as exc:
            log.warning("%s", exc)
            break   # not marked as logged, so the next cycle retries it
        store.mark_logged([entry_id], cases)
        new.extend(rows)
        added += 1

    if added:
        daily = refresh_daily(cfg, store.logged_cases_for(date.today().isoformat()))
        log.info("Added %d report(s) to the shared log; today's summary: %s", added, daily)
        notify(new, cfg, store, daily)
    return added


def _single_instance_lock(cfg: dict):
    """Hold an exclusive lock for the life of the process; two watchers would write duplicate rows."""
    import msvcrt
    path = resolve_path(cfg, cfg["outputs"]["data_dir"]) / "watch.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "a+")
    try:
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError:
        handle.close()
        return None
    return handle


def watch_forever(cfg: dict, intel: Intel, store: CaseStore) -> None:
    lock = _single_instance_lock(cfg)
    if lock is None:
        log.error("Another watcher is already running; exiting.")
        return
    seconds = max(30, int(cfg["watch"]["poll_seconds"]))
    log.info("Watching '%s' every %ds -> %s. Press Ctrl+C to stop.",
             cfg["mailbox"]["source_folder"], seconds, cfg["shared_report"]["folder"])
    while True:
        try:
            watch_once(cfg, intel, store)
        except FolderNotFound as exc:
            log.error("%s", exc)
        except Exception:
            log.exception("Watch cycle failed; retrying next cycle")
        time.sleep(seconds)
