"""Read reports from an Outlook folder through Classic Outlook (COM), analyze them, tag and move them."""
from __future__ import annotations

import logging
import re
import shutil
import tempfile
import time
from datetime import datetime
from pathlib import Path

from .config import resolve_path
from .intel import Intel
from .models import CaseResult
from .pipeline import analyze_bytes, save_case, unanalyzable
from .scoring import worst
from .store import CaseStore

log = logging.getLogger(__name__)

OL_MAIL_ITEM = 43
OL_EMBEDDED_ITEM = 5
OL_MSG_FORMAT = 3
OL_INBOX = 6
FORWARD_PREFIX = re.compile(r"^\s*(fw|fwd|tr|wg)\s*:", re.I)


class FolderNotFound(Exception):
    pass


def connect():
    try:
        import pythoncom
        import win32com.client
    except ImportError as exc:
        raise RuntimeError("pywin32 is not installed. Run: pip install pywin32") from exc
    pythoncom.CoInitialize()
    return win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")


def _child(folder, name: str):
    for sub in folder.Folders:
        if sub.Name.lower() == name.lower():
            return sub
    return None


def _walk(root, parts: list[str]):
    folder = root
    for part in parts:
        folder = _child(folder, part)
        if folder is None:
            return None
    return folder


def find_folder(ns, store_name: str, path: str):
    parts = [p for p in re.split(r"[\\/]", path) if p]
    roots = [ns.Folders.Item(store_name)] if store_name else [ns.DefaultStore.GetRootFolder(), ns.GetDefaultFolder(OL_INBOX)]
    for root in roots:
        folder = _walk(root, parts)
        if folder is not None:
            return folder
    raise FolderNotFound(f"Outlook folder '{path}' not found in {'mailbox ' + store_name if store_name else 'your default mailbox'}. "
                         "Run 'python -m phishanalyzer list-folders' to see the exact names.")


def ensure_subfolder(parent, name: str):
    return _child(parent, name) or parent.Folders.Add(name)


def list_folders(cfg: dict, depth: int = 3) -> None:
    ns = connect()

    def show(folder, level):
        print("  " * level + f"- {folder.Name}  ({folder.Items.Count} items)")
        if level < depth:
            for sub in folder.Folders:
                show(sub, level + 1)

    for store in ns.Folders:
        show(store, 0)


def _reporter(item) -> str:
    try:
        if item.SenderEmailType == "EX":
            user = item.Sender.GetExchangeUser()
            if user:
                return user.PrimarySmtpAddress
    except Exception:
        pass
    return item.SenderEmailAddress or ""


def _safe_name(name: str) -> str:
    return re.sub(r"[^\w.\- ]", "_", name)[:120] or "attachment"


def received_time(item) -> datetime:
    """Outlook returns local time; drop pywin32's tzinfo so it compares with datetime.now()."""
    t = item.ReceivedTime
    return datetime(t.year, t.month, t.day, t.hour, t.minute, t.second)


def is_user_report(item, cfg: dict) -> bool:
    """True for a user's report (e.g. '[Phish Alert] ...'); False for team replies like 'RE: [Phish Alert] ...'."""
    pattern = cfg["mailbox"].get("report_subject_regex") or ""
    return not pattern or re.search(pattern, item.Subject or "", re.I) is not None


def analyze_item(item, cfg: dict, intel: Intel, workdir: Path) -> list[tuple[CaseResult, bytes, str]]:
    """Analyze every email attached to one Outlook report. Returns (result, raw email bytes, attachment name)."""
    reporter = _reporter(item)
    reported_at = received_time(item).isoformat(sep=" ", timespec="minutes")
    subject = item.Subject or ""
    meta = {"reported_by": reporter, "reported_at": reported_at}
    results: list[CaseResult] = []
    raws: list[bytes] = []
    names: list[str] = []

    for i in range(1, item.Attachments.Count + 1):
        att = item.Attachments.Item(i)
        name = att.FileName or f"attachment{i}"
        embedded = att.Type == OL_EMBEDDED_ITEM
        if not (embedded or name.lower().endswith((".eml", ".msg"))):
            continue
        if embedded and not name.lower().endswith((".msg", ".eml")):
            name += ".msg"
        path = workdir / f"{i}_{_safe_name(name)}"
        att.SaveAsFile(str(path))
        data = path.read_bytes()
        log.info("Analyzing '%s' reported by %s", name, reporter)
        results.append(analyze_bytes(data, name, cfg, intel, source=f"Outlook: {subject} / {name}", **meta))
        raws.append(data)
        names.append(name)

    if not results:
        is_report = bool(cfg["mailbox"].get("report_subject_regex"))
        if is_report or FORWARD_PREFIX.match(subject) or not cfg["mailbox"].get("analyze_item_without_attachment", True):
            results.append(unanalyzable(cfg, subject, source=f"Outlook: {subject}", **meta))
            raws.append(b"")
            names.append("")
        else:
            # The phishing email itself was moved/redirected into the folder: analyze the item directly.
            path = workdir / "item.msg"
            item.SaveAs(str(path), OL_MSG_FORMAT)
            data = path.read_bytes()
            results.append(analyze_bytes(data, "item.msg", cfg, intel, source=f"Outlook item: {subject}", **meta))
            raws.append(data)
            names.append("item.msg")
    return list(zip(results, raws, names))


def process_item(item, cfg: dict, intel: Intel, store: CaseStore, workdir: Path) -> list[CaseResult]:
    analyzed = analyze_item(item, cfg, intel, workdir)
    results = [r for r, _, _ in analyzed]
    for result, raw, _ in analyzed:
        paths = save_case(result, cfg, store, raw or None)
        print_summary(result, paths["html"])
    return results


def _tag_and_move(item, source_folder, verdict: str, cfg: dict) -> None:
    mcfg = cfg["mailbox"]
    category = f"{mcfg['category_prefix']}{verdict.title()}"
    existing = [c.strip() for c in (item.Categories or "").split(",") if c.strip()]
    item.Categories = ", ".join(existing + [category])
    item.UnRead = False
    item.Save()
    if mcfg.get("move_processed"):
        processed = ensure_subfolder(source_folder, mcfg["processed_subfolder"])
        item.Move(ensure_subfolder(processed, verdict.title()))


def process_once(cfg: dict, intel: Intel, store: CaseStore) -> int:
    ns = connect()
    mcfg = cfg["mailbox"]
    folder = find_folder(ns, mcfg.get("store", ""), mcfg["source_folder"])
    items = folder.Items
    snapshot = [items.Item(i) for i in range(1, items.Count + 1)]   # Move() changes the live collection
    prefix = mcfg["category_prefix"]
    workroot = resolve_path(cfg, cfg["outputs"]["quarantine_dir"])
    workroot.mkdir(parents=True, exist_ok=True)
    count = 0
    for item in snapshot:
        try:
            if item.Class != OL_MAIL_ITEM or not is_user_report(item, cfg):
                continue
            if any(c.strip().startswith(prefix) for c in (item.Categories or "").split(",")):
                continue
            if store.is_processed(item.EntryID):
                continue
            workdir = Path(tempfile.mkdtemp(prefix="case_", dir=workroot))
            try:
                results = process_item(item, cfg, intel, store, workdir)
            finally:
                shutil.rmtree(workdir, ignore_errors=True)
            entry_id = item.EntryID
            _tag_and_move(item, folder, worst([r.verdict for r in results]), cfg)
            store.mark_processed(entry_id, [r.case_id for r in results])
            count += 1
        except Exception:
            log.exception("Failed to process an item in '%s'", mcfg["source_folder"])
    log.info("Processed %d new report(s) from '%s'", count, mcfg["source_folder"])
    return count


def run_forever(cfg: dict, intel: Intel, store: CaseStore) -> None:
    minutes = max(1, int(cfg["mailbox"].get("poll_minutes", 5)))
    log.info("Watching '%s' every %d minute(s). Press Ctrl+C to stop.", cfg["mailbox"]["source_folder"], minutes)
    while True:
        try:
            process_once(cfg, intel, store)
        except FolderNotFound as exc:
            log.error("%s", exc)
        except Exception:
            log.exception("Polling run failed")
        time.sleep(minutes * 60)


def print_summary(result: CaseResult, report_path: Path | None = None) -> None:
    o = result.original
    print("")
    print("=" * 78)
    print(f" {result.verdict}  |  score {result.score}/100  |  confidence {result.confidence}  |  {result.case_id}")
    print("=" * 78)
    print(f" Subject : {o.get('subject', '')}")
    print(f" From    : {o.get('from', '')}")
    if result.reported_by:
        print(f" Reporter: {result.reported_by}")
    top = sorted(result.findings, key=lambda f: (f.hard_verdict is None, -f.points))[:8]
    if top:
        print(" Top findings:")
        for f in top:
            pts = f"[{f.hard_verdict}]" if f.hard_verdict else f"[{f.points:+d}]"
            print(f"   {pts:<14} {f.title}" + (f"  ({f.evidence[:90]})" if f.evidence else ""))
    for err in result.errors[:3]:
        print(f" ! {err}")
    if report_path:
        print(f" Report  : {report_path}")
