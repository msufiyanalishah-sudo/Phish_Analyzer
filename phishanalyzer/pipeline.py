"""Run every analyzer over one email and save the case."""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime
from pathlib import Path

from .analyzers.attachments import analyze_attachments
from .analyzers.auth import analyze_auth
from .analyzers.body import analyze_body
from .analyzers.headers import analyze_headers, hget
from .analyzers.llm import analyze_llm
from .analyzers.sender import analyze_sender
from .analyzers.urls import analyze_urls
from .config import resolve_path
from .intel import Intel
from .models import CaseResult
from .parsing import ParsedEmail, parse_email
from .report import write_reports
from .scoring import finalize
from .store import CaseStore

log = logging.getLogger(__name__)


def new_case_id(raw: bytes) -> str:
    return f"PH-{datetime.now():%Y%m%d-%H%M%S}-{hashlib.sha256(raw).hexdigest()[:6].upper()}"


def _step(result: CaseResult, name: str, fn, *args):
    try:
        return fn(*args)
    except Exception as exc:   # one broken check must not kill the whole case
        log.exception("%s failed", name)
        result.errors.append(f"{name} failed: {exc}")
        return None


def analyze_parsed(pe: ParsedEmail, cfg: dict, intel: Intel, reported_by: str = "", reported_at: str = "",
                   source: str = "") -> CaseResult:
    result = CaseResult(case_id=new_case_id(pe.raw), source=source or pe.filename, reported_by=reported_by,
                        reported_at=reported_at, analyzed_at=datetime.now().isoformat(timespec="seconds"),
                        message_sha256=hashlib.sha256(pe.raw).hexdigest())
    result.notes += pe.notes + intel.notes
    _step(result, "Header analysis", analyze_headers, pe, result, cfg)
    _step(result, "Authentication analysis", analyze_auth, pe, result, cfg)

    emails = pe.flatten()
    if len(emails) > 1:
        result.add("content", "Email carries another email as an attachment", 5,
                   ", ".join(e.filename for e in emails[1:]), tags=["nested_email"])
    texts = [t for e in emails for t in e.text_bodies]
    htmls = [t for e in emails for t in e.html_bodies]
    attachments = [a for e in emails for a in e.attachments]

    candidates = _step(result, "Body analysis", analyze_body, texts, htmls, result, cfg) or []
    candidates += _step(result, "Attachment analysis", analyze_attachments, attachments, result, cfg, intel) or []
    _step(result, "URL analysis", analyze_urls, candidates, result, cfg, intel)
    _step(result, "Sender reputation", analyze_sender, result, cfg, intel)
    _step(result, "Claude review", analyze_llm, pe, result, cfg, intel)
    return finalize(result, cfg, intel.active)


def analyze_bytes(data: bytes, filename: str, cfg: dict, intel: Intel, **meta) -> CaseResult:
    pe = parse_email(data, filename, max_depth=cfg["analysis"]["max_nested_depth"])
    return analyze_parsed(pe, cfg, intel, **meta)


def unanalyzable(cfg: dict, subject: str, reported_by: str = "", reported_at: str = "", source: str = "",
                 reason: str = "") -> CaseResult:
    raw = f"{subject}|{reported_by}|{reported_at}".encode()
    result = CaseResult(case_id=new_case_id(raw), source=source, reported_by=reported_by, reported_at=reported_at,
                        analyzed_at=datetime.now().isoformat(timespec="seconds"))
    result.original = {"subject": subject}
    result.add("report", "The report does not contain the original email as an attachment", 0,
               reason or "The reporter probably used a normal Forward, which drops the original headers.",
               hard_verdict="UNANALYZABLE")
    return finalize(result, cfg, False)


def analyze_report_bytes(data: bytes, filename: str, cfg: dict, intel: Intel, **meta) -> list[CaseResult]:
    """Treat `data` as a user's report (PAB / forward-as-attachment) and analyze every email attached to it."""
    wrapper = parse_email(data, filename, max_depth=cfg["analysis"]["max_nested_depth"])
    if not wrapper.nested:
        return [unanalyzable(cfg, hget(wrapper.message, "Subject"), source=filename, **meta)]
    return [analyze_parsed(child, cfg, intel, source=f"{filename} -> {child.filename}", **meta)
            for child in wrapper.nested]


def save_case(result: CaseResult, cfg: dict, store: CaseStore, raw: bytes | None = None) -> dict[str, Path]:
    key = store.dedupe_key(result)
    duplicate = store.find_duplicate(key)
    if duplicate and duplicate != result.case_id:
        result.duplicate_of = duplicate
        result.notes.append(f"The same email was already analyzed in case {duplicate}.")
    case_dir = resolve_path(cfg, cfg["outputs"]["report_dir"]) / result.case_id
    paths = write_reports(result, case_dir)
    if raw is not None and cfg["outputs"].get("save_raw_email"):
        qdir = resolve_path(cfg, cfg["outputs"]["quarantine_dir"]) / result.case_id
        qdir.mkdir(parents=True, exist_ok=True)
        (qdir / "original.eml.quarantine").write_bytes(raw)
    store.add_case(result, key, paths["html"])
    return paths
