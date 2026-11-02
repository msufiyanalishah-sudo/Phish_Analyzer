"""Tell the analyst when the watcher finishes: a desktop popup for every email, an email alert for bad ones."""
from __future__ import annotations

import logging
from pathlib import Path

from .config import resolve_path
from .daily_report import current_user_address, group_entries, render_email, send_mail
from .models import CaseResult
from .store import CaseStore

log = logging.getLogger(__name__)

ICON = {"MALICIOUS": "\U0001F534", "SUSPICIOUS": "\U0001F7E0", "CLEAN": "\U0001F7E2", "SIMULATION": "\U0001F535",
        "UNANALYZABLE": "⚪"}
MAX_SINGLE_POPUPS = 3   # more than this in one cycle (e.g. after a restart) -> one summary popup


def _popup(title: str, message: str, target: Path | None, urgent: bool = False) -> None:
    from winotify import Notification, audio
    toast = Notification(app_id="Phish Analyzer", title=title[:120], msg=message[:250],
                         duration="long" if urgent else "short",
                         launch=target.resolve().as_uri() if target else "")
    toast.set_audio(audio.Reminder if urgent else audio.Default, loop=False)
    if target:
        toast.add_actions(label="Open report", launch=target.resolve().as_uri())
    toast.show()


def desktop_popups(new: list[tuple[CaseResult, Path]], daily: Path | None) -> None:
    if len(new) <= MAX_SINGLE_POPUPS:
        for r, html in new:
            o = r.original
            _popup(f"{ICON.get(r.verdict, '')} {r.verdict} (score {r.score}): {o.get('subject', '')}",
                   f"From: {o.get('from_address', '')}\nReported by: {r.reported_by}", html,
                   urgent=r.verdict in ("MALICIOUS", "SUSPICIOUS"))
        return
    counts: dict[str, int] = {}
    for r, _ in new:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    order = ("MALICIOUS", "SUSPICIOUS", "CLEAN", "SIMULATION", "UNANALYZABLE")
    summary = ", ".join(f"{counts[v]} {v.title()}" for v in order if v in counts)
    _popup(f"Phish Analyzer: {len(new)} new reports analyzed", summary + "\nClick to open today's summary.", daily,
           urgent=bool(counts.get("MALICIOUS") or counts.get("SUSPICIOUS")))


def _as_list(value) -> list[str]:
    if not value:
        return []
    return [v.strip() for v in (value.split(";") if isinstance(value, str) else value) if v and v.strip()]


def recipients(verdict: str, cfg: dict) -> tuple[str, str]:
    """(to, cc) for a verdict: notifications.recipients.<VERDICT>, else notifications.to, else the signed-in user."""
    ncfg = cfg["notifications"]
    per = (ncfg.get("recipients") or {}).get(verdict) or {}
    to = _as_list(per.get("to")) or _as_list(ncfg.get("to")) or _as_list(cfg["daily_report"].get("to"))
    if not to:
        from .outlook_com import connect
        to = [current_user_address(connect())]
    return "; ".join(to), "; ".join(_as_list(per.get("cc")))


def email_alerts(new: list[tuple[CaseResult, Path]], cfg: dict, store: CaseStore) -> int:
    """One alert email per new malicious/suspicious email or campaign (not one per copy)."""
    ncfg = cfg["notifications"]
    entries = [{"result": r, "raw": b"", "name": "", "entry_id": r.case_id, "report": str(html)} for r, html in new]
    sent = 0
    for group in group_entries(entries):
        r = group["result"]
        if r.verdict not in ncfg["email_verdicts"] or store.was_alerted(group["key"]):
            continue
        copies = len(group["entry_ids"])
        heading = f"{r.verdict}: phishing report needs action"
        intro = (f"Analyzed just now from \"{cfg['mailbox']['source_folder']}\": {copies} report(s), reported by "
                 f"{', '.join(group['reporters']) or 'unknown'}. Full details are in the shared Phishing Alert log.")
        _, html = render_email([group], 0, cfg, [], heading=heading, intro=intro)
        subject = f"[{r.verdict}] Phish Alert: {r.original.get('subject', '')[:90]}" + (f" ({copies} reports)" if copies > 1 else "")
        to, cc = recipients(r.verdict, cfg)
        send_mail(to, subject, html, [], resolve_path(cfg, cfg["outputs"]["quarantine_dir"]), cc=cc)
        store.mark_alerted(group["key"])
        sent += 1
        log.info("Alert email sent to %s (cc %s): %s", to, cc or "-", subject)
    return sent


def notify(new: list[tuple[CaseResult, Path]], cfg: dict, store: CaseStore, daily: Path | None) -> None:
    ncfg = cfg["notifications"]
    if not new:
        return
    if ncfg.get("desktop"):
        try:
            desktop_popups(new, daily)
        except Exception:
            log.exception("Desktop popup failed")
    if ncfg.get("email_alerts"):
        try:
            email_alerts(new, cfg, store)
        except Exception:
            log.exception("Alert email failed")
