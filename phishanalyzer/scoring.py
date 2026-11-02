"""Turn findings into a verdict, confidence, recommended actions and an IOC list."""
from __future__ import annotations

from .models import CaseResult
from .utils import FREEMAIL_DOMAINS, domain_matches, domain_of, is_public_ip, registrable_domain

SEVERITY = {"CLEAN": 0, "SIMULATION": 1, "UNANALYZABLE": 2, "SUSPICIOUS": 3, "MALICIOUS": 4}

ACTIONS = {
    "MALICIOUS": [
        "Block the sender address/domain, the listed URLs and attachment hashes in the email gateway, proxy and EDR.",
        "Search and purge this message from all mailboxes (Message-ID / subject / sender).",
        "Check proxy and EDR logs for users who clicked the links or opened the attachments; "
        "reset their passwords and revoke sessions if they did.",
        "Add the IOCs to SIEM/EDR watchlists.",
    ],
    "SUSPICIOUS": [
        "Manual analyst review required before closing.",
        "Check whether other users received the same email; consider soft-deleting it pending review.",
    ],
    "CLEAN": [
        "No action required. Let the reporter know the email is safe.",
        "If it is unwanted marketing, block it as spam instead of phishing.",
    ],
    "SIMULATION": ["This is a phishing simulation. No incident; thank the reporter."],
    "UNANALYZABLE": ["Ask the reporter to report it again with the Phish Alert Button or Forward as Attachment (Ctrl+Alt+F)."],
}


def finalize(result: CaseResult, cfg: dict, intel_active: bool) -> CaseResult:
    thresholds = cfg["scoring"]
    hard = {f.hard_verdict for f in result.findings if f.hard_verdict}
    tags = result.tags
    score = max(0, min(100, sum(f.points for f in result.findings)))

    if "UNANALYZABLE" in hard:
        verdict, confidence = "UNANALYZABLE", "High"
    elif "SIMULATION" in hard:
        verdict, confidence = "SIMULATION", "High"
    elif "MALICIOUS" in hard:
        verdict, confidence = "MALICIOUS", "High"
        score = max(score, 90)
    elif "credential_lure" in tags and tags & {"lookalike", "new_domain", "internal_spoof"}:
        result.add("verdict", "Credential lure combined with a lookalike, new or spoofed domain", 0,
                   hard_verdict="MALICIOUS")
        verdict, confidence = "MALICIOUS", "High"
        score = max(score, 85)
    elif "internal_impersonation" in tags and tags & {"hr_lure", "credential_lure", "qr"}:
        result.add("verdict", "External sender impersonates our company with an HR/credential/QR lure", 0,
                   hard_verdict="MALICIOUS")
        verdict, confidence = "MALICIOUS", "High"
        score = max(score, 85)
    elif "qr" in tags and tags & {"credential_lure", "hr_lure", "bec", "brand_impersonation", "image_only", "victim_email"}:
        result.add("verdict", "QR-code phishing: QR code combined with a lure", 0, hard_verdict="MALICIOUS")
        verdict, confidence = "MALICIOUS", "High"
        score = max(score, 85)
    elif score >= thresholds["malicious"]:
        verdict, confidence = "MALICIOUS", "High" if score >= 80 else "Medium"
    elif score >= thresholds["suspicious"]:
        verdict, confidence = "SUSPICIOUS", "Medium"
    else:
        verdict = "CLEAN"
        confidence = "High" if intel_active and score < 15 else "Medium" if score < 15 else "Low"
        if not intel_active:
            result.notes.append("No threat-intel lookups ran, so a CLEAN verdict is based on static checks only.")

    result.verdict, result.score, result.confidence = verdict, score, confidence
    result.recommended_actions = list(ACTIONS[verdict])
    result.iocs = build_iocs(result, cfg)
    return result


def build_iocs(result: CaseResult, cfg: dict) -> dict[str, list[str]]:
    internal = cfg["heuristics"]["internal_domains"]
    emails = {result.original.get(k, "") for k in ("from_address", "reply_to", "return_path")}
    emails = sorted(e for e in emails if e and not domain_matches(domain_of(e), internal))
    domains = {registrable_domain(domain_of(e)) for e in emails}
    domains |= {u["domain"] for u in result.urls if not u.get("internal")}
    ip = result.originating_ip.get("ip", "")
    return {
        "ips": [ip] if ip and is_public_ip(ip) else [],
        "domains": sorted(d for d in domains if d and d not in FREEMAIL_DOMAINS),
        "urls": [u["url"] for u in result.urls if not u.get("internal")],
        "hashes": [a["sha256"] for a in result.attachments],
        "emails": emails,
    }


def worst(verdicts: list[str]) -> str:
    return max(verdicts, key=lambda v: SEVERITY.get(v, 0)) if verdicts else "UNANALYZABLE"
