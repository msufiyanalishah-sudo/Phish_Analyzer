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


COMBINATIONS = [   # strong together, but only evidence for an analyst: they raise the score, never force MALICIOUS
    ({"credential_lure"}, {"lookalike", "new_domain", "internal_spoof"},
     "Credential lure combined with a lookalike, new or spoofed domain"),
    ({"internal_impersonation"}, {"hr_lure", "credential_lure", "qr"},
     "External sender impersonates our company with an HR/credential/QR lure"),
    ({"qr"}, {"credential_lure", "hr_lure", "bec", "brand_impersonation", "image_only", "victim_email"},
     "QR-code phishing pattern: QR code combined with a lure"),
]


def finalize(result: CaseResult, cfg: dict, intel_active: bool) -> CaseResult:
    """MALICIOUS only on confirmed evidence: a link flagged by enough VirusTotal vendors, a malicious attachment,
    or a link to a login page on a non-legitimate site. Everything else is at most SUSPICIOUS."""
    thresholds = cfg["scoring"]
    tags = result.tags
    authenticated = result.auth.get("dmarc") == "pass"
    for required, any_of, title in COMBINATIONS:
        if not (required <= tags and tags & any_of):
            continue
        # Recruiters and HR vendors legitimately mention our company with HR words. From an authenticated sender,
        # the company-name pattern counts only with a payload-like carrier (QR code or an attached email).
        if "internal_impersonation" in required and authenticated and not tags & {"qr", "nested_email"}:
            continue
        result.add("verdict", title, 30, tags=["high_risk_pattern"])
    _claude_veto(result, cfg)
    hard = {f.hard_verdict for f in result.findings if f.hard_verdict}
    score = max(0, min(100, sum(f.points for f in result.findings)))
    score_malicious = thresholds.get("allow_score_malicious", False) and score >= thresholds["malicious"]

    if "UNANALYZABLE" in hard:
        verdict, confidence = "UNANALYZABLE", "High"
    elif "SIMULATION" in hard:
        verdict, confidence = "SIMULATION", "High"
    elif "MALICIOUS" in hard or score_malicious:
        verdict, confidence = "MALICIOUS", "High"
        score = max(score, 90) if "MALICIOUS" in hard else score
    elif score >= thresholds["suspicious"]:
        verdict = "SUSPICIOUS"
        confidence = "High" if score >= thresholds["malicious"] else "Medium"   # high-risk: review first
    else:
        verdict = "CLEAN"
        confidence = "High" if intel_active and score < 15 else "Medium" if score < 15 else "Low"
        if not intel_active:
            result.notes.append("No threat-intel lookups ran, so a CLEAN verdict is based on static checks only.")

    result.verdict, result.score, result.confidence = verdict, score, confidence
    result.recommended_actions = list(ACTIONS[verdict])
    result.iocs = build_iocs(result, cfg)
    return result


def _claude_veto(result: CaseResult, cfg: dict) -> None:
    """Claude may cancel only a login-path-only MALICIOUS signal. The email text is attacker-controlled, so it
    can never cancel VirusTotal hits, malicious attachments or VirusTotal-confirmed login pages."""
    llm = result.llm or {}
    malicious = [f for f in result.findings if f.hard_verdict == "MALICIOUS"]
    if not malicious or not all("login_heuristic" in f.tags for f in malicious):
        return
    if llm.get("intent") in ("legitimate", "spam_marketing") and \
            llm.get("confidence", 0) >= cfg.get("llm", {}).get("veto_confidence", 85):
        for f in malicious:
            f.hard_verdict = None
        result.add("verdict", "Login-style link not confirmed: Claude judged the email legitimate, so it stays SUSPICIOUS",
                   0, f"{llm['intent']} ({llm['confidence']}%)")


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
