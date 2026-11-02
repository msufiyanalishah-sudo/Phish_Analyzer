"""Identity/spoofing checks, Received-chain hops and the originating IP."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr, parsedate_to_datetime

from ..models import CaseResult
from ..parsing import ParsedEmail
from ..utils import (ESP_DOMAINS, FREEMAIL_DOMAINS, defang_domain, domain_matches, domain_of, is_ip, is_public_ip,
                     lookalike_of, registrable_domain)

SUSPICIOUS_MAILERS = ("phpmailer", "php/", "sendblaster", "gammadyne", "atomic mail", "mass mail",
                      "bulk mail", "king-phisher", "gophish", "swaks")
TRUSTED_INFRA_SUFFIXES = (".outlook.com", ".office365.com", ".microsoft.com", ".exchangelabs.com")
SENDER_IP_RE = re.compile(r"sender IP is ([0-9a-fA-F:.]+)", re.I)
IP_CANDIDATE_RE = re.compile(r"[0-9a-fA-F:.]{7,}")


def hget(msg, name: str) -> str:
    try:
        value = msg.get(name)
    except Exception:
        return ""
    return " ".join(str(value).split()) if value is not None else ""


def analyze_headers(pe: ParsedEmail, result: CaseResult, cfg: dict) -> None:
    msg = pe.message
    h = cfg["heuristics"]
    internal = h["internal_domains"]
    from_name, from_addr = parseaddr(hget(msg, "From"))
    reply_to = parseaddr(hget(msg, "Reply-To"))[1]
    return_path = parseaddr(hget(msg, "Return-Path"))[1]
    result.original = {
        "from": hget(msg, "From"), "from_address": from_addr, "display_name": from_name,
        "reply_to": reply_to, "return_path": return_path, "to": hget(msg, "To"), "cc": hget(msg, "Cc"),
        "subject": hget(msg, "Subject"), "date": hget(msg, "Date"), "message_id": hget(msg, "Message-ID"),
        "x_mailer": hget(msg, "X-Mailer") or hget(msg, "User-Agent"),
        "x_originating_ip": hget(msg, "X-Originating-IP").strip("[]"),
    }

    from_dom = domain_of(from_addr)
    from_reg = registrable_domain(from_dom)
    if not from_addr or not from_dom:
        result.add("header", "From address is missing or invalid", 15, result.original["from"] or "(empty)")

    rp_dom = domain_of(return_path)
    if rp_dom and from_reg and registrable_domain(rp_dom) != from_reg and not domain_matches(rp_dom, ESP_DOMAINS):
        result.add("header", "Return-Path domain differs from From domain", 10,
                   f"From: {defang_domain(from_reg)} / Return-Path: {defang_domain(rp_dom)}")

    rt_dom = domain_of(reply_to)
    if rt_dom and from_reg and registrable_domain(rt_dom) != from_reg:
        if registrable_domain(rt_dom) in FREEMAIL_DOMAINS:
            result.add("header", "Reply-To goes to a free email provider", 15, defang_domain(rt_dom), tags=["reply_to_mismatch"])
        else:
            result.add("header", "Reply-To domain differs from From domain", 10, defang_domain(rt_dom), tags=["reply_to_mismatch"])

    embedded = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", from_name or "")
    if embedded and any(e.lower() != from_addr.lower() for e in embedded):
        result.add("header", "Display name contains a different email address", 15, from_name, tags=["display_name_spoof"])

    if not domain_matches(from_dom, internal):
        for vip in h.get("vip_names") or []:
            if vip and vip.lower() in (from_name or "").lower():
                result.add("header", "External sender uses an executive's name", 25,
                           f"'{from_name}' from {defang_domain(from_dom)}", tags=["vip_impersonation"])
                break

    seen = set()
    for role, dom in (("From", from_dom), ("Reply-To", rt_dom), ("Return-Path", rp_dom)):
        if not dom or dom in seen:
            continue
        seen.add(dom)
        target = lookalike_of(dom, h["protected_domains"] + internal, h["trusted_domains"])
        if target:
            result.add("header", f"{role} domain looks like {target}", 25, defang_domain(dom), tags=["lookalike"])
        if "xn--" in dom:
            result.add("header", f"{role} domain uses punycode (possible homoglyph)", 15, defang_domain(dom), tags=["lookalike"])

    msgid_dom = result.original["message_id"].strip("<>").rsplit("@", 1)[-1].lower() if "@" in result.original["message_id"] else ""
    if msgid_dom and from_reg and registrable_domain(msgid_dom) != from_reg and not msgid_dom.endswith(TRUSTED_INFRA_SUFFIXES + (".prod.outlook.com",)):
        result.add("header", "Message-ID domain differs from sender domain", 3, defang_domain(msgid_dom))

    try:
        sent = parsedate_to_datetime(result.original["date"]) if result.original["date"] else None
        if sent and sent.tzinfo and sent > datetime.now(timezone.utc) + timedelta(days=1):
            result.add("header", "Date header is in the future", 5, result.original["date"])
    except (TypeError, ValueError):
        result.add("header", "Date header could not be parsed", 3, result.original["date"])

    mailer = result.original["x_mailer"].lower()
    if any(s in mailer for s in SUSPICIOUS_MAILERS):
        result.add("header", "Sent with a bulk/scripted mailer", 5, result.original["x_mailer"])

    # Phishing-simulation markers (KnowBe4, Cofense, GoPhish ...).
    header_names = {k.lower() for k in msg.keys()}
    markers = [m for m in h.get("simulation_markers") or [] if m.lower() in header_names]

    result.hops = parse_received(msg)
    ip, source = originating_ip(msg, result.hops, internal)
    result.originating_ip = {"ip": ip, "source": source}

    if markers:
        allowed_ips = h.get("simulation_sender_ips") or []
        if allowed_ips and ip not in allowed_ips:
            result.add("header", "Phishing-simulation header from an unexpected IP (possible fake)", 30,
                       f"{', '.join(markers)} from {ip or 'unknown IP'}")
        else:
            result.add("header", "Phishing-simulation header present", 0, ", ".join(markers), hard_verdict="SIMULATION")

    _company_name_abuse(pe, result, cfg, from_dom)

    for hop in result.hops:
        if hop.get("delay_seconds") is not None and hop["delay_seconds"] < -300:
            result.add("header", "Received timestamps are out of order (possible forged hops)", 5,
                       f"{hop['from_host']} -> {hop['by_host']}")
            break


def _company_name_abuse(pe: ParsedEmail, result: CaseResult, cfg: dict, from_dom: str) -> None:
    """External sender putting our company name in the subject, sender name or attachment names
    (e.g. 'Contoso SALARY INCREASE NOTICE.eml' sent from a random German domain)."""
    h = cfg["heuristics"]
    internal = h["internal_domains"]
    if not internal or domain_matches(from_dom, internal):
        return
    names = [n.lower() for n in h.get("org_names") or []] + [registrable_domain(d).split(".")[0] for d in internal]
    names = [n for n in dict.fromkeys(names) if len(n) >= 4]
    emails = pe.flatten()
    places = [result.original.get("subject", ""), result.original.get("display_name", "")]
    places += [e.filename for e in emails[1:]] + [a.filename for e in emails for a in e.attachments]
    hits = [p for p in places if p and any(n in p.lower() for n in names)]
    if hits:
        result.add("header", "External email uses our company name in the subject, sender name or attachment", 10,
                   "; ".join(hits[:3]), tags=["internal_impersonation"])


def parse_received(msg) -> list[dict]:
    hops = []
    for raw in msg.get_all("Received") or []:
        text = " ".join(str(raw).split())
        m_from = re.search(r"\bfrom\s+(.+?)(?=\sby\s|;|$)", text, re.I)
        m_by = re.search(r"\bby\s+(\S+)", text, re.I)
        from_part = (m_from.group(1) if m_from else "").replace("IPv6:", " ")
        ips = [c.strip(".:") for c in IP_CANDIDATE_RE.findall(from_part)]
        ips = [c for c in ips if is_ip(c)]
        stamp = text.rsplit(";", 1)[1].strip() if ";" in text else ""
        try:
            when = parsedate_to_datetime(stamp) if stamp else None
        except (TypeError, ValueError):
            when = None
        hops.append({
            "from_host": from_part.split()[0] if from_part.split() else "",
            "from_ip": ips[0] if ips else "",
            "by_host": m_by.group(1) if m_by else "",
            "timestamp": when.isoformat() if when else stamp,
            "_dt": when,
        })
    hops.reverse()  # oldest hop first
    for i, hop in enumerate(hops):
        prev = hops[i - 1]["_dt"] if i else None
        cur = hop["_dt"]
        hop["delay_seconds"] = int((cur - prev).total_seconds()) if prev and cur and prev.tzinfo and cur.tzinfo else None
    for hop in hops:
        hop.pop("_dt")
    return hops


def originating_ip(msg, hops: list[dict], internal_domains) -> tuple[str, str]:
    for value in msg.get_all("Authentication-Results") or []:
        m = SENDER_IP_RE.search(str(value))
        if m and is_ip(m.group(1)):
            return m.group(1), "Authentication-Results (sender IP)"
    for hop in reversed(hops):   # newest first: first external host that handed mail to our side
        ip, host = hop["from_ip"], hop["from_host"].lower()
        if not ip or not is_public_ip(ip):
            continue
        if host.endswith(TRUSTED_INFRA_SUFFIXES) or domain_matches(host, internal_domains):
            continue
        return ip, "Received chain (first external hop)"
    for hop in hops:
        if hop["from_ip"] and is_public_ip(hop["from_ip"]):
            return hop["from_ip"], "Received chain (earliest public IP)"
    return "", ""
