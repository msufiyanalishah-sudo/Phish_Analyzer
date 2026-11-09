"""Reputation of the originating IP and the sender domains (From / Reply-To / Return-Path)."""
from __future__ import annotations

import logging

from ..intel import Intel, IntelError
from ..models import CaseResult
from ..utils import FREEMAIL_DOMAINS, defang_domain, domain_matches, domain_of, is_ip, is_public_ip, registrable_domain

log = logging.getLogger(__name__)


def reverse_dns(ip: str, timeout: float) -> str:
    try:
        import dns.resolver
        import dns.reversename
        answer = dns.resolver.resolve(dns.reversename.from_address(ip), "PTR", lifetime=timeout)
        return str(answer[0]).rstrip(".")
    except Exception:
        return ""


def analyze_sender(result: CaseResult, cfg: dict, intel: Intel) -> None:
    h = cfg["heuristics"]
    oi = result.originating_ip
    ip = oi.get("ip", "")
    if ip and is_public_ip(ip):
        if cfg["network"].get("dns_checks"):
            oi["ptr"] = reverse_dns(ip, 4)
        country = ""
        if intel.vt:
            try:
                vt = intel.vt.ip(ip)
                oi["virustotal"] = vt
                country = vt.get("country", "")
                oi["asn_owner"] = vt.get("as_owner", "")
                mal = vt.get("malicious", 0)
                if mal >= 3:
                    result.add("ip", "Sender IP flagged malicious on VirusTotal", 20, f"{ip}: {mal} engines", tags=["bad_ip"])
                elif mal >= 1:
                    result.add("ip", "Sender IP flagged by a few VirusTotal engines", 10, f"{ip}: {mal} engines")
            except IntelError as exc:
                result.errors.append(str(exc))
        if intel.abuse:
            try:
                ab = intel.abuse.check(ip)
                oi["abuseipdb"] = ab
                country = country or ab.get("countryCode") or ""
                score = ab.get("abuseConfidenceScore") or 0
                if score >= 50:
                    result.add("ip", "Sender IP has a high AbuseIPDB score", 15, f"{ip}: {score}% ({ab.get('totalReports')} reports)", tags=["bad_ip"])
                elif score >= 25:
                    result.add("ip", "Sender IP has some AbuseIPDB reports", 5, f"{ip}: {score}%")
            except IntelError as exc:
                result.errors.append(str(exc))
        oi["country"] = country
        allowed = [c.upper() for c in h.get("allowed_countries") or []]
        if allowed and country and country.upper() not in allowed:
            result.add("ip", "Sender IP is in an unexpected country", 5, f"{ip}: {country}")

    seen: dict[str, dict] = {}
    for role, addr in (("From", result.original.get("from_address")), ("Reply-To", result.original.get("reply_to")),
                       ("Return-Path", result.original.get("return_path"))):
        domain = registrable_domain(domain_of(addr or ""))
        if not domain or is_ip(domain) or domain_matches(domain, h["internal_domains"]) or domain in FREEMAIL_DOMAINS:
            continue
        if domain in seen:
            seen[domain]["roles"].append(role)
            continue
        info = seen[domain] = {"domain": domain, "roles": [role]}
        if intel.rdap and not domain_matches(domain, h["trusted_domains"] + h["protected_domains"]):
            try:
                rd = intel.rdap.lookup(domain)
                info["created"], info["age_days"], info["registrar"] = rd.get("created"), rd.get("age_days"), rd.get("registrar")
                age = rd.get("age_days")
                if age is not None and age < h["new_domain_days"]:
                    result.add("domain", f"{role} domain was registered very recently", 20 if role == "From" else 15,
                               f"{defang_domain(domain)} ({age} days old)", tags=["new_domain"])
            except IntelError as exc:
                result.errors.append(str(exc))
        if intel.vt:
            try:
                vt = intel.vt.domain(domain)
                info["virustotal"] = vt
                mal = vt.get("malicious", 0)
                total = sum(vt.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
                if mal >= cfg["intel"]["virustotal"].get("malicious_threshold_domain", 5):
                    # Whole sender domains collect stale detections (hacked sites, old spam): strong evidence, not proof.
                    result.add("domain", f"{role} domain flagged by many VirusTotal engines", 40,
                               f"{defang_domain(domain)}: {mal}/{total} engines", tags=["vt_domain_bad"])
                elif mal >= 1:
                    result.add("domain", f"{role} domain flagged by a few VirusTotal engines", 20,
                               f"{defang_domain(domain)}: {mal}/{total} engines (low; may be stale)", tags=["vt_low"])
            except IntelError as exc:
                result.errors.append(str(exc))
    result.sender_domains = list(seen.values())
