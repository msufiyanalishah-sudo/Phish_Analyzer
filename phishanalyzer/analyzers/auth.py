"""SPF / DKIM / DMARC / ARC / CompAuth results, plus a DNS lookup of the sender's DMARC policy."""
from __future__ import annotations

import logging
import re

from ..models import CaseResult
from ..parsing import ParsedEmail
from ..utils import defang_domain, domain_matches, domain_of, registrable_domain

log = logging.getLogger(__name__)


def parse_auth_results(msg) -> dict:
    headers = [" ".join(str(v).split()) for v in (msg.get_all("Authentication-Results") or [])]
    res = {"spf": "none", "dkim": "none", "dmarc": "none", "compauth": "", "arc": "",
           "header_from": "", "smtp_mailfrom": "", "reason": "", "source": "", "raw": headers}
    if headers:
        ar = headers[0]   # top-most = added by our own receiving server
        res["source"] = "Authentication-Results (top-most)"
        for mech in ("spf", "dmarc", "compauth", "arc"):
            m = re.search(rf"(?<![\w.-]){mech}=([a-z]+)", ar, re.I)
            if m:
                res[mech] = m.group(1).lower()
        dkim = [d.lower() for d in re.findall(r"(?<![\w.-])dkim=([a-z]+)", ar, re.I)]
        if dkim:
            res["dkim"] = "pass" if "pass" in dkim else dkim[0]
        for key, pattern in (("header_from", r"header\.from=([^\s;]+)"), ("smtp_mailfrom", r"smtp\.mailfrom=([^\s;]+)"),
                             ("reason", r"reason=(\d+)")):
            m = re.search(pattern, ar, re.I)
            if m:
                res[key] = m.group(1).lower()
    else:
        spf = msg.get("Received-SPF")
        if spf:
            res["spf"] = str(spf).split()[0].lower()
            res["source"] = "Received-SPF"
    if not res["arc"]:
        for value in msg.get_all("ARC-Authentication-Results") or []:
            m = re.search(r"(?<![\w.-])arc=([a-z]+)", str(value), re.I)
            if m:
                res["arc"] = m.group(1).lower()
                break
    return res


def lookup_dmarc(domain: str, timeout: float) -> dict:
    try:
        import dns.resolver
    except ImportError:
        return {"error": "dnspython not installed"}
    for name in dict.fromkeys([domain, registrable_domain(domain)]):
        try:
            answers = dns.resolver.resolve(f"_dmarc.{name}", "TXT", lifetime=timeout)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception as exc:
            return {"error": f"DNS lookup failed: {exc}"}
        for record in answers:
            txt = b"".join(record.strings).decode(errors="replace")
            if txt.lower().startswith("v=dmarc1"):
                policy = re.search(r"\bp=(\w+)", txt, re.I)
                return {"domain": name, "record": txt, "policy": policy.group(1).lower() if policy else "none"}
    return {"domain": domain, "record": "", "policy": "missing"}


def analyze_auth(pe: ParsedEmail, result: CaseResult, cfg: dict) -> None:
    msg = pe.message
    auth = parse_auth_results(msg)
    internal = cfg["heuristics"]["internal_domains"]
    from_dom = domain_of(result.original.get("from_address", ""))
    is_internal = domain_matches(from_dom, internal)
    if cfg["network"].get("dns_checks") and from_dom:
        auth["dmarc_dns"] = lookup_dmarc(from_dom, min(cfg["network"].get("timeout_seconds", 20), 8))
    result.auth = auth

    if not auth["raw"] and auth["source"] == "":
        result.notes.append("No Authentication-Results header: SPF/DKIM/DMARC verdicts come from DNS checks only.")
    if auth["dmarc"] == "fail":
        result.add("auth", "DMARC failed", 20, auth["raw"][0][:300] if auth["raw"] else "", tags=["auth_fail"])
    if auth["spf"] in ("fail", "hardfail"):
        result.add("auth", "SPF failed", 10, auth["smtp_mailfrom"], tags=["auth_fail"])
    elif auth["spf"] == "softfail":
        result.add("auth", "SPF softfail", 5, auth["smtp_mailfrom"])
    elif auth["spf"] in ("permerror", "temperror"):
        result.add("auth", f"SPF {auth['spf']}", 3, auth["smtp_mailfrom"])
    if auth["dkim"] == "fail":
        result.add("auth", "DKIM signature failed", 5)
    if auth["compauth"] == "fail":
        result.add("auth", "Microsoft composite authentication (compauth) failed", 10,
                   f"reason={auth['reason']}" if auth["reason"] else "", tags=["auth_fail"])

    authed_internal = msg.get("X-MS-Exchange-Organization-AuthAs", "").strip().lower() == "internal" or (
        auth["dmarc"] == "pass" and domain_matches(auth["header_from"] or from_dom, internal))
    if is_internal and authed_internal:
        result.add("auth", "Authenticated sender from our own domain", -20, defang_domain(from_dom), tags=["internal_authenticated"])
    elif is_internal and auth["dmarc"] in ("fail", "none") and auth["raw"]:
        result.add("auth", "Claims to be from our own domain but is not authenticated", 25, defang_domain(from_dom),
                   tags=["internal_spoof"])

    dmarc_dns = auth.get("dmarc_dns") or {}
    if not is_internal and from_dom and dmarc_dns.get("policy") in ("missing", "none") and auth["dmarc"] != "pass":
        result.add("auth", f"Sender domain has a weak DMARC policy ({dmarc_dns['policy']})", 5, defang_domain(from_dom))
