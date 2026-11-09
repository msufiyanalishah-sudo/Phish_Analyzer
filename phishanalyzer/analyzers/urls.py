"""URL extraction, Safe Links unwrapping, heuristics, VirusTotal and domain-age checks."""
from __future__ import annotations

import base64
import logging
import re
from collections import defaultdict
from urllib.parse import parse_qs, unquote, urlsplit

from ..intel import Intel, IntelError
from ..models import CaseResult
from ..utils import (ESP_DOMAINS, defang_domain, defang_url, domain_matches, domain_of, is_ip, lookalike_of,
                     registrable_domain, url_host)

log = logging.getLogger(__name__)

URL_RE = re.compile(r"(?i)\b(?:https?|hxxps?)://[^\s<>\"'`]+|\bwww\.[a-z0-9-]+(?:\.[a-z0-9-]+)+[^\s<>\"'`]*")
TRAILING = ".,;:!?)]}'\""
IGNORED_HOSTS = {"www.w3.org", "w3.org", "schemas.microsoft.com", "schemas.openxmlformats.org", "purl.org",
                 "ns.adobe.com", "schema.org", "www.schema.org"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly", "buff.ly",
              "shorturl.at", "rb.gy", "t.ly", "s.id", "tiny.cc", "v.gd", "qrco.de", "bl.ink", "lnkd.in", "tr.im"}
FREE_HOSTING = ("web.app", "firebaseapp.com", "pages.dev", "workers.dev", "ngrok.io", "ngrok-free.app", "glitch.me",
                "weebly.com", "wixsite.com", "000webhostapp.com", "github.io", "netlify.app", "vercel.app",
                "herokuapp.com", "blogspot.com", "r2.dev", "azurewebsites.net", "web.core.windows.net",
                "blob.core.windows.net", "firebasestorage.googleapis.com", "storage.googleapis.com", "onrender.com",
                "repl.co", "notion.site", "ipfs.io", "dweb.link", "forms.gle", "sites.google.com", "jotform.com",
                "formstack.com", "typeform.com", "square.site", "godaddysites.com")
FILE_SHARING = ("wetransfer.com", "we.tl", "dropbox.com", "dropboxusercontent.com", "mega.nz", "drive.google.com",
                "1drv.ms", "onedrive.live.com", "box.com", "mediafire.com", "sendspace.com", "transfernow.net",
                "smash.gg", "filemail.com", "pcloud.link", "4shared.com", "zippyshare.com", "gofile.io", "files.fm")
FREE_HOSTING_PATHS = ("docs.google.com/forms", "forms.office.com", "forms.microsoft.com")
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "icu", "cyou", "sbs", "rest",
                   "quest", "lol", "bond", "cfd", "buzz", "monster", "work", "link", "support", "live", "ru", "su"}
LOGIN_WORDS = ("login", "signin", "sign-in", "logon", "verify", "verification", "account", "secure", "update",
               "password", "auth", "wp-admin", "wp-content", "wp-includes", "webmail", "owa", "invoice", "payment")

# flag -> (points, title, tags)
FLAG_RULES = {
    "lookalike": (25, "Link domain imitates a protected brand/domain", ["lookalike"]),
    "ip_host": (15, "Link points to a raw IP address", []),
    "punycode": (15, "Link uses a punycode (homoglyph) domain", ["lookalike"]),
    "userinfo": (10, "Link hides its real host with '@'", []),
    "shortener": (10, "Link uses a URL shortener", []),
    "free_hosting": (10, "Link is on free hosting / form service", ["free_hosting"]),
    "open_redirect": (10, "Link contains a redirect to another URL", []),
    "suspicious_tld": (5, "Link uses a high-risk top-level domain", []),
    "many_subdomains": (5, "Link has an unusually long subdomain chain", []),
    "file_share": (10, "Link to a file-sharing service or another company's SharePoint (common payload delivery)", ["file_share"]),
    "victim_email": (15, "Link carries the recipient's email address (personalized phishing page)", ["victim_email"]),
    "login_path": (5, "Link path looks like a login/verification page", []),
    "plain_http_login": (5, "Login-style link without HTTPS", []),
}


def normalize_url(raw: str) -> str:
    url = (raw or "").strip().strip("<>\"'")
    while url and url[-1] in TRAILING:
        url = url[:-1]
    if url.lower().startswith("hxxp"):
        url = "http" + url[4:]
    url = url.replace("[.]", ".").replace("(.)", ".")
    if url.lower().startswith("www."):
        url = "http://" + url
    return url if url.lower().startswith(("http://", "https://")) else ""


def extract_urls(text: str) -> list[str]:
    return [m.group(0) for m in URL_RE.finditer(text or "")]


def unwrap_url(url: str, depth: int = 0) -> str:
    """Return the real destination behind Safe Links / URL Defense / Google redirect wrappers."""
    if depth > 5:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    host = (parts.hostname or "").lower()
    qs = parse_qs(parts.query)
    if host.endswith("safelinks.protection.outlook.com") and "url" in qs:
        return unwrap_url(qs["url"][0], depth + 1)
    if host == "urldefense.proofpoint.com" and "u" in qs:
        return unwrap_url(unquote(qs["u"][0].replace("-", "%").replace("_", "/")), depth + 1)
    if host == "urldefense.com" and "/v3/__" in url:
        return unwrap_url(url.split("/v3/__", 1)[1].split("__", 1)[0], depth + 1)
    if host in ("www.google.com", "google.com") and parts.path == "/url":
        target = (qs.get("q") or qs.get("url") or [""])[0]
        if target.startswith("http"):
            return unwrap_url(target, depth + 1)
    return url


EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")


def _carries_email(url: str) -> bool:
    """Phishing kits pre-fill the victim's address: ?email=user@corp.com, base64 of it, or #user@corp.com."""
    text = unquote(url.split("://", 1)[-1])
    if EMAIL_RE.search(text.split("/", 1)[-1]):
        return True
    for token in B64_TOKEN_RE.findall(text):
        try:
            decoded = base64.b64decode(token.replace("-", "+").replace("_", "/") + "=" * (-len(token) % 4)).decode("utf-8")
        except Exception:
            continue
        if EMAIL_RE.fullmatch(decoded.strip()):
            return True
    return False


def _is_file_share(host: str, path: str, internal) -> bool:
    if host.endswith(".sharepoint.com"):
        tenant = host.split(".")[0].removesuffix("-my")
        return tenant not in {registrable_domain(d).split(".")[0] for d in internal}   # another company's tenant
    if host == "docs.google.com":
        return not path.startswith("/forms")
    return domain_matches(host, FILE_SHARING)


def _flags(entry: dict, protected, trusted, internal=()) -> list[str]:
    host = entry["host"]
    try:
        parts = urlsplit(entry["url"])
    except ValueError:
        return []
    path = f"{parts.path}?{parts.query}".lower()
    flags = []
    if _is_file_share(host, parts.path.lower(), internal):
        flags.append("file_share")
    if domain_matches(host, list(trusted) + list(protected)):
        return flags   # genuine brand domains (Microsoft quarantine links etc.) - only VirusTotal judges these
    target = lookalike_of(host, protected, trusted)
    if target:
        flags.append("lookalike")
        entry["lookalike_of"] = target
    if is_ip(host):
        flags.append("ip_host")
    if "xn--" in host:
        flags.append("punycode")
    if "@" in parts.netloc:
        flags.append("userinfo")
    if host in SHORTENERS or entry["domain"] in SHORTENERS:
        flags.append("shortener")
    host_path = host + parts.path.lower()
    if domain_matches(host, FREE_HOSTING) or host_path.startswith(FREE_HOSTING_PATHS):
        flags.append("free_hosting")
    if re.search(r"(?i)(?:^|[?&])(?:redirect|redir|url|next|goto|target|dest|continue|return)=(?:https?|%68%74%74%70)", parts.query or ""):
        flags.append("open_redirect")
    if not is_ip(host) and host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        flags.append("suspicious_tld")
    if host.count(".") >= 4:
        flags.append("many_subdomains")
    if _carries_email(entry["url"]):
        flags.append("victim_email")
    if any(w in path for w in LOGIN_WORDS):
        flags.append("login_path")
        if parts.scheme == "http":
            flags.append("plain_http_login")
    return flags


def analyze_urls(candidates: list[tuple[str, str]], result: CaseResult, cfg: dict, intel: Intel) -> None:
    h = cfg["heuristics"]
    internal = h["internal_domains"]
    entries: dict[str, dict] = {}
    for raw, source in candidates:
        url = normalize_url(raw)
        if not url:
            continue
        final = unwrap_url(url)
        host = url_host(final)
        if not host or host in IGNORED_HOSTS:
            continue
        entry = entries.get(final)
        if entry is None:
            entry = entries[final] = {
                "url": final, "url_defanged": defang_url(final), "wrapped_url": url if url != final else "",
                "host": host, "domain": registrable_domain(host), "sources": [], "flags": [],
                "internal": domain_matches(host, internal), "virustotal": None, "domain_age_days": None,
            }
        if source not in entry["sources"]:
            entry["sources"].append(source)

    groups: dict[str, list[str]] = defaultdict(list)
    for entry in entries.values():
        if entry["internal"]:
            continue
        entry["flags"] = _flags(entry, h["protected_domains"] + internal, h["trusted_domains"], internal)
        for flag in entry["flags"]:
            groups[flag].append(entry["url_defanged"])
    for flag, urls in groups.items():
        points, title, tags = FLAG_RULES[flag]
        more = f" (+{len(urls) - 5} more)" if len(urls) > 5 else ""
        result.add("url", title, points, "; ".join(urls[:5]) + more, tags=tags)

    external = sorted((e for e in entries.values() if not e["internal"]), key=lambda e: -len(e["flags"]))
    skip = h.get("vt_skip_domains") or []
    _virustotal([e for e in external if not domain_matches(e["host"], skip)], result, cfg, intel)
    _domain_age(external, result, cfg, intel)
    _login_pages(external, result, cfg)
    result.urls = list(entries.values())


# A link "goes to a login page" when its path, its final URL after redirects, or the page title seen by
# VirusTotal's crawler looks like a sign-in form. We never open links ourselves.
LOGIN_PATH_RE = re.compile(
    r"(?:^|[/_.\-])(?:log-?in|sign-?in|log-?on|sign-?on|sso|owa|webmail|wp-login|authenticate|authori[sz]e|"
    r"oauth2?|auth|password|passwd|credentials?|verify-?account|account-?verif\w*)(?=$|[/_.\-?#])", re.I)
LOGIN_TITLE_RE = re.compile(
    r"\b(?:sign[ -]?in|log[ -]?in|logon|webmail|outlook web|office ?365|microsoft ?365|one ?drive|share ?point|"
    r"docusign|enter (?:your )?password|verify your (?:account|identity|email))\b", re.I)


def _login_page_reason(entry: dict) -> str:
    vt = entry.get("virustotal") or {}
    if any("phish" in str(c).lower() for c in vt.get("categories") or []):
        return "VirusTotal categorizes the page as phishing"
    if vt.get("title") and LOGIN_TITLE_RE.search(vt["title"]):
        return f"page title seen by VirusTotal: '{vt['title'][:80]}'"
    final = vt.get("final_url") or ""
    if final and final != entry["url"]:
        try:
            if LOGIN_PATH_RE.search(urlsplit(final).path):
                return f"redirects to a login path: {defang_url(final)[:120]}"
        except ValueError:
            pass
    try:
        if LOGIN_PATH_RE.search(urlsplit(entry["url"]).path):
            return "login-style path in the link"
    except ValueError:
        pass
    return ""


def _login_pages(entries: list[dict], result: CaseResult, cfg: dict) -> None:
    h = cfg["heuristics"]
    legit = h["trusted_domains"] + h["protected_domains"] + h["internal_domains"] + list(h.get("vt_skip_domains") or [])
    legit += list(ESP_DOMAINS)
    sender = registrable_domain(domain_of(result.original.get("from_address", "")))
    sender_authenticated = result.auth.get("dmarc") == "pass"
    phishing, own_portal = [], []
    for entry in entries:
        if domain_matches(entry["host"], legit):
            continue   # the genuine Microsoft / Google / DocuSign sign-in pages are not phishing
        reason = _login_page_reason(entry)
        if not reason:
            continue
        entry["login_page"] = reason
        if sender_authenticated and entry["domain"] == sender:
            own_portal.append(f"{entry['url_defanged']} ({reason})")   # a real vendor linking to its own portal
        else:
            phishing.append(f"{entry['url_defanged']} ({reason})")
    if phishing:
        result.add("url", "Link goes to a login page on a non-legitimate site (credential phishing)", 50,
                   "; ".join(phishing[:5]), hard_verdict="MALICIOUS", tags=["login_page", "credential_lure"])
    if own_portal:
        result.add("url", "Link goes to the authenticated sender's own login portal", 5, "; ".join(own_portal[:3]))


def _virustotal(entries: list[dict], result: CaseResult, cfg: dict, intel: Intel) -> None:
    if not intel.vt or not entries:
        return
    vcfg = cfg["intel"]["virustotal"]
    url_threshold = vcfg["malicious_threshold_url"]
    domain_threshold = vcfg.get("malicious_threshold_domain", 5)
    flagged, bad_domain, weak = [], [], []
    for entry in entries[: vcfg["max_url_lookups"]]:
        try:
            report = intel.vt.url(entry["url"])
            if not report.get("found"):
                report = {"found": False, "domain_report": intel.vt.domain(entry["domain"])}
        except IntelError as exc:
            result.errors.append(str(exc))
            if "401" in str(exc) or "quota" in str(exc).lower():
                break
            continue
        entry["virustotal"] = report
        if report.get("found"):
            mal, sus = report.get("malicious", 0), report.get("suspicious", 0)
            if mal >= url_threshold:     # the only VirusTotal result that alone makes an email MALICIOUS
                flagged.append(f"{entry['url_defanged']} ({mal} vendors)")
            elif mal >= 1 or sus >= 2:
                weak.append(f"{entry['url_defanged']} (URL: {mal} malicious / {sus} suspicious)")
        else:
            dom = report.get("domain_report", {})
            mal, sus = dom.get("malicious", 0), dom.get("suspicious", 0)
            if mal >= domain_threshold:
                bad_domain.append(f"{entry['url_defanged']} (domain {defang_domain(entry['domain'])}: {mal} engines)")
            elif mal >= 1 or sus >= 2:
                weak.append(f"{entry['url_defanged']} (domain: {mal} malicious / {sus} suspicious)")
    if flagged:
        result.add("url", f"Link flagged malicious by {url_threshold}+ VirusTotal vendors", 50, "; ".join(flagged[:5]),
                   hard_verdict="MALICIOUS", tags=["vt_malicious"])
    if bad_domain:
        result.add("url", "Link's domain flagged by many VirusTotal engines (the link itself is unknown)", 30,
                   "; ".join(bad_domain[:5]), tags=["vt_domain_bad"])
    if weak:
        result.add("url", "Link or its domain flagged by a few VirusTotal engines", 20, "; ".join(weak[:5]))
    skipped = len(entries) - vcfg["max_url_lookups"]
    if skipped > 0:
        result.notes.append(f"{skipped} URL(s) were not checked on VirusTotal (max_url_lookups limit).")


def _domain_age(entries: list[dict], result: CaseResult, cfg: dict, intel: Intel) -> None:
    if not intel.rdap:
        return
    h = cfg["heuristics"]
    domains = [d for d in dict.fromkeys(e["domain"] for e in entries)
               if d and not is_ip(d) and not domain_matches(d, h["trusted_domains"] + h["protected_domains"])]
    young = []
    for domain in domains[: cfg["intel"]["rdap"]["max_domains"]]:
        try:
            info = intel.rdap.lookup(domain)
        except IntelError as exc:
            result.errors.append(str(exc))
            continue
        age = info.get("age_days")
        for e in entries:
            if e["domain"] == domain:
                e["domain_age_days"] = age
        if age is not None and age < h["new_domain_days"]:
            young.append(f"{defang_domain(domain)} ({age} days old)")
    if young:
        result.add("url", "Link domain was registered very recently", 15, "; ".join(young), tags=["new_domain"])
