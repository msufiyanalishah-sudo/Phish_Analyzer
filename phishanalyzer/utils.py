"""Small helpers shared by the analyzers: domains, IPs, lookalikes and defanging."""
from __future__ import annotations

import ipaddress
from email.utils import parseaddr
from urllib.parse import urlsplit

# Second-level suffixes where the registrable domain has three labels (example.co.uk).
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in",
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
    "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa", "med.sa",
    "co.ae", "gov.ae", "ac.ae", "net.ae", "org.ae",
    "com.qa", "gov.qa", "com.kw", "com.bh", "com.om", "co.om", "com.eg", "gov.eg",
    "co.za", "org.za", "com.br", "com.mx", "com.ar", "com.tr", "gov.tr",
    "com.cn", "com.hk", "com.sg", "com.my", "co.jp", "ne.jp", "co.kr", "co.nz", "co.id",
    "com.ph", "com.vn",
}

FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "ymail.com", "hotmail.com",
    "outlook.com", "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "mail.com",
    "gmx.com", "gmx.de", "gmx.net", "proton.me", "protonmail.com", "zoho.com", "yandex.com",
    "yandex.ru", "mail.ru", "qq.com", "163.com", "126.com", "tutanota.com", "rediffmail.com",
}

# Bulk-mail / marketing platforms: their bounce addresses and click-tracking links differ from the brand by design.
ESP_DOMAINS = (
    "list-manage.com", "mcsv.net", "mailchimp.com", "mcusercontent.com", "hubspotlinks.com", "hubspotemail.net",
    "hs-sites.com", "hubspot.com", "sendgrid.net", "mailgun.org", "mailgun.net", "constantcontact.com", "rs6.net",
    "sparkpostmail.com", "mandrillapp.com", "createsend.com", "cmail19.com", "cmail20.com", "exacttarget.com",
    "pardot.com", "mktoweb.com", "mktomail.com", "marketo.com", "awstrack.me", "amazonses.com", "mlsend.com",
    "sendinblue.com", "brevo.com", "sendibt3.com", "zcsend.net", "zohocampaigns.com", "eloqua.com", "en25.com",
    "salesforce.com", "klaviyomail.com", "klclick.com", "mailjet.com", "mjt.lu", "emlnk.com", "cvent.com",
)

# Character swaps attackers use in lookalike domains (paypa1, rnicrosoft, micros0ft).
_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("i", "l"),
                ("3", "e"), ("5", "s"), ("$", "s"), ("@", "a"))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.strip("[]")).is_global
    except ValueError:
        return False


def domain_of(address: str) -> str:
    addr = parseaddr(address or "")[1] or (address or "")
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].strip().strip(">").lower().rstrip(".")


def registrable_domain(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if not host or is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def url_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def domain_matches(domain: str, candidates) -> bool:
    """True when domain equals one of the candidates or is a subdomain of one."""
    domain = (domain or "").lower()
    return any(domain == c.lower() or domain.endswith("." + c.lower()) for c in candidates if c)


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _normalize(label: str) -> str:
    label = label.lower()
    for src, dst in _CONFUSABLES:
        label = label.replace(src, dst)
    return label.replace("-", "")


def lookalike_of(domain: str, protected, trusted=()) -> str | None:
    """Return the protected domain that `domain` imitates, or None."""
    domain = (domain or "").lower().rstrip(".")
    if not domain or is_ip(domain):
        return None
    if domain_matches(domain, protected) or domain_matches(domain, trusted):
        return None
    name = registrable_domain(domain).split(".")[0]
    labels = domain.split(".")
    for target in protected:
        tname = registrable_domain(target).split(".")[0].lower()
        if len(tname) < 4:
            continue
        if _normalize(name) == _normalize(tname):
            return target
        if levenshtein(name, tname) <= (1 if len(tname) <= 6 else 2):
            return target
        if any(tname in label or _normalize(tname) in _normalize(label) for label in labels):
            return target
    return None


def defang_domain(domain: str) -> str:
    return (domain or "").replace(".", "[.]")


def defang_email(address: str) -> str:
    return (address or "").replace("@", "[@]").replace(".", "[.]")


_RAW_URL_RE = None


def defang_text(text: str) -> str:
    """Defang every live http(s) URL inside free text (evidence strings, whole email bodies)."""
    global _RAW_URL_RE
    if _RAW_URL_RE is None:
        import re
        _RAW_URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>'\"]+")
    return _RAW_URL_RE.sub(lambda m: defang_url(m.group(0)), text or "")


def defang_url(url: str) -> str:
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url.replace(".", "[.]")
    if not parts.scheme or not parts.netloc:
        return url.replace(".", "[.]")
    prefix = f"{parts.scheme}://{parts.netloc}"
    rest = url[len(prefix):] if url.lower().startswith(prefix.lower()) else url.split(parts.netloc, 1)[-1]
    scheme = parts.scheme.lower().replace("http", "hxxp")
    return f"{scheme}://{parts.netloc.replace('.', '[.]')}{rest}"
