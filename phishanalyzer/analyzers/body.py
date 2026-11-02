"""Static body analysis: social-engineering language, brand impersonation and HTML tricks."""
from __future__ import annotations

import re
import warnings

from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

from ..models import CaseResult
from ..utils import ESP_DOMAINS, domain_matches, domain_of, registrable_domain, url_host
from .urls import extract_urls, unwrap_url

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

# group -> (points, tags, title, phrases)
KEYWORD_GROUPS = {
    "credential": (15, ["credential_lure"], "Asks for credentials or account verification", [
        "verify your account", "confirm your account", "verify your identity", "validate your", "your password",
        "password expires", "password will expire", "reset your password", "sign in to", "log in to", "login to",
        "update your account", "unusual sign-in", "unusual activity", "suspicious activity", "mailbox is full",
        "storage is full", "mailbox quota", "re-activate", "reactivate", "one-time code", "verification code",
        "confirm your email", "keep same password"]),
    "financial": (15, ["bec"], "Payment / bank-detail request (possible BEC)", [
        "wire transfer", "bank details", "bank account details", "change of bank", "new bank account",
        "payment details", "overdue invoice", "outstanding invoice", "remittance", "payroll", "direct deposit",
        "outstanding payment", "swift code", "iban"]),
    "gift_card": (15, ["bec"], "Gift-card request", ["gift card", "itunes card", "google play card", "steam card"]),
    "hr": (15, ["hr_lure"], "HR / salary lure", [
        "salary increase", "salary adjustment", "salary revision", "salary review", "salary increment", "pay raise",
        "pay rise", "bonus payment", "payslip", "pay slip", "employee handbook", "performance review", "appraisal",
        "hr policy", "benefits enrollment", "compensation review", "annual increment"]),
    "threat": (10, [], "Threatens suspension or loss", [
        "will be suspended", "has been suspended", "will be closed", "will be deleted", "will be terminated",
        "legal action", "account will be locked", "has been locked", "deactivated", "permanently disabled"]),
    "urgency": (5, [], "Urgency / pressure language", [
        "urgent", "immediately", "within 24 hours", "within 48 hours", "as soon as possible", "action required",
        "final notice", "last warning", "expires today", "right away"]),
    "lure": (5, [], "Common phishing lure theme", [
        "voicemail", "voice message", "shared a document", "shared a file", "sent you a document",
        "review and sign", "e-signature", "secure message", "encrypted message", "delivery failed",
        "track your package", "parcel", "shipment on hold", "fax"]),
}

# brand -> (terms in the email, tokens a legitimate sender domain contains)
BRANDS = {
    "Microsoft": (["microsoft", "office 365", "microsoft 365", "onedrive", "sharepoint", "microsoft teams"],
                  ["microsoft", "office", "outlook", "sharepoint", "onedrive", "live", "msft"]),
    "DocuSign": (["docusign"], ["docusign"]),
    "DHL": (["dhl"], ["dhl"]),
    "FedEx": (["fedex"], ["fedex"]),
    "Aramex": (["aramex"], ["aramex"]),
    "PayPal": (["paypal"], ["paypal"]),
    "Apple": (["apple id", "icloud"], ["apple", "icloud"]),
    "Amazon": (["amazon"], ["amazon"]),
    "Netflix": (["netflix"], ["netflix"]),
    "Adobe": (["adobe sign", "adobe document", "adobe acrobat"], ["adobe"]),
    "WeTransfer": (["wetransfer"], ["wetransfer"]),
    "Dropbox": (["dropbox"], ["dropbox"]),
    "LinkedIn": (["linkedin"], ["linkedin"]),
}

ZERO_WIDTH = "​‌‍⁠﻿"
RTLO = "‮"
HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?\s*(?:;|$)", re.I)
URLISH_TEXT = re.compile(r"^(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:[/:?#]\S*)?$", re.I)


def analyze_body(text_bodies: list[str], html_bodies: list[str], result: CaseResult, cfg: dict) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    visible = list(text_bodies)
    soups = []
    for html in html_bodies:
        soup = BeautifulSoup(html, "html.parser")
        soups.append(soup)
        visible.append(soup.get_text(" ", strip=True))
    full = " ".join([result.original.get("subject", ""), *visible])
    lower = " ".join(full.lower().split())

    hits_summary = {}
    for group, (points, tags, title, phrases) in KEYWORD_GROUPS.items():
        hits = [p for p in phrases if p in lower]
        if hits:
            hits_summary[group] = hits
            result.add("body", title, points, ", ".join(hits[:6]), tags=tags)

    if "internal_authenticated" not in result.tags:
        # A brand in the subject/display name is impersonation; in the body only when it asks for credentials
        # (otherwise every newsletter that mentions Microsoft or Amazon would score).
        sender = registrable_domain(domain_of(result.original.get("from_address", "")))
        headline = f"{result.original.get('subject', '')} {result.original.get('display_name', '')}".lower()
        asks_creds = "credential_lure" in result.tags
        for brand, (terms, legit) in BRANDS.items():
            if any(tok in sender for tok in legit):
                continue
            where = headline if not asks_creds else lower
            if any(re.search(rf"\b{re.escape(t)}\b", where) for t in terms):
                result.add("body", f"Uses the {brand} brand but the sender is not {brand}", 15,
                           f"sender domain: {sender or 'unknown'}", tags=["brand_impersonation"])
                break

    mismatches, forms, active = [], [], []
    password = False
    hidden = data_uris = images = 0
    for soup in soups:
        for tag in soup.find_all(True):
            for attr in ("href", "src", "action", "background", "data-href"):
                value = tag.get(attr)
                if not isinstance(value, str) or not value.strip():
                    continue
                value = value.strip()
                low = value.lower()
                if low.startswith("data:"):
                    if not low.startswith("data:image/"):
                        data_uris += 1
                elif low.startswith(("http://", "https://", "hxxp")):
                    candidates.append((value, f"body:{tag.name}[{attr}]"))
            if HIDDEN_STYLE.search(tag.get("style") or "") and len(tag.get_text(strip=True)) > 20:
                hidden += 1
        for a in soup.find_all("a", href=True):
            shown = a.get_text(" ", strip=True)
            if not URLISH_TEXT.match(shown):
                continue
            real = unwrap_url(a["href"].strip())
            shown_host = url_host(shown if "://" in shown else "http://" + shown)
            if domain_matches(url_host(real), ESP_DOMAINS):
                continue   # newsletter click-tracking, not deception
            if real.lower().startswith("http") and registrable_domain(shown_host) != registrable_domain(url_host(real)):
                mismatches.append(f"shows '{shown_host}' but goes to '{url_host(real)}'")
        forms += [f.get("action") or "(no action)" for f in soup.find_all("form")]
        if soup.find("input", attrs={"type": re.compile("password", re.I)}):
            password = True
        active += [t for t in ("script", "iframe", "object", "embed") if soup.find(t)]
        if soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
            active.append("meta refresh")
        images += len(soup.find_all("img"))

    for text in visible:
        candidates += [(u, "body:text") for u in extract_urls(text)]

    if mismatches:
        result.add("body", "Link text shows a different address than the real link", 10,
                   "; ".join(mismatches[:5]), tags=["link_mismatch"])
    if password:
        result.add("body", "Email contains a password field", 20, tags=["credential_lure"])
    if forms:
        result.add("body", "Email contains an HTML form", 15, ", ".join(forms[:3]), tags=["form"])
    if active:
        result.add("body", "Email contains active HTML content", 10, ", ".join(sorted(set(active))))
    # Newsletters hide a short preheader and pad it with zero-width characters, so only larger amounts count.
    if hidden > 1:
        result.add("body", "Email contains hidden text blocks", 5, f"{hidden} hidden element(s)")
    if data_uris:
        result.add("body", "Email embeds non-image data: URIs", 10, f"{data_uris} occurrence(s)")
    zero_width = sum(full.count(c) for c in ZERO_WIDTH)
    if zero_width > 40:
        result.add("body", "Many zero-width characters (filter evasion)", 5, f"{zero_width} characters")
    if RTLO in full:
        result.add("body", "Right-to-left override character used", 10)
    if html_bodies and images and len(" ".join(visible).strip()) < 80:
        result.add("body", "Email is mostly an image (possible QR / image-based phishing)", 5, tags=["image_only"])

    result.body = {"text_length": len(" ".join(visible)), "keyword_hits": hits_summary,
                   "link_mismatches": mismatches[:20], "forms": forms[:10], "active_content": sorted(set(active))}
    return candidates
