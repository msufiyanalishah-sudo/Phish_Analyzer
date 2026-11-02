"""VirusTotal v3, AbuseIPDB and RDAP (domain age) lookups."""
from __future__ import annotations

import base64
import logging
import time
from datetime import datetime, timezone

import requests

from .cache import Cache
from .errors import IntelError

log = logging.getLogger(__name__)


class VirusTotal:
    BASE = "https://www.virustotal.com/api/v3"
    GUI = "https://www.virustotal.com/gui"

    def __init__(self, api_key: str, session: requests.Session, cache: Cache, requests_per_minute: int, timeout: int):
        self.api_key = api_key
        self.session = session
        self.cache = cache
        self.timeout = timeout
        self._interval = 60.0 / max(int(requests_per_minute), 1)
        self._last = 0.0

    def file(self, sha256: str) -> dict:
        return self._get("file", sha256, f"/files/{sha256}")

    def url(self, url: str) -> dict:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return self._get("url", url_id, f"/urls/{url_id}")

    def domain(self, domain: str) -> dict:
        return self._get("domain", domain, f"/domains/{domain}")

    def ip(self, ip: str) -> dict:
        return self._get("ip-address", ip, f"/ip_addresses/{ip}")

    def _get(self, kind: str, ident: str, path: str) -> dict:
        key = f"vt:{kind}:{ident}"
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        for _ in range(3):
            wait = self._interval - (time.monotonic() - self._last)
            if wait > 0:
                log.info("VirusTotal rate limit: waiting %.0fs", wait)
                time.sleep(wait)
            self._last = time.monotonic()
            try:
                resp = self.session.get(self.BASE + path, headers={"x-apikey": self.api_key}, timeout=self.timeout)
            except requests.RequestException as exc:
                raise IntelError(f"VirusTotal request failed: {exc}") from exc
            if resp.status_code == 429:
                log.warning("VirusTotal quota hit (429); retrying in 60s")
                time.sleep(60)
                continue
            if resp.status_code == 401:
                raise IntelError("VirusTotal rejected the API key (401). Check VT_API_KEY in .env.")
            if resp.status_code == 404:
                summary = {"found": False}
                break
            if resp.status_code >= 400:
                raise IntelError(f"VirusTotal HTTP {resp.status_code} for {kind}")
            summary = self._summarize(kind, resp.json())
            break
        else:
            raise IntelError("VirusTotal quota exceeded (HTTP 429 three times).")
        self.cache.set(key, summary)
        return summary

    def _summarize(self, kind: str, payload: dict) -> dict:
        data = payload.get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation"),
            "label": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label", ""),
            "type": attrs.get("type_description", ""),
            "country": attrs.get("country", ""),
            "as_owner": attrs.get("as_owner", ""),
            "categories": sorted(set((attrs.get("categories") or {}).values()))[:5],
            "link": f"{self.GUI}/{kind}/{data.get('id', '')}",
        }


class AbuseIPDB:
    URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str, session: requests.Session, cache: Cache, timeout: int):
        self.api_key = api_key
        self.session = session
        self.cache = cache
        self.timeout = timeout

    def check(self, ip: str) -> dict:
        key = f"abuseipdb:{ip}"
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        try:
            resp = self.session.get(self.URL, params={"ipAddress": ip, "maxAgeInDays": 90},
                                    headers={"Key": self.api_key, "Accept": "application/json"}, timeout=self.timeout)
        except requests.RequestException as exc:
            raise IntelError(f"AbuseIPDB request failed: {exc}") from exc
        if resp.status_code >= 400:
            raise IntelError(f"AbuseIPDB HTTP {resp.status_code}")
        d = resp.json().get("data", {})
        summary = {k: d.get(k) for k in ("abuseConfidenceScore", "totalReports", "countryCode", "isp", "usageType", "domain")}
        self.cache.set(key, summary)
        return summary


class Rdap:
    URL = "https://rdap.org/domain/{}"

    def __init__(self, session: requests.Session, cache: Cache, timeout: int):
        self.session = session
        self.cache = cache
        self.timeout = timeout

    def lookup(self, domain: str) -> dict:
        key = f"rdap:{domain}"
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        try:
            resp = self.session.get(self.URL.format(domain), timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as exc:
            raise IntelError(f"RDAP lookup failed for {domain}: {exc}") from exc
        if resp.status_code == 404:
            info = {"found": False}
        elif resp.status_code >= 400:
            raise IntelError(f"RDAP HTTP {resp.status_code} for {domain}")
        else:
            info = {"found": True, "created": "", "age_days": None, "registrar": ""}
            for event in resp.json().get("events", []):
                if event.get("eventAction") == "registration":
                    created = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                    info["created"] = created.date().isoformat()
                    info["age_days"] = (datetime.now(timezone.utc) - created).days
            for ent in resp.json().get("entities", []):
                if "registrar" in ent.get("roles", []):
                    vcard = ent.get("vcardArray", [None, []])[1]
                    info["registrar"] = next((v[3] for v in vcard if v[0] == "fn"), "")
        self.cache.set(key, info)
        return info
