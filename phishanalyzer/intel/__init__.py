"""Threat-intel clients (VirusTotal, AbuseIPDB, RDAP) with a shared cache and HTTP session."""
from __future__ import annotations

import logging
import os

import requests

from ..config import resolve_path
from .cache import Cache
from .errors import IntelError
from .services import AbuseIPDB, Rdap, VirusTotal

log = logging.getLogger(__name__)

__all__ = ["Intel", "IntelError"]


class Intel:
    """Holds whichever intel services are configured; missing ones are None."""

    def __init__(self, cfg: dict, offline: bool = False):
        self.vt: VirusTotal | None = None
        self.abuse: AbuseIPDB | None = None
        self.rdap: Rdap | None = None
        self.llm = None                    # ClaudeReviewer when configured
        self.notes: list[str] = []
        if offline:
            self.notes.append("Threat-intel lookups were disabled for this run (--no-intel).")
            return

        icfg = cfg["intel"]
        net = cfg["network"]
        session = requests.Session()
        session.headers["User-Agent"] = "phish-analyzer/0.1"
        if net.get("ca_bundle"):
            session.verify = str(resolve_path(cfg, net["ca_bundle"]))
        timeout = net.get("timeout_seconds", 20)
        data_dir = resolve_path(cfg, cfg["outputs"]["data_dir"])
        data_dir.mkdir(parents=True, exist_ok=True)
        cache = Cache(data_dir / "intel_cache.sqlite", icfg.get("cache_hours", 24))

        vt_key = os.environ.get("VT_API_KEY", "").strip()
        if icfg["virustotal"].get("enabled"):
            if vt_key:
                self.vt = VirusTotal(vt_key, session, cache, icfg["virustotal"].get("requests_per_minute", 4), timeout)
            else:
                self.notes.append("VirusTotal skipped: VT_API_KEY is not set in .env.")
        abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
        if icfg["abuseipdb"].get("enabled") and abuse_key:
            self.abuse = AbuseIPDB(abuse_key, session, cache, timeout)
        if icfg["rdap"].get("enabled"):
            self.rdap = Rdap(session, cache, timeout)
        if cfg.get("llm", {}).get("enabled"):
            if os.environ.get("ANTHROPIC_API_KEY", "").strip():
                try:
                    from ..analyzers.llm import ClaudeReviewer
                    self.llm = ClaudeReviewer(cfg, cache)
                except ImportError:
                    self.notes.append("Claude review skipped: the 'anthropic' package is not installed.")
            else:
                self.notes.append("Claude review skipped: ANTHROPIC_API_KEY is not set in .env.")

    @property
    def active(self) -> bool:
        return any((self.vt, self.abuse, self.rdap))
