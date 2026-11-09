"""Configuration loading: built-in defaults, overridden by config.yaml, secrets from .env."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

DEFAULTS: dict[str, Any] = {
    "mailbox": {
        "mode": "outlook_com",
        "store": "",                      # empty = default mailbox; or a shared mailbox display name
        "source_folder": "Phishing",      # path from the mailbox root or from Inbox, e.g. "Inbox/Phishing"
        "processed_subfolder": "Processed",
        "move_processed": True,
        "category_prefix": "Phish-",
        "report_subject_regex": "",       # e.g. "^\\s*\\[Phish Alert\\]" to skip team replies in the folder
        "analyze_item_without_attachment": True,
        "poll_minutes": 5,
    },
    "network": {
        "use_system_trust": True,         # trust the Windows certificate store (corporate SSL inspection)
        "ca_bundle": "",
        "timeout_seconds": 20,
        "dns_checks": True,
    },
    "intel": {
        "virustotal": {
            "enabled": True,
            "requests_per_minute": 4,     # free tier
            "max_url_lookups": 10,
            "max_file_lookups": 10,
            "malicious_threshold_file": 3,
            "malicious_threshold_url": 3,   # vendors flagging a link before it alone makes the email MALICIOUS
            # Whole domains collect stale detections, so a domain needs more engines before it alone means MALICIOUS.
            "malicious_threshold_domain": 5,
        },
        "abuseipdb": {"enabled": True},
        "rdap": {"enabled": True, "max_domains": 8},
        "cache_hours": 24,
    },
    "heuristics": {
        "internal_domains": [],
        "protected_domains": [
            "microsoft.com", "office.com", "docusign.com", "docusign.net", "paypal.com", "apple.com",
            "amazon.com", "dhl.com", "fedex.com", "adobe.com", "dropbox.com", "google.com",
            "linkedin.com", "wetransfer.com", "netflix.com",
        ],
        # Legitimate domains that must never be reported as lookalikes.
        "trusted_domains": [
            "microsoftonline.com", "office365.com", "outlook.com", "live.com", "sharepoint.com",
            "onedrive.com", "msauth.net", "msftauth.net", "aka.ms", "docusign.net", "paypalobjects.com",
            "googleusercontent.com", "gstatic.com", "amazonaws.com", "linkedin.com", "licdn.com",
            "static.microsoft", "microsoft",   # Microsoft's own .microsoft TLD (CDN assets in Outlook mail)
        ],
        # Genuine domains not worth a VirusTotal lookup (saves the daily quota). File-sharing domains such as
        # sharepoint.com or wetransfer.com are deliberately NOT here: attackers host payloads on them.
        "vt_skip_domains": [
            "aka.ms", "microsoft.com", "office.com", "microsoftonline.com", "outlook.com", "office365.com",
            "static.microsoft", "msauth.net", "msftauth.net", "linkedin.com", "licdn.com", "gstatic.com",
            "w3.org", "apple.com", "google.com",
        ],
        "vip_names": [],
        "org_names": [],                  # company names besides the internal domain label, e.g. ["Contoso Ltd"]
        "new_domain_days": 30,
        "allowed_countries": [],          # e.g. ["SA", "PK", "AE"]; empty = no country check
        "simulation_markers": ["X-PHISHTEST", "X-KnowBe4", "X-PhishMe", "X-Gophish"],
        "simulation_sender_ips": [],      # if set, a simulation header is trusted only from these IPs
    },
    "analysis": {
        "max_nested_depth": 3,
        "max_archive_depth": 2,
        "max_archive_total_mb": 50,
    },
    # MALICIOUS needs confirmed evidence (VirusTotal-flagged link, malicious attachment, login page). A high score
    # alone gives a high-confidence SUSPICIOUS, unless allow_score_malicious is true.
    "scoring": {"suspicious": 30, "malicious": 60, "allow_score_malicious": False},
    "shared_report": {
        "folder": "",                     # OneDrive/SharePoint-synced folder for the team log
        "workbook": "Phishing Alert Log.xlsx",
    },
    "watch": {
        "poll_seconds": 120,              # how often to look for new reports
        "backfill_hours": 24,             # on start, also log reports from this far back
    },
    "notifications": {
        "desktop": True,                  # Windows popup for every analyzed report
        "email_alerts": True,             # email for these verdicts (once per email/campaign)
        "email_verdicts": ["MALICIOUS", "SUSPICIOUS"],
        "to": "",                         # empty = the signed-in Outlook user
    },
    "daily_report": {
        "to": "",                         # empty = the signed-in Outlook user
        "lookback_hours": 24,
        "attach_malicious": False,        # attached phishing emails get the report quarantined by Microsoft 365
        "attach_suspicious": False,
    },
    "outputs": {
        "report_dir": "reports",
        "data_dir": "data",
        "log_dir": "logs",
        "quarantine_dir": "quarantine",
        "save_raw_email": False,          # off: AV/EDR may quarantine saved phishing mail
    },
}


def _merge(base: dict, override: dict) -> dict:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    cfg = copy.deepcopy(DEFAULTS)
    path = Path(path) if path else Path("config.yaml")
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        _merge(cfg, data)
        cfg["_config_file"] = str(path.resolve())
        base = path.resolve().parent
    else:
        cfg["_config_file"] = ""
        base = Path.cwd()
    cfg["_base_dir"] = str(base)
    try:
        from dotenv import load_dotenv
        load_dotenv(base / ".env")
    except ImportError:
        pass
    return cfg


def resolve_path(cfg: dict[str, Any], value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else Path(cfg["_base_dir"]) / p
