# Configuration

Settings are read from `config.yaml` in the project folder (create it with `python -m phishanalyzer init`, or use another file with `-c path\to\file.yaml`). Anything not in your file uses the built-in default from `phishanalyzer/config.py`. API keys go in `.env`, never in `config.yaml`.

After changing settings, restart the watcher (Task Scheduler → *Phish Analyzer Watcher* → End → Run).

## `.env` (secrets)
| Key | Needed? | Where to get it |
|---|---|---|
| `VT_API_KEY` | Strongly recommended | virustotal.com → your profile → *API key* (free: 4 lookups/min, 500/day) |
| `ABUSEIPDB_API_KEY` | Optional | abuseipdb.com → *Account* → *API* |

## `mailbox`: where reports come from
| Setting | Default | Meaning |
|---|---|---|
| `store` | `""` | `""` = your default mailbox. For a shared mailbox, use its display name as shown in Outlook. |
| `source_folder` | `Phishing` | Folder path from the mailbox root or from Inbox, e.g. `Inbox/Phishing Alert`. Use `list-folders` to see the exact names. |
| `report_subject_regex` | `""` | Only items whose subject matches are processed. Example: `'^\s*\[Phish Alert\]'` skips team replies like `RE: [Phish Alert] ...`. Use single quotes in YAML. |
| `analyze_item_without_attachment` | `true` | If an item has no attached email and isn't a report, analyze the item itself (for emails moved into the folder directly). |
| `processed_subfolder`, `move_processed`, `category_prefix`, `poll_minutes` | | Only for the `once` / `run` mailbox mode: tag the report and move it to `<folder>/Processed/<Verdict>`. |

## `watch`: continuous mode
| Setting | Default | Meaning |
|---|---|---|
| `poll_seconds` | `120` | How often to check the folder for new reports |
| `backfill_hours` | `24` | On start, also process reports from this many hours back that aren't in the log yet |

## `shared_report`: team Excel log
| Setting | Default | Meaning |
|---|---|---|
| `folder` | `""` | OneDrive/SharePoint-synced folder, e.g. `C:\Users\you\OneDrive - Company\Team\Phishing Alert`. Required for `watch`. |
| `workbook` | `Phishing Alert Log.xlsx` | Name of the Excel file created in that folder |

## `notifications`: popups and alert emails
| Setting | Default | Meaning |
|---|---|---|
| `desktop` | `true` | Windows popup for every analyzed report |
| `email_alerts` | `true` | Send an alert email for the verdicts below (once per email or campaign) |
| `email_verdicts` | `[MALICIOUS, SUSPICIOUS]` | Which verdicts send an email |
| `to` | `""` | Default recipient(s). `""` = the signed-in Outlook user. |
| `recipients` | — | Per-verdict recipients, overriding `to`. See the example below. |

```yaml
notifications:
  recipients:
    MALICIOUS:
      to: [analyst1@company.com, analyst2@company.com]
      cc: [infosec@company.com]
    # SUSPICIOUS has no entry, so it goes to "to" (or to you)
```

## `daily_report`: summary email (`daily-report` command)
| Setting | Default | Meaning |
|---|---|---|
| `to` | `""` | Recipient(s); `""` = the signed-in Outlook user |
| `lookback_hours` | `24` | Period covered |
| `attach_malicious` / `attach_suspicious` | `false` | Attach the original phishing emails. **Leave this off**: Microsoft 365 quarantines emails that carry phishing samples. |

## `heuristics`: tuning detection
| Setting | Default | Meaning |
|---|---|---|
| `internal_domains` | `[]` | **Set this.** Your email domains. Used for spoofing checks, company-name impersonation, and "do not block our own domain". |
| `org_names` | `[]` | Extra company names to watch for (the first label of each internal domain is added automatically) |
| `vip_names` | `[]` | Executives attackers may impersonate in the display name |
| `protected_domains` | Microsoft, DocuSign, PayPal, DHL... | Domains checked for lookalikes. Your internal domains are always included. |
| `trusted_domains` | Microsoft, SharePoint, LinkedIn... | Genuine domains that must never be called lookalikes |
| `vt_skip_domains` | Microsoft, Google, LinkedIn... | Genuine domains not sent to VirusTotal (saves quota). Don't add file-sharing domains here. |
| `new_domain_days` | `30` | Domains younger than this are flagged |
| `allowed_countries` | `[]` | e.g. `[SA, AE, PK]`. Sender IPs elsewhere get +5. Empty = no check. |
| `simulation_markers` | KnowBe4, PhishMe, GoPhish headers | Headers that mark a phishing simulation |
| `simulation_sender_ips` | `[]` | If set, simulation headers are trusted only from these IPs. Recommended, so attackers can't fake a "simulation". |

Note: setting a list in `config.yaml` **replaces** the default list. To add a protected domain, copy the default list from `config.py` and extend it.

## `intel`: threat-intel services
| Setting | Default | Meaning |
|---|---|---|
| `virustotal.enabled` | `true` | Needs `VT_API_KEY` |
| `virustotal.requests_per_minute` | `4` | Free API limit. Raise it for a premium key. |
| `virustotal.max_url_lookups` / `max_file_lookups` | `10` / `10` | Per email, to protect the 500/day quota |
| `virustotal.malicious_threshold_file` | `3` | Engines needed to call a file hash MALICIOUS |
| `virustotal.malicious_threshold_url` | `3` | Vendors that must flag a link before it alone makes the email MALICIOUS |
| `virustotal.malicious_threshold_domain` | `5` | Engines from which a domain counts as "bad reputation" (adds points; never MALICIOUS on its own, since domains collect stale detections) |
| `abuseipdb.enabled` | `true` | Needs `ABUSEIPDB_API_KEY` |
| `rdap.enabled` / `rdap.max_domains` | `true` / `8` | Domain-age lookups (no key needed) |
| `cache_hours` | `24` | How long lookups are cached |

## `network`
| Setting | Default | Meaning |
|---|---|---|
| `use_system_trust` | `true` | Use the Windows certificate store, needed behind corporate SSL inspection (Fortinet, Zscaler...) |
| `ca_bundle` | `""` | Alternatively, a path to your corporate root CA `.pem` |
| `timeout_seconds` | `20` | Network timeout |
| `dns_checks` | `true` | DMARC record and reverse-DNS lookups |

## `scoring`
| Setting | Default | Meaning |
|---|---|---|
| `suspicious` | `30` | Score from which an email is SUSPICIOUS |
| `malicious` | `60` | Score from which SUSPICIOUS becomes **high confidence** |
| `allow_score_malicious` | `false` | `true` = a score ≥ `malicious` alone also makes an email MALICIOUS (old behaviour, more false positives). By default, MALICIOUS needs a VirusTotal-flagged link, a malicious attachment, or a login page. |

## `analysis`
| Setting | Default | Meaning |
|---|---|---|
| `max_nested_depth` | `3` | How deep emails attached inside emails are opened |
| `max_archive_depth` | `2` | How deep ZIPs inside ZIPs are opened |
| `max_archive_total_mb` | `50` | Stop extracting after this much data (zip-bomb protection) |

## `outputs`
| Setting | Default | Meaning |
|---|---|---|
| `report_dir` | `reports` | Local per-email reports |
| `data_dir` | `data` | Cache, case database, Excel backups |
| `log_dir` | `logs` | `phishanalyzer.log` |
| `quarantine_dir` | `quarantine` | Temporary work folder (emptied after each email) |
| `save_raw_email` | `false` | Keep a copy of each analyzed email. Antivirus may react to it. |
