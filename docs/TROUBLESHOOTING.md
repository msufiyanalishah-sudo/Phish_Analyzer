# Troubleshooting

Start with the log: `logs\phishanalyzer.log`. Every run, every analyzed email and every error is written there.

## Installation
| Symptom | Cause / fix |
|---|---|
| `python` is not recognized | Install Python 3.11+ from python.org (tick *Add to PATH*) or the Microsoft Store, then open a new terminal. |
| `pip install` fails with SSL errors | Corporate SSL inspection. Try `.venv\Scripts\python -m pip install --use-feature=truststore -r requirements.txt`, or ask IT for the proxy/CA settings. |
| `opencv-python-headless` won't install | It's optional (QR codes only). Skip `requirements-optional.txt`. Everything else still works. |
| `No module named phishanalyzer` | Run the commands from the project folder (where `README.md` is). |
| `WinError 3 ... pywin32 ... MAPIStubLibrary` during install, then `No module named 'pywin32_bootstrap'` on every command | Windows' 260-character path limit. Move or clone the project to a short path (e.g. `C:\Tools\phish-analyzer`), delete `.venv`, and install again, or ask IT to enable *Win32 long paths*. |
| `python -m venv` fails with `ensurepip ... non-zero exit status` | Usually antivirus scanning the new folder. Run the same command again. |
| `fatal: repository not found` on `git clone` | The repository is private. Ask the owner to add your GitHub account as a collaborator. |

## Outlook
| Symptom | Cause / fix |
|---|---|
| `Outlook folder '...' not found` | Run `list-folders`, then copy the exact path, e.g. `Inbox/Phishing Alert`, into `mailbox.source_folder`. For a shared mailbox, also set `mailbox.store`. |
| `pywin32 is not installed` / COM errors | Run `.venv\Scripts\python -m pip install pywin32`. The tool needs **Classic Outlook**; *New Outlook* has no automation interface. |
| Reports are skipped | `report_subject_regex` doesn't match their subject. Check it in YAML, using single quotes: `'^\s*\[Phish Alert\]'`. |
| Every report is UNANALYZABLE | Users forward phish normally (no attachment). Ask them to use the Phish Alert Button or *Forward as Attachment* (Ctrl+Alt+F). |

## Threat intel
| Symptom | Cause / fix |
|---|---|
| `VirusTotal skipped: VT_API_KEY is not set` | Add the key to `.env` in the project folder |
| `VirusTotal rejected the API key (401)` | Wrong or revoked key. Copy it again from virustotal.com. |
| `quota exceeded (HTTP 429)` | Free API: 500 lookups a day. Lower `max_url_lookups` / `max_file_lookups`, or wait for the reset. |
| Slow analysis, `rate limit: waiting` | Normal on the free API (4 per minute). Results are cached, so repeated links are fast. |
| RDAP / DNS errors in the report | A network or proxy block. The other checks still run. |

## Watcher, Excel and notifications
| Symptom | Cause / fix |
|---|---|
| Watcher not running after sign-in | Task Scheduler → *Phish Analyzer Watcher* → check *Last Run Result* and the log. The task starts 2 minutes after logon. |
| `Another watcher is already running; exiting.` | Only one watcher may run at a time (to avoid duplicate rows). Stop the other one first. |
| `Permission denied ... Phishing Alert Log.xlsx` | Someone has the workbook open in desktop Excel. It's retried automatically on the next cycle. Prefer viewing it in the browser. |
| OneDrive "conflict" copies of the workbook | Two people saved at the same moment. Keep the newest one; the tool only appends rows. |
| Wrong verdicts in old Excel rows after a rule change | Stop the watcher, run `python -m phishanalyzer relog` (it keeps a backup in `data\backups\` and doesn't touch Status/Analyst Notes), then start the watcher again. |
| No popups | *Windows Settings → System → Notifications*: allow notifications, and turn off Focus Assist / Do Not Disturb. |
| Alert email in Sent Items but nobody received it | Microsoft 365 quarantined it. Check Defender → *Quarantine*. The tool defangs every link in outgoing emails to prevent this; don't enable `attach_malicious`. |

## Verdict looks wrong
1. Open the email's HTML report. The **Why: findings** table lists every rule that fired, with its points.
2. **False positive?** Common fixes:
   - Add a genuine domain to `trusted_domains` (lookalike checks) or `vt_skip_domains`.
   - Raise `malicious_threshold_domain` for domains with stale detections.
   - Set `internal_domains` correctly.
3. **Missed phish?**
   - Check that the VirusTotal key works.
   - Install the QR-code extras.
   - Add executive names to `vip_names` and brands to `protected_domains`.
4. Re-check a single email with `python -m phishanalyzer analyze <file> --open`.
