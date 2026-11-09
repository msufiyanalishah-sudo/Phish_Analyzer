# Phish Analyzer

**Automatic triage for user-reported phishing emails.**

Phish Analyzer watches the Outlook folder where your users' phishing reports land (for example from the KnowBe4 *Phish Alert Button*), analyzes every reported email, and gives each one a verdict: **MALICIOUS**, **SUSPICIOUS**, **CLEAN**, **SIMULATION** or **UNANALYZABLE**. Each verdict comes with the reasons, what to block, what *not* to block, and the remediation steps.

The analysis is **static and safe**. Links are never opened, attachments are never executed, and HTML is never rendered. Only hashes, URLs, domains and IPs are looked up in threat-intel services; email content and files never leave your machine.

---

## Contents
1. [What it does](#what-it-does)
2. [What it checks](#what-it-checks)
3. [Requirements](#requirements)
4. [Installation (10 minutes)](#installation-10-minutes)
5. [Configuration](#configuration)
6. [Usage](#usage)
7. [Run it automatically (Task Scheduler)](#run-it-automatically-task-scheduler)
8. [Outputs](#outputs)
9. [How the verdict is decided](#how-the-verdict-is-decided)
10. [Privacy and safety](#privacy-and-safety)
11. [Project structure](#project-structure)
12. [Troubleshooting](#troubleshooting)
13. [More documentation](#more-documentation)

---

## What it does

```
User clicks "Phish Alert"  ─►  Outlook folder "Phishing Alert"  ─►  Phish Analyzer (every 2 minutes)
                                                                       │
     ┌─────────────────────────────────────────────────────────────────┤
     ▼                          ▼                         ▼            ▼
 Desktop popup         Alert email (MALICIOUS /     Shared Excel log   HTML report per email
 for every email       SUSPICIOUS, To + CC)         + daily summary    (+ JSON + IOC CSV)
```

- **Reads** each new report from an Outlook folder and extracts the attached original email (`.eml`, `.msg` or Outlook item).
- **Analyzes** headers, authentication, sender reputation, body, links, attachments and QR codes.
- **Decides** a verdict with a score (0–100), confidence, and a list of the reasons.
- **Tells you**: a Windows popup for every email, and an alert email for malicious or suspicious ones. The alert goes once per campaign, even if 20 people report the same phish.
- **Logs** everything to a shared Excel workbook (OneDrive / SharePoint) with a full HTML report per email and a daily summary.
- **Recommends** for each threat what to block (sender, domain, URL, hash, IP), what **not** to block (shared providers like Gmail, SharePoint, IONOS or Microsoft mail servers), and the next steps (purge, check sign-in logs, reset passwords...).

## What it checks

| Area | Checks |
|---|---|
| **Headers** | From / Reply-To / Return-Path mismatch, free-mail Reply-To, display-name spoofing, VIP/executive impersonation, lookalike and punycode domains (`micros0ft`, `paypa1`, `xn--`), external sender using your company name, Message-ID and Date anomalies, bulk/scripted mailers, phishing-simulation headers |
| **Authentication** | SPF, DKIM, DMARC, ARC and Microsoft CompAuth from `Authentication-Results`, plus a DNS lookup of the sender's DMARC policy |
| **Received hops** | Hop table, originating IP (Microsoft "sender IP" stamp or first external hop), reverse DNS, out-of-order timestamps |
| **Sender reputation** | VirusTotal (IP and domain), AbuseIPDB (optional), country, domain age (RDAP) |
| **Body** | Credential, payment/BEC, HR/salary, gift-card, threat, urgency and lure language; brand impersonation; link text vs real link; HTML forms and password fields; scripts and iframes; hidden text; zero-width and right-to-left tricks; image-only emails |
| **Links** | Unwraps Microsoft Safe Links, Proofpoint URL Defense and Google redirects; flags lookalike domains, raw IPs, punycode, shorteners, free hosting, file-sharing links (WeTransfer, Dropbox, other companies' SharePoint), risky TLDs, open redirects, login paths, and links that carry the victim's email address; VirusTotal URL/domain rating; domain age |
| **Attachments** | MD5/SHA1/SHA256 and VirusTotal hash lookup (files are never uploaded); real file type vs extension; double extensions and right-to-left names; executables, scripts, ISO/IMG/LNK/OneNote; Office macros (oletools) and remote templates; PDF JavaScript/Launch/embedded files and links; ZIP contents (recursive) and password-protected archives; HTML/SVG attachments with login forms or HTML smuggling |
| **QR codes** | Decodes QR codes in images (quishing) and checks the decoded links like any other URL |
| **Nested emails** | An email attached inside the reported email is analyzed too, recursively |
| **Claude second opinion** (optional) | Claude classifies the intent (credential phishing, BEC, malware, scam, marketing, legitimate) with a confidence and reasons. This adds or removes 15 points, and it can only cancel the weakest MALICIOUS signal (see the verdict section). |

## Requirements

| | |
|---|---|
| **OS** | Windows 10 or 11 |
| **Python** | 3.11 or newer (tested on 3.14) |
| **Outlook** | **Classic Outlook** (desktop), signed in to the mailbox that receives the reports. The *New Outlook* app has no automation interface and will not work. |
| **Internet** | For VirusTotal, AbuseIPDB and RDAP. Works behind corporate SSL inspection (uses the Windows certificate store). |
| **API keys** | [VirusTotal](https://www.virustotal.com/gui/my-apikey) (free; strongly recommended). [AbuseIPDB](https://www.abuseipdb.com/account/api) (free; optional). [Anthropic](https://console.anthropic.com/) (optional, paid: about $0.02 per email, for the Claude second opinion). |

Only the `analyze` command works without Outlook. It analyzes `.eml`/`.msg` files from disk.

## Installation (10 minutes)

**1. Get the code**

The repository is private, so ask the owner to add you as a collaborator first. Clone it into a **short path** such as `C:\Tools`: Windows' 260-character path limit breaks the `pywin32` install in deep folders.
```bash
git clone https://github.com/msufiyanalishah-sudo/Phish_Analyzer.git C:\Tools\phish-analyzer
```
```bash
cd C:\Tools\phish-analyzer
```

**2. Create a Python environment and install the packages**
```bash
python -m venv .venv
```
```bash
.venv\Scripts\python -m pip install -r requirements.txt
```
Optional, but recommended for QR-code (quishing) detection:
```bash
.venv\Scripts\python -m pip install -r requirements-optional.txt
```

**3. Create your settings files**
```bash
.venv\Scripts\python -m phishanalyzer init
```
This creates `config.yaml` and `.env` from the examples. Neither file is ever committed to Git.

**4. Add your API key.** Open `.env` and fill in:
```
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=
ANTHROPIC_API_KEY=
```
`ANTHROPIC_API_KEY` is optional. Without it, the Claude second opinion is skipped automatically.

**5. Set the minimum settings.** Open `config.yaml` and change at least:
```yaml
mailbox:
  source_folder: "Inbox/Phishing Alert"                 # where the reports land
  report_subject_regex: '^\s*\[Phish Alert\]'           # only real reports (skips "RE: [Phish Alert]" replies)
heuristics:
  internal_domains: ["yourcompany.com"]                 # your own email domains
```
Not sure of the folder name? Run `.venv\Scripts\python -m phishanalyzer list-folders`.

**6. Check that it works**
```bash
.venv\Scripts\python -m pytest -q
```
```bash
.venv\Scripts\python -m phishanalyzer analyze samples\sample_phish.eml --open
```
The sample should come out **MALICIOUS**, and the HTML report should open in your browser.

## Configuration

All settings live in `config.yaml`. Anything you leave out uses the built-in default from `phishanalyzer/config.py`. The most important ones:

| Setting | What it does |
|---|---|
| `mailbox.source_folder` | Outlook folder with the reports, e.g. `Inbox/Phishing Alert` |
| `mailbox.report_subject_regex` | Only items whose subject matches are treated as reports |
| `heuristics.internal_domains` | Your company domains: used for spoofing and company-name impersonation checks |
| `heuristics.vip_names` | Executive names that attackers impersonate |
| `shared_report.folder` | OneDrive/SharePoint-synced folder for the team Excel log |
| `notifications.recipients` | Who gets the alert email, per verdict (To and CC) |
| `intel.virustotal.*` | Rate limit and lookup limits for the free VirusTotal API |
| `scoring.suspicious` / `scoring.malicious` | Score thresholds (default 30 / 60) |

Every setting is explained in **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)**.

## Usage

Run every command from the project folder.

| Task | Command |
|---|---|
| Analyze one email file and open its report | `.venv\Scripts\python -m phishanalyzer analyze "C:\path\email.eml" --open` |
| Analyze a user's report that has the email **attached** | `.venv\Scripts\python -m phishanalyzer analyze "C:\path\report.eml" --report` |
| Analyze without internet lookups | add `--no-intel` |
| **Watch the folder continuously** (log + popups + alerts) | `.venv\Scripts\python -m phishanalyzer watch` |
| Run one watch cycle and exit | `.venv\Scripts\python -m phishanalyzer watch --once` |
| Preview the daily summary email (nothing is sent) | `.venv\Scripts\python -m phishanalyzer daily-report --dry-run` |
| Send the daily summary email | `.venv\Scripts\python -m phishanalyzer daily-report` |
| Re-analyze every row of the Excel log (after a rule change) | `.venv\Scripts\python -m phishanalyzer relog` |
| Show Outlook folder names | `.venv\Scripts\python -m phishanalyzer list-folders` |
| Use another config file | add `-c path\to\config.yaml` before the command |
| More detail in the console | add `-v` before the command |

**Analyzing a single email by hand**
1. In Outlook, open the report and save the attached `phish_alert_*.eml` (right-click → *Save As*). To check an ordinary email instead, drag it to the desktop, which gives you a `.msg` file.
2. In File Explorer, Shift + right-click the file and choose *Copy as path*.
3. Run `.venv\Scripts\python -m phishanalyzer analyze <paste path> --open`.

`analyze` returns exit code `1` if any email is MALICIOUS, so you can use it in scripts.

> **Other commands:** `once` and `run` process the folder in "mailbox mode". They also tag each report with an Outlook category (`Phish-Malicious`, ...) and move it to `<folder>\Processed\<Verdict>`. Use **either** `watch` **or** `run`, not both.

## Run it automatically (Task Scheduler)

So the watcher starts by itself every time you sign in, run this once in PowerShell **from the project folder**:

```powershell
$proj = (Get-Location).Path
$action = New-ScheduledTaskAction -Execute "$proj\.venv\Scripts\pythonw.exe" -Argument "-m phishanalyzer watch" -WorkingDirectory $proj
$trigger = New-ScheduledTaskTrigger -AtLogOn -User ([Security.Principal.WindowsIdentity]::GetCurrent().Name); $trigger.Delay = "PT2M"
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName "Phish Analyzer Watcher" -Action $action -Trigger $trigger -Settings $settings
```

- `pythonw.exe` runs it in the background with no window.
- Only one watcher can run at a time (it holds a lock), so a second copy just exits.
- After changing the code or `config.yaml`, restart the task: *Task Scheduler → Phish Analyzer Watcher → End → Run*.
- Check what it's doing in `logs\phishanalyzer.log`.

The PC must be on and you must be signed in, because the tool reads your Outlook. Reports that arrive while the PC is off are picked up on the next start (up to `watch.backfill_hours`, default 24 hours).

## Outputs

**For every analyzed email** (local, in `reports\<case-id>\`):
- `report.html`: readable report with the verdict, findings, authentication, sender IP, hops, URLs, attachments, IOCs and actions
- `result.json`: everything in machine-readable form
- `iocs.csv`: indicators

**Shared team log** (in `shared_report.folder`, when using `watch`):

| File | Contents |
|---|---|
| `Phishing Alert Log.xlsx` → sheet **Log** | One row per report: verdict, score, SPF/DKIM/DMARC, sender IP and reputation, URLs and VirusTotal results, attachments and hashes, QR codes, key findings, **Block**, **Do NOT block**, remediation, a link to the case report, plus **Status** and **Analyst Notes** columns for the team (never overwritten by the tool) |
| `Phishing Alert Log.xlsx` → sheet **IOCs** | Defanged and raw indicators of malicious and suspicious emails, ready for blocking |
| `Cases\<case-id>.html` | Full report for each email |
| `Daily\Phishing Report <date>.html` | Today's summary, rebuilt whenever a new report arrives |

**Notifications**
- Windows popup for every email. Click it to open the report. If more than 3 arrive at once, you get one summary popup instead.
- Alert email for the verdicts in `notifications.email_verdicts`, sent to the recipients in `notifications.recipients`, once per email or campaign.

## How the verdict is decided

To keep false positives low, an email is **MALICIOUS only on confirmed evidence**, meaning at least one of:

1. **A link flagged by ≥ 3 VirusTotal vendors** (`malicious_threshold_url`). This applies to links in the body, in attachments and in QR codes.
2. **A malicious attachment**:
   - a hash flagged by ≥ 3 VirusTotal vendors,
   - an executable, script, disk image or disguised file (double extension, wrong real type, right-to-left name),
   - an auto-running macro with suspicious functions, an Office remote template, or HTML smuggling,
   - an HTML attachment with a password field (a phishing page delivered as a file).
3. **A link to a login page on a non-legitimate site** (credential phishing). The tool never opens the link. A link counts as a login page if any of these is true:
   - VirusTotal's crawler saw a sign-in page title ("Sign in", "Outlook", "Office 365"...),
   - the link redirects to a login path,
   - VirusTotal categorizes the page as phishing,
   - the link's own path is a login path (`/login`, `/signin`, `/owa`, `wp-login`, `/auth`...).

   Genuine sign-in pages (Microsoft, Google, DocuSign... see `trusted_domains`) don't count. A link from an **authenticated** sender (DMARC pass) to **its own** domain's portal doesn't count either.

Everything else is scored: every finding adds points, or removes them (e.g. an authenticated internal sender).
- **0–29 → CLEAN**
- **30 and up → SUSPICIOUS**: Medium confidence below 60, **High confidence at 60+**.

A high-confidence SUSPICIOUS email strongly matches a phishing pattern, but the tool found no confirmed malicious link, attachment or login page. Examples: a QR-code payroll lure whose link VirusTotal doesn't know yet, or a lookalike sender without links. An analyst decides those.

**Claude second opinion** (when `ANTHROPIC_API_KEY` is set):
- "phishing / BEC / malware / scam" at ≥ 80% confidence adds 15 points; "legitimate / marketing" removes 15.
- It can **cancel** a MALICIOUS verdict only when the sole reason was a login-style path in a link (no VirusTotal evidence) and it is ≥ 85% sure the email is legitimate. The email then stays SUSPICIOUS.
- It can **never** cancel a VirusTotal-flagged link, a malicious attachment or a VirusTotal-confirmed login page. Attackers can write instructions to AI inside an email (prompt injection), so the hard evidence always wins.

Special verdicts:
   - **SIMULATION**: the email has a phishing-simulation header (KnowBe4, GoPhish...). Set `simulation_sender_ips` so attackers can't fake it.
   - **UNANALYZABLE**: the report has no attached email, because the user forwarded it normally. Ask them to use the Phish Alert Button or *Forward as Attachment* (Ctrl+Alt+F).

Details of every check and its points are in **[docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md)**.

> A verdict is decision support, not a final answer. **SUSPICIOUS** always needs an analyst's review, and that's why the Block list for it reads "Block if an analyst confirms".

## Privacy and safety

- **Nothing is executed or opened.** Links are not visited, attachments are not run, HTML is not rendered.
- **What leaves your machine:** lookups of hashes, URLs, domains and IPs (VirusTotal, AbuseIPDB) and domain names (rdap.org). Files are **never uploaded**, and URLs are **never submitted** for scanning.
- **Claude second opinion (only if `ANTHROPIC_API_KEY` is set):** the subject, sender, authentication results, visible body text (up to 8,000 characters), defanged links and attachment names are sent to Anthropic's API. Internal email addresses, your company name and phone numbers are masked first; reporters and recipients are never sent. Anthropic does not train models on API data. **Get your organization's approval before enabling it.**
- **Everything shown to people is defanged** (`hxxps://evil[.]com`). Every email the tool sends is defanged automatically, because a live phishing link in an email gets it quarantined by Microsoft 365. Raw indicators are only in the Excel IOCs sheet and `result.json`.
- **Secrets stay local:** `.env` (API keys), `config.yaml`, `reports\`, `data\`, `logs\` and `Exports\` are in `.gitignore`.
- Antivirus/EDR may react to phishing attachments while they're briefly saved for analysis. Prefer a SOC analysis workstation.

## Project structure

```
phish-analyzer/
├── phishanalyzer/
│   ├── __main__.py          command line (analyze, watch, daily-report, relog, ...)
│   ├── config.py            default settings
│   ├── parsing.py           .eml / .msg parsing, nested emails
│   ├── pipeline.py          runs all analyzers for one email, saves the case
│   ├── analyzers/
│   │   ├── headers.py       identity, spoofing, lookalikes, hops, originating IP
│   │   ├── auth.py          SPF / DKIM / DMARC / ARC / CompAuth
│   │   ├── sender.py        IP and domain reputation
│   │   ├── body.py          language, brands, HTML tricks
│   │   ├── urls.py          link extraction, unwrapping, heuristics, VirusTotal, domain age
│   │   └── attachments.py   file types, macros, PDF, ZIP, HTML, QR codes, hashes
│   ├── intel/               VirusTotal, AbuseIPDB, RDAP clients + cache
│   ├── scoring.py           verdict, confidence, IOCs
│   ├── report.py            per-email HTML / JSON / CSV
│   ├── outlook_com.py       Outlook access
│   ├── watch.py             continuous mode
│   ├── shared_log.py        Excel log, case pages, daily summary
│   ├── notify.py            popups and alert emails
│   ├── daily_report.py      summary email, block / do-not-block remediation
│   └── relog.py             re-analyze existing Excel rows
├── tests/                   automated tests (pytest)
├── samples/                 synthetic test emails (safe)
├── docs/                    configuration, how it works, troubleshooting
├── config.example.yaml      copy to config.yaml (via "init")
└── .env.example             copy to .env (via "init")
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `Outlook folder '...' not found` | Run `list-folders` and copy the exact path into `mailbox.source_folder`, e.g. `Inbox/Phishing Alert` |
| `VirusTotal skipped: VT_API_KEY is not set` | Put the key in `.env` (not in `config.yaml`) |
| Lots of `VirusTotal rate limit: waiting` lines | Normal on the free API (4 lookups a minute). Results are cached for 24 hours. |
| Alert email shows in Sent Items but nobody receives it | It was probably quarantined. Check Defender quarantine. Current versions defang every link to prevent this. |
| `Permission denied ... Phishing Alert Log.xlsx` | Someone has the workbook open in desktop Excel. The tool retries on the next cycle. |
| No popups | Check *Windows Settings → Notifications* and Focus Assist |
| `pip install` fails with `WinError 3 ... MAPIStubLibrary`, then `No module named 'pywin32_bootstrap'` | The folder path is too long. Clone into a short path like `C:\Tools\phish-analyzer`, delete `.venv` and install again. |

More fixes are in **[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)**.

## More documentation
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md): every setting explained
- [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md): the analysis pipeline, every check, and the scoring
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md): common problems and fixes
