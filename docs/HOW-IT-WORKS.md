# How it works

This page explains what happens to a reported email, every check that can fire, and how the final verdict is computed. The numbers below match the code in `phishanalyzer/`.

## 1. Pipeline

```
Outlook report  ──►  extract attached email (.eml / .msg / Outlook item)
                       │
                       ▼
                parse MIME (parsing.py) ─► headers, text/HTML bodies, attachments, nested emails
                       │
                       ▼
   ┌───────────────┬───────────────┬──────────────┬────────────────┬──────────────┐
   headers.py      auth.py         body.py        attachments.py   urls.py        sender.py
   identity,       SPF/DKIM/       language,      types, macros,   unwrap, flags, IP + domain
   lookalikes,     DMARC/ARC/      brands, HTML   PDF, ZIP, HTML,  VirusTotal,    reputation
   hops, IP        CompAuth        tricks         QR, hashes, VT   domain age
   └───────────────┴───────────────┴──────────────┴────────────────┴──────────────┘
                       │  each check adds a "finding" (points, evidence, optional hard verdict)
                       ▼
                scoring.py ─► verdict, score, confidence, IOCs, recommended actions
                       │
                       ▼
     report.py (HTML/JSON/CSV) · shared_log.py (Excel + daily page) · notify.py (popup + email)
```

- Every check is isolated. If one fails (for example, a network error), the rest still run, and the error is listed in the report.
- Threat-intel lookups are cached for 24 hours in `data\intel_cache.sqlite` and rate-limited for the free VirusTotal API (4 per minute).
- Links, domains and IPs on Microsoft's own infrastructure (`vt_skip_domains`) are not sent to VirusTotal, to save the daily quota.

## 2. Findings and points

Points add up to the score (capped at 0–100). A finding marked **HARD** makes the email MALICIOUS regardless of the score.

### Headers (`headers.py`)
| Points | Finding |
|---:|---|
| 25 | From / Reply-To / Return-Path domain looks like a protected domain (lookalike: edit distance, homoglyphs like `0→o`, `rn→m`, brand inside another domain) |
| 25 | External sender uses an executive's name (`vip_names`) |
| 15 | Domain uses punycode (`xn--`) |
| 15 | Reply-To goes to a free email provider (Gmail, Outlook.com...) |
| 15 | Display name contains a different email address |
| 15 | From address missing or invalid |
| 10 | Reply-To domain differs from From domain |
| 10 | Return-Path domain differs from From domain (ignored for known bulk-mail platforms) |
| 10 | External email uses **your company name** in the subject, sender name or attachment name |
| 5 | Sent with a bulk/scripted mailer (PHPMailer, GoPhish...) |
| 5 | Date header in the future · Received timestamps out of order |
| 3 | Message-ID domain differs · Date header unparseable |
| 30 | Phishing-simulation header from an IP not in `simulation_sender_ips` (possible fake) |
| — | Phishing-simulation header present → verdict **SIMULATION** |

**Originating IP:** taken from Microsoft's `Authentication-Results` "sender IP is ..." stamp if present, otherwise the first external hop in the `Received` chain.

### Authentication (`auth.py`)
Uses the **top-most** `Authentication-Results` header (stamped by your own mail server), plus a DNS lookup of the sender's DMARC policy.

| Points | Finding |
|---:|---|
| 20 | DMARC failed |
| 10 | SPF failed |
| 10 | Microsoft CompAuth failed |
| 5 | SPF softfail · DKIM failed · sender domain has no/`p=none` DMARC policy |
| 3 | SPF permerror/temperror |
| 25 | Claims to be from your own domain but is not authenticated |
| **−20** | Authenticated sender from your own domain |

### Body (`body.py`)
| Points | Finding |
|---:|---|
| 15 | Credential language ("verify your account", "password expires", "mailbox is full"...) |
| 15 | Payment / bank-detail language (possible BEC) · Gift-card request · HR/salary lure |
| 10 | Threat language ("will be suspended", "legal action"...) |
| 5 | Urgency ("immediately", "within 24 hours") · lure themes (voicemail, shared document, parcel...) |
| 15 | Uses a brand (Microsoft, DocuSign, DHL...) but the sender isn't that brand. This counts only if the brand is in the subject/sender name, or the email asks for credentials. |
| 20 | Contains a password field |
| 15 | Contains an HTML form |
| 10 | Link text shows a different address than the real link (newsletter click-tracking is ignored) |
| 10 | Active HTML (script, iframe, object, meta refresh) · non-image `data:` URIs · right-to-left override |
| 5 | Hidden text blocks (more than one) · many zero-width characters · mostly an image |

### Links (`urls.py`)
Links are collected from the text and HTML bodies, attachments (PDF, Office, HTML) and QR codes. Microsoft Safe Links, Proofpoint URL Defense and Google redirects are unwrapped to the real destination.

| Points | Finding |
|---:|---|
| 25 | Domain imitates a protected brand/domain |
| 15 | Raw IP address · punycode · carries the recipient's email address (personalized phishing kit) |
| 15 | Domain registered within `new_domain_days` (default 30) |
| 10 | URL shortener · free hosting/form service · `@` hiding the host · open redirect |
| 10 | File-sharing link (WeTransfer, Dropbox, Google Drive, MEGA, **another company's SharePoint**) |
| 5 | High-risk TLD · long subdomain chain · login-style path · login page without HTTPS |
| 20 | URL or its domain flagged by a few VirusTotal engines |
| 50 **HARD** | URL flagged by ≥ `malicious_threshold_url` (2) engines, or, if VirusTotal doesn't know the URL, its domain by ≥ `malicious_threshold_domain` (5) |

### Attachments (`attachments.py`)
| Points | Finding |
|---:|---|
| 50 **HARD** | Executable, script or disk image (`.exe .js .vbs .ps1 .hta .lnk .iso .img .one .msi`...) |
| 50 **HARD** | Double extension (`invoice.pdf.exe`) · right-to-left name trick · EXE disguised as another type · encrypted archive containing an executable |
| 50 **HARD** | Auto-running macro with suspicious functions (oletools) · HTML smuggling |
| 40 **HARD** | Office document loads a remote template/object |
| 50 **HARD** | Hash flagged by ≥ `malicious_threshold_file` (3) VirusTotal engines |
| 30 | HTML attachment contains a login form |
| 20 | Office macros present · PDF JavaScript/Launch · password-protected archive · HTML script that redirects/decodes · hash flagged by 1–2 engines |
| 15 | HTML/SVG attachment · content doesn't match the extension |
| 10 | PDF embedded file · image contains a QR code · archive too large (possible zip bomb) |
| 5 | Unsupported archive format (RAR/7z) · corrupt ZIP |

Files are **never uploaded** to VirusTotal. Only their SHA256 hash is looked up. Images are not looked up, since they are almost never on VirusTotal; their QR codes are decoded instead.

### Sender reputation (`sender.py`)
| Points | Finding |
|---:|---|
| 20 | Sender IP flagged by ≥ 3 VirusTotal engines (10 for 1–2) |
| 15 | AbuseIPDB confidence ≥ 50% (5 for ≥ 25%) |
| 5 | Sender IP in a country outside `allowed_countries` |
| 20 / 15 | From / Reply-To domain registered within `new_domain_days` |
| 20 | Sender domain flagged by a few VirusTotal engines (may be stale) |
| 50 **HARD** | Sender domain flagged by ≥ `malicious_threshold_domain` (5) engines |
| 5 | Email carries another email as an attachment |

## 3. Combination rules (HARD → MALICIOUS)
Some weak signals are strong together:

| Combination | Example |
|---|---|
| Credential lure **+** lookalike, newly registered or spoofed-internal domain | "Your password expires" from `micros0ft-secure.com` |
| Your company name **+** HR, credential or QR lure, from an external sender | "Contoso SALARY INCREASE NOTICE" from a random `.de` domain |
| QR code **+** any lure (credential, HR, payment, brand, image-only, victim email in link) | Image with a QR code to `...?email=<base64 of victim>` |

## 4. Verdict
| Verdict | When |
|---|---|
| **MALICIOUS** | Any HARD finding or combination rule, or score ≥ `scoring.malicious` (60) |
| **SUSPICIOUS** | Score ≥ `scoring.suspicious` (30). Always needs an analyst's review. |
| **CLEAN** | Score below 30 |
| **SIMULATION** | Phishing-simulation header from a trusted source |
| **UNANALYZABLE** | The report doesn't contain the original email (the user did a normal Forward) |

**Confidence:** High for hard rules and scores ≥ 80. Medium for scores in between. For CLEAN, High only when threat-intel lookups actually ran.

## 5. Remediation advice
For MALICIOUS and SUSPICIOUS emails, the tool writes three lists (in `daily_report.build_remediation`):

- **Block**: sender addresses, attacker domains and URL domains, exact URLs on shared hosting, attachment hashes, the sender IP (only if it's not shared mail infrastructure).
- **Do NOT block**: your own domain, free-mail and big providers (block the address only), legitimate services like SharePoint, WeTransfer or Microsoft (block the exact URL only), shared mail servers (IONOS, Microsoft, Google, SendGrid...), and bulk-mail bounce addresses.
- **Remediation steps**:
  - purge the email (by attachment name for campaigns),
  - check proxy logs for clicks,
  - check Entra ID sign-ins for the targeted users,
  - QR-code awareness,
  - EDR scan for malware,
  - a Finance/HR warning for payment or payroll lures.

For SUSPICIOUS emails the list is titled **"Block if an analyst confirms"**.

## 6. Campaign grouping
Copies of the same attack are grouped into one row in the daily summary, and get **one** alert email. Copies count as the same when they carry the same attached email name, the same attachments (by hash) or the same Message-ID, even if each copy comes from a different sender.
