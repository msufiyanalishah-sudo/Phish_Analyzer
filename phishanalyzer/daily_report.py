"""Daily summary: analyze the last N hours of user reports and email the verdicts, remediation and malicious samples."""
from __future__ import annotations

import csv
import io
import logging
import re
import shutil
import tempfile
from datetime import datetime, timedelta
from html import escape
from pathlib import Path

from .analyzers.urls import FREE_HOSTING, SHORTENERS
from .config import resolve_path
from .intel import Intel
from .models import CaseResult
from .outlook_com import OL_MAIL_ITEM, analyze_item, connect, find_folder, is_user_report, received_time
from .pipeline import save_case
from .scoring import SEVERITY
from .store import CaseStore
from .utils import (ESP_DOMAINS, FREEMAIL_DOMAINS, defang_domain, defang_email, defang_text, defang_url, domain_matches, domain_of,
                    registrable_domain)

log = logging.getLogger(__name__)

# Shared email / cloud infrastructure: blocking these IPs would break legitimate mail.
SHARED_INFRA = ("microsoft", "outlook.com", "google", "amazon", "amazonses", "cloudflare", "akamai", "sendgrid",
                "mailgun", "mailchimp", "rocket science", "mcsv.net", "sparkpost", "mandrill", "zoho", "yahoo",
                "oracle", "salesforce", "mimecast", "proofpoint", "barracuda", "kundenserver", "ionos", "1and1",
                "secureserver", "godaddy", "hostinger", "ovh", "gmx", "web.de", "titan.email", "emailsrvr",
                "rackspace", "hubspot", "ntesmail", "qq.com", "aliyun", "yandex", "mail.ru", "protonmail")
COLORS = {"MALICIOUS": "#b42318", "SUSPICIOUS": "#b54708", "CLEAN": "#067647", "SIMULATION": "#175cd3",
          "UNANALYZABLE": "#475467"}
ICON = {"MALICIOUS": "&#128308;", "SUSPICIOUS": "&#128992;", "CLEAN": "&#128994;", "SIMULATION": "&#128309;",
        "UNANALYZABLE": "&#9898;"}


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(i for i in items if i))


def build_remediation(r: CaseResult, cfg: dict, targets: list[str] | None = None) -> dict[str, list[str]]:
    """What to block, what NOT to block (and why), and what else to do for one analyzed email.
    `targets` are the users who reported it (they received it)."""
    if r.verdict not in ("MALICIOUS", "SUSPICIOUS"):
        return {"block": [], "do_not_block": [], "actions": list(r.recommended_actions)}
    h = cfg["heuristics"]
    internal = h["internal_domains"]
    legit = list(FREEMAIL_DOMAINS) + h["trusted_domains"] + h["protected_domains"]
    hosting = list(SHORTENERS) + list(FREE_HOSTING)   # abused shared hosting: block exact URLs, never the domain
    shared = legit + hosting
    block, keep, actions = [], [], []
    blocked_domains: set[str] = set()
    blocked_addresses: set[str] = set()
    o = r.original
    malicious = r.verdict == "MALICIOUS"

    for role, addr in (("Sender", o.get("from_address")), ("Reply-To", o.get("reply_to")),
                       ("Return-Path", o.get("return_path"))):
        if not addr:
            continue
        dom = domain_of(addr)
        if domain_matches(dom, internal):
            keep.append(f"{role} {defang_email(addr)}: our own domain. Do not block; check for spoofing or a compromised account.")
            continue
        if role == "Return-Path" and domain_matches(dom, ESP_DOMAINS):
            keep.append(f"Return-Path {defang_domain(registrable_domain(dom))}: bulk-mail bounce address. Blocking it has no effect.")
            continue
        if addr.lower() not in blocked_addresses:
            blocked_addresses.add(addr.lower())
            block.append(f"Email address ({role}): {defang_email(addr)}")
        reg = registrable_domain(dom)
        if reg in FREEMAIL_DOMAINS or domain_matches(reg, shared):
            keep.append(f"Domain {defang_domain(reg)}: public/shared provider. Block the address only, not the domain.")
        elif malicious and reg not in blocked_domains:
            blocked_domains.add(reg)
            if r.auth.get("dmarc") == "pass" and "lookalike" not in r.tags:
                block.append(f"Sender domain: {defang_domain(reg)} (optional: it passed SPF/DKIM/DMARC, so this is "
                             "probably a compromised real account)")
            else:
                block.append(f"Sender domain: {defang_domain(reg)}")

    for u in r.urls:
        if u.get("internal"):
            continue
        vt_bad = ((u.get("virustotal") or {}).get("malicious", 0) or
                  ((u.get("virustotal") or {}).get("domain_report") or {}).get("malicious", 0))
        young = u.get("domain_age_days") is not None and u["domain_age_days"] < h["new_domain_days"]
        sender_dom = registrable_domain(domain_of(o.get("from_address", "")))
        risky = bool(u["flags"]) or vt_bad or young or u["domain"] == sender_dom
        if domain_matches(u["host"], legit):
            if vt_bad:
                block.append(f"Exact URL: {u['url_defanged']}")
            keep.append(f"Domain {defang_domain(u['domain'])}: legitimate service. Do not block the domain.")
        elif domain_matches(u["host"], hosting):
            if risky or malicious:
                block.append(f"Exact URL: {u['url_defanged']}")
                keep.append(f"Domain {defang_domain(u['domain'])}: legitimate shared service. Block the exact URL only.")
        elif malicious:
            # Any non-legitimate link inside a confirmed phish is attacker infrastructure.
            block.append(f"URL domain: {defang_domain(u['domain'])}")
        elif risky:
            block.append(f"Exact URL: {u['url_defanged']}")
        else:
            keep.append(f"{defang_domain(u['domain'])}: no bad signals found. Review before blocking.")

    ip = r.originating_ip.get("ip", "")
    if ip:
        owner = " ".join(str(r.originating_ip.get(k, "")) for k in ("asn_owner", "ptr")).lower()
        shown = ip.replace(".", "[.]")
        if any(s in owner for s in SHARED_INFRA):
            keep.append(f"Sender IP {shown}: shared mail infrastructure ({owner.strip()}). Do not block.")
        elif malicious:
            block.append(f"Sender IP: {shown}")

    for a in r.attachments:
        if a["inline"] and a["true_type"] in ("png", "jpeg", "gif", "bmp"):
            continue
        if a["flags"] or malicious:
            block.append(f"File hash (EDR/gateway): {a['sha256']}  ({a['name']})")

    tags = r.tags
    if malicious:
        nested = next((f.evidence for f in r.findings if "nested_email" in f.tags), "")
        if nested:
            actions.append(f"Search and purge from all mailboxes every email with the attachment \"{nested}\" "
                           "(each copy can have a different sender and subject).")
        else:
            actions.append(f"Search and purge from all mailboxes: subject \"{o.get('subject', '')}\" "
                           f"from {defang_email(o.get('from_address', ''))}.")
        if r.urls:
            actions.append("Check proxy/firewall logs for anyone who opened the links above.")
        if tags & {"credential_lure", "brand_impersonation", "lookalike", "victim_email", "qr", "hr_lure", "internal_impersonation"}:
            who = f" ({len(targets)} users: {', '.join(targets[:15])}{' ...' if len(targets) > 15 else ''})" if targets else ""
            actions.append(f"Check Entra ID sign-in logs for the recipients{who}; if anyone entered credentials, "
                           "reset the password and revoke sessions.")
        if "qr" in tags:
            actions.append("QR-code phishing: remind targeted users not to scan QR codes in emails; check mobile/MDM "
                           "and Entra sign-ins from unmanaged phones, because the scan happens outside the corporate proxy.")
        if "malware" in tags or "macro" in tags:
            actions.append("Run an EDR scan on devices where the attachment was opened; isolate any device that ran it.")
        if "bec" in tags and "hr_lure" not in tags:
            actions.append("Alert Finance/HR: verify any payment, payroll or bank-detail change by phone using a known number.")
        if "internal_spoof" in tags:
            actions.append("Our own domain was spoofed: confirm DMARC is enforced (p=reject) and check the sending source.")
        if "reply_to_mismatch" in tags:
            actions.append(f"Block replies to {defang_email(o.get('reply_to', ''))} at the gateway.")
    else:
        actions += ["Analyst review needed before blocking anything.",
                    "Consider soft-deleting the email from mailboxes while it is reviewed."]
    return {"block": _dedupe(block), "do_not_block": _dedupe(keep), "actions": _dedupe(actions)}


def collect(cfg: dict, intel: Intel, store: CaseStore, hours: float, include_reported: bool) -> list[dict]:
    ns = connect()
    folder = find_folder(ns, cfg["mailbox"].get("store", ""), cfg["mailbox"]["source_folder"])
    items = folder.Items
    items.Sort("[ReceivedTime]", True)
    cutoff = datetime.now() - timedelta(hours=hours)
    workroot = resolve_path(cfg, cfg["outputs"]["quarantine_dir"])
    workroot.mkdir(parents=True, exist_ok=True)
    entries = []
    for i in range(1, items.Count + 1):
        item = items.Item(i)
        if item.Class != OL_MAIL_ITEM:
            continue
        if received_time(item) < cutoff:
            break
        if not is_user_report(item, cfg):
            continue
        entry_id = item.EntryID
        if not include_reported and store.is_reported(entry_id):
            continue
        workdir = Path(tempfile.mkdtemp(prefix="daily_", dir=workroot))
        try:
            analyzed = analyze_item(item, cfg, intel, workdir)
        except Exception as exc:
            log.exception("Could not analyze '%s'", item.Subject)
            entries.append({"error": f"{item.Subject}: {exc}", "entry_id": entry_id})
            continue
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        for result, raw, name in analyzed:
            paths = save_case(result, cfg, store, raw or None)
            log.info("%-12s %s", result.verdict, result.original.get("subject", ""))
            entries.append({"result": result, "raw": raw, "name": name, "entry_id": entry_id, "report": paths["html"]})
    return entries


def campaign_key(r: CaseResult) -> str:
    """Same attachments = same campaign, even when every copy comes from a different sender."""
    nested = next((f.evidence for f in r.findings if "nested_email" in f.tags), "")
    hashes = sorted(a["sha256"] for a in r.attachments if not a["inline"] and a["size"] > 1024)
    if nested and r.verdict in ("MALICIOUS", "SUSPICIOUS"):
        return "campaign:" + nested.lower()      # e.g. every 'Contoso SALARY INCREASE NOTICE.eml'
    if hashes:
        return "campaign:" + "|".join(hashes)
    return CaseStore.dedupe_key(r) or r.case_id


def group_entries(entries: list[dict]) -> list[dict]:
    """One group per distinct email: several users often report the same phish."""
    groups: dict[str, dict] = {}
    for e in entries:
        if "result" not in e:
            continue
        r = e["result"]
        key = campaign_key(r)
        g = groups.setdefault(key, {"key": key, "result": r, "raw": e["raw"], "report": e["report"], "reporters": [],
                                    "entry_ids": [], "results": []})
        g["results"].append(r)
        if r.reported_by and r.reported_by not in g["reporters"]:
            g["reporters"].append(r.reported_by)
        g["entry_ids"].append(e["entry_id"])
        if SEVERITY.get(r.verdict, 0) > SEVERITY.get(g["result"].verdict, 0):
            g.update(result=r, raw=e["raw"], report=e["report"])
    return sorted(groups.values(), key=lambda g: (-SEVERITY.get(g["result"].verdict, 0), -g["result"].score))


def _e(v) -> str:
    return escape("" if v is None else str(v))


def _list(items: list[str], color: str = "#1d2433") -> str:
    if not items:
        return "<span style='color:#7a8394'>None</span>"
    return "<ul style='margin:4px 0 0 18px;padding:0'>" + "".join(
        f"<li style='margin:2px 0;color:{color}'>{_e(i)}</li>" for i in items) + "</ul>"


def render_email(groups: list[dict], hours: float, cfg: dict, errors: list[str],
                 heading: str = "", intro: str = "", attached: bool = False) -> tuple[str, str]:
    counts = {v: 0 for v in ("MALICIOUS", "SUSPICIOUS", "CLEAN", "SIMULATION", "UNANALYZABLE")}
    for g in groups:
        counts[g["result"].verdict] = counts.get(g["result"].verdict, 0) + 1
    total_reports = sum(len(g["entry_ids"]) for g in groups)
    today = datetime.now().strftime("%d %b %Y")
    subject = (f"Daily Phishing Report {today}: {counts['MALICIOUS']} Malicious, {counts['SUSPICIOUS']} Suspicious, "
               f"{counts['CLEAN']} Clean ({total_reports} reports)")

    cell = "padding:6px 8px;border-bottom:1px solid #e6e8ec;font-size:13px;vertical-align:top"
    tiles = "".join(
        f"<td style='padding:10px 14px;background:{COLORS[v]};color:#fff;font-size:13px'><b style='font-size:20px'>{n}</b><br>{v.title()}</td>"
        f"<td style='width:6px'></td>" for v, n in counts.items())
    rows = []
    for i, g in enumerate(groups, 1):
        r = g["result"]
        reasons = "; ".join(f.title for f in sorted(r.findings, key=lambda f: (f.hard_verdict is None, -f.points))
                            if f.points > 0 or f.hard_verdict)[:220]
        rows.append(
            f"<tr><td style='{cell}'>{i}</td>"
            f"<td style='{cell};color:{COLORS.get(r.verdict, '#475467')};white-space:nowrap'><b>{ICON.get(r.verdict, '')} {_e(r.verdict)}</b></td>"
            f"<td style='{cell}'>{r.score}</td><td style='{cell}'>{_e(r.original.get('subject', ''))}</td>"
            f"<td style='{cell}'>{_e(defang_email(r.original.get('from_address', '')))}</td>"
            f"<td style='{cell}'>{len(g['reporters']) or len(g['entry_ids'])}</td><td style='{cell}'>{_e(reasons) or '-'}</td></tr>")
    table = ("<table style='border-collapse:collapse;width:100%'><tr style='background:#f3f4f6'>" +
             "".join(f"<th style='{cell};text-align:left'>{h}</th>" for h in ("#", "Verdict", "Score", "Subject", "Sender", "Reports", "Why")) +
             "</tr>" + "".join(rows) + "</table>") if rows else "<p>No new reports in this period.</p>"

    details = []
    for i, g in enumerate(groups, 1):
        r = g["result"]
        if r.verdict not in ("MALICIOUS", "SUSPICIOUS"):
            continue
        rem = build_remediation(r, cfg, g["reporters"])
        for sibling in g["results"]:   # campaign copies from other senders add their own indicators
            if sibling is not r:
                extra = build_remediation(sibling, cfg)
                rem["block"] = _dedupe(rem["block"] + extra["block"])
                rem["do_not_block"] = _dedupe(rem["do_not_block"] + extra["do_not_block"])
        senders = _dedupe([x.original.get("from_address", "") for x in g["results"]])
        others = f" (+{len(senders) - 1} other senders)" if len(senders) > 1 else ""
        color = COLORS[r.verdict]
        block_title = "Block" if r.verdict == "MALICIOUS" else "Block if an analyst confirms"
        details.append(f"""
<div style='border:1px solid #e3e6eb;border-left:5px solid {color};border-radius:6px;padding:12px 16px;margin:14px 0'>
 <div style='font-size:15px'><b style='color:{color}'>#{i} {_e(r.verdict)}</b> (score {r.score}, {_e(r.confidence)} confidence): <b>{_e(r.original.get('subject', ''))}</b></div>
 <div style='font-size:12px;color:#55607a;margin-top:4px'>From {_e(defang_email(r.original.get('from_address', '')))}{_e(others)} &middot;
   Reply-To {_e(defang_email(r.original.get('reply_to', '')) or '-')} &middot; Reported by {_e(', '.join(g['reporters']) or '-')} &middot; Case {_e(r.case_id)}</div>
 <div style='margin-top:10px;font-size:13px'><b>Why</b>{_list([f'{f.title}: {f.evidence}' if f.evidence else f.title for f in sorted(r.findings, key=lambda f: (f.hard_verdict is None, -f.points)) if f.points > 0 or f.hard_verdict][:8])}</div>
 <div style='margin-top:10px;font-size:13px'><b style='color:#b42318'>&#128683; {block_title}</b>{_list(rem['block'])}</div>
 <div style='margin-top:10px;font-size:13px'><b style='color:#067647'>&#9989; Do NOT block</b>{_list(rem['do_not_block'])}</div>
 <div style='margin-top:10px;font-size:13px'><b>&#128295; Remediation steps</b>{_list(rem['actions'])}</div>
 <div style='margin-top:8px;font-size:12px;color:#55607a'>Full report: {_e(g['report'])}</div>
</div>""")

    other = [g for g in groups if g["result"].verdict in ("CLEAN", "SIMULATION", "UNANALYZABLE")]
    other_html = _list([f"{g['result'].verdict}: {g['result'].original.get('subject', '')}. {g['result'].recommended_actions[0]}"
                        for g in other]) if other else ""
    err_html = f"<h3 style='font-size:14px'>Errors</h3>{_list(errors, '#b42318')}" if errors else ""
    attach_note = "The original malicious emails are attached as .eml files. Do not open them outside a sandbox." \
        if attached else ""

    html = f"""<html><body style='font-family:Segoe UI,Arial,sans-serif;color:#1d2433'>
<h2 style='margin:0 0 4px'>{_e(heading) or f"Daily Phishing Report: {today}"}</h2>
<div style='color:#55607a;font-size:13px'>{_e(intro) or f'Reports in "{_e(cfg["mailbox"]["source_folder"])}" from the last {hours:g} hours: {total_reports} reports, {len(groups)} unique emails.'}</div>
<table style='margin:14px 0'><tr>{tiles}</tr></table>
<div style='font-size:13px;color:#b42318'>{attach_note}</div>
<h3 style='font-size:15px;margin-top:18px'>All reported emails</h3>{table}
<h3 style='font-size:15px;margin-top:22px'>Malicious and suspicious: remediation</h3>
{''.join(details) or "<p>None.</p>"}
{"<h3 style='font-size:15px;margin-top:22px'>Clean / other</h3>" + other_html if other else ""}
{err_html}
<p style='font-size:11px;color:#7a8394;margin-top:20px'>Generated automatically by phish-analyzer (static analysis; links were not opened and attachments were not executed). All indicators, including the attached iocs.csv, are defanged. Raw values for blocking are in the IOCs sheet of the shared Phishing Alert Log.</p>
</body></html>"""
    return subject, html


def ioc_csv(groups: list[dict]) -> bytes:
    """Defanged IOCs only: live malicious URLs in an attachment get the whole email quarantined by
    Microsoft 365. Raw values for blocking tools are in the shared workbook's IOCs sheet."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["case_id", "verdict", "subject", "type", "value_defanged"])
    for g in groups:
        r = g["result"]
        if r.verdict not in ("MALICIOUS", "SUSPICIOUS"):
            continue
        for kind, values in r.iocs.items():
            for v in values:
                shown = defang_url(v) if kind == "urls" else defang_email(v) if kind == "emails" else \
                    v.replace(".", "[.]") if kind in ("domains", "ips") else v
                writer.writerow([r.case_id, r.verdict, r.original.get("subject", ""), kind, shown])
    return buf.getvalue().encode("utf-8-sig")


def report_attachments(groups: list[dict], cfg: dict) -> list[tuple[str, bytes]]:
    dcfg = cfg["daily_report"]
    files = []
    for i, g in enumerate(groups, 1):
        r = g["result"]
        wanted = (r.verdict == "MALICIOUS" and dcfg.get("attach_malicious")) or \
                 (r.verdict == "SUSPICIOUS" and dcfg.get("attach_suspicious"))
        if wanted and g["raw"]:
            subject = re.sub(r"[^\w\- ]", "_", r.original.get("subject", "email"))[:50].strip() or "email"
            files.append((f"{r.verdict}_{i:02d}_{subject}.eml", g["raw"]))
    if any(g["result"].verdict in ("MALICIOUS", "SUSPICIOUS") for g in groups):
        files.append((f"iocs_{datetime.now():%Y%m%d}.csv", ioc_csv(groups)))
    return files


def current_user_address(ns) -> str:
    try:
        user = ns.CurrentUser.AddressEntry.GetExchangeUser()
        if user:
            return user.PrimarySmtpAddress
    except Exception:
        pass
    return ns.CurrentUser.Address


def send_mail(to: str, subject: str, html: str, files: list[tuple[str, bytes]], workroot: Path, cc: str = "") -> None:
    """`to` and `cc` are '; '-separated address lists."""
    import win32com.client
    mail = win32com.client.Dispatch("Outlook.Application").CreateItem(0)
    mail.To = to
    if cc:
        mail.CC = cc
    mail.Subject = defang_text(subject)
    # Safety net: one live phishing URL anywhere in the body gets the whole email quarantined.
    mail.HTMLBody = defang_text(html)
    workdir = Path(tempfile.mkdtemp(prefix="send_", dir=workroot))
    try:
        for name, data in files:
            path = workdir / name
            path.write_bytes(data)
            mail.Attachments.Add(str(path))   # Outlook copies the file into the message
        mail.Send()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def run_daily_report(cfg: dict, intel: Intel, store: CaseStore, hours: float | None = None, dry_run: bool = False,
                     to: str = "", include_reported: bool = False) -> Path:
    hours = hours or cfg["daily_report"].get("lookback_hours", 24)
    entries = collect(cfg, intel, store, hours, include_reported)
    errors = [e["error"] for e in entries if "error" in e]
    groups = group_entries(entries)
    files = report_attachments(groups, cfg)
    subject, html = render_email(groups, hours, cfg, errors, attached=any(n.endswith(".eml") for n, _ in files))

    out_dir = resolve_path(cfg, cfg["outputs"]["report_dir"]) / "daily"
    out_dir.mkdir(parents=True, exist_ok=True)
    preview = out_dir / f"daily-{datetime.now():%Y%m%d-%H%M}.html"
    preview.write_text(html, encoding="utf-8")

    print(f"\n{subject}")
    for g in groups:
        r = g["result"]
        print(f"  {r.verdict:<12} score {r.score:>3}  x{len(g['entry_ids'])}  {r.original.get('subject', '')[:70]}")
    print(f"Attachments: {', '.join(n for n, _ in files) or 'none'}")
    print(f"Preview: {preview}")

    if dry_run:
        print("Dry run: email NOT sent.")
        return preview
    ns = connect()
    recipient = to or cfg["daily_report"].get("to") or current_user_address(ns)
    send_mail(recipient, subject, html, files, resolve_path(cfg, cfg["outputs"]["quarantine_dir"]))
    store.mark_reported(_dedupe([e["entry_id"] for e in entries]))
    print(f"Sent to {recipient}.")
    return preview
