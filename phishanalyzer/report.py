"""JSON, HTML and IOC-CSV reports. Everything human-readable is defanged."""
from __future__ import annotations

import csv
import json
from html import escape
from pathlib import Path

from .models import CaseResult
from .utils import defang_domain, defang_email, defang_text, defang_url

COLORS = {"MALICIOUS": "#b42318", "SUSPICIOUS": "#b54708", "CLEAN": "#067647", "SIMULATION": "#175cd3",
          "UNANALYZABLE": "#475467", "UNKNOWN": "#475467"}


def write_reports(result: CaseResult, case_dir: Path) -> dict[str, Path]:
    case_dir.mkdir(parents=True, exist_ok=True)
    paths = {"json": case_dir / "result.json", "html": case_dir / "report.html", "iocs": case_dir / "iocs.csv"}
    paths["json"].write_text(json.dumps(result.to_dict(), indent=2, default=str), encoding="utf-8")
    paths["html"].write_text(render_html(result), encoding="utf-8")
    with paths["iocs"].open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["case_id", "verdict", "type", "value"])
        for kind, values in result.iocs.items():
            for value in values:
                writer.writerow([result.case_id, result.verdict, kind, value])
    return paths


def _e(value) -> str:
    return escape("" if value is None else str(value))


def _table(headers: list[str], rows: list[list]) -> str:
    if not rows:
        return "<p class='muted'>None</p>"
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{_e(c)}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _vt(report: dict | None) -> str:
    if not report:
        return "not checked"
    if not report.get("found"):
        dom = report.get("domain_report")
        return f"URL unknown; domain {dom.get('malicious', 0)} malicious" if dom else "not found"
    return f"{report.get('malicious', 0)} malicious / {report.get('suspicious', 0)} suspicious"


def render_html(r: CaseResult) -> str:
    o = r.original
    a = r.auth
    color = COLORS.get(r.verdict, "#475467")
    findings = sorted(r.findings, key=lambda f: (f.hard_verdict is None, -f.points))
    oi = r.originating_ip

    summary = _table(["Field", "Value"], [
        ["Subject", o.get("subject")],
        ["From", f"{o.get('display_name', '')} <{defang_email(o.get('from_address', ''))}>"],
        ["Reply-To", defang_email(o.get("reply_to", ""))],
        ["Return-Path", defang_email(o.get("return_path", ""))],
        ["To", o.get("to")], ["Date", o.get("date")], ["Message-ID", o.get("message_id")],
        ["Reported by", r.reported_by], ["Reported at", r.reported_at], ["Analyzed at", r.analyzed_at],
        ["Source", r.source], ["Duplicate of", r.duplicate_of or "-"],
    ])
    finding_rows = [[("HARD: " + f.hard_verdict) if f.hard_verdict else f"{f.points:+d}", f.category, f.title,
                     defang_text(f.evidence)]
                    for f in findings]
    dmarc_dns = a.get("dmarc_dns") or {}
    auth = _table(["Check", "Result"], [
        ["SPF", a.get("spf")], ["DKIM", a.get("dkim")], ["DMARC", a.get("dmarc")],
        ["CompAuth (Microsoft)", f"{a.get('compauth', '')} {('reason=' + a['reason']) if a.get('reason') else ''}"],
        ["ARC", a.get("arc")], ["header.from", defang_domain(a.get("header_from", ""))],
        ["smtp.mailfrom", defang_domain(a.get("smtp_mailfrom", ""))],
        ["DMARC policy (DNS)", dmarc_dns.get("policy") or dmarc_dns.get("error") or "not checked"],
    ])
    ip = oi.get("ip", "")
    ip_table = _table(["Field", "Value"], [
        ["Originating IP", ip.replace(".", "[.]") if ip else "not found"], ["Found in", oi.get("source")],
        ["Reverse DNS", oi.get("ptr", "")], ["Country", oi.get("country", "")], ["ASN owner", oi.get("asn_owner", "")],
        ["VirusTotal", _vt(oi.get("virustotal"))],
        ["AbuseIPDB", f"{(oi.get('abuseipdb') or {}).get('abuseConfidenceScore', 'not checked')}"],
        ["X-Originating-IP", o.get("x_originating_ip", "")],
    ])
    hops = _table(["#", "From host", "From IP", "By", "Time", "Delay (s)"],
                  [[i + 1, h["from_host"], h["from_ip"], h["by_host"], h["timestamp"], h.get("delay_seconds")]
                   for i, h in enumerate(r.hops)])
    urls = _table(["URL (defanged)", "Flags", "VirusTotal", "Domain age (days)", "Found in"],
                  [[u["url_defanged"], ", ".join(u["flags"]) or ("internal" if u.get("internal") else "-"),
                    _vt(u.get("virustotal")), u.get("domain_age_days") if u.get("domain_age_days") is not None else "-",
                    ", ".join(u["sources"][:3])] for u in r.urls])
    atts = _table(["Name", "True type", "Size", "SHA256", "Flags", "VirusTotal"],
                  [[x["name"], x["true_type"], x["size"], x["sha256"], "; ".join(x["flags"]) or "-", _vt(x.get("virustotal"))]
                   for x in r.attachments])
    domains = _table(["Domain", "Roles", "Created", "Registrar", "VirusTotal"],
                     [[defang_domain(d["domain"]), ", ".join(d["roles"]), d.get("created", "-"), d.get("registrar", "-"),
                       _vt(d.get("virustotal"))] for d in r.sender_domains])
    ioc_rows = []
    for kind, values in r.iocs.items():
        for v in values:
            shown = defang_url(v) if kind == "urls" else defang_email(v) if kind == "emails" else \
                defang_domain(v) if kind in ("domains", "ips") else v
            ioc_rows.append([kind, shown])
    actions = "".join(f"<li>{_e(x)}</li>" for x in r.recommended_actions)
    notes = "".join(f"<li>{_e(x)}</li>" for x in r.notes) or "<li class='muted'>None</li>"
    errors = "".join(f"<li>{_e(x)}</li>" for x in r.errors) or "<li class='muted'>None</li>"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(r.case_id)} - {_e(r.verdict)}</title>
<style>
 body{{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f5f6f8;color:#1d2433}}
 main{{max-width:1100px;margin:0 auto;padding:24px 16px}}
 .banner{{background:{color};color:#fff;border-radius:10px;padding:18px 22px;display:flex;flex-wrap:wrap;gap:12px 32px;align-items:baseline}}
 .banner h1{{margin:0;font-size:28px;letter-spacing:.5px}} .banner span{{font-size:15px;opacity:.95}}
 section{{background:#fff;border:1px solid #e3e6eb;border-radius:10px;padding:16px 18px;margin-top:16px;overflow-x:auto}}
 h2{{font-size:17px;margin:0 0 10px}} table{{border-collapse:collapse;width:100%;font-size:13px}}
 th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #eef0f3;vertical-align:top;word-break:break-word}}
 th{{background:#f8f9fb;font-weight:600}} .muted{{color:#7a8394}} ul{{margin:6px 0 0 18px;padding:0}}
 footer{{font-size:12px;color:#7a8394;margin-top:16px}}
</style></head><body><main>
<div class="banner"><h1>{_e(r.verdict)}</h1><span>Score {r.score}/100</span><span>Confidence: {_e(r.confidence)}</span>
<span>Case {_e(r.case_id)}</span></div>
<section><h2>Recommended actions</h2><ul>{actions}</ul></section>
<section><h2>Why: findings</h2>{_table(["Points", "Area", "Finding", "Evidence"], finding_rows)}</section>
<section><h2>Email</h2>{summary}</section>
<section><h2>Authentication</h2>{auth}</section>
<section><h2>Sender IP</h2>{ip_table}</section>
<section><h2>Sender domains</h2>{domains}</section>
<section><h2>Received hops (oldest first)</h2>{hops}</section>
<section><h2>URLs</h2>{urls}</section>
<section><h2>Attachments</h2>{atts}</section>
<section><h2>Indicators of compromise</h2>{_table(["Type", "Value"], ioc_rows)}</section>
<section><h2>Notes</h2><ul>{notes}</ul><h2 style="margin-top:12px">Errors</h2><ul>{errors}</ul></section>
<footer>Generated by phish-analyzer. Static analysis only: links were not opened and attachments were not executed.</footer>
</main></body></html>"""
