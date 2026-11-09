"""Static attachment analysis: hashes, true file type, macros, PDFs, archives, HTML, QR codes, VirusTotal."""
from __future__ import annotations

import hashlib
import io
import logging
import re
import zipfile
from pathlib import PurePosixPath

from ..intel import Intel, IntelError
from ..models import CaseResult
from ..parsing import Attachment
from ..utils import defang_text
from .urls import extract_urls

log = logging.getLogger(__name__)

EXEC_EXTS = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1",
             ".psm1", ".hta", ".msi", ".msp", ".jar", ".lnk", ".cpl", ".dll", ".reg", ".iso", ".img", ".vhd", ".vhdx",
             ".one", ".appx", ".msix", ".appinstaller", ".application", ".xll", ".chm", ".url", ".scf",
             ".library-ms", ".settingcontent-ms", ".svgz"}
HTML_EXTS = {".htm", ".html", ".shtml", ".xhtml", ".svg", ".mht", ".mhtml", ".shtm"}
MACRO_EXTS = {".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppsm", ".sldm"}
OFFICE_EXTS = MACRO_EXTS | {".doc", ".docx", ".xls", ".xlsx", ".xlsb", ".ppt", ".pptx", ".rtf", ".dot", ".xlt"}
DOC_LIKE_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".csv", ".ppt", ".pptx"}
IMAGE_KINDS = {"png", "jpeg", "gif", "bmp"}
# extension -> file kinds its content may legitimately be
EXPECTED_KIND = {
    ".pdf": {"pdf"}, ".docx": {"ooxml", "zip"}, ".xlsx": {"ooxml", "zip"}, ".pptx": {"ooxml", "zip"},
    ".docm": {"ooxml", "zip"}, ".xlsm": {"ooxml", "zip"}, ".pptm": {"ooxml", "zip"}, ".doc": {"ole", "rtf"},
    ".xls": {"ole"}, ".ppt": {"ole"}, ".zip": {"zip", "ooxml"}, ".rar": {"rar"}, ".7z": {"7z"}, ".gz": {"gzip"},
    ".png": {"png"}, ".jpg": {"jpeg"}, ".jpeg": {"jpeg"}, ".gif": {"gif"}, ".rtf": {"rtf"},
    ".txt": {"text", "unknown"}, ".csv": {"text", "unknown"},
}
PDF_KEYWORDS = {b"/JavaScript": "JavaScript", b"/JS": "JavaScript", b"/OpenAction": "OpenAction", b"/AA": "AutoAction",
                b"/Launch": "Launch", b"/EmbeddedFile": "EmbeddedFile", b"/XFA": "XFA form", b"/SubmitForm": "SubmitForm"}
HTML_SMUGGLING = re.compile(r"atob\(|fromCharCode|msSaveOrOpenBlob|new Blob\(|createObjectURL|document\.write\(|"
                            r"window\.location|location\.replace|eval\(|unescape\(", re.I)
RTLO = "‮"


def sniff(data: bytes) -> str:
    head = data[:2048]
    if head.startswith(b"MZ"):
        return "exe"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"PK\x03\x04"):
        return "ooxml" if b"[Content_Types].xml" in data[:65536] else "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"Rar!"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"MSCF"):
        return "cab"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if head.startswith(b"{\\rt"):
        return "rtf"
    if head.startswith(b"\x89PNG"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith(b"GIF8"):
        return "gif"
    if head.startswith(b"BM"):
        return "bmp"
    if any(data[o:o + 5] == b"CD001" for o in (0x8001, 0x8801, 0x9001)):
        return "iso"
    lowered = head.lower()
    if any(t in lowered for t in (b"<html", b"<!doctype html", b"<script", b"<svg", b"<body", b"<form")):
        return "html"
    try:
        head.decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "unknown"


def _extensions(name: str) -> list[str]:
    return [s.lower() for s in PurePosixPath(name.replace("\\", "/")).suffixes]


def analyze_attachments(items: list[Attachment], result: CaseResult, cfg: dict, intel: Intel) -> list[tuple[str, str]]:
    acfg = cfg["analysis"]
    budget = {"bytes": acfg["max_archive_total_mb"] * 1024 * 1024}
    candidates: list[tuple[str, str]] = []
    records: list[dict] = []
    queue = [(att, 0) for att in items]
    while queue:
        att, depth = queue.pop(0)
        records.append(_analyze_one(att, depth, result, cfg, candidates, queue, budget))
    _virustotal(records, result, cfg, intel)
    result.attachments = records
    return candidates


def _analyze_one(att: Attachment, depth: int, result: CaseResult, cfg: dict, candidates: list, queue: list, budget: dict) -> dict:
    data = att.data
    name = att.filename
    exts = _extensions(name)
    ext = exts[-1] if exts else ""
    kind = sniff(data)
    rec = {
        "name": name, "declared_type": att.content_type, "true_type": kind, "size": len(data), "inline": att.inline,
        "source": att.source, "md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(), "flags": [], "virustotal": None,
    }
    label = f"'{name}'"

    def flag(title, points, hard=None, tags=None, evidence=None):
        rec["flags"].append(title)
        result.add("attachment", title, points, evidence or label, hard_verdict=hard, tags=tags)

    if RTLO in name:
        flag("File name uses a right-to-left override to hide its extension", 50, "MALICIOUS", ["malware"])
    if len(exts) >= 2 and exts[-2] in DOC_LIKE_EXTS and ext in EXEC_EXTS:
        flag("Double file extension hiding an executable", 50, "MALICIOUS", ["malware"])
    elif ext in EXEC_EXTS or kind in ("exe", "lnk", "iso"):
        flag("Executable, script or disk-image attachment", 50, "MALICIOUS", ["malware"],
             f"{label} (type: {kind})")
    if kind == "exe" and ext not in {".exe", ".dll", ".scr", ".com", ".cpl", ".sys", ".msi"}:
        flag("Executable disguised with a different extension", 50, "MALICIOUS", ["malware"], f"{label} is really an EXE")
    elif ext in EXPECTED_KIND and kind not in EXPECTED_KIND[ext]:
        flag("File content does not match its extension", 15, evidence=f"{label}: extension {ext}, content {kind}")

    if ext in HTML_EXTS or kind == "html":
        _html_attachment(data, flag, candidates, name)
    if kind in ("ole", "ooxml", "rtf") or ext in OFFICE_EXTS:
        _office(data, name, kind, flag, candidates)
    if kind == "pdf":
        _pdf(data, flag, candidates, name)
    if kind == "zip":
        _zip(att, depth, flag, queue, budget, cfg)
    elif kind in ("rar", "7z", "gzip", "cab"):
        flag("Archive could not be inspected (unsupported format)", 5, evidence=f"{label} ({kind})")
    if kind in IMAGE_KINDS:
        for url in _decode_qr(data, rec):
            candidates.append((url, f"qr:{name}"))
        if rec.get("qr_codes"):
            result.add("attachment", "Image contains a QR code", 10,
                       f"{label}: {defang_text(', '.join(rec['qr_codes'][:3]))}", tags=["qr"])
    return rec


def _html_attachment(data: bytes, flag, candidates: list, name: str) -> None:
    text = data.decode("utf-8", errors="replace")
    low = text.lower()
    flag("HTML/SVG attachment (common phishing and smuggling vector)", 15, tags=["html_attachment"])
    if re.search(r"""type\s*=\s*["']?password""", low):
        # A local HTML page asking for a password is a phishing login page delivered as a file.
        flag("HTML attachment is a login page (password field)", 50, "MALICIOUS", ["credential_lure", "login_page"])
    elif "<form" in low:
        flag("HTML attachment contains a form", 30, tags=["credential_lure"])
    smuggling = sorted(set(m.group(0) for m in HTML_SMUGGLING.finditer(text)))
    long_b64 = re.search(r"[A-Za-z0-9+/=]{2000,}", text)
    if smuggling and long_b64:
        flag("HTML smuggling pattern (script decodes an embedded payload)", 50, "MALICIOUS", ["malware"],
             f"'{name}': {', '.join(smuggling[:5])}")
    elif smuggling:
        flag("HTML attachment runs script that redirects or decodes data", 20, evidence=f"'{name}': {', '.join(smuggling[:5])}")
    candidates += [(u, f"attachment:{name}") for u in extract_urls(text)]


def _office(data: bytes, name: str, kind: str, flag, candidates: list) -> None:
    if kind in ("ooxml", "zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for member in zf.namelist():
                    if not member.endswith(".rels"):
                        continue
                    rels = zf.read(member).decode("utf-8", errors="replace")
                    for target, rtype in _external_rels(rels):
                        if "attachedTemplate" in rtype or "oleObject" in rtype:
                            flag("Office document loads a remote template/object", 40, "MALICIOUS", ["malware"],
                                 f"'{name}' -> {defang_text(target)}")
                        candidates.append((target, f"attachment:{name}"))
        except zipfile.BadZipFile:
            pass
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        if kind == "ooxml" and b"vbaProject.bin" in data:
            flag("Office document contains macros", 20, tags=["macro"])
        return
    try:
        parser = VBA_Parser(filename=name, data=data)
    except Exception as exc:
        log.debug("olevba could not open %s: %s", name, exc)
        return
    try:
        if not parser.detect_vba_macros():
            return
        results = parser.analyze_macros() or []
        types = {r[0] for r in results}
        keywords = sorted({r[1] for r in results if r[0] in ("AutoExec", "Suspicious")})
        if "AutoExec" in types and "Suspicious" in types:
            flag("Macro runs automatically and uses suspicious functions", 50, "MALICIOUS", ["malware", "macro"],
                 f"'{name}': {', '.join(keywords[:8])}")
        else:
            flag("Office document contains macros", 20, tags=["macro"], evidence=f"'{name}': {', '.join(keywords[:8]) or 'macro present'}")
        candidates += [(r[1], f"macro:{name}") for r in results if r[0] == "IOC" and str(r[1]).startswith("http")]
    finally:
        parser.close()


def _external_rels(rels_xml: str) -> list[tuple[str, str]]:
    out = []
    for rel in re.findall(r"<Relationship\b[^>]*>", rels_xml):
        if 'TargetMode="External"' not in rel:
            continue
        target = re.search(r'Target="([^"]+)"', rel)
        rtype = re.search(r'Type="([^"]+)"', rel)
        if target and target.group(1).lower().startswith(("http", "\\\\", "file:")):
            out.append((target.group(1), rtype.group(1) if rtype else ""))
    return out


def _pdf(data: bytes, flag, candidates: list, name: str) -> None:
    found = sorted({label for key, label in PDF_KEYWORDS.items() if re.search(re.escape(key) + rb"(?![A-Za-z])", data)})
    if "JavaScript" in found or "Launch" in found:
        flag("PDF contains JavaScript or a Launch action", 20, evidence=f"'{name}': {', '.join(found)}")
    elif "EmbeddedFile" in found:
        flag("PDF contains an embedded file", 10, evidence=f"'{name}'")
    for uri in re.findall(rb"/URI\s*\(([^)]{4,500})\)", data):
        candidates.append((uri.decode("latin-1", errors="replace"), f"attachment:{name}"))
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        for page in reader.pages[:20]:
            for annot in page.get("/Annots") or []:
                action = annot.get_object().get("/A") or {}
                uri = action.get("/URI") if hasattr(action, "get") else None
                if uri:
                    candidates.append((str(uri), f"attachment:{name}"))
    except Exception:
        pass   # pypdf optional / malformed PDFs


def _zip(att: Attachment, depth: int, flag, queue: list, budget: dict, cfg: dict) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(att.data))
    except zipfile.BadZipFile:
        flag("Corrupt ZIP archive", 5, evidence=f"'{att.filename}'")
        return
    with zf:
        infos = zf.infolist()
        if any(i.flag_bits & 0x1 for i in infos):
            flag("Password-protected archive (hides content from scanners)", 20, tags=["encrypted_archive"],
                 evidence=f"'{att.filename}': {', '.join(i.filename for i in infos[:5])}")
        if depth >= cfg["analysis"]["max_archive_depth"]:
            return
        for info in infos:
            if info.is_dir() or info.flag_bits & 0x1:
                if info.flag_bits & 0x1 and PurePosixPath(info.filename).suffix.lower() in EXEC_EXTS:
                    flag("Encrypted archive contains an executable", 50, "MALICIOUS", ["malware"],
                         f"'{att.filename}' -> {info.filename}")
                continue
            if info.file_size > budget["bytes"]:
                flag("Archive content too large to inspect (possible zip bomb)", 10, evidence=info.filename)
                break
            budget["bytes"] -= info.file_size
            queue.append((Attachment(f"{att.filename}/{info.filename}", "application/octet-stream",
                                     zf.read(info), source=f"archive:{att.filename}"), depth + 1))


def _decode_qr(data: bytes, rec: dict) -> list[str]:
    try:
        import cv2
        import numpy as np
    except ImportError:
        return []
    try:
        img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
        if img is None:
            return []
        ok, decoded, _, _ = cv2.QRCodeDetector().detectAndDecodeMulti(img)
    except Exception:
        return []
    codes = [d for d in decoded if d] if ok else []
    rec["qr_codes"] = codes
    return [c for c in codes if c.lower().startswith(("http", "www."))]


def _virustotal(records: list[dict], result: CaseResult, cfg: dict, intel: Intel) -> None:
    if not intel.vt:
        return
    vcfg = cfg["intel"]["virustotal"]
    threshold = vcfg["malicious_threshold_file"]
    # Images are almost never on VirusTotal and burn the daily quota (QR codes are decoded separately).
    todo = [r for r in records if r["true_type"] not in IMAGE_KINDS]
    for rec in todo[: vcfg["max_file_lookups"]]:
        try:
            report = intel.vt.file(rec["sha256"])
        except IntelError as exc:
            result.errors.append(str(exc))
            if "401" in str(exc) or "quota" in str(exc).lower():
                break
            continue
        rec["virustotal"] = report
        mal = report.get("malicious", 0)
        if mal >= threshold:
            rec["flags"].append("VirusTotal: malicious")
            result.add("attachment", "Attachment hash flagged malicious on VirusTotal", 50,
                       f"'{rec['name']}': {mal} engines {report.get('label') or ''}".strip(),
                       hard_verdict="MALICIOUS", tags=["vt_malicious", "malware"])
        elif mal >= 1:
            rec["flags"].append("VirusTotal: low detections")
            result.add("attachment", "Attachment hash flagged by a few VirusTotal engines", 20, f"'{rec['name']}': {mal} engines")
