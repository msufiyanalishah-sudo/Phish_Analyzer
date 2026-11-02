"""Load .eml / .msg data and split it into headers, bodies, attachments and nested emails."""
from __future__ import annotations

import email
import logging
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage

log = logging.getLogger(__name__)

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
EMAIL_EXTENSIONS = (".eml", ".msg")


@dataclass
class Attachment:
    filename: str
    content_type: str
    data: bytes
    inline: bool = False
    source: str = "email"


@dataclass
class ParsedEmail:
    message: EmailMessage
    raw: bytes
    filename: str = ""
    text_bodies: list[str] = field(default_factory=list)
    html_bodies: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    nested: list["ParsedEmail"] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def flatten(self) -> list["ParsedEmail"]:
        out = [self]
        for child in self.nested:
            out.extend(child.flatten())
        return out


def load_message(data: bytes, filename: str = "") -> EmailMessage:
    if filename.lower().endswith(".msg") or data.startswith(OLE_MAGIC):
        return msg_bytes_to_email(data)
    return email.message_from_bytes(data, policy=policy.default)


def parse_email(data: bytes, filename: str = "", depth: int = 0, max_depth: int = 3) -> ParsedEmail:
    msg = load_message(data, filename)
    converted = filename.lower().endswith(".msg") or data.startswith(OLE_MAGIC)
    pe = ParsedEmail(message=msg, raw=_to_bytes(msg) if converted else data, filename=filename)
    if converted:
        pe.notes.append(f"{filename or 'message'} was an Outlook .msg file and was converted for analysis.")
    _collect(msg, pe, depth, max_depth)
    return pe


def _to_bytes(msg: EmailMessage) -> bytes:
    try:
        return msg.as_bytes()
    except Exception:  # malformed headers can break the generator
        return str(msg).encode("utf-8", "replace")


def _payload_bytes(part) -> bytes:
    try:
        return part.get_payload(decode=True) or b""
    except Exception:
        return b""


def _decode_text(part, payload: bytes) -> str:
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _collect(part, pe: ParsedEmail, depth: int, max_depth: int) -> None:
    ctype = part.get_content_type()
    if ctype == "message/rfc822":
        payload = part.get_payload()
        inner = payload[0] if isinstance(payload, list) and payload else None
        if inner is not None:
            _add_nested(pe, _to_bytes(inner), part.get_filename() or "attached-message.eml", depth, max_depth)
        return
    if part.is_multipart():
        for sub in part.iter_parts():
            _collect(sub, pe, depth, max_depth)
        return

    filename = part.get_filename()
    disposition = part.get_content_disposition()
    payload = _payload_bytes(part)
    if not filename and disposition != "attachment" and ctype in ("text/plain", "text/html"):
        text = _decode_text(part, payload)
        (pe.html_bodies if ctype == "text/html" else pe.text_bodies).append(text)
        return
    if (filename and filename.lower().endswith(EMAIL_EXTENSIONS)) or ctype == "application/vnd.ms-outlook":
        _add_nested(pe, payload, filename or "attached.msg", depth, max_depth)
        return
    pe.attachments.append(Attachment(
        filename=filename or f"unnamed.{ctype.split('/')[-1]}",
        content_type=ctype,
        data=payload,
        inline=disposition == "inline" or bool(part.get("Content-ID")),
    ))


def _add_nested(pe: ParsedEmail, data: bytes, name: str, depth: int, max_depth: int) -> None:
    if depth + 1 > max_depth:
        pe.notes.append(f"Nested email '{name}' skipped: maximum depth {max_depth} reached.")
        pe.attachments.append(Attachment(name, "message/rfc822", data))
        return
    try:
        pe.nested.append(parse_email(data, name, depth + 1, max_depth))
    except Exception as exc:
        log.warning("Could not parse nested email %s: %s", name, exc)
        pe.notes.append(f"Nested email '{name}' could not be parsed: {exc}")
        pe.attachments.append(Attachment(name, "message/rfc822", data))


# ---------------------------------------------------------------- .msg support

def msg_bytes_to_email(data: bytes) -> EmailMessage:
    try:
        import extract_msg
    except ImportError as exc:
        raise RuntimeError("The 'extract-msg' package is required to read .msg files.") from exc
    msg = extract_msg.openMsg(data)
    try:
        return _msg_to_email(msg)
    finally:
        try:
            msg.close()
        except Exception:
            pass


def _msg_to_email(m) -> EmailMessage:
    out = EmailMessage()
    body = getattr(m, "body", None) or ""
    out.set_content(body if isinstance(body, str) else str(body))
    html = getattr(m, "htmlBody", None)
    if html:
        out.add_alternative(html.decode("utf-8", "replace") if isinstance(html, bytes) else str(html), subtype="html")

    for att in getattr(m, "attachments", []) or []:
        name = (getattr(att, "longFilename", None) or getattr(att, "shortFilename", None)
                or getattr(att, "name", None) or "attachment.bin")
        data = getattr(att, "data", None)
        if isinstance(data, (bytes, bytearray)):
            out.add_attachment(bytes(data), maintype="application", subtype="octet-stream", filename=name)
        elif data is not None and hasattr(data, "attachments"):   # embedded Outlook item
            inner = _msg_to_email(data)
            out.add_attachment(_to_bytes(inner), maintype="application", subtype="octet-stream",
                               filename=name if name.lower().endswith(EMAIL_EXTENSIONS) else name + ".eml")

    # Put the original transport headers (Received, Authentication-Results, ...) on the new message.
    header = getattr(m, "header", None)
    items = list(header.items()) if header is not None else []
    if not items:
        items = [("From", getattr(m, "sender", "") or ""), ("To", getattr(m, "to", "") or ""),
                 ("Subject", getattr(m, "subject", "") or ""), ("Date", str(getattr(m, "date", "") or ""))]
    mime_headers = {"content-type", "content-transfer-encoding", "mime-version"}
    transport = [out.policy.header_source_parse([f"{k}: {v}\r\n"])
                 for k, v in items if k.lower() not in mime_headers]
    # EmailMessage has no public API to prepend raw headers in order.
    out._headers = transport + [h for h in out._headers if h[0].lower() in mime_headers]
    return out
