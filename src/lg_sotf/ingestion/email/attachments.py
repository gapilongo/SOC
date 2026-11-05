"""Attachment facts: content sniffing and risk labels. Attachment bytes are inspected, never kept.

Only the first bytes and, for ZIP-based files, the archive's central
directory are read (``zipfile`` lists entries without decompressing them, so
an archive bomb is never expanded). Nothing is executed, rendered or written
to disk; the caller keeps the SHA-256 and these facts only.

Risk labels (any of them makes an attachment risky):

``macro_office``          macro-enabled Office (``.docm``/``.xlsm``/..., OOXML with
                          ``vbaProject.bin``, legacy OLE documents with a VBA project)
``html``                  HTML/SVG/MHT (credential-harvest pages, smuggling)
``disk_image``            ISO/IMG/VHD(X) (mark-of-the-web bypass)
``shortcut``              LNK/URL/SCF shortcuts
``script_or_executable``  scripts, executables, installers and add-ins by extension or content
``encrypted_archive``     ZIP with encrypted entries (password-protected, hides content from scanners)
``encrypted_document``    password-protected Office document
``onenote``               OneNote files (embedded-script lure)
``archive_with_risky_content``  an archive listing an entry of one of the risky kinds above
``extension_mismatch``    the name claims a harmless type but the content is executable/HTML/image
``deceptive_filename``    bidirectional-override or other format characters in the name
"""

from __future__ import annotations

import io
import unicodedata
import zipfile
from typing import List, Optional, Set, Tuple

MAX_ZIP_ENTRIES = 1_000
MAX_FILENAME_CHARS = 256

MACRO_EXTENSIONS = frozenset({"docm", "dotm", "xlsm", "xltm", "xlam", "xlsb", "pptm", "potm", "ppam", "ppsm", "sldm"})
LEGACY_OFFICE_EXTENSIONS = frozenset({"doc", "dot", "xls", "xlt", "ppt", "pps", "pot"})
HTML_EXTENSIONS = frozenset({"htm", "html", "shtml", "xhtml", "svg", "svgz", "mht", "mhtml", "xht"})
DISK_IMAGE_EXTENSIONS = frozenset({"iso", "img", "vhd", "vhdx"})
SHORTCUT_EXTENSIONS = frozenset({"lnk", "url", "scf", "website"})
SCRIPT_EXTENSIONS = frozenset(
    {
        "js", "jse", "vbs", "vbe", "wsf", "wsh", "wsc", "hta", "ps1", "psm1", "bat", "cmd", "scr", "exe", "dll",
        "msi", "msix", "appx", "jar", "cpl", "com", "pif", "reg", "vb", "application", "appref-ms", "xll",
        "sh", "py", "apk", "dmg", "pkg", "chm", "inf", "msc", "gadget", "sct", "xsl",
    }
)
ONENOTE_EXTENSIONS = frozenset({"one", "onepkg"})
ARCHIVE_EXTENSIONS = frozenset({"zip", "rar", "7z", "gz", "tgz", "tar", "cab", "arj", "ace", "xz", "bz2", "zipx"})
# Names that promise harmless content: executable, HTML or disk-image content under them is deceptive.
HARMLESS_EXTENSIONS = frozenset(
    {"pdf", "txt", "jpg", "jpeg", "png", "gif", "bmp", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "rtf"}
)
RISKY_SNIFFED = frozenset({"pe", "elf", "lnk", "html", "iso", "vhd", "onenote", "macho"})

RISK_LABELS = (
    "macro_office",
    "html",
    "disk_image",
    "shortcut",
    "script_or_executable",
    "encrypted_archive",
    "encrypted_document",
    "onenote",
    "archive_with_risky_content",
    "extension_mismatch",
    "deceptive_filename",
)

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_ONENOTE_MAGIC = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")
_LNK_MAGIC = b"\x4c\x00\x00\x00\x01\x14\x02\x00"
_HTML_MARKERS = (b"<!doctype html", b"<html", b"<script", b"<head", b"<body", b"<svg", b"<iframe", b"<form")


def extension(filename: str) -> str:
    name = filename.strip().rstrip(". ").lower()
    return name.rsplit(".", 1)[1] if "." in name else ""


def clean_filename(value: Optional[str]) -> Tuple[str, bool]:
    """A displayable filename (control/format characters removed, capped) and whether any were present."""
    if not value:
        return "", False
    deceptive = False
    out: List[str] = []
    for ch in value:
        category = unicodedata.category(ch)
        if category == "Cf":
            deceptive = True
            continue
        if category == "Cc":
            continue
        out.append(ch)
    return "".join(out).strip()[:MAX_FILENAME_CHARS], deceptive


def sniff(data: bytes) -> str:  # noqa: C901
    """A content type label from magic bytes (``pdf``, ``zip``, ``ole``, ``pe``, ``html``...), else ``unknown``."""
    head = data[:4_096]
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith(_OLE_MAGIC):
        return "ole"
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "macho"
    if head.startswith(_LNK_MAGIC):
        return "lnk"
    if head.startswith(_ONENOTE_MAGIC):
        return "onenote"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"MSCF"):
        return "cab"
    if head.startswith(b"{\\rtf"):
        return "rtf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if head.startswith(b"conectix") or head.startswith(b"vhdxfile"):
        return "vhd"
    for offset in (0x8001, 0x8801, 0x9001):
        if data[offset : offset + 5] == b"CD001":
            return "iso"
    lowered = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if any(lowered.startswith(marker) for marker in _HTML_MARKERS) or b"<html" in lowered[:1_024]:
        return "html"
    try:
        head.decode("utf-8")
    except UnicodeDecodeError:
        return "unknown"
    return "text"


def _zip_facts(data: bytes) -> Tuple[bool, bool, bool, Set[str]]:
    """(OOXML, has a VBA project, has encrypted entries, risk labels of listed entries)."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()[:MAX_ZIP_ENTRIES]
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError, EOFError, NotImplementedError):
        return False, False, False, set()
    names = [info.filename.lower() for info in infos]
    ooxml = "[content_types].xml" in names
    vba = any(name.endswith("vbaproject.bin") for name in names)
    encrypted = any(info.flag_bits & 0x1 for info in infos)
    inner: Set[str] = set()
    for name in names:
        inner.update(_extension_risks(extension(name.rsplit("/", 1)[-1])))
    return ooxml, vba, encrypted, inner


def _extension_risks(ext: str) -> Set[str]:
    risks: Set[str] = set()
    if ext in MACRO_EXTENSIONS:
        risks.add("macro_office")
    if ext in HTML_EXTENSIONS:
        risks.add("html")
    if ext in DISK_IMAGE_EXTENSIONS:
        risks.add("disk_image")
    if ext in SHORTCUT_EXTENSIONS:
        risks.add("shortcut")
    if ext in SCRIPT_EXTENSIONS:
        risks.add("script_or_executable")
    if ext in ONENOTE_EXTENSIONS:
        risks.add("onenote")
    return risks


def classify(filename: str, declared_type: str, data: bytes, *, deceptive_name: bool = False) -> Tuple[str, List[str]]:
    """(sniffed type, sorted risk labels) for one attachment."""
    sniffed = sniff(data)
    ext = extension(filename)
    risks = _extension_risks(ext)
    declared = declared_type.lower()
    if sniffed == "zip":
        ooxml, vba, encrypted, inner = _zip_facts(data)
        if ooxml:
            sniffed = "ooxml"
            if vba:
                risks.add("macro_office")
        else:
            if encrypted:
                risks.add("encrypted_archive")
            if inner:
                risks.add("archive_with_risky_content")
    elif sniffed == "ole":
        if b"EncryptedPackage" in data or "EncryptedPackage".encode("utf-16-le") in data:
            risks.add("encrypted_document")
        if b"_VBA_PROJECT" in data or "_VBA_PROJECT".encode("utf-16-le") in data:
            risks.add("macro_office")
    elif sniffed in ("pe", "elf", "macho"):
        risks.add("script_or_executable")
    elif sniffed == "lnk":
        risks.add("shortcut")
    elif sniffed in ("iso", "vhd"):
        risks.add("disk_image")
    elif sniffed == "onenote":
        risks.add("onenote")
    elif sniffed == "html" or declared in ("text/html", "image/svg+xml", "application/xhtml+xml"):
        risks.add("html")
    if ext in HARMLESS_EXTENSIONS and sniffed in RISKY_SNIFFED:
        risks.add("extension_mismatch")
    if deceptive_name:
        risks.add("deceptive_filename")
    return sniffed, sorted(risks)
