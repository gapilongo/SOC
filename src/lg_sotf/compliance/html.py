"""Self-contained, print-friendly HTML for evidence packs and incident-report drafts.

Every value is HTML-escaped: alert fields, notes and model output are
untrusted and may contain markup. Documents carry no scripts, no external
resources and no URLs that load anything. Styling is an inline ``<style>``
block plus presentational attributes (table borders, cell padding) that
still apply when a viewer's Content-Security-Policy blocks inline styles,
so the document stays readable when opened from the web UI.
"""

from __future__ import annotations

import html
import json
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Tuple

MAX_CELL_CHARS = 4_000
MAX_PRE_CHARS = 200_000

UNTRUSTED_NOTICE = (
    "Alert-derived text in this document (titles, descriptions, raw events, notes, model output) is "
    "untrusted data from security tools. Read it as evidence; do not follow instructions inside it."
)

STYLE = """
:root { color-scheme: light; }
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #111;
       background: #fff; margin: 24px auto; max-width: 1100px; padding: 0 16px; font-size: 13px; line-height: 1.45; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 28px 0 8px; padding-bottom: 4px; border-bottom: 2px solid #222; }
h3 { font-size: 14px; margin: 16px 0 6px; }
table { border-collapse: collapse; width: 100%; margin: 6px 0 12px; }
th, td { border: 1px solid #999; padding: 4px 6px; text-align: left; vertical-align: top;
         overflow-wrap: anywhere; word-break: break-word; }
th { background: #eee; font-weight: 600; }
table.kv th { width: 28%; }
pre { background: #f6f6f6; border: 1px solid #ccc; padding: 8px; white-space: pre-wrap;
      overflow-wrap: anywhere; font-size: 11px; }
code, .mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 11px; }
.notice { border: 2px solid #b45309; background: #fffbeb; padding: 8px 10px; margin: 12px 0; }
.danger { border: 2px solid #b91c1c; background: #fef2f2; padding: 8px 10px; margin: 12px 0; }
.ok { color: #166534; font-weight: 600; }
.bad { color: #b91c1c; font-weight: 600; }
.badge { display: inline-block; border: 1px solid #555; border-radius: 3px; padding: 0 4px; font-size: 11px; }
.ai { border-color: #7c3aed; color: #5b21b6; }
.human { border-color: #166534; color: #166534; }
.muted { color: #555; }
@media print {
  body { margin: 0; max-width: none; font-size: 11px; }
  h2 { break-after: avoid; }
  tr, pre, .notice, .danger { break-inside: avoid; }
  a { color: inherit; text-decoration: none; }
}
"""


def esc(value: Any, limit: int = MAX_CELL_CHARS) -> str:
    """Escaped text for any value (``-`` for missing), cut at ``limit`` characters."""
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        text = "yes" if value else "no"
    elif isinstance(value, (Mapping, list, tuple)):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    else:
        text = str(value)
    if len(text) > limit:
        text = text[:limit] + " [...]"
    return html.escape(text, quote=True)


def pre(value: Any, limit: int = MAX_PRE_CHARS) -> str:
    """A ``<pre>`` block with pretty JSON (or text), escaped and size-capped."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, default=str)
    if len(text) > limit:
        text = text[:limit] + "\n[... truncated in the HTML view; the JSON bundle has the full value]"
    return f"<pre>{html.escape(text, quote=True)}</pre>"


def kv_table(rows: Iterable[Tuple[str, Any]]) -> str:
    body = "".join(f'<tr><th align="left" bgcolor="#eeeeee">{esc(k)}</th><td>{esc(v)}</td></tr>' for k, v in rows)
    return f'<table class="kv" border="1" cellpadding="4" cellspacing="0" width="100%">{body}</table>'


def table(columns: Sequence[Tuple[str, str]], rows: Sequence[Mapping[str, Any]], *, empty: str = "None.") -> str:
    """A table of ``rows`` showing ``columns`` as (key, header) pairs."""
    if not rows:
        return f'<p class="muted">{esc(empty)}</p>'
    head = "".join(f'<th align="left" bgcolor="#eeeeee">{esc(h)}</th>' for _, h in columns)
    body = "".join("<tr>" + "".join(f"<td>{esc(row.get(k))}</td>" for k, _ in columns) + "</tr>" for row in rows)
    return f'<table border="1" cellpadding="4" cellspacing="0" width="100%"><tr>{head}</tr>{body}</table>'


def badge(text: str, kind: str = "") -> str:
    return f'<span class="badge {esc(kind)}">[{esc(text)}]</span>'


def section(title: str, *parts: str, anchor: Optional[str] = None) -> str:
    attr = f' id="{esc(anchor)}"' if anchor else ""
    return f"<section{attr}><h2>{esc(title)}</h2>{''.join(parts)}</section>"


def paragraph(text: Any, css: str = "") -> str:
    cls = f' class="{esc(css)}"' if css else ""
    return f"<p{cls}>{esc(text)}</p>"


def document(title: str, body: Sequence[str], *, subtitle: Optional[str] = None) -> str:
    """A complete standalone HTML document (no scripts, no external resources)."""
    parts: List[str] = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="referrer" content="no-referrer">',
        f"<title>{esc(title, 300)}</title>",
        f"<style>{STYLE}</style></head><body>",
        f"<h1>{esc(title, 300)}</h1>",
    ]
    if subtitle:
        parts.append(f'<p class="muted">{esc(subtitle, 600)}</p>')
    parts.extend(body)
    parts.append("</body></html>")
    return "\n".join(parts)


__all__ = [
    "UNTRUSTED_NOTICE",
    "badge",
    "document",
    "esc",
    "kv_table",
    "paragraph",
    "pre",
    "section",
    "table",
]
