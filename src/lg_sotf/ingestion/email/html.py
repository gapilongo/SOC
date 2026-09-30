"""Link and text extraction from HTML email bodies with the stdlib ``html.parser``.

The HTML is tokenised, never rendered: no scripts run, no resources load, no
CSS applies. What is collected:

* links: ``<a href>`` and ``<area href>`` with their visible text, ``<form
  action>`` (credential forms in HTML attachments) and ``<meta
  http-equiv="refresh">`` targets; relative URLs are resolved only against
  an absolute ``<base href>``;
* visible text (outside ``<script>``, ``<style>``, ``<head>`` and
  ``<template>``), for the body excerpt and wording checks.

Input is capped by the caller; output is capped here (links, link text and
text characters), so hostile markup cannot grow memory without bound.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import urljoin

from lg_sotf.ingestion.email.urls import MAX_LINK_TEXT_CHARS, split_url

_HIDDEN_TAGS = frozenset({"script", "style", "head", "template", "noscript", "title"})
_REFRESH_URL_RE = re.compile(r"(?i)url\s*=\s*['\"]?([^'\"\s>]+)")
_SPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class HtmlLink:
    url: str
    text: str
    kind: str  # "a" | "form" | "meta"


class _LinkParser(HTMLParser):
    def __init__(self, max_links: int, max_text_chars: int) -> None:
        super().__init__(convert_charrefs=True)
        self.max_links = max_links
        self.max_text_chars = max_text_chars
        self.links: List[HtmlLink] = []
        self.text_parts: List[str] = []
        self.text_chars = 0
        self.links_dropped = 0
        self._base: Optional[str] = None
        self._hidden_depth = 0
        self._anchor: Optional[Tuple[str, List[str]]] = None

    # -- helpers ---------------------------------------------------------------

    def _resolve(self, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        url = value.strip()
        if split_url(url) is not None:
            return url
        if self._base is not None and not url.lower().startswith(("javascript:", "data:", "mailto:", "vbscript:")):
            joined = urljoin(self._base, url)
            return joined if split_url(joined) is not None else None
        return None

    def _add(self, url: Optional[str], text: str, kind: str) -> None:
        if url is None:
            return
        if len(self.links) >= self.max_links:
            self.links_dropped += 1
            return
        self.links.append(HtmlLink(url, _SPACE_RE.sub(" ", text).strip()[:MAX_LINK_TEXT_CHARS], kind))

    def _text(self, data: str) -> None:
        room = self.max_text_chars - self.text_chars
        if room <= 0:
            return
        chunk = data[:room]
        self.text_parts.append(chunk)
        self.text_chars += len(chunk)

    # -- HTMLParser hooks ------------------------------------------------------

    def handle_starttag(self, tag: str, attrs: Sequence[Tuple[str, Optional[str]]]) -> None:
        values: Dict[str, str] = {k.lower(): v for k, v in attrs if v is not None}
        if tag in _HIDDEN_TAGS:
            self._hidden_depth += 1
        if tag == "base" and self._base is None:
            href = (values.get("href") or "").strip()
            if split_url(href) is not None:
                self._base = href
        elif tag in ("a", "area"):
            url = self._resolve(values.get("href"))
            if tag == "area":
                self._add(url, values.get("alt", ""), "a")
            elif url is not None:
                self._close_anchor()
                self._anchor = (url, [])
        elif tag == "form":
            self._add(self._resolve(values.get("action")), "", "form")
        elif tag == "meta" and values.get("http-equiv", "").lower() == "refresh":
            match = _REFRESH_URL_RE.search(values.get("content", ""))
            if match:
                self._add(self._resolve(match.group(1)), "", "meta")
        elif tag in ("br", "p", "div", "tr", "li"):
            self._text(" ")

    def handle_startendtag(self, tag: str, attrs: Sequence[Tuple[str, Optional[str]]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag in _HIDDEN_TAGS:
            self._hidden_depth = max(0, self._hidden_depth - 1)

    def handle_endtag(self, tag: str) -> None:
        if tag in _HIDDEN_TAGS:
            self._hidden_depth = max(0, self._hidden_depth - 1)
        elif tag == "a":
            self._close_anchor()

    def handle_data(self, data: str) -> None:
        if self._hidden_depth:
            return
        if self._anchor is not None and sum(len(p) for p in self._anchor[1]) < MAX_LINK_TEXT_CHARS:
            self._anchor[1].append(data)
        self._text(data)

    def _close_anchor(self) -> None:
        if self._anchor is not None:
            url, parts = self._anchor
            self._anchor = None
            self._add(url, "".join(parts), "a")

    def finish(self) -> None:
        # Malformed trailing markup must not lose what was already parsed.
        with contextlib.suppress(Exception):
            self.close()
        self._close_anchor()


@dataclass(frozen=True)
class HtmlScan:
    links: List[HtmlLink]
    text: str
    links_dropped: int


def scan_html(markup: str, *, max_links: int, max_text_chars: int) -> HtmlScan:
    """Links and visible text of ``markup`` (already capped by the caller)."""
    parser = _LinkParser(max_links, max_text_chars)
    # html.parser is lenient; anything it still raises ends the scan and keeps what was found.
    with contextlib.suppress(Exception):
        parser.feed(markup)
    parser.finish()
    text = _SPACE_RE.sub(" ", "".join(parser.text_parts)).strip()
    return HtmlScan(parser.links, text, parser.links_dropped)
