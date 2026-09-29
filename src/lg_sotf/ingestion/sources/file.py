"""File source for development and demos only; refused in staging/production.

Config: ``path`` to a JSON Lines file (one event per line). The cursor is the
byte offset after the last complete line read, so appended lines are picked
up by the next poll and a partially written last line waits for its newline.
If the file shrinks (rotated or truncated) reading restarts at the beginning.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, AsyncGenerator, Dict, List, Mapping, Optional, Tuple

from lg_sotf.ingestion.errors import SourceConfigError, SourceProtocolError, SourceUnavailable
from lg_sotf.ingestion.sources.base import CURSOR_VERSION, FetchedPage, PullConnector, SourceHealth

MAX_LINE_BYTES = 1_048_576


def _read_lines(path: str, offset: int, max_lines: int) -> Tuple[List[bytes], int, int]:
    """Complete lines from ``offset``; returns (lines, new offset, file size)."""
    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        if offset > size:
            offset = 0
        fh.seek(offset)
        lines: List[bytes] = []
        position = offset
        while len(lines) < max_lines:
            line = fh.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            if not line.endswith(b"\n"):
                if len(line) > MAX_LINE_BYTES:
                    raise SourceProtocolError(f"line at byte {position} is longer than {MAX_LINE_BYTES} bytes")
                break
            position += len(line)
            lines.append(line)
        return lines, position, size


class FileConnector(PullConnector):
    source_type = "file"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        if self.settings.is_production:
            raise SourceConfigError("file sources are for development only and are refused in staging/production")
        self._path = self.config_str("path")

    async def test(self) -> SourceHealth:
        exists = await asyncio.to_thread(os.path.isfile, self._path)
        if not exists:
            return SourceHealth(False, "file not found")
        return SourceHealth(True, "file is readable")

    async def pages(self, cursor: Optional[Mapping[str, Any]]) -> AsyncGenerator[FetchedPage, None]:
        offset = cursor.get("offset", 0) if cursor else 0
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            offset = 0
        while True:
            try:
                lines, offset, _ = await asyncio.to_thread(_read_lines, self._path, offset, self.options.page_size)
            except FileNotFoundError as exc:
                raise SourceUnavailable("file source path does not exist") from exc
            except OSError as exc:
                raise SourceUnavailable(f"file source could not be read ({type(exc).__name__})") from exc
            events: List[Dict[str, Any]] = []
            for number, line in enumerate(lines):
                text = line.strip()
                if not text:
                    continue
                try:
                    value = json.loads(text)
                except ValueError:
                    value = {"_lgsotf_unparsed_line": number, "error": "invalid JSON"}
                events.append(value if isinstance(value, dict) else {"_lgsotf_non_object": value})
            yield FetchedPage(events, {"v": CURSOR_VERSION, "offset": offset}, self.deps.now())
            if len(lines) < self.options.page_size:
                return
