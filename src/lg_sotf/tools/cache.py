"""Bounded TTL cache for read-only tool results."""

from __future__ import annotations

import time
from collections import OrderedDict
from typing import Callable, Generic, Hashable, Optional, Tuple, TypeVar

V = TypeVar("V")


class TTLCache(Generic[V]):
    """LRU cache with a per-entry time to live. Not thread-safe; use from one event loop."""

    def __init__(self, maxsize: int = 1_024, ttl_s: float = 300.0, *, clock: Callable[[], float] = time.monotonic):
        if maxsize < 1:
            raise ValueError("maxsize must be >= 1")
        if ttl_s <= 0:
            raise ValueError("ttl_s must be > 0")
        self.maxsize = maxsize
        self.ttl_s = ttl_s
        self._clock = clock
        self._data: OrderedDict[Hashable, Tuple[float, V]] = OrderedDict()

    def get(self, key: Hashable) -> Optional[V]:
        entry = self._data.get(key)
        if entry is None:
            return None
        expires, value = entry
        if expires <= self._clock():
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return value

    def set(self, key: Hashable, value: V) -> None:
        self._data[key] = (self._clock() + self.ttl_s, value)
        self._data.move_to_end(key)
        while len(self._data) > self.maxsize:
            self._data.popitem(last=False)

    def clear(self) -> None:
        self._data.clear()

    def __len__(self) -> int:
        return len(self._data)
