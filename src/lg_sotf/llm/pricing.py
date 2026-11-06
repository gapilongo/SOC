"""Model price table (USD per million tokens) and cost computation.

Anthropic first-party prices as of 2026-09. Cache writes use the 5-minute TTL
rate (1.25x input); 1-hour writes are charged at 2x input. Operators can
override or extend the table with ``llm.prices`` (see :func:`price_table`).

Some providers charge more at certain hours: a price may carry peak windows
(:class:`PeakWindow`), and :func:`compute_cost` applies the multiplier of the
window covering the moment of the call (the recorder passes "now").

Models served by a self-hosted provider are metered under
``local/<model>`` (:func:`local_model_id`) and cost nothing, like the fake
model, unless ``llm.prices`` names that id (an internal chargeback rate).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, Mapping, Optional, Tuple

from lg_sotf.settings import Settings

_MTOK = Decimal(1_000_000)
_SNAPSHOT_SUFFIX = re.compile(r"^(?P<alias>.+)-\d{8}$")


@dataclass(frozen=True)
class PeakWindow:
    """UTC hours ``[start_hour, end_hour)`` on Monday to Friday where every rate is multiplied."""

    start_hour: int
    end_hour: int
    multiplier: Decimal

    def covers(self, at: datetime) -> bool:
        return at.weekday() < 5 and self.start_hour <= at.hour < self.end_hour


@dataclass(frozen=True)
class ModelPrice:
    input: Decimal
    output: Decimal
    cache_write: Decimal
    cache_read: Decimal
    peak: Tuple[PeakWindow, ...] = ()

    @classmethod
    def of(
        cls,
        input: str,  # noqa: A002 - mirrors the price table
        output: str,
        cache_write: str,
        cache_read: str,
        peak: Tuple[PeakWindow, ...] = (),
    ) -> ModelPrice:
        return cls(Decimal(input), Decimal(output), Decimal(cache_write), Decimal(cache_read), peak)

    def multiplier_at(self, at: Optional[datetime]) -> Decimal:
        """The multiplier of the first peak window covering ``at`` (UTC), else 1."""
        if at is not None:
            for window in self.peak:
                if window.covers(at):
                    return window.multiplier
        return Decimal(1)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ModelPrice:
        inp = Decimal(str(data["input"]))
        out = Decimal(str(data["output"]))
        cw = Decimal(str(data.get("cache_write", inp * Decimal("1.25"))))
        cr = Decimal(str(data.get("cache_read", inp * Decimal("0.1"))))
        return cls(inp, out, cw, cr)


DEEPSEEK_PEAK = (PeakWindow(1, 4, Decimal(2)), PeakWindow(6, 10, Decimal(2)))

DEFAULT_PRICES: Dict[str, ModelPrice] = {
    "claude-fable-5-1": ModelPrice.of("10.00", "50.00", "12.50", "0.25"),
    "claude-fable-5": ModelPrice.of("10.00", "50.00", "12.50", "1.00"),
    "claude-opus-5-5": ModelPrice.of("4.00", "20.00", "5.00", "0.20"),
    "claude-opus-5": ModelPrice.of("5.00", "25.00", "6.25", "0.50"),
    "claude-opus-4-8": ModelPrice.of("5.00", "25.00", "6.25", "0.50"),
    "claude-opus-4-7": ModelPrice.of("5.00", "25.00", "6.25", "0.50"),
    "claude-opus-4-6": ModelPrice.of("5.00", "25.00", "6.25", "0.50"),
    "claude-sonnet-5-5": ModelPrice.of("2.00", "10.00", "2.50", "0.20"),
    "claude-sonnet-5": ModelPrice.of("2.00", "10.00", "2.50", "0.20"),
    "claude-sonnet-4-6": ModelPrice.of("3.00", "15.00", "3.75", "0.30"),
    "claude-haiku-4-5": ModelPrice.of("1.00", "5.00", "1.25", "0.10"),
    # Gemini API paid tier, standard (not batch/flex) text prices, from
    # https://ai.google.dev/gemini-api/docs/pricing as read on 2026-09-30. Cache reads are the
    # context-caching rate; Gemini charges cache storage per hour rather than a write premium,
    # so writes are priced as input (storage is not metered here).
    "gemini-2.5-flash": ModelPrice.of("0.30", "2.50", "0.30", "0.03"),
    "gemini-3.5-flash-lite": ModelPrice.of("0.30", "2.50", "0.30", "0.03"),
    # DeepSeek off-peak prices from https://api-docs.deepseek.com/quick_start/pricing/ as read
    # on 2026-11-06. Peak hours (01:00-04:00 and 06:00-10:00 UTC, Monday to Friday) cost twice
    # as much; Chinese public holidays are off-peak there but not modelled here, so a holiday
    # call is over- rather than under-counted. Cache reads are DeepSeek's cache-hit rate; there
    # is no cache-write premium, so writes are priced as input. ``deepseek-v4-flash`` is the
    # retired name the API still accepts and bills at the Flash price.
    "deepseek-flash": ModelPrice.of("0.15", "0.60", "0.15", "0.003", DEEPSEEK_PEAK),
    "deepseek-v4-flash": ModelPrice.of("0.15", "0.60", "0.15", "0.003", DEEPSEEK_PEAK),
    "deepseek-v4-pro": ModelPrice.of("0.66", "1.98", "0.66", "0.022", DEEPSEEK_PEAK),
}

ZERO_PRICE = ModelPrice.of("0", "0", "0", "0")
LOCAL_PREFIX = "local/"
FREE_MODEL_PREFIXES = ("fake", LOCAL_PREFIX)


def local_model_id(model: str) -> str:
    """The usage id of a model served by a self-hosted provider (``local/<model>``)."""
    return model if model.startswith(LOCAL_PREFIX) else f"{LOCAL_PREFIX}{model}"


def price_table(settings: Optional[Settings] = None) -> Dict[str, ModelPrice]:
    """Default prices merged with the optional ``llm.prices`` override mapping."""
    table = dict(DEFAULT_PRICES)
    overrides = getattr(settings.llm, "prices", None) if settings is not None else None
    if overrides:
        for model, data in dict(overrides).items():
            table[model] = data if isinstance(data, ModelPrice) else ModelPrice.from_mapping(
                data if isinstance(data, Mapping) else data.model_dump()
            )
    return table


def lookup_price(model: str, table: Mapping[str, ModelPrice]) -> Optional[ModelPrice]:
    """Exact match, else the alias of a dated snapshot id (``claude-haiku-4-5-20251001``).

    Free models (fake, ``local/...``) cost zero unless the table prices them explicitly.
    """
    if model in table:
        return table[model]
    if model.startswith(FREE_MODEL_PREFIXES):
        return ZERO_PRICE
    m = _SNAPSHOT_SUFFIX.match(model)
    if m and m.group("alias") in table:
        return table[m.group("alias")]
    return None


def compute_cost(
    price: ModelPrice,
    *,
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int = 0,
    cache_write_tokens: int = 0,
    cache_write_1h_tokens: int = 0,
    at: Optional[datetime] = None,
) -> Decimal:
    """Unrounded cost in USD.

    ``input_tokens`` excludes cached tokens; ``cache_write_1h_tokens`` is the
    1-hour-TTL share of ``cache_write_tokens``. ``at`` (an aware UTC time) selects
    a peak multiplier when the price has peak windows; without it the base rate applies.
    """
    write_5m = max(cache_write_tokens - cache_write_1h_tokens, 0)
    total = (
        price.input * input_tokens
        + price.output * output_tokens
        + price.cache_read * cache_read_tokens
        + price.cache_write * write_5m
        + price.input * 2 * cache_write_1h_tokens
    )
    return total * price.multiplier_at(at) / _MTOK
