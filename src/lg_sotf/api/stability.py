"""API stability tiers and deprecation notices (docs/api.md, "Stability and deprecation").

Every operation in the OpenAPI document carries ``x-stability``:

* ``stable``: covered by the compatibility promise. CI (``scripts/check_api_compat.py``,
  oasdiff) fails a change that breaks one; removing one needs a deprecation with a
  sunset at least ``STABLE_DEPRECATION_DAYS`` days away.
* ``beta``: may change in a minor release; CI reports breaking changes without failing.
* ``internal``: for the bundled UI only; no promise.

A router's tier is set where it is mounted (:func:`lg_sotf.api.app.api_routers`);
a route can override it, or be deprecated, with :func:`route_contract`. A
deprecated route's responses carry ``Deprecation`` (RFC 9745), ``Sunset``
(RFC 8594) and ``Link: <...>; rel="deprecation"``, and the document marks it
``deprecated: true`` with ``x-sunset``, the extension oasdiff reads to refuse a
removal before that date.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from email.utils import format_datetime
from typing import Any, Final, List, Literal, Mapping, Optional, Tuple, get_args

from fastapi import APIRouter
from fastapi.routing import APIRoute
from starlette.types import ASGIApp, Message, Receive, Scope, Send

Stability = Literal["stable", "beta", "internal"]
STABILITY_LEVELS: Final[Tuple[str, ...]] = get_args(Stability)
STABILITY_KEY: Final = "x-stability"
SUNSET_KEY: Final = "x-sunset"
DEPRECATED_SINCE_KEY: Final = "x-deprecated-since"
STABLE_DEPRECATION_DAYS: Final = 180
DEPRECATION_DOCS: Final = "https://github.com/gapilongo/SOC/blob/main/docs/api.md#stability-and-deprecation"
DEPRECATION_HEADERS: Final = ("Deprecation", "Sunset", "Link")


def _midnight_utc(day: date) -> datetime:
    return datetime.combine(day, time.min, tzinfo=UTC)


@dataclass(frozen=True)
class Deprecation:
    """A route is deprecated from ``since`` and may be removed from ``sunset`` (both 00:00 UTC)."""

    since: date
    sunset: date
    link: str = DEPRECATION_DOCS

    def __post_init__(self) -> None:
        if self.sunset <= self.since:
            raise ValueError("the sunset date must come after the deprecation date")

    def headers(self) -> List[Tuple[bytes, bytes]]:
        """``Deprecation`` is an RFC 9651 date (``@`` + Unix seconds); ``Sunset`` an HTTP date."""
        return [
            (b"deprecation", f"@{int(_midnight_utc(self.since).timestamp())}".encode("latin-1")),
            (b"sunset", format_datetime(_midnight_utc(self.sunset), usegmt=True).encode("latin-1")),
            (b"link", f'<{self.link}>; rel="deprecation"; type="text/html"'.encode("latin-1")),
        ]

    def openapi_extra(self) -> dict[str, Any]:
        return {
            DEPRECATED_SINCE_KEY: self.since.isoformat(),
            SUNSET_KEY: self.sunset.isoformat(),
            "externalDocs": {"description": "Deprecation notice", "url": self.link},
        }

    @classmethod
    def from_openapi_extra(cls, extra: Mapping[str, Any]) -> Optional[Deprecation]:
        if SUNSET_KEY not in extra or DEPRECATED_SINCE_KEY not in extra:
            return None
        link = (extra.get("externalDocs") or {}).get("url") or DEPRECATION_DOCS
        return cls(
            since=date.fromisoformat(extra[DEPRECATED_SINCE_KEY]),
            sunset=date.fromisoformat(extra[SUNSET_KEY]),
            link=link,
        )


def route_contract(
    *, stability: Optional[Stability] = None, deprecation: Optional[Deprecation] = None
) -> dict[str, Any]:
    """Keyword arguments for a route decorator, e.g.
    ``@router.get("/old", **route_contract(deprecation=Deprecation(since=..., sunset=...)))``."""
    extra: dict[str, Any] = {}
    if stability is not None:
        extra[STABILITY_KEY] = stability
    kwargs: dict[str, Any] = {"openapi_extra": extra}
    if deprecation is not None:
        extra.update(deprecation.openapi_extra())
        kwargs["deprecated"] = True
    return kwargs


def classify(router: APIRouter, level: Stability) -> APIRouter:
    """Give each route of ``router`` that does not declare its own tier the tier ``level`` (idempotent)."""
    for route in router.routes:
        if isinstance(route, APIRoute):
            extra = route.openapi_extra or {}
            if STABILITY_KEY not in extra:
                route.openapi_extra = {STABILITY_KEY: level, **extra}
    return router


def route_deprecation(route: object) -> Optional[Deprecation]:
    """The deprecation notice of a matched route, if it declares one."""
    if not getattr(route, "deprecated", False):
        return None
    extra = getattr(route, "openapi_extra", None)
    return Deprecation.from_openapi_extra(extra) if isinstance(extra, Mapping) else None


class DeprecationHeadersMiddleware:
    """Adds the deprecation headers to every response of a deprecated route, errors included.

    The router records the matched route in the scope before the response
    starts, so the route is known here even when a handler raised.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                notice = route_deprecation(scope.get("route"))
                if notice is not None:
                    message = {**message, "headers": [*(message.get("headers") or []), *notice.headers()]}
            await send(message)

        await self.app(scope, receive, send_wrapper)
