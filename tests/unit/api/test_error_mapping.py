"""Characterization golden: which HTTP status and error code each exception becomes.

Covers every class registered in ``api/errors.py install_error_handlers`` plus
every ``Exception`` subclass defined in ``lg_sotf``. The handler is resolved
the way Starlette does it (the first class in ``type(exc).__mro__`` that has a
registered handler), then invoked with a minimal instance, so the golden
records what a client would actually receive.

The golden is today's behaviour, not a statement that it is right: a diff is
a reviewed change. After an intended change, regenerate with ``REGENERATE``.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import os
import pkgutil
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type

from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

import lg_sotf
from lg_sotf.api.app import create_app
from lg_sotf.api.errors import install_error_handlers
from lg_sotf.settings import Settings

GOLDEN = Path(__file__).with_name("error_mapping.golden.json")
UPDATE_ENV = "LG_SOTF_UPDATE_GOLDENS"
REGENERATE = f"{UPDATE_ENV}=1 python -m pytest tests/unit/api/test_error_mapping.py"

# Status and code come from the instance (``HTTPException(status_code, ...)``), not the class.
PER_INSTANCE = "<instance>"

# Modules that only import inside their host program. Nothing else may fail to import.
NOT_IMPORTABLE = {
    "lg_sotf.db.migrations.env",  # Alembic env script: needs alembic.context.config, set by the alembic CLI
}

# Dummy values for required constructor parameters, picked by annotation text (first match wins).
_DUMMIES: Tuple[Tuple[str, Any], ...] = (
    ("Sequence", []),
    ("List", []),
    ("Mapping", {}),
    ("Dict", {}),
    ("bool", False),
    ("float", 1.0),
    ("int", 1),
)


def _import_all_modules() -> None:
    def failed(name: str) -> None:
        raise ImportError(f"cannot walk package {name}")

    for info in pkgutil.walk_packages(lg_sotf.__path__, "lg_sotf.", onerror=failed):
        if info.name not in NOT_IMPORTABLE:
            importlib.import_module(info.name)


def _qualified(cls: type) -> str:
    return f"{cls.__module__}.{cls.__qualname__}"


def _lg_sotf_exceptions() -> Set[Type[Exception]]:
    _import_all_modules()
    found: Set[Type[Exception]] = set()
    pending: List[type] = [Exception]
    while pending:
        for sub in pending.pop().__subclasses__():
            if sub in found:
                continue
            pending.append(sub)
            if sub.__module__.split(".")[0] == "lg_sotf" and "<locals>" not in sub.__qualname__:
                found.add(sub)
    return found


class _Recorder:
    """Stands in for the app to capture exactly what ``install_error_handlers`` registers."""

    def __init__(self) -> None:
        self.handlers: Dict[Any, Callable[..., Any]] = {}

    def add_exception_handler(self, key: Any, handler: Callable[..., Any]) -> None:
        self.handlers[key] = handler


def _required_params(cls: Any) -> List[inspect.Parameter]:
    if cls.__init__ is BaseException.__init__:
        return []
    params = list(inspect.signature(cls.__init__).parameters.values())[1:]
    return [p for p in params if p.default is p.empty and p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)]


def _dummy(param: inspect.Parameter) -> Any:
    annotation = param.annotation if isinstance(param.annotation, str) else repr(param.annotation)
    for marker, value in _DUMMIES:
        if marker in annotation:
            return value
    return "x"


def _instance(cls: type) -> BaseException:
    params = _required_params(cls)
    if not params:
        return cls("message")
    args = [_dummy(p) for p in params if p.kind is not p.KEYWORD_ONLY]
    kwargs = {p.name: _dummy(p) for p in params if p.kind is p.KEYWORD_ONLY}
    return cls(*args, **kwargs)


def _resolve(handlers: Dict[Any, Callable[..., Any]], cls: type) -> Optional[Callable[..., Any]]:
    # Same lookup as starlette._exception_handler._lookup_exception_handler.
    for klass in cls.__mro__:
        if klass in handlers:
            return handlers[klass]
    return None


def _outcome(handler: Callable[..., Any], cls: type) -> List[Any]:
    if issubclass(cls, StarletteHTTPException) and any(p.name == "status_code" for p in _required_params(cls)):
        return [PER_INSTANCE, PER_INSTANCE]
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""})
    response = asyncio.run(handler(request, _instance(cls)))
    body = json.loads(bytes(response.body))
    return [response.status_code, body["error"]["code"]]


def _mapping(settings: Settings) -> Dict[str, List[Any]]:
    app = create_app(settings, configure_observability=False)
    handlers = dict(app.exception_handlers)
    assert not [k for k in handlers if isinstance(k, int)], "status-code handlers bypass the MRO lookup"
    recorder = _Recorder()
    install_error_handlers(recorder)  # type: ignore[arg-type]
    assert set(recorder.handlers) <= set(handlers), "create_app must install the error handlers"
    classes: Set[type] = set(recorder.handlers) | _lg_sotf_exceptions()
    mapping: Dict[str, List[Any]] = {}
    for cls in classes:
        handler = _resolve(handlers, cls)
        assert handler is not None, f"{_qualified(cls)} has no handler (Exception should catch it)"
        name = _qualified(cls)
        assert name not in mapping, f"duplicate qualified name {name}"
        mapping[name] = _outcome(handler, cls)
    return dict(sorted(mapping.items()))


def _render(mapping: Dict[str, List[Any]]) -> str:
    # One class per line, keys sorted, so a diff reads as "this class now maps to that".
    lines = [f"  {json.dumps(name)}: {json.dumps(mapping[name])}" for name in sorted(mapping)]
    return "{\n" + ",\n".join(lines) + "\n}\n"


def test_error_mapping_matches_golden(make_settings: Callable[..., Settings]) -> None:
    text = _render(_mapping(make_settings()))
    if os.environ.get(UPDATE_ENV) == "1":
        GOLDEN.write_text(text, encoding="utf-8")
        return
    assert GOLDEN.exists(), f"{GOLDEN.name} is missing; create it with: {REGENERATE}"
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    current = json.loads(text)
    changed = sorted(k for k in golden.keys() & current.keys() if golden[k] != current[k])
    diff = {
        "added": sorted(current.keys() - golden.keys()),
        "removed": sorted(golden.keys() - current.keys()),
        "changed": {k: {"golden": golden[k], "now": current[k]} for k in changed},
    }
    assert current == golden, (
        f"exception -> (status, code) mapping changed: {json.dumps(diff, indent=2)}\n"
        f"If this is intended, regenerate the golden and review its diff: {REGENERATE}"
    )
