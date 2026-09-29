"""Secret redaction for alert payloads, prompts and log records.

``redact`` walks JSON-like structures and returns a redacted deep copy plus
the number of replacements. Text is scanned for well-known credential shapes
(private keys, cloud/API keys, JWTs, auth headers, credentials embedded in
connection strings, password-like CLI arguments and ``key=value`` pairs).
Values under secret-labelled keys, including ``{"name": ..., "value": ...}``
and ``[name, value]`` pairs, are replaced whole. Generic high-entropy strings
are only redacted when they are labelled as a secret, so hashes, GUIDs and
other indicators analysts need stay intact.

Every rule runs in time linear in the input. Text beyond
:data:`MAX_TEXT_CHARS` and structures nested deeper than :data:`MAX_DEPTH`
are replaced by markers rather than passed through unscanned.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter
from functools import lru_cache
from typing import Any, Callable, FrozenSet, List, Mapping, NamedTuple, Optional, Pattern, Set, Tuple, Union

REDACTED = "[REDACTED]"
PRIVATE_KEY_REDACTED = "[REDACTED:private_key]"
TOO_DEEP = "[REDACTED: nesting too deep]"
MAX_TEXT_CHARS = 1_048_576
MAX_DEPTH = 64

_STRONG_LABEL = (
    r"password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"secret[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|session[_-]?(?:id|token|key)|"
    r"credentials?|cookie|authorization|(?:password|pwd|nt|ntlm|lm)[_-]?hash|sas[_-]?token|conn(?:ection)?[_-]?string"
)
_WEAK_LABEL = r"key|auth|signature|sig"

# Dict keys are normalised to snake_case before matching; the label must end
# the key so fields such as ``password_last_set`` or ``token_type`` survive.
_STRONG_KEY = re.compile(rf"^(?:.*[_\-. ])?(?:{_STRONG_LABEL}|pass)s?$", re.IGNORECASE)
_WEAK_KEY = re.compile(rf"^(?:.*[_\-. ])?(?:{_WEAK_LABEL})s?$", re.IGNORECASE)
_NOT_SECRET_KEY = re.compile(
    r"(?:^|_)(?:type|count|length|len|expires?|expiry|expiration|id_type|name|kind|format|"
    r"last_set|last_used|age|policy|required|enabled|present|status|"
    r"(?:input|output|total|max|prompt|completion|reasoning|estimated|used|remaining|"
    r"cache_read|cache_write|cache_creation)(?:_input)?_tokens)$",
    re.IGNORECASE,
)
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_TOKEN_CHARS = re.compile(r"^[A-Za-z0-9+/=_\-]+$")
_AUTH_SCHEMES = frozenset({"bearer", "basic", "digest", "token", "negotiate", "ntlm", "apikey"})
_BASE64_SIGNAL = re.compile(r"[0-9+/=]")

# {"name": "Authorization", "value": "..."} style header / env-var lists.
_PAIR_NAME_KEYS: FrozenSet[str] = frozenset(
    {"name", "key", "header", "field", "param", "parameter", "variable", "attribute", "label"}
)
_PAIR_VALUE_KEYS: FrozenSet[str] = frozenset({"value", "values", "val", "data", "content"})
_MAX_LABEL_CHARS = 128

_Replacement = Union[str, Callable[["re.Match[str]"], str]]


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_high_entropy(value: str, *, min_length: int = 16, min_entropy: float = 3.3) -> bool:
    """Heuristic for opaque credential-like tokens (base64/hex/url-safe alphabets only)."""
    if len(value) < min_length or not _TOKEN_CHARS.match(value):
        return False
    classes = sum(
        1
        for pred in (str.islower, str.isupper, str.isdigit)
        if any(pred(ch) for ch in value)
    ) + (1 if any(not ch.isalnum() for ch in value) else 0)
    return classes >= 2 and _entropy(value) >= min_entropy


def _b64decode(value: str, *, strict_padding: bool) -> Optional[bytes]:
    if len(value) > 4096 or (strict_padding and len(value) % 4):
        return None
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _decodes_to_basic_credentials(value: str) -> bool:
    """Whether ``value`` is base64 of printable ``user:password`` text."""
    raw = _b64decode(value, strict_padding=False)
    if raw is None:
        return False
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    _, sep, password = decoded.partition(":")
    return bool(sep and password) and decoded.isprintable()


def _labelled_value(m: re.Match[str]) -> str:
    whole: str = m.group(0)
    value: str = m.group("val")
    inner = value.strip("\"'")
    if not inner or inner.startswith("[REDACTED") or inner.lower() in _AUTH_SCHEMES:
        return whole
    if m.group("weak") and not looks_high_entropy(inner):
        return whole
    quote = value[0] if value[:1] in ("'", '"') and value[-1:] == value[:1] and len(value) > 1 else ""
    return f"{m.group('key')}{m.group('q')}{m.group('sep')}{quote}{REDACTED}{quote}"


def _mask_val(m: re.Match[str]) -> str:
    """Replace only the ``val`` group of a match, keeping surrounding quotes."""
    value: str = m.group("val")
    if value.strip("\"'").startswith("[REDACTED"):
        return str(m.group(0))
    quote = value[0] if value[:1] in ("'", '"') and len(value) > 1 and value[-1] == value[0] else ""
    whole = str(m.group(0))
    start, end = m.start("val") - m.start(), m.end("val") - m.start()
    return f"{whole[:start]}{quote}{REDACTED}{quote}{whole[end:]}"


def _basic_credentials(m: re.Match[str]) -> str:
    value: str = m.group("val")
    text = m.string
    # A bare "Basic <b64>" string is a header value lifted out of its header. RFC 7617
    # credentials are padded base64, which keeps phrases like "Basic Information" intact.
    whole_text = (
        m.start() <= 16
        and len(text) - m.end() <= 16
        and not text[: m.start()].strip()
        and not text[m.end() :].strip()
        and _b64decode(value, strict_padding=True) is not None
    )
    if whole_text or _decodes_to_basic_credentials(value) or (len(value) >= 12 and _BASE64_SIGNAL.search(value)):
        return f"{m.group('h')}{REDACTED}"
    return str(m.group(0))


_PK_BEGIN = re.compile(r"-----BEGIN (?:[A-Z0-9]{1,24} ){0,4}PRIVATE KEY(?: BLOCK)?-----")
_PK_END = re.compile(r"-----END (?:[A-Z0-9]{1,24} ){0,4}PRIVATE KEY(?: BLOCK)?-----")


def _redact_private_keys(text: str) -> Tuple[str, int]:
    """Replace PEM/OpenSSH/PGP private key blocks; an unterminated block runs to the end of the text.

    A regex with a lazy body is quadratic on many unterminated headers, so the
    scan is done by hand: each character is visited a bounded number of times.
    """
    if "-----BEGIN " not in text:
        return text, 0
    parts: List[str] = []
    count = 0
    copied_to = 0
    cursor = 0
    while True:
        begin = text.find("-----BEGIN ", cursor)
        if begin < 0:
            break
        header = _PK_BEGIN.match(text, begin)
        if header is None:
            cursor = begin + 1
            continue
        parts.append(text[copied_to:begin])
        parts.append(PRIVATE_KEY_REDACTED)
        count += 1
        end = _PK_END.search(text, header.end())
        if end is None:
            copied_to = len(text)
            break
        copied_to = cursor = end.end()
    parts.append(text[copied_to:])
    return "".join(parts), count


class _Rule(NamedTuple):
    pattern: Pattern[str]
    replacement: _Replacement
    # Lowercase literals of which at least one occurs in every match; a rule is skipped
    # when none is in the text, which avoids most regex passes on benign strings.
    triggers: Tuple[str, ...]


# Commands whose short flags carry credentials. Tool names are matched case-insensitively,
# flags case-sensitively (mysql -P is the port, sshpass -P the prompt).
_MYSQL_TOOLS = r"mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mysqlcheck|mysqlpump|mariadb(?:-dump|-admin)?"
_ARG_GAP = r"[^\n|;&]{0,256}?"
_FLAG_TRIGGERS = ("pass", "pwd", "secret", "token", "key")
_LABEL_TRIGGERS = ("pass", "pwd", "secret", "token", "key", "session", "credential", "cookie", "auth", "hash", "conn", "sig")

_RULES: Tuple[_Rule, ...] = (
    _Rule(
        re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA|AGPA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b"),
        "[REDACTED:aws_access_key]",
        ("akia", "asia", "aida", "aroa", "agpa", "anpa", "anva", "aipa"),
    ),
    _Rule(
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}"),
        "[REDACTED:jwt]",
        ("eyj",),
    ),
    _Rule(
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}"),
        "[REDACTED:api_key]",
        ("sk-ant-",),
    ),
    _Rule(
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}"),
        "[REDACTED:api_key]",
        ("sk-",),
    ),
    _Rule(
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}"),
        "[REDACTED:api_key]",
        ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
    ),
    _Rule(
        re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
        "[REDACTED:api_key]",
        ("xox",),
    ),
    _Rule(
        re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"),
        "[REDACTED:api_key]",
        ("k_live_", "k_test_"),
    ),
    _Rule(
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "[REDACTED:api_key]",
        ("aiza",),
    ),
    _Rule(
        re.compile(r"\blgk_[0-9a-f]{32}_[A-Za-z0-9_-]{16,}"),
        "[REDACTED:api_key]",
        ("lgk_",),
    ),
    _Rule(
        re.compile(
            r"(?i)\b(?P<h>(?:proxy-)?authorization\s*[:=]\s*[\"']?\s*(?:bearer|basic|digest|token|negotiate|ntlm|apikey)\s+)"
            r"(?!\[REDACTED)[^\s\"',;]+"
        ),
        lambda m: f"{m.group('h')}{REDACTED}",
        ("authorization",),
    ),
    _Rule(
        re.compile(r"(?i)\b(?P<h>bearer\s+)(?!\[REDACTED)[A-Za-z0-9\-._~+/]{12,}=*"),
        lambda m: f"{m.group('h')}{REDACTED}",
        ("bearer",),
    ),
    _Rule(
        re.compile(r"(?i)\b(?P<h>basic\s+)(?!\[REDACTED)(?P<val>[A-Za-z0-9+/]{4,}={0,2})"),
        _basic_credentials,
        ("basic",),
    ),
    _Rule(
        re.compile(r"(?i)\b(?P<scheme>[a-z][a-z0-9+.-]{1,24}://)(?P<user>[^\s:/@\"'<>]*):(?!\[REDACTED)[^\s@/\"'<>]+@"),
        lambda m: f"{m.group('scheme')}{m.group('user')}:{REDACTED}@",
        ("://",),
    ),
    _Rule(
        re.compile(
            r"(?i)(?<![\w-])--?(?:[a-z0-9]{1,20}[-_]){0,3}(?:password|passwd|pass|pwd|secret|token|api[-_]?key|"
            r"access[-_]?key|secret[-_]?key|client[-_]?secret|auth[-_]?token)(?:\s+(?!-)|=)"
            r"(?P<val>\"[^\"]*\"|'[^']*'|[^\s\"']+)"
        ),
        _mask_val,
        _FLAG_TRIGGERS,
    ),
    _Rule(
        re.compile(rf"(?i:\b(?:{_MYSQL_TOOLS})(?:\.exe)?\b){_ARG_GAP}\s-p(?P<val>\"[^\"]*\"|'[^']*'|[^\s\"';|&]+)"),
        _mask_val,
        ("mysql", "mariadb"),
    ),
    _Rule(
        re.compile(rf"(?i:\bsshpass\b){_ARG_GAP}\s-p\s*(?P<val>\"[^\"]*\"|'[^']*'|[^\s\"']+)"),
        _mask_val,
        ("sshpass",),
    ),
    _Rule(
        re.compile(
            rf"(?i:\b(?:curl|wget)(?:\.exe)?\b){_ARG_GAP}\s(?:-u|-U|--user|--proxy-user)(?:\s+|=)?"
            r"(?P<q>[\"'])?[^\s:\"']*:(?P<val>(?(q)[^\"']*|[^\s\"']+))"
        ),
        _mask_val,
        ("curl", "wget"),
    ),
    _Rule(
        re.compile(
            rf"(?i:\b(?:smbclient|rpcclient|smbmap|smbcacls)(?:\.exe)?\b){_ARG_GAP}\s(?:-U|--user(?:name)?)(?:\s+|=)"
            r"(?P<q>[\"'])?[^\s%\"']+%(?P<val>(?(q)[^\"']*|[^\s\"']+))"
        ),
        _mask_val,
        ("smbclient", "rpcclient", "smbmap", "smbcacls"),
    ),
    _Rule(
        re.compile(r"(?i)(?P<flag>\bConvertTo-SecureString\s+(?:-String\s+)?)(?P<val>\"[^\"]*\"|'[^']*')"),
        _mask_val,
        ("convertto-securestring",),
    ),
    _Rule(
        re.compile(r"(?i)(?P<flag>\bnet1?(?:\.exe)?\s+user\s+(?:\"[^\"]+\"|\S+)\s+)(?P<val>(?![/*])(?:\"[^\"]*\"|\S+))"),
        _mask_val,
        ("user",),
    ),
    _Rule(
        # The lookahead lists every label's first letter so most positions are rejected
        # without trying each alternative (about 3.5x faster on large text).
        re.compile(
            rf"(?i)(?=[pstacnlk])(?P<key>(?P<strong>{_STRONG_LABEL})|(?P<weak>{_WEAK_LABEL}))\b"
            r"(?P<q>[\"']?)(?P<sep>\s*[:=]\s*)(?P<val>\"[^\"]*\"|'[^']*'|[^\s,;&\"'}\]]+)"
        ),
        _labelled_value,
        _LABEL_TRIGGERS,
    ),
)


_GATES: Tuple[Pattern[str], ...] = tuple(re.compile("|".join(map(re.escape, r.triggers))) for r in _RULES)
_ANY_TRIGGER = re.compile(
    "|".join(map(re.escape, sorted({t for r in _RULES for t in r.triggers}, key=len, reverse=True)))
)


def redact_text(text: str) -> Tuple[str, int]:
    """Redact credentials in free text. Returns the new text and replacement count.

    Text longer than :data:`MAX_TEXT_CHARS` is cut at that length and the
    unscanned remainder replaced by a marker (counted as one redaction).
    """
    overflow = len(text) - MAX_TEXT_CHARS
    if overflow > 0:
        text = text[:MAX_TEXT_CHARS]
    text, total = _redact_private_keys(text)
    # casefold() maps more characters to their ASCII form than lower() (e.g. U+017F, U+212A),
    # matching what the IGNORECASE patterns accept.
    folded = text.casefold()
    rules = zip(_RULES, _GATES, strict=True) if _ANY_TRIGGER.search(folded) else ()
    for (pattern, replacement, _), gate in rules:
        if gate.search(folded) is None:
            continue
        if isinstance(replacement, str):
            text, n = pattern.subn(replacement, text)
            total += n
        else:
            changed = 0

            def _apply(m: re.Match[str], _fn: Callable[[re.Match[str]], str] = replacement) -> str:
                nonlocal changed
                out = _fn(m)
                if out != m.group(0):
                    changed += 1
                return out

            text = pattern.sub(_apply, text)
            total += changed
    if overflow > 0:
        text += f"[REDACTED: {overflow} chars beyond the redaction scan limit]"
        total += 1
    return text, total


@lru_cache(maxsize=8192)
def _normalise_key(key: str) -> str:
    return _CAMEL.sub("_", key).lower()


_NOT_SECRET, _STRONG, _WEAK = 0, 1, 2


@lru_cache(maxsize=8192)
def _key_class(key: str) -> int:
    # Field names repeat across events, so the regex work is done once per distinct key.
    norm = _normalise_key(key)
    if _NOT_SECRET_KEY.search(norm):
        return _NOT_SECRET
    if _STRONG_KEY.match(norm):
        return _STRONG
    if _WEAK_KEY.match(norm):
        return _WEAK
    return _NOT_SECRET


def is_secret_key(key: str, value: Any = None) -> bool:
    """Whether a mapping key (or the name half of a name/value pair) labels a secret value."""
    if len(key) > _MAX_LABEL_CHARS:
        return False
    kind = _key_class(key)
    if kind == _WEAK:
        return isinstance(value, str) and looks_high_entropy(value)
    return kind == _STRONG


def _maskable(value: Any) -> bool:
    """Values a secret label hides: anything except None, booleans, empties and prior redactions."""
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, (str, bytes, Mapping, list, tuple, set, frozenset)) and len(value) == 0:
        return False
    return not (isinstance(value, str) and value.startswith("[REDACTED"))


def _secret_pair_values(obj: Mapping[Any, Any]) -> Set[Any]:
    """Value keys of a ``{"name": <secret label>, "value": ...}`` mapping that must be masked."""
    names = [
        v
        for k, v in obj.items()
        if isinstance(k, str) and len(k) <= 16 and isinstance(v, str) and _normalise_key(k) in _PAIR_NAME_KEYS
    ]
    if not names:
        return set()
    masked: Set[Any] = set()
    for k, v in obj.items():
        if isinstance(k, str) and len(k) <= 16 and _normalise_key(k) in _PAIR_VALUE_KEYS and _maskable(v):
            if any(is_secret_key(name, v) for name in names):
                masked.add(k)
    return masked


def _redact(obj: Any, depth: int) -> Tuple[Any, int]:
    if isinstance(obj, str):
        return redact_text(obj)
    is_container = isinstance(obj, (Mapping, list, tuple, set, frozenset))
    if not is_container:
        return obj, 0
    if depth >= MAX_DEPTH:
        return TOO_DEEP, 1
    if isinstance(obj, Mapping):
        out: dict = {}
        count = 0
        pair_values = _secret_pair_values(obj)
        for k, v in obj.items():
            if (isinstance(k, str) and _maskable(v) and is_secret_key(k, v)) or k in pair_values:
                out[k] = REDACTED
                count += 1
                continue
            out[k], n = _redact(v, depth + 1)
            count += n
        return out, count
    items = list(obj)
    if (
        isinstance(obj, (list, tuple))
        and len(items) == 2
        and isinstance(items[0], str)
        and _maskable(items[1])
        and is_secret_key(items[0], items[1])
    ):
        pair = [items[0], REDACTED]
        return (tuple(pair) if isinstance(obj, tuple) else pair), 1
    redacted_items = []
    count = 0
    for item in items:
        new, n = _redact(item, depth + 1)
        redacted_items.append(new)
        count += n
    return (tuple(redacted_items) if isinstance(obj, tuple) else redacted_items), count


def redact(obj: Any) -> Tuple[Any, int]:
    """Return a redacted deep copy of ``obj`` and the number of redactions.

    Mappings become ``dict``, sets become ``list``, tuples stay tuples.
    Scalars other than strings are returned unchanged unless they sit under a
    secret label. Containers nested deeper than :data:`MAX_DEPTH` are replaced
    by :data:`TOO_DEEP`.
    """
    return _redact(obj, 0)
