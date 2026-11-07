"""Python-version guard for the safe regex engine.

``lg_sotf.security.safe_regex`` walks the parse tree of CPython's private
``re._parser`` and compares opcodes from ``re._constants`` by identity. Neither
module is a public API, so a Python upgrade may rename an opcode or change the
shape of an argument tuple. These tests pin every name and every shape the
engine reads, so such a change fails here, loudly, instead of silently
accepting or mis-matching suppression patterns.

When a new Python version passes them, add it to ``VERIFIED_PYTHONS``.
"""

from __future__ import annotations

import re
import re._constants as sre_constants
import re._parser as sre_parser
import sys
from pathlib import Path
from typing import Any, List, Tuple

import pytest

from lg_sotf.security import safe_regex

VERIFIED_PYTHONS = {(3, 11), (3, 12), (3, 13), (3, 14)}

ENGINE_SOURCE = Path(safe_regex.__file__).read_text(encoding="utf-8")


def _items(pattern: str) -> List[Tuple[Any, Any]]:
    return list(sre_parser.parse(pattern))


def test_running_python_is_a_verified_version() -> None:
    version = sys.version_info[:2]
    assert version in VERIFIED_PYTHONS, (
        f"Python {version[0]}.{version[1]} is not verified for lg_sotf.security.safe_regex, which reads the "
        "CPython-private re._parser and re._constants. Run this file; if every shape test passes, add the "
        "version to VERIFIED_PYTHONS, otherwise adapt the engine first."
    )


def test_every_constant_the_engine_reads_exists() -> None:
    used = sorted(set(re.findall(r"sre_constants\.([A-Z_]+)", ENGINE_SOURCE)))
    assert len(used) > 20, "the engine no longer reads re._constants through the sre_constants alias"
    missing = [name for name in used if not hasattr(sre_constants, name)]
    assert not missing, f"re._constants lost names the safe regex engine reads: {missing}"


def test_parse_returns_op_argument_pairs_and_global_flags() -> None:
    parsed = sre_parser.parse("(?s)ab")
    assert isinstance(parsed.state.flags, int) and parsed.state.flags & re.DOTALL
    items = list(parsed)
    assert items == [(sre_constants.LITERAL, ord("a")), (sre_constants.LITERAL, ord("b"))]
    assert items[0][0] is sre_constants.LITERAL


@pytest.mark.parametrize(
    ("pattern", "op", "low", "high"),
    [
        ("a{2,5}", "MAX_REPEAT", 2, 5),
        ("a*", "MAX_REPEAT", 0, "MAXREPEAT"),
        ("a+?", "MIN_REPEAT", 1, "MAXREPEAT"),
        ("a*+", "POSSESSIVE_REPEAT", 0, "MAXREPEAT"),
    ],
)
def test_repeats_are_low_high_body(pattern: str, op: str, low: int, high: Any) -> None:
    [(found, av)] = _items(pattern)
    assert found is getattr(sre_constants, op)
    lo, hi, body = av
    assert lo == low
    assert hi == (sre_constants.MAXREPEAT if high == "MAXREPEAT" else high)
    assert list(body) == [(sre_constants.LITERAL, ord("a"))]


def test_subpattern_is_group_add_flags_del_flags_body() -> None:
    [(op, av)] = _items("(?i-s:a)")
    assert op is sre_constants.SUBPATTERN
    group, add_flags, del_flags, body = av
    assert group is None and add_flags == re.IGNORECASE and del_flags == re.DOTALL
    assert list(body) == [(sre_constants.LITERAL, ord("a"))]
    [(op, av)] = _items("(a)")
    assert op is sre_constants.SUBPATTERN and av[0] == 1


def test_branch_is_none_and_alternatives() -> None:
    [(op, av)] = _items("ab|c")
    assert op is sre_constants.BRANCH
    assert av[0] is None
    assert [list(alt) for alt in av[1]] == [
        [(sre_constants.LITERAL, ord("a")), (sre_constants.LITERAL, ord("b"))],
        [(sre_constants.LITERAL, ord("c"))],
    ]


def test_atomic_group_argument_is_its_body() -> None:
    [(op, av)] = _items("(?>ab)")
    assert op is sre_constants.ATOMIC_GROUP
    assert list(av) == [(sre_constants.LITERAL, ord("a")), (sre_constants.LITERAL, ord("b"))]


def test_character_classes() -> None:
    [(op, av)] = _items(r"[^a-c\d_]")
    assert op is sre_constants.IN
    assert list(av) == [
        (sre_constants.NEGATE, None),
        (sre_constants.RANGE, (ord("a"), ord("c"))),
        (sre_constants.CATEGORY, sre_constants.CATEGORY_DIGIT),
        (sre_constants.LITERAL, ord("_")),
    ]
    assert _items("[^a]") == [(sre_constants.NOT_LITERAL, ord("a"))]
    assert _items(".") == [(sre_constants.ANY, None)]
    categories = [_items(f"[\\{c}x]")[0][1][0][1] for c in "dDsSwW"]
    assert categories == [
        sre_constants.CATEGORY_DIGIT, sre_constants.CATEGORY_NOT_DIGIT,
        sre_constants.CATEGORY_SPACE, sre_constants.CATEGORY_NOT_SPACE,
        sre_constants.CATEGORY_WORD, sre_constants.CATEGORY_NOT_WORD,
    ]


def test_anchors() -> None:
    assert _items("^a$") == [
        (sre_constants.AT, sre_constants.AT_BEGINNING),
        (sre_constants.LITERAL, ord("a")),
        (sre_constants.AT, sre_constants.AT_END),
    ]
    assert _items(r"\Aa\Z")[0] == (sre_constants.AT, sre_constants.AT_BEGINNING_STRING)
    assert _items(r"\Aa\Z")[-1] == (sre_constants.AT, sre_constants.AT_END_STRING)
    assert _items(r"\b")[0][0] is sre_constants.AT


@pytest.mark.parametrize(
    ("pattern", "op"),
    [
        (r"(a)\1", "GROUPREF"),
        ("(a)?(?(1)b|c)", "GROUPREF_EXISTS"),
        ("(?=a)", "ASSERT"),
        ("(?<=a)", "ASSERT"),
        ("(?!a)", "ASSERT_NOT"),
    ],
)
def test_forbidden_constructs_keep_their_opcodes(pattern: str, op: str) -> None:
    ops = [found for found, _ in _items(pattern)]
    assert getattr(sre_constants, op) in ops


def test_parse_errors_carry_a_message() -> None:
    with pytest.raises(re.error) as raised:
        sre_parser.parse("[")
    assert raised.value.msg == "unterminated character set"
