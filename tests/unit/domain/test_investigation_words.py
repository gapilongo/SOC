"""Every code the workflow can produce has a plain sentence (PRD-2.8a).

The investigation view never shows a decide code, a blocker name, a close
reason or an engine node name. These tests read the codes from the
workflow's own source, so adding one without a sentence in
``lg_sotf.domain.investigation.words`` fails here.
"""

from __future__ import annotations

import ast
import inspect
from typing import Any, Iterator, List, Set, cast, get_args

import pytest

from lg_sotf.core import nodes
from lg_sotf.core.nodes import WorkflowNodes
from lg_sotf.core.retro_reopen import REOPEN_ACTION
from lg_sotf.domain import closure, routing
from lg_sotf.domain.investigation import words
from lg_sotf.models.vocabulary import BENIGN_DECISIONS
from lg_sotf.services import escalation, folded
from lg_sotf.tools.enrichment.base import Status

pytestmark = pytest.mark.unit


def _tree(module: Any) -> ast.Module:
    return ast.parse(inspect.getsource(module))


def _function(tree: ast.AST, name: str) -> ast.AST:
    found = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name == name]
    assert len(found) == 1, name
    return found[0]


def _text(node: ast.AST, module: Any) -> str:
    """A string literal, or a constant of ``module``'s namespace (``closure.MODEL_CLOSED``)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    assert isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name), ast.dump(node)
    return str(getattr(getattr(module, node.value.id), node.attr))


def decide_codes() -> Set[str]:
    """Every code a decision or an escalation can carry, read from the code that writes it."""
    codes: Set[str] = set()
    for call in ast.walk(_tree(routing)):
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "Decision":
            codes.add(_text(call.args[3], routing))
    for node in ast.walk(_tree(nodes)):
        # decision["code"] = "response_review" and routing.routing_digest("group_review", ...)
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Subscript):
            key = node.targets[0].slice
            if isinstance(key, ast.Constant) and key.value == "code":
                codes.add(_text(node.value, nodes))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "routing_digest":
            if isinstance(node.args[0], ast.Constant):
                codes.add(str(node.args[0].value))
    return codes | set(escalation.REASON_WEIGHTS) | set(escalation.OWN_REVIEW_REASONS)


def blocker_names() -> Set[str]:
    """The names in the ``checks`` tables of the two closure policies."""
    names: Set[str] = set()
    tree = _tree(closure)
    for function in ("model_close_blockers", "evidence_close_blockers"):
        tables = [
            n.value for n in ast.walk(_function(tree, function))
            if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "checks"
        ]
        assert len(tables) == 1 and isinstance(tables[0], ast.Tuple), function
        for row in tables[0].elts:
            assert isinstance(row, ast.Tuple)
            names.add(_text(row.elts[0], closure))
    return names


def _reasons(node: ast.AST) -> Iterator[str]:
    """The close reasons an expression can evaluate to (dictionary lookups such as ``.get("type")`` aside)."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
        return
    if isinstance(node, ast.JoinedStr):
        prefix = node.values[0]
        assert isinstance(prefix, ast.Constant) and prefix.value == "analyst:"
        yield from (f"analyst:{decision}" for decision in sorted(BENIGN_DECISIONS))
    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node.value
    elif isinstance(node, ast.Attribute):
        yield _text(node, nodes)
    else:
        for child in ast.iter_child_nodes(node):
            yield from _reasons(child)


def close_reasons() -> Set[str]:
    """Every reason ``WorkflowNodes.outcome`` returns, what the gate records as the closer, and the folded close."""
    tree = _tree(nodes)
    reasons: Set[str] = set()
    for node in ast.walk(_function(tree, "outcome")):
        if isinstance(node, ast.Return):
            assert isinstance(node.value, ast.Tuple) and len(node.value.elts) == 2
            reasons.update(_reasons(node.value.elts[1]))
    for node in ast.walk(_function(tree, "gate")):
        if isinstance(node, ast.Dict):
            reasons.update(
                _text(value, nodes) for key, value in zip(node.keys, node.values, strict=True)
                if isinstance(key, ast.Constant) and key.value == "type"
            )
    assert 'f"analyst:{decision}"' in inspect.getsource(folded)
    return reasons


def test_every_decide_code_has_a_sentence() -> None:
    codes = decide_codes()
    assert {"grey_zone", "model_closed", "response_review", "group_review", "blind_audit"} <= codes
    assert sorted(codes - set(words.DECIDE_SENTENCES)) == []


def test_every_blocker_has_a_sentence() -> None:
    names = blocker_names()
    assert {"tier_off", "never_close_class", "steering_text", "deep_tier_not_benign"} <= names
    assert sorted(names - set(words.BLOCKER_SENTENCES)) == []
    assert sorted(set(words.BLOCKER_SENTENCES) - names) == []  # no sentence for a blocker that is gone


def test_every_close_reason_says_who_closed_the_alert() -> None:
    reasons = close_reasons()
    assert {"analyst:true_positive", "analyst:false_positive", "suppression_rule", "verdict_cache", "policy:close",
            closure.MODEL_CLOSE_REASON, "triage:false_positive"} <= reasons
    assert sorted(reasons - set(words.CLOSE_REASONS)) == []
    assert {entry.closed_by for entry in words.CLOSE_REASONS.values()} == {
        "ai", "suppression_rule", "cached_verdict", "analyst"
    }


def test_every_engine_node_has_a_plain_step() -> None:
    engine_nodes = set(WorkflowNodes(cast(Any, None))._impl)
    assert {"gate", "triage", "analysis", "decide", "close"} <= engine_nodes
    assert sorted(engine_nodes - set(words.NODE_STEPS)) == []
    assert sorted(set(words.NODE_STEPS) - engine_nodes) == []
    assert all(key.split(":")[0] in engine_nodes for key in words.NODE_STEP_VARIANTS)
    assert REOPEN_ACTION in words.EVENT_STEPS


def test_every_lookup_status_is_typed() -> None:
    """A provider status is ``ok`` (success), ``not_found`` (empty) or a reason the lookup could not be made."""
    assert sorted(set(get_args(Status)) - {"ok", "not_found"} - set(words.LOOKUP_STATUS_SENTENCES)) == []
    assert {kind for kind, _ in words.LOOKUP_STATUS_SENTENCES.values()} == {"no_source", "tool_failed"}


def _sentences() -> List[str]:
    out = [*words.DECIDE_SENTENCES.values(), *words.BLOCKER_SENTENCES.values(), words.UNKNOWN_REASON]
    out += [entry.sentence for entry in words.CLOSE_REASONS.values()]
    out += [step.text for table in (words.NODE_STEPS, words.NODE_STEP_VARIANTS, words.EVENT_STEPS) for step in table.values()]
    out += [sentence for _, sentence in words.LOOKUP_STATUS_SENTENCES.values()]
    out += [sentence for _, sentence in words.LOOKUP_CLAIMS.values()]
    out += [words.NO_LOOKUP_WHY, words.TOOL_ERROR_SENTENCE, words.NO_TELEMETRY[1], words.NOT_INVESTIGATED[1]]
    out += [words.NO_ANALYSIS[1], *(pending.why for pending in words.PENDING_HARNESS)]
    return out


def test_sentences_are_plain_fixed_text() -> None:
    """No placeholder to format alert text into, and no code identifier (decide codes, blockers and engine node
    names such as ``plan_response`` are written with underscores)."""
    for sentence in _sentences():
        assert sentence and sentence[0].isupper() and sentence.endswith("."), sentence
        assert not any(mark in sentence for mark in ("{", "}", "%s", "_")), sentence


def test_an_unknown_code_still_gets_a_sentence() -> None:
    assert words.decide_sentence("grey_zone") == words.DECIDE_SENTENCES["grey_zone"]
    assert words.decide_sentence("code_of_a_newer_release") == words.UNKNOWN_REASON
    assert words.decide_sentence(None) == words.UNKNOWN_REASON
