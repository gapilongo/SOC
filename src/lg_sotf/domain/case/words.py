"""The plain sentences of the case read model.

Fixed text only: nothing from an alert, an analyst or a provider is ever
formatted into one of these. Decide codes and close reasons keep the
sentences of the investigation read model
(:mod:`lg_sotf.domain.investigation.words`), so an alert reads the same on
both pages.
"""

from __future__ import annotations

from typing import Final, Mapping, NamedTuple, Optional, Tuple

from lg_sotf.domain.investigation.words import Step

__all__ = [
    "CASE_CLAIMED",
    "CASE_DECIDED",
    "CASE_OPENED",
    "EVENT_STEPS",
    "LINKED",
    "LINK_CODE",
    "NOT_AVAILABLE",
    "REOPENED_BY",
    "Missing",
]

#: The reason code of a link and of a reopening (``lg_sotf.core.retro_reopen.REOPEN_REASON``).
LINK_CODE: Final = "related_threat"

#: Why the safety net linked an alert to the case.
LINKED: Final = (
    "A model judged a related alert a threat: same host, user or address, within 24 hours. A model's judgement "
    "is not a confirmation, so the safety net links what the AI closed to the case and leaves it closed. A "
    "person's confirmation of the threat reopens it."
)

#: What reopened an alert, by who recorded the reopening (``person``, ``workflow``, or unknown).
REOPENED_BY: Final[Mapping[Optional[str], str]] = {
    "person": (
        "A person confirmed a related threat (a true positive, an approved response action or a blind-audit "
        "label), so the safety net reopened this alert, which the AI had closed on the model's word."
    ),
    "workflow": (
        "A related threat was confirmed (an analyst's true positive, or a response action that ran), so the "
        "safety net reopened this alert, which the AI had closed on the model's word."
    ),
    None: "A related threat was confirmed, so the safety net reopened this alert, which the AI had closed on the model's word.",
}

CASE_OPENED: Final = Step("policy", "The case was opened for a person's decision.")
CASE_CLAIMED: Final = Step("person", "An analyst claimed the case.")
CASE_DECIDED: Final = Step("person", "An analyst recorded the decision on the case.")

#: Timeline events of an alert that only the case shows, as plain steps.
EVENT_STEPS: Final[Mapping[str, Step]] = {
    "alert.linked": Step("policy", "The safety net linked this alert to the case. It stays closed."),
    "alert.reopened": Step("policy", "The safety net reopened this alert after a related threat was confirmed."),
}


class Missing(NamedTuple):
    """A field the stored data cannot fill: its path, why, and the issue of the story that fills it (if any)."""

    field: str
    reason: str
    issue: Optional[int] = None


#: What the design of the case page shows and the backend cannot give yet.
NOT_AVAILABLE: Final[Tuple[Missing, ...]] = (
    Missing(
        "key",
        "A case has no readable reference yet. The case is the escalation, and its id is the key.",
    ),
    Missing(
        "summary",
        "Nobody writes a summary of a case yet. The counts of its alerts are given instead.",
    ),
    Missing(
        "alerts[].link.shared_entity",
        "The safety net records that an alert shares a host, user or address with the threat, not which one.",
    ),
    Missing(
        "alerts[].reopened.confirmation",
        "A reopening records who or what acted, not which confirmation caused it.",
    ),
    Missing(
        "alerts[].flagged",
        "An alert cannot be flagged for the next blind-audit sample yet.",
    ),
    Missing(
        "alerts[].closed_by.rule_reviewed_at",
        "A suppression rule records when it was created and when it expires, not when it was last reviewed.",
    ),
    Missing(
        "actions[].decision_reason",
        "An approval or a rejection of a response action records who decided and when, not a reason.",
    ),
    Missing(
        "entities[].context",
        "No asset or identity context is stored for a host or a user.",
    ),
)
