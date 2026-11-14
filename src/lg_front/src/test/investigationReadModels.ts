/**
 * Investigation read models as `GET /alerts/{id}/investigation` returns them, for the investigation
 * view's tests: an escalated alert (the console v2 prototype's scenario, with the response a true
 * positive would propose), an alert the AI closed and sampled for audit, and an alert whose response
 * plan is on the ledger.
 *
 * Generated from the backend's own assembly (`lg_sotf.domain.investigation.assemble` over
 * `tests/fixtures/investigation.py`), then committed: they are what the API serialises, not a
 * hand-written guess, and `InvestigationOut` holds them to the OpenAPI schema (contract.check.ts).
 * Synthetic data only.
 */

import type { InvestigationOut } from '../modules/soc/api/types';

export const ESCALATED_INVESTIGATION: InvestigationOut = {
  "schema_version": 1,
  "alert_id": "alert-1",
  "tenant_id": "tenant-a",
  "generated_at": "2026-11-14T10:04:00Z",
  "hidden_for_blind_audit": false,
  "outcome": {
    "category": "needs_decision",
    "reason": {
      "code": "inconclusive",
      "sentence": "No automatic rule applies to this alert, so a person decides."
    },
    "blockers": [
      {
        "code": "tier_off",
        "sentence": "This customer has not allowed the AI to close alerts on the model's word."
      },
      {
        "code": "fast_tier_threat",
        "sentence": "The first model assessment called it a likely or confirmed threat."
      },
      {
        "code": "deep_tier_not_benign",
        "sentence": "The deeper analysis did not judge it benign."
      }
    ],
    "evidence": [],
    "closed_by": null
  },
  "summary": {
    "text": "Word ran a hidden, encoded PowerShell command that downloaded a script from a three-day-old domain and ran it in memory. Isolate the host and reset the user's sessions.",
    "written_by": "model"
  },
  "claims": [
    {
      "id": "C-01",
      "text": "Word started PowerShell directly from an email attachment that came from the internet.",
      "written_by": "model",
      "direction": "malicious",
      "observation_ids": [],
      "check": "unsupported",
      "check_reason": "The model named no observation for it."
    },
    {
      "id": "C-02",
      "text": "The PowerShell command is hidden and encoded. Decoded, it downloads a script and runs it in memory.",
      "written_by": "model",
      "direction": "malicious",
      "observation_ids": [],
      "check": "unsupported",
      "check_reason": "The model named no observation for it."
    },
    {
      "id": "C-03",
      "text": "The script came from cdn-invoice-portal.example, a domain registered three days ago.",
      "written_by": "model",
      "direction": "malicious",
      "observation_ids": [],
      "check": "unsupported",
      "check_reason": "The model named no observation for it."
    },
    {
      "id": "C-04",
      "text": "There is no sign yet that the attacker moved to other hosts.",
      "written_by": "model",
      "direction": "benign",
      "observation_ids": [],
      "check": "unsupported",
      "check_reason": "The model named no observation for it."
    },
    {
      "id": "C-05",
      "text": "A threat-intelligence source reports a value of this alert as suspicious.",
      "written_by": "rules",
      "direction": "malicious",
      "observation_ids": [
        "O-03"
      ],
      "check": "supported",
      "check_reason": null
    }
  ],
  "observations": [
    {
      "id": "O-01",
      "tool": "history",
      "title": "Earlier alerts of this customer for the same entity",
      "kind": "user",
      "target": "m.keller",
      "sources": [
        "history"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "empty",
      "verdict": null,
      "cached": false,
      "excerpt": [
        {
          "text": "history  not_found",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    },
    {
      "id": "O-02",
      "tool": "history",
      "title": "Earlier alerts of this customer for the same entity",
      "kind": "host",
      "target": "WS-FIN-0142",
      "sources": [
        "history"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "empty",
      "verdict": null,
      "cached": false,
      "excerpt": [
        {
          "text": "history  not_found",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    },
    {
      "id": "O-03",
      "tool": "reputation",
      "title": "Threat-intelligence reputation",
      "kind": "domain",
      "target": "cdn-invoice-portal.example",
      "sources": [
        "virustotal"
      ],
      "at": "2026-11-14T10:04:00Z",
      "outcome": "success",
      "verdict": "suspicious",
      "cached": false,
      "excerpt": [
        {
          "text": "virustotal  ok  suspicious",
          "marks": []
        },
        {
          "text": "  malicious_votes: 2",
          "marks": []
        },
        {
          "text": "  creation_date: 2026-11-11",
          "marks": []
        },
        {
          "text": "  registrar: Example Registrar",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": "41be7d0c9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a",
      "output_sha256": "9f2c81d7aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa41e1"
    },
    {
      "id": "O-04",
      "tool": "reputation",
      "title": "Threat-intelligence reputation",
      "kind": "ip",
      "target": "203.0.113.50",
      "sources": [
        "virustotal",
        "abuseipdb"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "empty",
      "verdict": null,
      "cached": false,
      "excerpt": [
        {
          "text": "virustotal  not_found",
          "marks": []
        },
        {
          "text": "abuseipdb  not_found",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    },
    {
      "id": "O-05",
      "tool": "reputation",
      "title": "Threat-intelligence reputation",
      "kind": "hash",
      "target": "5d1e0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0ab07c",
      "sources": [
        "virustotal"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "empty",
      "verdict": null,
      "cached": false,
      "excerpt": [
        {
          "text": "virustotal  not_found",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    },
    {
      "id": "O-06",
      "tool": "reputation",
      "title": "Threat-intelligence reputation",
      "kind": "url",
      "target": "https://cdn-invoice-portal.example/a.ps1",
      "sources": [
        "virustotal"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "failed",
      "verdict": null,
      "cached": false,
      "excerpt": [
        {
          "text": "virustotal  error",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    }
  ],
  "not_established": {
    "empty": [
      "O-01",
      "O-02",
      "O-04",
      "O-05"
    ],
    "not_checked": [
      {
        "what": "What else happened on the host and for the user around the alert",
        "why": "The investigation cannot query the source's own event data yet."
      }
    ],
    "unavailable": [
      {
        "what": "Threat-intelligence reputation",
        "why": "The source did not answer.",
        "kind": "tool_failed",
        "source": "virustotal",
        "observation_id": "O-06"
      }
    ]
  },
  "steps": [
    {
      "ts": "2026-11-14T09:44:26Z",
      "actor": "code",
      "text": "Alert received.",
      "produced": null
    },
    {
      "ts": "2026-11-14T09:44:27Z",
      "actor": "policy",
      "text": "Checked the suppression rules and earlier analyst verdicts. None applied.",
      "produced": null
    },
    {
      "ts": "2026-11-14T09:44:28Z",
      "actor": "model",
      "text": "First assessment of the alert by the fast model and the rules.",
      "produced": "confidence 78 · 2 threat signals"
    },
    {
      "ts": "2026-11-14T09:44:29Z",
      "actor": "code",
      "text": "Looked for related alerts of this customer.",
      "produced": "2 related alerts"
    },
    {
      "ts": "2026-11-14T09:44:33Z",
      "actor": "model",
      "text": "Deeper analysis: the model read the alert, chose reputation lookups and wrote its conclusion.",
      "produced": "4 lookups · verdict malicious"
    },
    {
      "ts": "2026-11-14T09:44:34Z",
      "actor": "policy",
      "text": "No automatic rule applies to this alert, so a person decides.",
      "produced": null
    },
    {
      "ts": "2026-11-14T09:44:35Z",
      "actor": "policy",
      "text": "Sent to an analyst.",
      "produced": "level L2 · priority 8"
    }
  ],
  "track_record": {
    "category": "needs_decision",
    "basis": "analyst_decisions",
    "window_days": 90,
    "total": 34,
    "confirmed": 31,
    "min_samples": 30,
    "rate": 0.9118
  },
  "response": {
    "source": "preview",
    "actions": [
      {
        "action_id": null,
        "action_type": "isolate_host",
        "target": "WS-FIN-0142",
        "description": "Isolate the host from the network",
        "risk": "high",
        "reversible": true,
        "inverse_action": "release_host",
        "irreversible_note": null,
        "status": null,
        "guardrail": {
          "verdict": "passed",
          "code": null,
          "reason": null
        },
        "without_preapproval": "awaiting_approval",
        "can_preapprove": false,
        "role_lock": "admin",
        "approval_entry": "isolate_host:WS-FIN-0142"
      },
      {
        "action_id": null,
        "action_type": "terminate_process",
        "target": "powershell.exe PID 7340",
        "description": "Terminate a process through EDR",
        "risk": "medium",
        "reversible": false,
        "inverse_action": null,
        "irreversible_note": "A stopped process is not restarted",
        "status": null,
        "guardrail": {
          "verdict": "passed",
          "code": null,
          "reason": null
        },
        "without_preapproval": "awaiting_approval",
        "can_preapprove": true,
        "role_lock": null,
        "approval_entry": "terminate_process:powershell.exe PID 7340"
      },
      {
        "action_id": null,
        "action_type": "block_domain",
        "target": "cdn-invoice-portal.example",
        "description": "Block the domain",
        "risk": "medium",
        "reversible": true,
        "inverse_action": "unblock_domain",
        "irreversible_note": null,
        "status": null,
        "guardrail": {
          "verdict": "passed",
          "code": null,
          "reason": null
        },
        "without_preapproval": "awaiting_approval",
        "can_preapprove": true,
        "role_lock": null,
        "approval_entry": "block_domain:cdn-invoice-portal.example"
      },
      {
        "action_id": null,
        "action_type": "revoke_sessions",
        "target": "m.keller@northwind.example",
        "description": null,
        "risk": "high",
        "reversible": false,
        "inverse_action": null,
        "irreversible_note": "Tokens already issued stay valid up to 1 hour",
        "status": null,
        "guardrail": {
          "verdict": "passed",
          "code": null,
          "reason": null
        },
        "without_preapproval": "awaiting_approval",
        "can_preapprove": false,
        "role_lock": "admin",
        "approval_entry": "revoke_sessions:m.keller@northwind.example"
      },
      {
        "action_id": null,
        "action_type": "collect_forensics",
        "target": "WS-FIN-0142",
        "description": null,
        "risk": "low",
        "reversible": false,
        "inverse_action": null,
        "irreversible_note": "A collected package cannot be un-collected",
        "status": null,
        "guardrail": {
          "verdict": "passed",
          "code": null,
          "reason": null
        },
        "without_preapproval": "awaiting_approval",
        "can_preapprove": true,
        "role_lock": null,
        "approval_entry": "collect_forensics:WS-FIN-0142"
      },
      {
        "action_id": null,
        "action_type": "reset_password",
        "target": "m.keller@northwind.example",
        "description": null,
        "risk": "critical",
        "reversible": false,
        "inverse_action": null,
        "irreversible_note": "The old password cannot be restored",
        "status": null,
        "guardrail": {
          "verdict": "blocked",
          "code": "autonomy_disabled",
          "reason": "The tenant's autonomy policy switches off critical-risk actions"
        },
        "without_preapproval": "blocked",
        "can_preapprove": false,
        "role_lock": "disabled",
        "approval_entry": "reset_password:m.keller@northwind.example"
      }
    ]
  },
  "pending_harness": [
    {
      "field": "claims[].observation_ids",
      "why": "The model does not cite observations yet, so only claims the rules derive from a lookup name one.",
      "issue": 201
    },
    {
      "field": "claims[].check",
      "why": "No checker compares claims with observations yet: a claim is supported only when a lookup backs it, and none is ever rejected.",
      "issue": 207
    },
    {
      "field": "observations[].excerpt[].marks",
      "why": "Highlight ranges are set by typed query templates, which do not exist yet.",
      "issue": 200
    },
    {
      "field": "observations",
      "why": "Only reputation and history lookups are recorded. Typed facts from the source's own event data come with the evidence tools.",
      "issue": 200
    },
    {
      "field": "not_established.not_checked",
      "why": "Without a playbook the list names only the lookups today's analysis could have made.",
      "issue": 205
    },
    {
      "field": "steps",
      "why": "The steps come from the workflow's timeline. Playbook selection, the lookups of a playbook and the checker's result are not recorded yet.",
      "issue": 356
    }
  ]
};

export const AI_CLOSED_INVESTIGATION: InvestigationOut = {
  "schema_version": 1,
  "alert_id": "alert-1",
  "tenant_id": "tenant-a",
  "generated_at": "2026-11-14T10:04:00Z",
  "hidden_for_blind_audit": false,
  "outcome": {
    "category": "ai_closed_audit",
    "reason": {
      "code": "ai_closed:audit_required",
      "sentence": "The AI closed it on the model's word. No independent evidence backs the close, so it is sampled for audit."
    },
    "blockers": [],
    "evidence": [],
    "closed_by": {
      "kind": "ai",
      "reason": {
        "code": "ai_closed:audit_required",
        "sentence": "The AI closed it on the model's word. No independent evidence backs the close, so it is sampled for audit."
      },
      "at": "2026-11-14T10:04:00Z",
      "rule_id": null,
      "rule_name": null,
      "source_alert_id": null,
      "decision": null
    }
  },
  "summary": {
    "text": "A routine package install by the configuration management agent, seen on 38 hosts this week.",
    "written_by": "model"
  },
  "claims": [
    {
      "id": "C-01",
      "text": "The package install matches the configuration management agent's schedule.",
      "written_by": "model",
      "direction": "benign",
      "observation_ids": [],
      "check": "unsupported",
      "check_reason": "The model named no observation for it."
    },
    {
      "id": "C-02",
      "text": "A threat-intelligence source reports a value of this alert as suspicious.",
      "written_by": "rules",
      "direction": "malicious",
      "observation_ids": [
        "O-03"
      ],
      "check": "supported",
      "check_reason": null
    }
  ],
  "observations": [
    {
      "id": "O-01",
      "tool": "history",
      "title": "Earlier alerts of this customer for the same entity",
      "kind": "user",
      "target": "m.keller",
      "sources": [
        "history"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "empty",
      "verdict": null,
      "cached": false,
      "excerpt": [
        {
          "text": "history  not_found",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    },
    {
      "id": "O-02",
      "tool": "history",
      "title": "Earlier alerts of this customer for the same entity",
      "kind": "host",
      "target": "WS-FIN-0142",
      "sources": [
        "history"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "empty",
      "verdict": null,
      "cached": false,
      "excerpt": [
        {
          "text": "history  not_found",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    },
    {
      "id": "O-03",
      "tool": "reputation",
      "title": "Threat-intelligence reputation",
      "kind": "domain",
      "target": "cdn-invoice-portal.example",
      "sources": [
        "virustotal"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "success",
      "verdict": "suspicious",
      "cached": false,
      "excerpt": [
        {
          "text": "virustotal  ok  suspicious",
          "marks": []
        },
        {
          "text": "  malicious_votes: 2",
          "marks": []
        },
        {
          "text": "  creation_date: 2026-11-11",
          "marks": []
        },
        {
          "text": "  registrar: Example Registrar",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    },
    {
      "id": "O-04",
      "tool": "reputation",
      "title": "Threat-intelligence reputation",
      "kind": "ip",
      "target": "203.0.113.50",
      "sources": [
        "virustotal",
        "abuseipdb"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "empty",
      "verdict": null,
      "cached": false,
      "excerpt": [
        {
          "text": "virustotal  not_found",
          "marks": []
        },
        {
          "text": "abuseipdb  not_found",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    },
    {
      "id": "O-05",
      "tool": "reputation",
      "title": "Threat-intelligence reputation",
      "kind": "hash",
      "target": "5d1e0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0ab07c",
      "sources": [
        "virustotal"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "empty",
      "verdict": null,
      "cached": false,
      "excerpt": [
        {
          "text": "virustotal  not_found",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    },
    {
      "id": "O-06",
      "tool": "reputation",
      "title": "Threat-intelligence reputation",
      "kind": "url",
      "target": "https://cdn-invoice-portal.example/a.ps1",
      "sources": [
        "virustotal"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "failed",
      "verdict": null,
      "cached": false,
      "excerpt": [
        {
          "text": "virustotal  error",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    }
  ],
  "not_established": {
    "empty": [
      "O-01",
      "O-02",
      "O-04",
      "O-05"
    ],
    "not_checked": [
      {
        "what": "What else happened on the host and for the user around the alert",
        "why": "The investigation cannot query the source's own event data yet."
      }
    ],
    "unavailable": [
      {
        "what": "Threat-intelligence reputation",
        "why": "The source did not answer.",
        "kind": "tool_failed",
        "source": "virustotal",
        "observation_id": "O-06"
      }
    ]
  },
  "steps": [
    {
      "ts": "2026-11-14T09:44:26Z",
      "actor": "code",
      "text": "Alert received.",
      "produced": null
    },
    {
      "ts": "2026-11-14T09:44:27Z",
      "actor": "policy",
      "text": "Checked the suppression rules and earlier analyst verdicts. None applied.",
      "produced": null
    },
    {
      "ts": "2026-11-14T09:44:28Z",
      "actor": "model",
      "text": "First assessment of the alert by the fast model and the rules.",
      "produced": "confidence 78 · 2 threat signals"
    },
    {
      "ts": "2026-11-14T09:44:29Z",
      "actor": "code",
      "text": "Looked for related alerts of this customer.",
      "produced": "2 related alerts"
    },
    {
      "ts": "2026-11-14T09:44:33Z",
      "actor": "model",
      "text": "Deeper analysis: the model read the alert, chose reputation lookups and wrote its conclusion.",
      "produced": "4 lookups · verdict malicious"
    },
    {
      "ts": "2026-11-14T09:44:34Z",
      "actor": "policy",
      "text": "No automatic rule applies to this alert, so a person decides.",
      "produced": null
    },
    {
      "ts": "2026-11-14T09:44:35Z",
      "actor": "policy",
      "text": "Sent to an analyst.",
      "produced": "level L2 · priority 8"
    }
  ],
  "track_record": {
    "category": "ai_closed_audit",
    "basis": "blind_audit_labels",
    "window_days": 90,
    "total": 12,
    "confirmed": 11,
    "min_samples": 30,
    "rate": null
  },
  "response": {
    "source": "none",
    "actions": []
  },
  "pending_harness": [
    {
      "field": "claims[].observation_ids",
      "why": "The model does not cite observations yet, so only claims the rules derive from a lookup name one.",
      "issue": 201
    },
    {
      "field": "claims[].check",
      "why": "No checker compares claims with observations yet: a claim is supported only when a lookup backs it, and none is ever rejected.",
      "issue": 207
    },
    {
      "field": "observations[].excerpt[].marks",
      "why": "Highlight ranges are set by typed query templates, which do not exist yet.",
      "issue": 200
    },
    {
      "field": "observations",
      "why": "Only reputation and history lookups are recorded. Typed facts from the source's own event data come with the evidence tools.",
      "issue": 200
    },
    {
      "field": "not_established.not_checked",
      "why": "Without a playbook the list names only the lookups today's analysis could have made.",
      "issue": 205
    },
    {
      "field": "steps",
      "why": "The steps come from the workflow's timeline. Playbook selection, the lookups of a playbook and the checker's result are not recorded yet.",
      "issue": 356
    }
  ]
};

export const RESPONSE_PLAN_INVESTIGATION: InvestigationOut = {
  "schema_version": 1,
  "alert_id": "alert-1",
  "tenant_id": "tenant-a",
  "generated_at": "2026-11-14T10:04:00Z",
  "hidden_for_blind_audit": false,
  "outcome": {
    "category": "needs_decision",
    "reason": {
      "code": "inconclusive",
      "sentence": "No automatic rule applies to this alert, so a person decides."
    },
    "blockers": [
      {
        "code": "tier_off",
        "sentence": "This customer has not allowed the AI to close alerts on the model's word."
      },
      {
        "code": "fast_tier_threat",
        "sentence": "The first model assessment called it a likely or confirmed threat."
      },
      {
        "code": "deep_tier_not_benign",
        "sentence": "The deeper analysis did not judge it benign."
      }
    ],
    "evidence": [],
    "closed_by": null
  },
  "summary": {
    "text": "Word ran a hidden, encoded PowerShell command that downloaded a script from a three-day-old domain and ran it in memory. Isolate the host and reset the user's sessions.",
    "written_by": "model"
  },
  "claims": [
    {
      "id": "C-01",
      "text": "Word started PowerShell directly from an email attachment that came from the internet.",
      "written_by": "model",
      "direction": "malicious",
      "observation_ids": [],
      "check": "unsupported",
      "check_reason": "The model named no observation for it."
    },
    {
      "id": "C-02",
      "text": "The PowerShell command is hidden and encoded. Decoded, it downloads a script and runs it in memory.",
      "written_by": "model",
      "direction": "malicious",
      "observation_ids": [],
      "check": "unsupported",
      "check_reason": "The model named no observation for it."
    },
    {
      "id": "C-03",
      "text": "The script came from cdn-invoice-portal.example, a domain registered three days ago.",
      "written_by": "model",
      "direction": "malicious",
      "observation_ids": [],
      "check": "unsupported",
      "check_reason": "The model named no observation for it."
    },
    {
      "id": "C-04",
      "text": "There is no sign yet that the attacker moved to other hosts.",
      "written_by": "model",
      "direction": "benign",
      "observation_ids": [],
      "check": "unsupported",
      "check_reason": "The model named no observation for it."
    },
    {
      "id": "C-05",
      "text": "A threat-intelligence source reports a value of this alert as suspicious.",
      "written_by": "rules",
      "direction": "malicious",
      "observation_ids": [
        "O-03"
      ],
      "check": "supported",
      "check_reason": null
    }
  ],
  "observations": [
    {
      "id": "O-01",
      "tool": "history",
      "title": "Earlier alerts of this customer for the same entity",
      "kind": "user",
      "target": "m.keller",
      "sources": [
        "history"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "empty",
      "verdict": null,
      "cached": false,
      "excerpt": [
        {
          "text": "history  not_found",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    },
    {
      "id": "O-02",
      "tool": "history",
      "title": "Earlier alerts of this customer for the same entity",
      "kind": "host",
      "target": "WS-FIN-0142",
      "sources": [
        "history"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "empty",
      "verdict": null,
      "cached": false,
      "excerpt": [
        {
          "text": "history  not_found",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    },
    {
      "id": "O-03",
      "tool": "reputation",
      "title": "Threat-intelligence reputation",
      "kind": "domain",
      "target": "cdn-invoice-portal.example",
      "sources": [
        "virustotal"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "success",
      "verdict": "suspicious",
      "cached": false,
      "excerpt": [
        {
          "text": "virustotal  ok  suspicious",
          "marks": []
        },
        {
          "text": "  malicious_votes: 2",
          "marks": []
        },
        {
          "text": "  creation_date: 2026-11-11",
          "marks": []
        },
        {
          "text": "  registrar: Example Registrar",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    },
    {
      "id": "O-04",
      "tool": "reputation",
      "title": "Threat-intelligence reputation",
      "kind": "ip",
      "target": "203.0.113.50",
      "sources": [
        "virustotal",
        "abuseipdb"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "empty",
      "verdict": null,
      "cached": false,
      "excerpt": [
        {
          "text": "virustotal  not_found",
          "marks": []
        },
        {
          "text": "abuseipdb  not_found",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    },
    {
      "id": "O-05",
      "tool": "reputation",
      "title": "Threat-intelligence reputation",
      "kind": "hash",
      "target": "5d1e0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0ab07c",
      "sources": [
        "virustotal"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "empty",
      "verdict": null,
      "cached": false,
      "excerpt": [
        {
          "text": "virustotal  not_found",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    },
    {
      "id": "O-06",
      "tool": "reputation",
      "title": "Threat-intelligence reputation",
      "kind": "url",
      "target": "https://cdn-invoice-portal.example/a.ps1",
      "sources": [
        "virustotal"
      ],
      "at": "2026-11-14T09:44:29Z",
      "outcome": "failed",
      "verdict": null,
      "cached": false,
      "excerpt": [
        {
          "text": "virustotal  error",
          "marks": []
        }
      ],
      "excerpt_truncated": false,
      "input_sha256": null,
      "output_sha256": null
    }
  ],
  "not_established": {
    "empty": [
      "O-01",
      "O-02",
      "O-04",
      "O-05"
    ],
    "not_checked": [
      {
        "what": "What else happened on the host and for the user around the alert",
        "why": "The investigation cannot query the source's own event data yet."
      }
    ],
    "unavailable": [
      {
        "what": "Threat-intelligence reputation",
        "why": "The source did not answer.",
        "kind": "tool_failed",
        "source": "virustotal",
        "observation_id": "O-06"
      }
    ]
  },
  "steps": [
    {
      "ts": "2026-11-14T09:44:26Z",
      "actor": "code",
      "text": "Alert received.",
      "produced": null
    },
    {
      "ts": "2026-11-14T09:44:27Z",
      "actor": "policy",
      "text": "Checked the suppression rules and earlier analyst verdicts. None applied.",
      "produced": null
    },
    {
      "ts": "2026-11-14T09:44:28Z",
      "actor": "model",
      "text": "First assessment of the alert by the fast model and the rules.",
      "produced": "confidence 78 · 2 threat signals"
    },
    {
      "ts": "2026-11-14T09:44:29Z",
      "actor": "code",
      "text": "Looked for related alerts of this customer.",
      "produced": "2 related alerts"
    },
    {
      "ts": "2026-11-14T09:44:33Z",
      "actor": "model",
      "text": "Deeper analysis: the model read the alert, chose reputation lookups and wrote its conclusion.",
      "produced": "4 lookups · verdict malicious"
    },
    {
      "ts": "2026-11-14T09:44:34Z",
      "actor": "policy",
      "text": "No automatic rule applies to this alert, so a person decides.",
      "produced": null
    },
    {
      "ts": "2026-11-14T09:44:35Z",
      "actor": "policy",
      "text": "Sent to an analyst.",
      "produced": "level L2 · priority 8"
    }
  ],
  "track_record": {
    "category": "needs_decision",
    "basis": "analyst_decisions",
    "window_days": 90,
    "total": 120,
    "confirmed": 96,
    "min_samples": 30,
    "rate": 0.8
  },
  "response": {
    "source": "plan",
    "actions": [
      {
        "action_id": "00000000-0000-4000-8000-000000000001",
        "action_type": "terminate_process",
        "target": "powershell.exe PID 7340",
        "description": "Terminate a process through EDR",
        "risk": "medium",
        "reversible": false,
        "inverse_action": null,
        "irreversible_note": "A stopped process is not restarted",
        "status": "succeeded",
        "guardrail": null,
        "without_preapproval": null,
        "can_preapprove": null,
        "role_lock": null,
        "approval_entry": null
      },
      {
        "action_id": "00000000-0000-4000-8000-000000000002",
        "action_type": "isolate_host",
        "target": "WS-FIN-0142",
        "description": "Isolate the host from the network",
        "risk": "high",
        "reversible": true,
        "inverse_action": "release_host",
        "irreversible_note": null,
        "status": "awaiting_approval",
        "guardrail": {
          "verdict": "passed",
          "code": null,
          "reason": null
        },
        "without_preapproval": null,
        "can_preapprove": null,
        "role_lock": null,
        "approval_entry": null
      },
      {
        "action_id": "00000000-0000-4000-8000-000000000003",
        "action_type": "block_domain",
        "target": "cdn-invoice-portal.example",
        "description": "Block the domain",
        "risk": "medium",
        "reversible": true,
        "inverse_action": "unblock_domain",
        "irreversible_note": null,
        "status": "dry_run",
        "guardrail": null,
        "without_preapproval": null,
        "can_preapprove": null,
        "role_lock": null,
        "approval_entry": null
      },
      {
        "action_id": "00000000-0000-4000-8000-000000000004",
        "action_type": "reset_password",
        "target": "m.keller@northwind.example",
        "description": null,
        "risk": "critical",
        "reversible": false,
        "inverse_action": null,
        "irreversible_note": null,
        "status": "blocked",
        "guardrail": {
          "verdict": "blocked",
          "code": "autonomy_disabled",
          "reason": "The tenant's autonomy policy switches off critical-risk actions"
        },
        "without_preapproval": null,
        "can_preapprove": null,
        "role_lock": null,
        "approval_entry": null
      }
    ]
  },
  "pending_harness": [
    {
      "field": "claims[].observation_ids",
      "why": "The model does not cite observations yet, so only claims the rules derive from a lookup name one.",
      "issue": 201
    },
    {
      "field": "claims[].check",
      "why": "No checker compares claims with observations yet: a claim is supported only when a lookup backs it, and none is ever rejected.",
      "issue": 207
    },
    {
      "field": "observations[].excerpt[].marks",
      "why": "Highlight ranges are set by typed query templates, which do not exist yet.",
      "issue": 200
    },
    {
      "field": "observations",
      "why": "Only reputation and history lookups are recorded. Typed facts from the source's own event data come with the evidence tools.",
      "issue": 200
    },
    {
      "field": "not_established.not_checked",
      "why": "Without a playbook the list names only the lookups today's analysis could have made.",
      "issue": 205
    },
    {
      "field": "steps",
      "why": "The steps come from the workflow's timeline. Playbook selection, the lookups of a playbook and the checker's result are not recorded yet.",
      "issue": 356
    }
  ]
};
