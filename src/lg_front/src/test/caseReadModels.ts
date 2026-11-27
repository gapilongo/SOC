/**
 * Case read models as `GET /cases/{id}` returns them, for the case page's tests and screenshots: the
 * console v2 prototype's case (nine alerts on one host, claimed and waiting for its decision), and the
 * same case after the analyst's true positive.
 *
 * Generated from the backend's own assembly (`lg_sotf.domain.case.assemble` over
 * `tests/fixtures/case.py`, printed by `python -m tests.fixtures.case`), then committed: they are what
 * the API serialises, not a hand-written guess, and `CaseOut` holds them to the OpenAPI schema
 * (contract.check.ts). `tests/unit/domain/test_case.py` fails when this file drifts from the backend.
 * Synthetic data only.
 */

import type { CaseOut } from '../modules/soc/api/types';

export const OPEN_CASE: CaseOut = {
  "schema_version": 1,
  "id": "esc-2291",
  "tenant_id": "northwind",
  "generated_at": "2026-11-14T10:04:12Z",
  "alert_id": "alr-48213",
  "title": "Encoded PowerShell launched by Microsoft Word",
  "status": "claimed",
  "active": true,
  "severity": "critical",
  "category": "needs_decision",
  "reason": {
    "code": "inconclusive",
    "sentence": "No automatic rule applies to this alert, so a person decides."
  },
  "opened_at": "2026-11-14T09:44:35Z",
  "sla_deadline": "2026-11-14T10:08:12Z",
  "owner": {
    "user_id": "5b0c7a52-6f0e-4c58-9d0e-1f2a3b4c5d6e",
    "email": "ines.moreau@brightwater.example",
    "since": "2026-11-14T09:52:10Z"
  },
  "version": 3,
  "decision": null,
  "counts": {
    "alerts": 9,
    "open": 3,
    "processing": 1,
    "closed": 5,
    "linked": 2,
    "reopened": 0,
    "flagged": 0,
    "withheld": 0,
    "closed_by": {
      "ai_evidence": 0,
      "ai_audit": 2,
      "suppression_rule": 1,
      "cached_verdict": 1,
      "analyst": 1
    },
    "actions_awaiting_approval": 3
  },
  "alerts": [
    {
      "id": "alr-47702",
      "title": "Failed logon burst: 6 failures in 2 minutes",
      "severity": "low",
      "status": "closed",
      "state": "closed",
      "role": "attached",
      "occurred_at": "2026-11-13T16:20:00Z",
      "closed_at": "2026-11-13T16:41:00Z",
      "disposition": "benign",
      "entities": [
        {
          "kind": "user",
          "value": "m.keller"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": "needs_review",
      "why": null,
      "closed_by": {
        "kind": "analyst",
        "reason": {
          "code": "analyst:benign_positive",
          "sentence": "An analyst decided it is real activity that is expected here."
        },
        "at": "2026-11-13T16:41:00Z",
        "decision": "benign_positive",
        "analyst": {
          "user_id": "5b0c7a52-6f0e-4c58-9d0e-1f2a3b4c5d6e",
          "email": "ines.moreau@brightwater.example"
        },
        "notes": null,
        "decided_in_case_id": "esc-2207",
        "policy": null,
        "tier": null,
        "rule_id": null,
        "rule_name": null,
        "source_alert_id": null
      },
      "blind_audit": {
        "state": "not_sampled",
        "label": null,
        "agrees": null,
        "labelled_at": null
      },
      "link": null,
      "reopened": null,
      "flagged": null,
      "can_reopen": false
    },
    {
      "id": "alr-48190",
      "title": "Package installed: Adobe Acrobat Reader update 24.004",
      "severity": "info",
      "status": "closed",
      "state": "closed",
      "role": "linked",
      "occurred_at": "2026-11-14T09:14:07Z",
      "closed_at": "2026-11-14T09:14:13Z",
      "disposition": "benign",
      "entities": [
        {
          "kind": "host",
          "value": "WS-FIN-0142"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": "ai_closed_audit",
      "why": null,
      "closed_by": {
        "kind": "ai",
        "reason": {
          "code": "ai_closed:audit_required",
          "sentence": "The AI closed it on the model's word. No independent evidence backs the close, so it is sampled for audit."
        },
        "at": "2026-11-14T09:14:13Z",
        "decision": null,
        "analyst": null,
        "notes": null,
        "decided_in_case_id": null,
        "policy": {
          "code": "model_closed",
          "sentence": "The AI judged the alert benign and closed it on the model's word. No independent evidence backs the close, so it is sampled for audit."
        },
        "tier": "auto_full_audit",
        "rule_id": null,
        "rule_name": null,
        "source_alert_id": null
      },
      "blind_audit": {
        "state": "labelled",
        "label": "benign",
        "agrees": true,
        "labelled_at": "2026-11-14T09:58:40Z"
      },
      "link": {
        "reason": {
          "code": "related_threat",
          "sentence": "A model judged a related alert a threat: same host, user or address, within 24 hours. A model's judgement is not a confirmation, so the safety net links what the AI closed to the case and leaves it closed. A person's confirmation of the threat reopens it."
        },
        "threat_alert_id": "alr-48213",
        "at": "2026-11-14T09:44:35Z"
      },
      "reopened": null,
      "flagged": null,
      "can_reopen": true
    },
    {
      "id": "alr-48212",
      "title": "Outlook opened a Word attachment from the internet zone",
      "severity": "low",
      "status": "closed",
      "state": "closed",
      "role": "linked",
      "occurred_at": "2026-11-14T09:41:49Z",
      "closed_at": "2026-11-14T09:41:55Z",
      "disposition": "benign",
      "entities": [
        {
          "kind": "user",
          "value": "m.keller"
        },
        {
          "kind": "host",
          "value": "WS-FIN-0142"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": "ai_closed_audit",
      "why": null,
      "closed_by": {
        "kind": "ai",
        "reason": {
          "code": "ai_closed:audit_required",
          "sentence": "The AI closed it on the model's word. No independent evidence backs the close, so it is sampled for audit."
        },
        "at": "2026-11-14T09:41:55Z",
        "decision": null,
        "analyst": null,
        "notes": null,
        "decided_in_case_id": null,
        "policy": {
          "code": "model_closed",
          "sentence": "The AI judged the alert benign and closed it on the model's word. No independent evidence backs the close, so it is sampled for audit."
        },
        "tier": "auto_full_audit",
        "rule_id": null,
        "rule_name": null,
        "source_alert_id": null
      },
      "blind_audit": {
        "state": "not_sampled",
        "label": null,
        "agrees": null,
        "labelled_at": null
      },
      "link": {
        "reason": {
          "code": "related_threat",
          "sentence": "A model judged a related alert a threat: same host, user or address, within 24 hours. A model's judgement is not a confirmation, so the safety net links what the AI closed to the case and leaves it closed. A person's confirmation of the threat reopens it."
        },
        "threat_alert_id": "alr-48213",
        "at": "2026-11-14T09:44:35Z"
      },
      "reopened": null,
      "flagged": null,
      "can_reopen": true
    },
    {
      "id": "alr-48213",
      "title": "Encoded PowerShell launched by Microsoft Word",
      "severity": "high",
      "status": "waiting_human",
      "state": "open",
      "role": "primary",
      "occurred_at": "2026-11-14T09:41:52Z",
      "closed_at": null,
      "disposition": null,
      "entities": [
        {
          "kind": "user",
          "value": "m.keller"
        },
        {
          "kind": "host",
          "value": "WS-FIN-0142"
        },
        {
          "kind": "ip",
          "value": "203.0.113.50"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": "needs_decision",
      "why": {
        "code": "inconclusive",
        "sentence": "No automatic rule applies to this alert, so a person decides."
      },
      "closed_by": null,
      "blind_audit": {
        "state": "not_sampled",
        "label": null,
        "agrees": null,
        "labelled_at": null
      },
      "link": null,
      "reopened": null,
      "flagged": null,
      "can_reopen": false
    },
    {
      "id": "alr-48219",
      "title": "LSASS memory read by rundll32 via comsvcs.dll MiniDump",
      "severity": "critical",
      "status": "waiting_human",
      "state": "open",
      "role": "attached",
      "occurred_at": "2026-11-14T09:43:58Z",
      "closed_at": null,
      "disposition": null,
      "entities": [
        {
          "kind": "host",
          "value": "WS-FIN-0142"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": "needs_decision",
      "why": {
        "code": "high_risk",
        "sentence": "The assessed threat is high enough for the response policy, so a response was proposed."
      },
      "closed_by": null,
      "blind_audit": {
        "state": "not_sampled",
        "label": null,
        "agrees": null,
        "labelled_at": null
      },
      "link": null,
      "reopened": null,
      "flagged": null,
      "can_reopen": false
    },
    {
      "id": "alr-48214",
      "title": "Periodic HTTPS beacon to a newly registered domain",
      "severity": "high",
      "status": "waiting_approval",
      "state": "open",
      "role": "attached",
      "occurred_at": "2026-11-14T09:44:02Z",
      "closed_at": null,
      "disposition": null,
      "entities": [
        {
          "kind": "host",
          "value": "WS-FIN-0142"
        },
        {
          "kind": "domain",
          "value": "cdn-invoice-portal.example"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": "needs_decision",
      "why": {
        "code": "awaiting_approval",
        "sentence": "A response was proposed and waits for a person to approve it."
      },
      "closed_by": null,
      "blind_audit": {
        "state": "not_sampled",
        "label": null,
        "agrees": null,
        "labelled_at": null
      },
      "link": null,
      "reopened": null,
      "flagged": null,
      "can_reopen": false
    },
    {
      "id": "alr-48226",
      "title": "Microsoft Defender signature update completed",
      "severity": "info",
      "status": "closed",
      "state": "closed",
      "role": "attached",
      "occurred_at": "2026-11-14T09:47:30Z",
      "closed_at": "2026-11-14T09:47:35Z",
      "disposition": "benign",
      "entities": [
        {
          "kind": "host",
          "value": "WS-FIN-0142"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": null,
      "why": null,
      "closed_by": {
        "kind": "suppression_rule",
        "reason": {
          "code": "suppression_rule",
          "sentence": "A suppression rule of this customer matched the alert, so no investigation ran."
        },
        "at": "2026-11-14T09:47:35Z",
        "decision": null,
        "analyst": null,
        "notes": null,
        "decided_in_case_id": null,
        "policy": null,
        "tier": null,
        "rule_id": "sup-014",
        "rule_name": "Defender definition updates",
        "source_alert_id": null
      },
      "blind_audit": {
        "state": "not_sampled",
        "label": null,
        "agrees": null,
        "labelled_at": null
      },
      "link": null,
      "reopened": null,
      "flagged": null,
      "can_reopen": false
    },
    {
      "id": "alr-48231",
      "title": "PowerShell listed every user in Active Directory (Get-ADUser)",
      "severity": "medium",
      "status": "closed",
      "state": "closed",
      "role": "attached",
      "occurred_at": "2026-11-14T09:51:16Z",
      "closed_at": "2026-11-14T09:51:21Z",
      "disposition": "benign",
      "entities": [
        {
          "kind": "host",
          "value": "WS-FIN-0142"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": null,
      "why": null,
      "closed_by": {
        "kind": "cached_verdict",
        "reason": {
          "code": "verdict_cache",
          "sentence": "An analyst had already decided that the same detection and behaviour is benign. That verdict was applied, so no new investigation ran."
        },
        "at": "2026-11-14T09:51:21Z",
        "decision": "benign_positive",
        "analyst": null,
        "notes": null,
        "decided_in_case_id": null,
        "policy": null,
        "tier": null,
        "rule_id": null,
        "rule_name": null,
        "source_alert_id": "alr-46011"
      },
      "blind_audit": {
        "state": "not_sampled",
        "label": null,
        "agrees": null,
        "labelled_at": null
      },
      "link": null,
      "reopened": null,
      "flagged": null,
      "can_reopen": false
    },
    {
      "id": "alr-48247",
      "title": "Scheduled task \"OneDriveSync\" created by powershell.exe",
      "severity": "medium",
      "status": "processing",
      "state": "processing",
      "role": "attached",
      "occurred_at": "2026-11-14T10:01:44Z",
      "closed_at": null,
      "disposition": null,
      "entities": [
        {
          "kind": "host",
          "value": "WS-FIN-0142"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": null,
      "why": null,
      "closed_by": null,
      "blind_audit": {
        "state": "not_sampled",
        "label": null,
        "agrees": null,
        "labelled_at": null
      },
      "link": null,
      "reopened": null,
      "flagged": null,
      "can_reopen": false
    }
  ],
  "alerts_truncated": false,
  "entities": [
    {
      "kind": "host",
      "value": "WS-FIN-0142",
      "alerts": 8
    },
    {
      "kind": "user",
      "value": "m.keller",
      "alerts": 3
    },
    {
      "kind": "domain",
      "value": "cdn-invoice-portal.example",
      "alerts": 2
    },
    {
      "kind": "ip",
      "value": "203.0.113.50",
      "alerts": 1
    },
    {
      "kind": "url",
      "value": "https://cdn-invoice-portal.example/a.ps1",
      "alerts": 1
    },
    {
      "kind": "process",
      "value": "powershell.exe",
      "alerts": 1
    },
    {
      "kind": "hash",
      "value": "5d1e0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0ab07c",
      "alerts": 1
    }
  ],
  "actions": [
    {
      "action_id": "00000000-0000-0000-0000-000048213001",
      "action_type": "isolate_host",
      "target": "WS-FIN-0142",
      "description": null,
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
      "approval_entry": null,
      "alert_id": "alr-48213",
      "created_at": "2026-11-14T09:44:36Z"
    },
    {
      "action_id": "00000000-0000-0000-0000-000048213002",
      "action_type": "block_domain",
      "target": "cdn-invoice-portal.example",
      "description": null,
      "risk": "medium",
      "reversible": true,
      "inverse_action": "unblock_domain",
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
      "approval_entry": null,
      "alert_id": "alr-48213",
      "created_at": "2026-11-14T09:44:37Z"
    },
    {
      "action_id": "00000000-0000-0000-0000-000048213003",
      "action_type": "block_ip",
      "target": "203.0.113.50",
      "description": null,
      "risk": "low",
      "reversible": true,
      "inverse_action": "unblock_ip",
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
      "approval_entry": null,
      "alert_id": "alr-48213",
      "created_at": "2026-11-14T09:44:38Z"
    },
    {
      "action_id": "00000000-0000-0000-0000-000048213004",
      "action_type": "reset_password",
      "target": "m.keller@northwind.example",
      "description": null,
      "risk": "critical",
      "reversible": false,
      "inverse_action": null,
      "irreversible_note": "A reset password cannot be restored.",
      "status": "blocked",
      "guardrail": {
        "verdict": "blocked",
        "code": "autonomy_disabled",
        "reason": "The tenant's autonomy policy disables actions of this risk."
      },
      "without_preapproval": null,
      "can_preapprove": null,
      "role_lock": null,
      "approval_entry": null,
      "alert_id": "alr-48213",
      "created_at": "2026-11-14T09:44:39Z"
    },
    {
      "action_id": "00000000-0000-0000-0000-000048213005",
      "action_type": "quarantine_file",
      "target": "Invoice_INV-20931.docm",
      "description": null,
      "risk": "medium",
      "reversible": true,
      "inverse_action": "release_file",
      "irreversible_note": null,
      "status": "dry_run",
      "guardrail": {
        "verdict": "passed",
        "code": null,
        "reason": null
      },
      "without_preapproval": null,
      "can_preapprove": null,
      "role_lock": null,
      "approval_entry": null,
      "alert_id": "alr-48213",
      "created_at": "2026-11-14T09:44:40Z"
    },
    {
      "action_id": "00000000-0000-0000-0000-000048213006",
      "action_type": "block_url",
      "target": "https://cdn-invoice-portal.example/a.ps1",
      "description": null,
      "risk": "medium",
      "reversible": true,
      "inverse_action": "unblock_url",
      "irreversible_note": null,
      "status": "succeeded",
      "guardrail": null,
      "without_preapproval": null,
      "can_preapprove": null,
      "role_lock": null,
      "approval_entry": null,
      "alert_id": "alr-48214",
      "created_at": "2026-11-14T09:44:41Z"
    },
    {
      "action_id": "00000000-0000-0000-0000-000048213007",
      "action_type": "revoke_sessions",
      "target": "m.keller@northwind.example",
      "description": null,
      "risk": "medium",
      "reversible": false,
      "inverse_action": null,
      "irreversible_note": "Revoked sessions cannot be restored.",
      "status": "failed",
      "guardrail": null,
      "without_preapproval": null,
      "can_preapprove": null,
      "role_lock": null,
      "approval_entry": null,
      "alert_id": "alr-48214",
      "created_at": "2026-11-14T09:44:42Z"
    }
  ],
  "timeline": [
    {
      "ts": "2026-11-13T16:20:04Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-47702",
      "by": null
    },
    {
      "ts": "2026-11-13T16:20:40Z",
      "kind": "step.escalate",
      "actor": "policy",
      "text": "Sent to an analyst.",
      "produced": "level L1 · priority 3",
      "alert_id": "alr-47702",
      "by": null
    },
    {
      "ts": "2026-11-13T16:41:00Z",
      "kind": "analyst.decision",
      "actor": "person",
      "text": "An analyst recorded a decision.",
      "produced": "benign positive",
      "alert_id": "alr-47702",
      "by": {
        "user_id": "5b0c7a52-6f0e-4c58-9d0e-1f2a3b4c5d6e",
        "email": "ines.moreau@brightwater.example"
      }
    },
    {
      "ts": "2026-11-14T09:14:11Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-48190",
      "by": null
    },
    {
      "ts": "2026-11-14T09:14:13Z",
      "kind": "step.close",
      "actor": "policy",
      "text": "The AI closed it on the model's word. No independent evidence backs the close, so it is sampled for audit.",
      "produced": "benign",
      "alert_id": "alr-48190",
      "by": null
    },
    {
      "ts": "2026-11-14T09:41:53Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-48212",
      "by": null
    },
    {
      "ts": "2026-11-14T09:41:55Z",
      "kind": "step.close",
      "actor": "policy",
      "text": "The AI closed it on the model's word. No independent evidence backs the close, so it is sampled for audit.",
      "produced": "benign",
      "alert_id": "alr-48212",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:02Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-48219",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:06Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-48214",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:26Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-48213",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:35Z",
      "kind": "case.opened",
      "actor": "policy",
      "text": "The case was opened for a person's decision.",
      "produced": null,
      "alert_id": null,
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:35Z",
      "kind": "step.escalate",
      "actor": "policy",
      "text": "Sent to an analyst.",
      "produced": "level L2 · priority 8",
      "alert_id": "alr-48213",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:35Z",
      "kind": "step.plan_response",
      "actor": "policy",
      "text": "Proposed response actions. None runs without the customer's policy or an approval.",
      "produced": "4 awaiting approval · 1 blocked",
      "alert_id": "alr-48213",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:35Z",
      "kind": "alert.linked",
      "actor": "policy",
      "text": "The safety net linked this alert to the case. It stays closed.",
      "produced": null,
      "alert_id": "alr-48190",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:35Z",
      "kind": "alert.linked",
      "actor": "policy",
      "text": "The safety net linked this alert to the case. It stays closed.",
      "produced": null,
      "alert_id": "alr-48212",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:36Z",
      "kind": "step.escalate",
      "actor": "policy",
      "text": "Sent to an analyst.",
      "produced": "level L2 · priority 9",
      "alert_id": "alr-48219",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:40Z",
      "kind": "step.plan_response",
      "actor": "policy",
      "text": "Proposed response actions. None runs without the customer's policy or an approval.",
      "produced": "2 awaiting approval",
      "alert_id": "alr-48214",
      "by": null
    },
    {
      "ts": "2026-11-14T09:47:34Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-48226",
      "by": null
    },
    {
      "ts": "2026-11-14T09:47:35Z",
      "kind": "step.gate",
      "actor": "policy",
      "text": "A suppression rule matched the alert. No investigation ran.",
      "produced": null,
      "alert_id": "alr-48226",
      "by": null
    },
    {
      "ts": "2026-11-14T09:51:20Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-48231",
      "by": null
    },
    {
      "ts": "2026-11-14T09:51:21Z",
      "kind": "step.gate",
      "actor": "policy",
      "text": "An earlier analyst verdict for the same detection applied. No investigation ran.",
      "produced": null,
      "alert_id": "alr-48231",
      "by": null
    },
    {
      "ts": "2026-11-14T09:52:10Z",
      "kind": "case.claimed",
      "actor": "person",
      "text": "An analyst claimed the case.",
      "produced": null,
      "alert_id": null,
      "by": {
        "user_id": "5b0c7a52-6f0e-4c58-9d0e-1f2a3b4c5d6e",
        "email": "ines.moreau@brightwater.example"
      }
    },
    {
      "ts": "2026-11-14T10:01:48Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-48247",
      "by": null
    }
  ],
  "timeline_truncated": false,
  "not_available": [
    {
      "field": "key",
      "reason": "A case has no readable reference yet. The case is the escalation, and its id is the key.",
      "issue": null
    },
    {
      "field": "summary",
      "reason": "Nobody writes a summary of a case yet. The counts of its alerts are given instead.",
      "issue": null
    },
    {
      "field": "alerts[].link.shared_entity",
      "reason": "The safety net records that an alert shares a host, user or address with the threat, not which one.",
      "issue": null
    },
    {
      "field": "alerts[].reopened.confirmation",
      "reason": "A reopening records who or what acted, not which confirmation caused it.",
      "issue": null
    },
    {
      "field": "alerts[].closed_by.rule_reviewed_at",
      "reason": "A suppression rule records when it was created and when it expires, not when it was last reviewed.",
      "issue": null
    },
    {
      "field": "actions[].decision_reason",
      "reason": "An approval or a rejection of a response action records who decided and when, not a reason.",
      "issue": null
    },
    {
      "field": "entities[].context",
      "reason": "No asset or identity context is stored for a host or a user.",
      "issue": null
    }
  ]
};

export const DECIDED_CASE: CaseOut = {
  "schema_version": 1,
  "id": "esc-2291",
  "tenant_id": "northwind",
  "generated_at": "2026-11-14T10:12:00Z",
  "alert_id": "alr-48213",
  "title": "Encoded PowerShell launched by Microsoft Word",
  "status": "decided",
  "active": false,
  "severity": "critical",
  "category": "needs_decision",
  "reason": {
    "code": "inconclusive",
    "sentence": "No automatic rule applies to this alert, so a person decides."
  },
  "opened_at": "2026-11-14T09:44:35Z",
  "sla_deadline": "2026-11-14T10:08:12Z",
  "owner": {
    "user_id": "5b0c7a52-6f0e-4c58-9d0e-1f2a3b4c5d6e",
    "email": "ines.moreau@brightwater.example",
    "since": "2026-11-14T09:52:10Z"
  },
  "version": 4,
  "decision": {
    "decision": "true_positive",
    "notes": "The dump is visible in the process tree. Isolating the host.",
    "decided_by": {
      "user_id": "5b0c7a52-6f0e-4c58-9d0e-1f2a3b4c5d6e",
      "email": "ines.moreau@brightwater.example"
    },
    "decided_at": "2026-11-14T10:09:30Z"
  },
  "counts": {
    "alerts": 9,
    "open": 2,
    "processing": 3,
    "closed": 4,
    "linked": 0,
    "reopened": 2,
    "flagged": 0,
    "withheld": 0,
    "closed_by": {
      "ai_evidence": 0,
      "ai_audit": 0,
      "suppression_rule": 1,
      "cached_verdict": 1,
      "analyst": 2
    },
    "actions_awaiting_approval": 3
  },
  "alerts": [
    {
      "id": "alr-47702",
      "title": "Failed logon burst: 6 failures in 2 minutes",
      "severity": "low",
      "status": "closed",
      "state": "closed",
      "role": "attached",
      "occurred_at": "2026-11-13T16:20:00Z",
      "closed_at": "2026-11-13T16:41:00Z",
      "disposition": "benign",
      "entities": [
        {
          "kind": "user",
          "value": "m.keller"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": "needs_review",
      "why": null,
      "closed_by": {
        "kind": "analyst",
        "reason": {
          "code": "analyst:benign_positive",
          "sentence": "An analyst decided it is real activity that is expected here."
        },
        "at": "2026-11-13T16:41:00Z",
        "decision": "benign_positive",
        "analyst": {
          "user_id": "5b0c7a52-6f0e-4c58-9d0e-1f2a3b4c5d6e",
          "email": "ines.moreau@brightwater.example"
        },
        "notes": null,
        "decided_in_case_id": "esc-2207",
        "policy": null,
        "tier": null,
        "rule_id": null,
        "rule_name": null,
        "source_alert_id": null
      },
      "blind_audit": {
        "state": "not_sampled",
        "label": null,
        "agrees": null,
        "labelled_at": null
      },
      "link": null,
      "reopened": null,
      "flagged": null,
      "can_reopen": false
    },
    {
      "id": "alr-48190",
      "title": "Package installed: Adobe Acrobat Reader update 24.004",
      "severity": "info",
      "status": "queued",
      "state": "processing",
      "role": "reopened",
      "occurred_at": "2026-11-14T09:14:07Z",
      "closed_at": null,
      "disposition": null,
      "entities": [
        {
          "kind": "host",
          "value": "WS-FIN-0142"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": null,
      "why": null,
      "closed_by": null,
      "blind_audit": {
        "state": "labelled",
        "label": "benign",
        "agrees": true,
        "labelled_at": "2026-11-14T09:58:40Z"
      },
      "link": null,
      "reopened": {
        "reason": {
          "code": "related_threat",
          "sentence": "A person confirmed a related threat (a true positive, an approved response action or a blind-audit label), so the safety net reopened this alert, which the AI had closed on the model's word."
        },
        "note": null,
        "threat_alert_id": "alr-48213",
        "mode": "requeued",
        "confirmed_by": "person",
        "by": {
          "user_id": "5b0c7a52-6f0e-4c58-9d0e-1f2a3b4c5d6e",
          "email": "ines.moreau@brightwater.example"
        },
        "at": "2026-11-14T10:09:31Z"
      },
      "flagged": null,
      "can_reopen": false
    },
    {
      "id": "alr-48212",
      "title": "Outlook opened a Word attachment from the internet zone",
      "severity": "low",
      "status": "queued",
      "state": "processing",
      "role": "reopened",
      "occurred_at": "2026-11-14T09:41:49Z",
      "closed_at": null,
      "disposition": null,
      "entities": [
        {
          "kind": "user",
          "value": "m.keller"
        },
        {
          "kind": "host",
          "value": "WS-FIN-0142"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": null,
      "why": null,
      "closed_by": null,
      "blind_audit": {
        "state": "not_sampled",
        "label": null,
        "agrees": null,
        "labelled_at": null
      },
      "link": null,
      "reopened": {
        "reason": {
          "code": "related_threat",
          "sentence": "A person confirmed a related threat (a true positive, an approved response action or a blind-audit label), so the safety net reopened this alert, which the AI had closed on the model's word."
        },
        "note": null,
        "threat_alert_id": "alr-48213",
        "mode": "requeued",
        "confirmed_by": "person",
        "by": {
          "user_id": "5b0c7a52-6f0e-4c58-9d0e-1f2a3b4c5d6e",
          "email": "ines.moreau@brightwater.example"
        },
        "at": "2026-11-14T10:09:31Z"
      },
      "flagged": null,
      "can_reopen": false
    },
    {
      "id": "alr-48213",
      "title": "Encoded PowerShell launched by Microsoft Word",
      "severity": "high",
      "status": "closed",
      "state": "closed",
      "role": "primary",
      "occurred_at": "2026-11-14T09:41:52Z",
      "closed_at": "2026-11-14T10:09:50Z",
      "disposition": "malicious",
      "entities": [
        {
          "kind": "user",
          "value": "m.keller"
        },
        {
          "kind": "host",
          "value": "WS-FIN-0142"
        },
        {
          "kind": "ip",
          "value": "203.0.113.50"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": "needs_decision",
      "why": null,
      "closed_by": {
        "kind": "analyst",
        "reason": {
          "code": "analyst:true_positive",
          "sentence": "An analyst confirmed a real threat."
        },
        "at": "2026-11-14T10:09:50Z",
        "decision": "true_positive",
        "analyst": {
          "user_id": "5b0c7a52-6f0e-4c58-9d0e-1f2a3b4c5d6e",
          "email": "ines.moreau@brightwater.example"
        },
        "notes": "The dump is visible in the process tree. Isolating the host.",
        "decided_in_case_id": "esc-2291",
        "policy": null,
        "tier": null,
        "rule_id": null,
        "rule_name": null,
        "source_alert_id": null
      },
      "blind_audit": {
        "state": "not_sampled",
        "label": null,
        "agrees": null,
        "labelled_at": null
      },
      "link": null,
      "reopened": null,
      "flagged": null,
      "can_reopen": false
    },
    {
      "id": "alr-48219",
      "title": "LSASS memory read by rundll32 via comsvcs.dll MiniDump",
      "severity": "critical",
      "status": "waiting_human",
      "state": "open",
      "role": "attached",
      "occurred_at": "2026-11-14T09:43:58Z",
      "closed_at": null,
      "disposition": null,
      "entities": [
        {
          "kind": "host",
          "value": "WS-FIN-0142"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": "needs_decision",
      "why": {
        "code": "high_risk",
        "sentence": "The assessed threat is high enough for the response policy, so a response was proposed."
      },
      "closed_by": null,
      "blind_audit": {
        "state": "not_sampled",
        "label": null,
        "agrees": null,
        "labelled_at": null
      },
      "link": null,
      "reopened": null,
      "flagged": null,
      "can_reopen": false
    },
    {
      "id": "alr-48214",
      "title": "Periodic HTTPS beacon to a newly registered domain",
      "severity": "high",
      "status": "waiting_approval",
      "state": "open",
      "role": "attached",
      "occurred_at": "2026-11-14T09:44:02Z",
      "closed_at": null,
      "disposition": null,
      "entities": [
        {
          "kind": "host",
          "value": "WS-FIN-0142"
        },
        {
          "kind": "domain",
          "value": "cdn-invoice-portal.example"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": "needs_decision",
      "why": {
        "code": "awaiting_approval",
        "sentence": "A response was proposed and waits for a person to approve it."
      },
      "closed_by": null,
      "blind_audit": {
        "state": "not_sampled",
        "label": null,
        "agrees": null,
        "labelled_at": null
      },
      "link": null,
      "reopened": null,
      "flagged": null,
      "can_reopen": false
    },
    {
      "id": "alr-48226",
      "title": "Microsoft Defender signature update completed",
      "severity": "info",
      "status": "closed",
      "state": "closed",
      "role": "attached",
      "occurred_at": "2026-11-14T09:47:30Z",
      "closed_at": "2026-11-14T09:47:35Z",
      "disposition": "benign",
      "entities": [
        {
          "kind": "host",
          "value": "WS-FIN-0142"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": null,
      "why": null,
      "closed_by": {
        "kind": "suppression_rule",
        "reason": {
          "code": "suppression_rule",
          "sentence": "A suppression rule of this customer matched the alert, so no investigation ran."
        },
        "at": "2026-11-14T09:47:35Z",
        "decision": null,
        "analyst": null,
        "notes": null,
        "decided_in_case_id": null,
        "policy": null,
        "tier": null,
        "rule_id": "sup-014",
        "rule_name": "Defender definition updates",
        "source_alert_id": null
      },
      "blind_audit": {
        "state": "not_sampled",
        "label": null,
        "agrees": null,
        "labelled_at": null
      },
      "link": null,
      "reopened": null,
      "flagged": null,
      "can_reopen": false
    },
    {
      "id": "alr-48231",
      "title": "PowerShell listed every user in Active Directory (Get-ADUser)",
      "severity": "medium",
      "status": "closed",
      "state": "closed",
      "role": "attached",
      "occurred_at": "2026-11-14T09:51:16Z",
      "closed_at": "2026-11-14T09:51:21Z",
      "disposition": "benign",
      "entities": [
        {
          "kind": "host",
          "value": "WS-FIN-0142"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": null,
      "why": null,
      "closed_by": {
        "kind": "cached_verdict",
        "reason": {
          "code": "verdict_cache",
          "sentence": "An analyst had already decided that the same detection and behaviour is benign. That verdict was applied, so no new investigation ran."
        },
        "at": "2026-11-14T09:51:21Z",
        "decision": "benign_positive",
        "analyst": null,
        "notes": null,
        "decided_in_case_id": null,
        "policy": null,
        "tier": null,
        "rule_id": null,
        "rule_name": null,
        "source_alert_id": "alr-46011"
      },
      "blind_audit": {
        "state": "not_sampled",
        "label": null,
        "agrees": null,
        "labelled_at": null
      },
      "link": null,
      "reopened": null,
      "flagged": null,
      "can_reopen": false
    },
    {
      "id": "alr-48247",
      "title": "Scheduled task \"OneDriveSync\" created by powershell.exe",
      "severity": "medium",
      "status": "processing",
      "state": "processing",
      "role": "attached",
      "occurred_at": "2026-11-14T10:01:44Z",
      "closed_at": null,
      "disposition": null,
      "entities": [
        {
          "kind": "host",
          "value": "WS-FIN-0142"
        }
      ],
      "hidden_for_blind_audit": false,
      "category": null,
      "why": null,
      "closed_by": null,
      "blind_audit": {
        "state": "not_sampled",
        "label": null,
        "agrees": null,
        "labelled_at": null
      },
      "link": null,
      "reopened": null,
      "flagged": null,
      "can_reopen": false
    }
  ],
  "alerts_truncated": false,
  "entities": [
    {
      "kind": "host",
      "value": "WS-FIN-0142",
      "alerts": 8
    },
    {
      "kind": "user",
      "value": "m.keller",
      "alerts": 3
    },
    {
      "kind": "domain",
      "value": "cdn-invoice-portal.example",
      "alerts": 2
    },
    {
      "kind": "ip",
      "value": "203.0.113.50",
      "alerts": 1
    },
    {
      "kind": "url",
      "value": "https://cdn-invoice-portal.example/a.ps1",
      "alerts": 1
    },
    {
      "kind": "process",
      "value": "powershell.exe",
      "alerts": 1
    },
    {
      "kind": "hash",
      "value": "5d1e0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0ab07c",
      "alerts": 1
    }
  ],
  "actions": [
    {
      "action_id": "00000000-0000-0000-0000-000048213001",
      "action_type": "isolate_host",
      "target": "WS-FIN-0142",
      "description": null,
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
      "approval_entry": null,
      "alert_id": "alr-48213",
      "created_at": "2026-11-14T09:44:36Z"
    },
    {
      "action_id": "00000000-0000-0000-0000-000048213002",
      "action_type": "block_domain",
      "target": "cdn-invoice-portal.example",
      "description": null,
      "risk": "medium",
      "reversible": true,
      "inverse_action": "unblock_domain",
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
      "approval_entry": null,
      "alert_id": "alr-48213",
      "created_at": "2026-11-14T09:44:37Z"
    },
    {
      "action_id": "00000000-0000-0000-0000-000048213003",
      "action_type": "block_ip",
      "target": "203.0.113.50",
      "description": null,
      "risk": "low",
      "reversible": true,
      "inverse_action": "unblock_ip",
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
      "approval_entry": null,
      "alert_id": "alr-48213",
      "created_at": "2026-11-14T09:44:38Z"
    },
    {
      "action_id": "00000000-0000-0000-0000-000048213004",
      "action_type": "reset_password",
      "target": "m.keller@northwind.example",
      "description": null,
      "risk": "critical",
      "reversible": false,
      "inverse_action": null,
      "irreversible_note": "A reset password cannot be restored.",
      "status": "blocked",
      "guardrail": {
        "verdict": "blocked",
        "code": "autonomy_disabled",
        "reason": "The tenant's autonomy policy disables actions of this risk."
      },
      "without_preapproval": null,
      "can_preapprove": null,
      "role_lock": null,
      "approval_entry": null,
      "alert_id": "alr-48213",
      "created_at": "2026-11-14T09:44:39Z"
    },
    {
      "action_id": "00000000-0000-0000-0000-000048213005",
      "action_type": "quarantine_file",
      "target": "Invoice_INV-20931.docm",
      "description": null,
      "risk": "medium",
      "reversible": true,
      "inverse_action": "release_file",
      "irreversible_note": null,
      "status": "dry_run",
      "guardrail": {
        "verdict": "passed",
        "code": null,
        "reason": null
      },
      "without_preapproval": null,
      "can_preapprove": null,
      "role_lock": null,
      "approval_entry": null,
      "alert_id": "alr-48213",
      "created_at": "2026-11-14T09:44:40Z"
    },
    {
      "action_id": "00000000-0000-0000-0000-000048213006",
      "action_type": "block_url",
      "target": "https://cdn-invoice-portal.example/a.ps1",
      "description": null,
      "risk": "medium",
      "reversible": true,
      "inverse_action": "unblock_url",
      "irreversible_note": null,
      "status": "succeeded",
      "guardrail": null,
      "without_preapproval": null,
      "can_preapprove": null,
      "role_lock": null,
      "approval_entry": null,
      "alert_id": "alr-48214",
      "created_at": "2026-11-14T09:44:41Z"
    },
    {
      "action_id": "00000000-0000-0000-0000-000048213007",
      "action_type": "revoke_sessions",
      "target": "m.keller@northwind.example",
      "description": null,
      "risk": "medium",
      "reversible": false,
      "inverse_action": null,
      "irreversible_note": "Revoked sessions cannot be restored.",
      "status": "failed",
      "guardrail": null,
      "without_preapproval": null,
      "can_preapprove": null,
      "role_lock": null,
      "approval_entry": null,
      "alert_id": "alr-48214",
      "created_at": "2026-11-14T09:44:42Z"
    }
  ],
  "timeline": [
    {
      "ts": "2026-11-13T16:20:04Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-47702",
      "by": null
    },
    {
      "ts": "2026-11-13T16:20:40Z",
      "kind": "step.escalate",
      "actor": "policy",
      "text": "Sent to an analyst.",
      "produced": "level L1 · priority 3",
      "alert_id": "alr-47702",
      "by": null
    },
    {
      "ts": "2026-11-13T16:41:00Z",
      "kind": "analyst.decision",
      "actor": "person",
      "text": "An analyst recorded a decision.",
      "produced": "benign positive",
      "alert_id": "alr-47702",
      "by": {
        "user_id": "5b0c7a52-6f0e-4c58-9d0e-1f2a3b4c5d6e",
        "email": "ines.moreau@brightwater.example"
      }
    },
    {
      "ts": "2026-11-14T09:14:11Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-48190",
      "by": null
    },
    {
      "ts": "2026-11-14T09:14:13Z",
      "kind": "step.close",
      "actor": "policy",
      "text": "The AI closed it on the model's word. No independent evidence backs the close, so it is sampled for audit.",
      "produced": "benign",
      "alert_id": "alr-48190",
      "by": null
    },
    {
      "ts": "2026-11-14T09:41:53Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-48212",
      "by": null
    },
    {
      "ts": "2026-11-14T09:41:55Z",
      "kind": "step.close",
      "actor": "policy",
      "text": "The AI closed it on the model's word. No independent evidence backs the close, so it is sampled for audit.",
      "produced": "benign",
      "alert_id": "alr-48212",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:02Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-48219",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:06Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-48214",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:26Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-48213",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:35Z",
      "kind": "case.opened",
      "actor": "policy",
      "text": "The case was opened for a person's decision.",
      "produced": null,
      "alert_id": null,
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:35Z",
      "kind": "step.escalate",
      "actor": "policy",
      "text": "Sent to an analyst.",
      "produced": "level L2 · priority 8",
      "alert_id": "alr-48213",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:35Z",
      "kind": "step.plan_response",
      "actor": "policy",
      "text": "Proposed response actions. None runs without the customer's policy or an approval.",
      "produced": "4 awaiting approval · 1 blocked",
      "alert_id": "alr-48213",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:35Z",
      "kind": "alert.linked",
      "actor": "policy",
      "text": "The safety net linked this alert to the case. It stays closed.",
      "produced": null,
      "alert_id": "alr-48190",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:35Z",
      "kind": "alert.linked",
      "actor": "policy",
      "text": "The safety net linked this alert to the case. It stays closed.",
      "produced": null,
      "alert_id": "alr-48212",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:36Z",
      "kind": "step.escalate",
      "actor": "policy",
      "text": "Sent to an analyst.",
      "produced": "level L2 · priority 9",
      "alert_id": "alr-48219",
      "by": null
    },
    {
      "ts": "2026-11-14T09:44:40Z",
      "kind": "step.plan_response",
      "actor": "policy",
      "text": "Proposed response actions. None runs without the customer's policy or an approval.",
      "produced": "2 awaiting approval",
      "alert_id": "alr-48214",
      "by": null
    },
    {
      "ts": "2026-11-14T09:47:34Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-48226",
      "by": null
    },
    {
      "ts": "2026-11-14T09:47:35Z",
      "kind": "step.gate",
      "actor": "policy",
      "text": "A suppression rule matched the alert. No investigation ran.",
      "produced": null,
      "alert_id": "alr-48226",
      "by": null
    },
    {
      "ts": "2026-11-14T09:51:20Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-48231",
      "by": null
    },
    {
      "ts": "2026-11-14T09:51:21Z",
      "kind": "step.gate",
      "actor": "policy",
      "text": "An earlier analyst verdict for the same detection applied. No investigation ran.",
      "produced": null,
      "alert_id": "alr-48231",
      "by": null
    },
    {
      "ts": "2026-11-14T09:52:10Z",
      "kind": "case.claimed",
      "actor": "person",
      "text": "An analyst claimed the case.",
      "produced": null,
      "alert_id": null,
      "by": {
        "user_id": "5b0c7a52-6f0e-4c58-9d0e-1f2a3b4c5d6e",
        "email": "ines.moreau@brightwater.example"
      }
    },
    {
      "ts": "2026-11-14T10:01:48Z",
      "kind": "alert.received",
      "actor": "code",
      "text": "Alert received.",
      "produced": null,
      "alert_id": "alr-48247",
      "by": null
    },
    {
      "ts": "2026-11-14T10:09:30Z",
      "kind": "case.decided",
      "actor": "person",
      "text": "An analyst recorded the decision on the case.",
      "produced": "true positive",
      "alert_id": null,
      "by": {
        "user_id": "5b0c7a52-6f0e-4c58-9d0e-1f2a3b4c5d6e",
        "email": "ines.moreau@brightwater.example"
      }
    },
    {
      "ts": "2026-11-14T10:09:31Z",
      "kind": "alert.reopened",
      "actor": "policy",
      "text": "The safety net reopened this alert after a related threat was confirmed.",
      "produced": null,
      "alert_id": "alr-48190",
      "by": {
        "user_id": "5b0c7a52-6f0e-4c58-9d0e-1f2a3b4c5d6e",
        "email": "ines.moreau@brightwater.example"
      }
    },
    {
      "ts": "2026-11-14T10:09:31Z",
      "kind": "alert.reopened",
      "actor": "policy",
      "text": "The safety net reopened this alert after a related threat was confirmed.",
      "produced": null,
      "alert_id": "alr-48212",
      "by": {
        "user_id": "5b0c7a52-6f0e-4c58-9d0e-1f2a3b4c5d6e",
        "email": "ines.moreau@brightwater.example"
      }
    },
    {
      "ts": "2026-11-14T10:09:50Z",
      "kind": "step.close",
      "actor": "person",
      "text": "An analyst confirmed a real threat.",
      "produced": "malicious",
      "alert_id": "alr-48213",
      "by": null
    }
  ],
  "timeline_truncated": false,
  "not_available": [
    {
      "field": "key",
      "reason": "A case has no readable reference yet. The case is the escalation, and its id is the key.",
      "issue": null
    },
    {
      "field": "summary",
      "reason": "Nobody writes a summary of a case yet. The counts of its alerts are given instead.",
      "issue": null
    },
    {
      "field": "alerts[].link.shared_entity",
      "reason": "The safety net records that an alert shares a host, user or address with the threat, not which one.",
      "issue": null
    },
    {
      "field": "alerts[].reopened.confirmation",
      "reason": "A reopening records who or what acted, not which confirmation caused it.",
      "issue": null
    },
    {
      "field": "alerts[].closed_by.rule_reviewed_at",
      "reason": "A suppression rule records when it was created and when it expires, not when it was last reviewed.",
      "issue": null
    },
    {
      "field": "actions[].decision_reason",
      "reason": "An approval or a rejection of a response action records who decided and when, not a reason.",
      "issue": null
    },
    {
      "field": "entities[].context",
      "reason": "No asset or identity context is stored for a host or a user.",
      "issue": null
    }
  ]
};
