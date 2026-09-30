"""Notification channels: formatters (pure functions of the event payload) and senders.

* **Slack**: incoming webhook, Block Kit. Untrusted text (alert titles,
  entities, targets) goes in ``plain_text`` objects or is escaped for
  ``mrkdwn`` (``&``, ``<``, ``>``), so an alert cannot mention ``@channel``
  or inject links.
* **Microsoft Teams**: a Workflows (Power Automate) "When a Teams webhook
  request is received" flow, which accepts an Adaptive Card message.
  Office 365 connectors (``outlook.office.com/webhook``) are retired.
* **Email**: SMTP with STARTTLS or implicit TLS (install settings),
  recipients per integration, plain text plus a simple HTML part.
* **Webhook**: the event payload as canonical JSON, HMAC-SHA256 signed with
  the scheme of the response webhook connector
  (:func:`lg_sotf.services.connectors.webhook.sign`): ``X-LGSOTF-Signature:
  v1=<hex>`` over ``"<timestamp>.<body>"``, ``X-LGSOTF-Timestamp``,
  ``X-LGSOTF-Event`` (the event type), ``Idempotency-Key`` (the event id,
  identical on every retry) and ``X-LGSOTF-Delivery`` (the outbox row).
  Receivers verify with :func:`~lg_sotf.services.connectors.webhook.verify_signature`
  and deduplicate on the signed body's ``id``.

Every formatter renders from the summary payload of
:mod:`lg_sotf.integrations.events` (never the raw alert).
"""

from __future__ import annotations

import asyncio
import html
import smtplib
import ssl
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from lg_sotf.integrations.events import EVENT_LABELS, with_links
from lg_sotf.integrations.http import DeliveryError, HttpResult, IntegrationHttp, tls_verify
from lg_sotf.services.connectors.webhook import (
    DELIVERY_HEADER,
    EVENT_HEADER,
    IDEMPOTENCY_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    encode_body,
    sign,
)
from lg_sotf.settings import Settings

PRODUCT = "LG-SOTF"
SLACK_HEADER_CHARS = 150
MAX_ENTITY_LINE_CHARS = 1_500

SEVERITY_MARKS: Dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}
TEAMS_COLORS: Dict[str, str] = {"critical": "attention", "high": "attention", "medium": "warning", "low": "accent", "info": "default"}


# ---------------------------------------------------------------- summaries


def _alert(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    alert = payload.get("alert")
    return alert if isinstance(alert, Mapping) else {}


def _section(payload: Mapping[str, Any], name: str) -> Optional[Mapping[str, Any]]:
    value = payload.get(name)
    return value if isinstance(value, Mapping) else None


def label(payload: Mapping[str, Any]) -> str:
    return EVENT_LABELS.get(str(payload.get("event")), str(payload.get("event") or "Event"))


def headline(payload: Mapping[str, Any]) -> str:
    """``"<event label>: <alert title>"`` (plain text)."""
    return f"{label(payload)}: {_alert(payload).get('title') or '(untitled alert)'}"


def _pct(value: Any) -> Optional[str]:
    return f"{float(value):.0f}%" if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def facts(payload: Mapping[str, Any]) -> List[Tuple[str, str]]:
    """(name, value) pairs shown by every channel, most important first; values are plain text."""
    alert = _alert(payload)
    out: List[Tuple[str, str]] = [("Severity", str(alert.get("severity") or "unknown").upper())]
    if alert.get("verdict"):
        out.append(("Verdict", str(alert["verdict"])))
    confidence = _pct(alert.get("confidence"))
    if confidence:
        out.append(("Confidence", confidence))
    if isinstance(alert.get("threat_score"), (int, float)):
        out.append(("Threat score", f"{float(alert['threat_score']):.0f}/100"))
    esc = _section(payload, "escalation")
    if esc is not None:
        level = str(esc.get("level") or "")
        if esc.get("from_level") and esc.get("from_level") != level:
            level = f"{esc['from_level']} -> {level}"
        out.append(("Escalation", f"{level} priority {esc.get('priority')}".strip()))
        if esc.get("decision"):
            out.append(("Decision", str(esc["decision"]).replace("_", " ")))
        elif esc.get("sla_deadline"):
            out.append(("SLA deadline", str(esc["sla_deadline"])[:19].replace("T", " ") + " UTC"))
        if esc.get("sla_expired"):
            out.append(("SLA", "expired at the highest level"))
    action = _section(payload, "action")
    if action is not None:
        out.append(("Action", f"{action.get('type')} on {action.get('target')}"))
        out.append(("Risk", str(action.get("risk_level"))))
        status = str(action.get("status"))
        if action.get("dry_run"):
            status += " (no external system was called)"
        out.append(("Status", status))
        if action.get("approval_reason"):
            out.append(("Why approval", str(action["approval_reason"]).replace("_", " ")))
        if action.get("error"):
            out.append(("Error", str(action["error"])))
    return out


def entity_line(payload: Mapping[str, Any]) -> Optional[str]:
    entities = _alert(payload).get("entities")
    if not isinstance(entities, Mapping) or not entities:
        return None
    parts = [f"{kind}: {', '.join(str(v) for v in values)}" for kind, values in entities.items() if values]
    text = " | ".join(parts)
    return text[:MAX_ENTITY_LINE_CHARS] if text else None


def link(payload: Mapping[str, Any], base_url: str) -> Optional[str]:
    return with_links(payload, base_url)["links"].get("alert")


# -------------------------------------------------------------------- Slack


def slack_escape(text: str) -> str:
    """Escape for Slack ``mrkdwn`` (control characters ``&``, ``<``, ``>``)."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_message(
    payload: Mapping[str, Any], base_url: str, *, interactive: bool = False
) -> Dict[str, Any]:
    """Block Kit message for an incoming webhook.

    With ``interactive`` (a Slack app with interactivity and a signing
    secret), ``action.awaiting_approval`` gets Approve/Reject buttons whose
    clicks come back to ``POST /api/v1/integrations/slack/interactions``.
    """
    title = headline(payload)
    header = title if len(title) <= SLACK_HEADER_CHARS else title[: SLACK_HEADER_CHARS - 3] + "..."
    blocks: List[Dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": header, "emoji": False}},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*{name}*\n{slack_escape(value)}"[:2_000]} for name, value in facts(payload)[:10]
            ],
        },
    ]
    entities = entity_line(payload)
    if entities:
        blocks.append({"type": "context", "elements": [{"type": "plain_text", "text": entities, "emoji": False}]})
    elements: List[Dict[str, Any]] = []
    url = link(payload, base_url)
    if url:
        elements.append(
            {"type": "button", "text": {"type": "plain_text", "text": f"Open in {PRODUCT}"}, "url": url[:3_000],
             "action_id": "lgsotf_open"}
        )
    action = _section(payload, "action")
    if interactive and payload.get("event") == "action.awaiting_approval" and action is not None:
        value = str(action.get("id"))
        elements.append(
            {"type": "button", "style": "primary", "text": {"type": "plain_text", "text": "Approve"},
             "action_id": "lgsotf_approve", "value": value}
        )
        elements.append(
            {"type": "button", "style": "danger", "text": {"type": "plain_text", "text": "Reject"},
             "action_id": "lgsotf_reject", "value": value,
             "confirm": {"title": {"type": "plain_text", "text": "Reject this action?"},
                         "text": {"type": "plain_text", "text": "The action will not be executed."},
                         "confirm": {"type": "plain_text", "text": "Reject"},
                         "deny": {"type": "plain_text", "text": "Cancel"}}}
        )
    if elements:
        blocks.append({"type": "actions", "elements": elements})
    return {"text": slack_escape(title)[:3_000], "blocks": blocks, "unfurl_links": False, "unfurl_media": False}


# -------------------------------------------------------------------- Teams


def teams_escape(text: str) -> str:
    """Neutralise Adaptive Card markdown links and emphasis in untrusted text."""
    for char in ("\\", "[", "]", "*", "_", "`"):
        text = text.replace(char, "\\" + char)
    return text


def teams_message(payload: Mapping[str, Any], base_url: str) -> Dict[str, Any]:
    """An Adaptive Card message for a Teams Workflows webhook."""
    severity = str(_alert(payload).get("severity") or "info")
    body: List[Dict[str, Any]] = [
        {"type": "TextBlock", "text": PRODUCT + " - " + label(payload), "weight": "Bolder", "size": "Small",
         "color": TEAMS_COLORS.get(severity, "default")},
        {"type": "TextBlock", "text": teams_escape(str(_alert(payload).get("title") or "(untitled alert)")),
         "weight": "Bolder", "size": "Medium", "wrap": True},
        {"type": "FactSet", "facts": [{"title": n, "value": teams_escape(v)} for n, v in facts(payload)[:10]]},
    ]
    entities = entity_line(payload)
    if entities:
        body.append({"type": "TextBlock", "text": teams_escape(entities), "wrap": True, "isSubtle": True, "size": "Small"})
    card: Dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    }
    url = link(payload, base_url)
    if url:
        card["actions"] = [{"type": "Action.OpenUrl", "title": f"Open in {PRODUCT}", "url": url}]
    return {
        "type": "message",
        "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}
        ],
    }


# -------------------------------------------------------------------- email


def email_message(
    payload: Mapping[str, Any],
    base_url: str,
    *,
    sender: str,
    recipients: Sequence[str],
    subject_prefix: str = "[LG-SOTF]",
) -> EmailMessage:
    """Plain text plus a simple HTML alternative; every value is HTML-escaped."""
    title = headline(payload)
    subject = f"{subject_prefix} {title}".strip()
    rows = facts(payload)
    entities = entity_line(payload)
    url = link(payload, base_url)
    text_lines = [title, ""] + [f"{n}: {v}" for n, v in rows]
    if entities:
        text_lines += ["", f"Entities: {entities}"]
    if url:
        text_lines += ["", f"Open in {PRODUCT}: {url}"]
    text_lines += ["", f"-- {PRODUCT} notification. Configure it under Integrations."]
    cells = "".join(
        f"<tr><th align=\"left\" style=\"padding:2px 12px 2px 0\">{html.escape(n)}</th>"
        f"<td style=\"padding:2px 0\">{html.escape(v)}</td></tr>"
        for n, v in rows
    )
    html_body = (
        "<!doctype html><html><body style=\"font-family:sans-serif;font-size:14px\">"
        f"<h2 style=\"font-size:16px\">{html.escape(title)}</h2>"
        f"<table>{cells}</table>"
        + (f"<p style=\"color:#555\">Entities: {html.escape(entities)}</p>" if entities else "")
        + (f"<p><a href=\"{html.escape(url, quote=True)}\">Open in {PRODUCT}</a></p>" if url else "")
        + f"<p style=\"color:#888;font-size:12px\">{PRODUCT} notification.</p></body></html>"
    )
    msg = EmailMessage()
    msg["Subject"] = subject[:200]
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=sender.rpartition("@")[2] or None)
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content("\n".join(text_lines))
    msg.add_alternative(html_body, subtype="html")
    return msg


SmtpFactory = Callable[..., Any]


def _smtp_send(settings: Settings, message: EmailMessage, smtp_factory: Optional[SmtpFactory]) -> None:
    cfg = settings.integrations
    context = ssl.create_default_context()
    timeout = cfg.smtp_timeout_s
    if smtp_factory is not None:
        client = smtp_factory(cfg.smtp_host, cfg.smtp_port, timeout=timeout)
    elif cfg.smtp_security == "tls":
        client = smtplib.SMTP_SSL(cfg.smtp_host or "", cfg.smtp_port, timeout=timeout, context=context)
    else:
        client = smtplib.SMTP(cfg.smtp_host or "", cfg.smtp_port, timeout=timeout)
    with client:
        client.ehlo()
        if cfg.smtp_security == "starttls":
            client.starttls(context=context)
            client.ehlo()
        if cfg.smtp_username:
            password = cfg.smtp_password.get_secret_value() if cfg.smtp_password else ""
            client.login(cfg.smtp_username, password)
        client.send_message(message)


async def send_email(
    settings: Settings,
    payload: Mapping[str, Any],
    base_url: str,
    config: Mapping[str, Any],
    *,
    smtp_factory: Optional[SmtpFactory] = None,
) -> Dict[str, Any]:
    cfg = settings.integrations
    if not cfg.smtp_host or not cfg.smtp_from:
        raise DeliveryError("SMTP is not configured on this install (integrations.smtp_host, smtp_from)",
                            retryable=True, code="smtp_not_configured")
    recipients = [str(r) for r in config.get("recipients") or []]
    if not recipients:
        raise DeliveryError("the integration has no recipients", retryable=False, code="no_recipients")
    message = email_message(
        payload, base_url, sender=cfg.smtp_from, recipients=recipients,
        subject_prefix=str(config.get("subject_prefix") or "[LG-SOTF]"),
    )
    try:
        await asyncio.wait_for(
            asyncio.to_thread(_smtp_send, settings, message, smtp_factory), timeout=cfg.smtp_timeout_s * 3
        )
    except smtplib.SMTPRecipientsRefused as exc:
        raise DeliveryError(f"recipients refused ({len(exc.recipients)})", retryable=False, code="smtp_refused") from None
    except smtplib.SMTPAuthenticationError as exc:
        raise DeliveryError(f"SMTP authentication failed ({exc.smtp_code})", retryable=True, code="smtp_auth") from None
    except smtplib.SMTPResponseException as exc:
        raise DeliveryError(
            f"SMTP error {exc.smtp_code}", retryable=400 <= exc.smtp_code < 500, code="smtp_error"
        ) from None
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        raise DeliveryError(f"SMTP connection failed ({type(exc).__name__})", retryable=True,
                            code="smtp_unreachable") from None
    return {"recipients": len(recipients)}


# ------------------------------------------------------------------ webhook


def webhook_request(
    payload: Mapping[str, Any], base_url: str, secret: str, *, delivery_id: str, clock: Callable[[], float] = time.time
) -> Tuple[bytes, Dict[str, str]]:
    """Body and headers of a signed ``lg-sotf.event.v1`` delivery (signed afresh on every attempt)."""
    body = encode_body(with_links(payload, base_url))
    timestamp = str(int(clock()))
    headers = {
        "Content-Type": "application/json",
        TIMESTAMP_HEADER: timestamp,
        SIGNATURE_HEADER: sign(secret, timestamp, body),
        EVENT_HEADER: str(payload.get("event")),
        IDEMPOTENCY_HEADER: str(payload.get("id")),
        DELIVERY_HEADER: delivery_id,
    }
    return body, headers


# ------------------------------------------------------------------ senders


def _summary(result: HttpResult) -> Dict[str, Any]:
    return {"http_status": result.status}


async def send_notification(
    kind: str,
    *,
    http: IntegrationHttp,
    settings: Settings,
    payload: Mapping[str, Any],
    base_url: str,
    config: Mapping[str, Any],
    secret: Mapping[str, str],
    delivery_id: str,
    retries: int = 0,
    smtp_factory: Optional[SmtpFactory] = None,
) -> Dict[str, Any]:
    """Deliver one event to a notification channel; returns a small result, raises :class:`DeliveryError`."""
    if kind == "email":
        return await send_email(settings, payload, base_url, config, smtp_factory=smtp_factory)
    if kind == "webhook":
        signing_secret = secret.get("signing_secret")
        if not signing_secret:
            raise DeliveryError("the webhook signing secret is not set", retryable=False, code="missing_secret")
        body, headers = webhook_request(payload, base_url, signing_secret, delivery_id=delivery_id)
        result = await http.request(
            "POST", str(config.get("url")), content=body, headers=headers, verify=tls_verify(config), retries=retries
        )
        return _summary(result)
    webhook_url = secret.get("webhook_url")
    if not webhook_url:
        raise DeliveryError("the webhook URL is not set", retryable=False, code="missing_secret")
    if kind == "slack":
        message = slack_message(payload, base_url, interactive=bool(config.get("interactive_approvals")))
    elif kind == "teams":
        message = teams_message(payload, base_url)
    else:
        raise DeliveryError(f"{kind} is not a notification channel", retryable=False, code="unsupported")
    result = await http.request("POST", webhook_url, json_body=message, retries=retries)
    return _summary(result)
