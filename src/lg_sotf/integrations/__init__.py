"""Integrations hub: notifications (Slack, Teams, email, signed webhooks) and ticketing (Jira, ServiceNow).

* :mod:`~lg_sotf.integrations.events`   event payload (``lg-sotf.event.v1``), summaries, links
* :mod:`~lg_sotf.integrations.outbox`   enqueueing events in the state change's transaction
* :mod:`~lg_sotf.integrations.config`   per-kind configuration and credential schemas
* :mod:`~lg_sotf.integrations.http`     outbound HTTP through the destination policy
* :mod:`~lg_sotf.integrations.channels` formatters and senders per channel
* :mod:`~lg_sotf.integrations.ticketing` Jira and ServiceNow clients, ticket creation and sync
* :mod:`~lg_sotf.integrations.delivery` the scheduler's outbox delivery and ticket sync jobs

See ``docs/integrations.md``.
"""
