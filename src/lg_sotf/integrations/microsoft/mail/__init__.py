"""Microsoft 365 mail through Microsoft Graph: ``mail.remediate`` and ``mail.notify`` (``docs/microsoft-mail.md``).

* :mod:`~lg_sotf.integrations.microsoft.mail.capabilities` the two capability declarations
* :mod:`~lg_sotf.integrations.microsoft.mail.remediate`    ``purge_message`` and its rollback ``restore_message``
* :mod:`~lg_sotf.integrations.microsoft.mail.notify`       ``notify_reporter``
* :mod:`~lg_sotf.integrations.microsoft.mail.mailboxes`    Graph mailbox requests, recipients and per-mailbox steps
* :mod:`~lg_sotf.integrations.microsoft.mail.templates`    the fixed reply to reporters

``block_sender`` has no direct capability: no Graph or REST API manages the
Tenant Allow/Block List, so it stays on the SOAR webhook (or dry run).
"""

from typing import Tuple

from lg_sotf.integrations.microsoft.capability import CapabilitySpec
from lg_sotf.integrations.microsoft.mail.capabilities import MAIL_NOTIFY, MAIL_REMEDIATE

CAPABILITIES: Tuple[CapabilitySpec, ...] = (MAIL_REMEDIATE, MAIL_NOTIFY)
