"""Direct response in Microsoft Entra ID through Microsoft Graph (``docs/microsoft-entra.md``).

* :mod:`~lg_sotf.integrations.microsoft.entra.users`    resolving the target user; shared result helpers
* :mod:`~lg_sotf.integrations.microsoft.entra.guard`    the privileged-target guard (fails closed)
* :mod:`~lg_sotf.integrations.microsoft.entra.account`  ``entra.account``: disable_user, enable_user
* :mod:`~lg_sotf.integrations.microsoft.entra.sessions` ``entra.sessions``: revoke_sessions
* :mod:`~lg_sotf.integrations.microsoft.entra.password` ``entra.password``: reset_password
* :mod:`~lg_sotf.integrations.microsoft.entra.risk`     ``entra.risk``: confirm_compromised, dismiss_user_risk
"""

from typing import Tuple

from lg_sotf.integrations.microsoft.capability import CapabilitySpec
from lg_sotf.integrations.microsoft.entra.capabilities import ENTRA_ACCOUNT, ENTRA_PASSWORD, ENTRA_RISK, ENTRA_SESSIONS

CAPABILITIES: Tuple[CapabilitySpec, ...] = (ENTRA_ACCOUNT, ENTRA_SESSIONS, ENTRA_PASSWORD, ENTRA_RISK)

__all__ = ["CAPABILITIES"]
