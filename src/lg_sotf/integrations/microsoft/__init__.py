"""Direct response in Microsoft 365, Entra ID and Defender for Endpoint (the framework; ``docs/microsoft.md``).

Framework modules (frozen interfaces the capability packages build on):

* :mod:`~lg_sotf.integrations.microsoft.clouds`   the fixed hosts and token scopes per cloud
* :mod:`~lg_sotf.integrations.microsoft.auth`     app-only tokens (secret or certificate), cached per integration
* :mod:`~lg_sotf.integrations.microsoft.http`     guarded, bounded, retried Graph and Defender requests
* :mod:`~lg_sotf.integrations.microsoft.odata`    validation and encoding of untrusted targets
* :mod:`~lg_sotf.integrations.microsoft.alert_view` the read-only view of the action's alert
* :mod:`~lg_sotf.integrations.microsoft.capability` the capability seam (specs, handlers, context)
* :mod:`~lg_sotf.integrations.microsoft.catalog`  the merged, checked capability catalog
* :mod:`~lg_sotf.integrations.microsoft.connection_test` the connection test report

Capability packages: :mod:`~lg_sotf.integrations.microsoft.mail`,
:mod:`~lg_sotf.integrations.microsoft.entra` and
:mod:`~lg_sotf.integrations.microsoft.defender`, each exporting
``CAPABILITIES: Tuple[CapabilitySpec, ...]``.

The connector that executes ledger actions with them is
:mod:`lg_sotf.services.connectors.microsoft`. Import submodules directly.
"""
