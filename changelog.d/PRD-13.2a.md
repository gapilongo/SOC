### Added

- Guided Wazuh setup: Sources > Connect Wazuh step by step checks a Wazuh
  connection before the source is saved and says what to change. For the
  indexer it checks, in order, the settings, that the install may reach the
  host and the indexer answers, the TLS certificate, the sign-in, the
  permission on the alerts index, the index itself and the clocks. A failed
  check names what is missing, for example the index pattern and the
  permission `indices:data/read/search`, the CA certificate, or the host to
  add to the PoV allow-list. For alerts pushed by the Wazuh manager it checks
  the push source and that the API key has the `ingest` scope. API:
  `POST /onboarding/connectors/wazuh/check` (the tenant's own admins, 20 runs
  per tenant per minute), audited as `source.setup_checked`. See
  docs/onboarding.md.

### Security

- The guided checks never return, log or audit the entered password, user
  name or API key, and an unknown API key, a mistyped one and another
  tenant's key get the same answer. The indexer is reached through the
  install's destination policy, and a refused destination keeps its single
  generic message.
