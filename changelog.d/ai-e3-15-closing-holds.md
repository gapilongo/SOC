### Security

- The AI no longer closes a Kerberos service ticket request for an RC4 or
  DES ticket on the models' word (#456). This is the request Kerberoasting
  makes: Windows event 4769 with ticket encryption type `0x17`, `0x18`,
  `0x1` or `0x3`. Wazuh reports it as rule 60106 "Windows Logon Success",
  level 3, and a model reads it as a normal sign-in to a service. Such an
  alert is now in the never-close class `credential_access`, whatever
  ATT&CK id its rule carries: a benign model verdict sends it to an analyst
  at every autonomy tier, and a declared scanner or test source does not
  close it. Requests for an AES ticket, for a machine account (a service name
  ending in `$`) and for `krbtgt` are unchanged. When the event's encryption
  type or service name cannot be read, the alert does not close either. If
  your domain still issues RC4 tickets for service accounts in normal use,
  these alerts now go to your analysts instead of being closed.
- At the autonomy tier `auto_full_audit`, a response that a person approved,
  or that really ran, now also holds back later closes on the same host or
  user (#456, follow-up of #435). Until now such a response reopened the
  related alerts the AI had already closed, but an alert that arrived
  afterwards could still close on the models' word. It now goes to an
  analyst with the reason code `related_open_threat`, for as long as the
  alert with the response is open (up to seven days from its ingestion) and
  for 24 hours after it closed as malicious. A response that only waits for
  an approval, one a person rejected, one the tenant's dry-run mode only
  simulated without anybody's approval, and an approved rollback hold
  nothing, as before.
