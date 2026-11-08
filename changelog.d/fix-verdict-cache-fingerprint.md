### Security

- The verdict cache could close a malicious alert at the gate because it
  matched alerts by fingerprint alone (rule, hosts, users, IPs, hashes,
  domains). On one host, a ransomware `PSEXESVC` service matched an Edge
  update service an analyst had closed as benign, and a web shell's `ps`
  running as uid 33 matched monitoring's `ps` running as root. The cache now
  uses a verdict key: the fingerprint plus the process image, normalised
  command line, service name and image path, user/uid and parent process.
- A cached verdict now closes an alert only after two separate analyst
  benign decisions on the same verdict key within 7 days, at the alert's
  severity or higher. It is never used for critical alerts, nor within 7
  days of a confirmed threat on that key or on any alert with the same
  fingerprint. One decision on a grouped escalation counts once.
- A benign decision on a grouped escalation now closes an attached alert only
  when it has the same verdict key as the reviewed alert; otherwise the
  attached alert gets its own escalation, as before.
- Cached verdicts written before this change are no longer read, so repeats
  are investigated until analysts have decided them twice again. They expire
  within 7 days; `DELETE /tenant/verdict-cache` removes them now.
