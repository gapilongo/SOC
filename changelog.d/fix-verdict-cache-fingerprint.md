### Security

- The verdict cache could close a malicious alert at the gate because it
  matched alerts by fingerprint alone (rule, hosts, users, IPs, hashes,
  domains). On one host, a ransomware `PSEXESVC` service matched an Edge
  update service an analyst had closed as benign, and a web shell's `ps`
  running as uid 33 matched monitoring's `ps` running as root. The cache now
  uses a verdict key: the fingerprint plus the process image, command line,
  service name and image path, user/uid, parent process, the objects an
  attacker creates (scheduled tasks, registry keys, target files, Sysmon WMI
  subscriptions) and the request context (URLs, user agents, O365 operations
  and parameters, queries, process-access rights), compared in full: nothing
  is masked or truncated.
- Alerts with no process, command, service or created object, alerts in a
  never-close class (credential access, log clearing, tampering, ransomware,
  persistence through named objects) and alerts normalised by a model never
  close from the cache and get no suggested rule; request context alone (a
  user agent, a URL, an O365 operation) is never enough. Model-normalised
  alerts also skip suppression rules.
- A cached verdict now closes an alert only after two different analysts
  decided it benign within 7 days, at the alert's severity or higher. One
  analyst's decisions, including a bulk close, count once. It is never used
  for critical alerts, nor within 7 days of a confirmed threat on that key or
  on any alert with the same fingerprint.
- Suppression rules suggested from false-positive decisions (one decision, or
  a batch of escalations) match the alert's verdict key instead of its
  fingerprint, so enabling one no longer suppresses a different service or
  command on the same host. With the analyst oracle on corpus_v1, enabling
  every suggestion closed 4 attacks before this change and none after.
- When a threat is confirmed on an alert (an analyst `true_positive`, a
  blind-audit malicious label, a planned response or a malicious close),
  every enabled suppression rule that would close that alert is disabled and
  recorded as `suppression.revoked` in the audit log. A failure is logged as
  an error and counted in `lgsotf_revocation_failures_total`.
- Migration 0016 disables every enabled suggested rule that matches a
  fingerprint alone (audited `suppression.revoked`, reason
  `fingerprint_suggestion`), and the gate ignores such rules even if they are
  enabled again. Replace them with rules on `verdict_key`.
- A benign decision on a grouped escalation now closes an attached alert only
  when it has the same verdict key as the reviewed alert; otherwise the
  attached alert gets its own escalation, as before.
- Cached verdicts written before this change are no longer read, so repeats
  are investigated until two analysts have decided them again. They expire
  within 7 days; `DELETE /tenant/verdict-cache` removes them now.
