### Added

- Evidence-fact schema 1.1.0, a backward-compatible minor version of
  `schemas/evidence-fact/v1.json`: every 1.0 fact is still valid. It adds
  the facts the Wazuh evidence tools will return (`host_activity`: what a
  host did around an alert; `logon_fanout`: how many accounts, sources and
  hosts a logon pattern touched; `prevalence`: how widely a file, an image, a
  service or a command is seen), the processes a process started
  (`children` on `process_lineage`), and `complete`, which is false when the
  source cut a result or its time window had not closed, so that "nothing
  was found" is never read from a partial answer. Every list holds at most
  50 items and every text field has a maximum length. Published now; the tools
  that produce these facts come in a later release. See
  docs/evidence-facts.md.
