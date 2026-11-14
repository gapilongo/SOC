### Added

- Wazuh evidence tools (`lg_sotf.tools.wazuh`, INT3.4): four registered
  tools that read what surrounds an alert on the tenant's own Wazuh indexer
  and answer with typed evidence facts (schema 1.1). The analysis does not
  call them yet; the investigation executor uses them in a later release.
  - `wazuh.host_activity`: what a host's alerts show around a moment (up to
    60 minutes before and after): counts by rule group and technique, the
    highest rule level, and the 50 highest alerts.
  - `wazuh.logon_fanout`: every logon of one source address, source host,
    user or target host over up to 24 hours: failures, successes, lockouts,
    distinct users, sources and hosts, and the time from the first failure
    to the first success after it. Windows and sshd. A caller cannot narrow
    it to an outcome or a logon type, so a fact never reports zero for what
    it did not read. Windows user and host names are matched and counted
    whatever case they were typed in.
  - `wazuh.process_lineage`: a process's parents (up to 8) and what it
    started, down to what its children started. Name the process by its
    GUID when the alert has one; an image gives one fact per process that
    matches, and none is complete when there are several.
  - `wazuh.prevalence`: on how many of the tenant's agents a file hash, a
    process image, a service's image path or a service name was seen over up
    to 30 days.
  - The tools are query templates. A caller gives typed, bounded values and
    never a query, a field or an index; every search is checked against an
    allow-list before it is sent, and the only request the client can make
    is `POST /<index>/_search` on the index pattern of the Wazuh source the
    alert came from, with that source's credentials, through the install's
    destination rules. Only the scheme, the host and the port of the
    source's `base_url` are used: for the tools, a `base_url` with a path or
    a query is refused. They need the permission the pull source needs and
    nothing more. Switch them off for a tenant with
    `tools.wazuh_indexer.enabled: false`.
  - A call that finds nothing is `empty`. An indexer that is down, refuses
    the credentials, answers only part of a search that matched nothing, or
    holds no index for the pattern is `failed` with a fixed reason; so is
    any answer but an HTTP 200, and a response without an aggregation that
    was asked for. A fact is `complete` only when every shard answered
    every search, no cap cut what the fact lists or how far a process's
    parents were followed, its time window had closed and the index reached
    back to the window's start.
  - Limits found on a Wazuh 4.14 indexer are in docs/evidence-facts.md:
    process lineage needs the manager to raise Sysmon process creations, a
    file hash is searched in file-integrity events only, and values are
    compared whole and case-sensitively.
- The offline event store answers the same tools
  (`lg_sotf.eval.wazuh_events.EventStoreBackend`), so evaluation and tests
  get the facts from the corpus telemetry. A live test checks that a Wazuh
  4.14 indexer gives the same facts.

### Changed

- A tool can now say that its answer was cut (`Tool.whole` in the tool
  registry): a result is `complete` only when it is below its row cap and
  the tool does not say a cap inside the source, an open time window or the
  source's retention cut it.
- INV-14, "Evidence tools are read-only, templated and capped", is now
  enforced: it was pending until the Wazuh templates and their allow-list
  tests existed.
- A shadow run may read the tenant's own Wazuh indexer through the evidence
  tools. It is the second reviewed read a shadow run is allowed (after the
  local health listener): it tells no third party anything and changes
  nothing. Every other outbound request of a shadow run is still refused.
