### Added

- Telemetry for the evaluation corpus (AI-E1.10). An investigation needs
  what surrounds an alert, and `corpus_v1` held alerts only.
  - `corpus_v1_events.jsonl.gz`: 291 context events around the corpus alerts
    of the Windows logon-failure and service-install families (the logon
    before a service install, the success after a typo, retry cadences,
    PsExec process trees, the fleet's updater installs). `corpus_v1.jsonl.gz`
    itself is unchanged.
  - `corpus_skills_v1.jsonl.gz`: 196 labelled alerts of those two families
    (63 and 60 attacks, 73 benign) with their own context events. 28 are
    context-abuse attacks that sit inside what the tenant declared: a spray
    from the admin workstation, PsExec by an admin account followed by
    discovery, an "updater" service outside the patch window, a service
    account used interactively.
  - Gold evidence for both (`*_gold.json`): per item, the benign hypothesis
    the telemetry supports, the malicious indicators and never-close
    conditions of ADR 0014 that are true, and the documents they rest on.
  - `lg_sotf.eval.tool_fixtures.EventStore`: an in-memory store of a
    dataset's alerts and events that answers indexer-style queries as of a
    moment, so a replayed investigation never sees the future.
  - `scripts/load_corpus_telemetry.py`: loads the telemetry around chosen
    corpus items into a lab's Wazuh indexer with timestamps moved to the
    present, idempotently. The indexer URL and credentials come from the
    environment and are never printed, and the script refuses a host that
    was not passed with `--host`. See `docs/evaluation.md` ("Corpus
    telemetry, gold evidence and the skills corpus").
