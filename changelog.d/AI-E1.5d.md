### Fixed

- Shadow runs no longer slow down production triage. Their LLM calls now use
  slots of their own, one per model tier and worker process by default
  (`llm.fast.shadow_max_concurrency`, `llm.deep.shadow_max_concurrency`), so
  a live call never waits for a shadow call and can no longer time out
  behind one.
