### Fixed

- An alert retro-reopen requeues (a related response plan with no open case
  to fold it into) now gets its run message as soon as the reopen commits,
  so a worker reviews it at once instead of after the orphan sweep
  (2 x `worker.visibility_timeout_s`), which stays the backstop (#350).
