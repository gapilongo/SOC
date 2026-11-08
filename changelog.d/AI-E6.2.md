### Added

- `docs/ai-system-card.md`, the AI system card for compliance and security
  reviewers: intended and out-of-scope uses, the model profiles and where
  each one runs, every kind of model call and the read-only tools, what the
  AI decides and what people decide (routing, autonomy, approvals, the kill
  switches), the safety invariants, the evaluation evidence with its
  intervals and known gaps, logging and traceability, data handling and
  retention, and the human oversight design. It maps the system to the EU AI
  Act (risk-classification reasoning with its caveats, Articles 4, 12 to 15,
  26 and 50) and to NIS2 Art. 21(2) and Implementing Regulation 2024/2690.
  It is not legal advice.
- `python scripts/export_invariants.py` now also writes the invariants table
  of the system card, and CI fails when the card is stale, misses an offered
  model profile or a model call, or presents DeepSeek as supported.
