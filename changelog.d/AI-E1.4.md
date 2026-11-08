### Added

- Evaluation cassettes: `lg-sotf eval --cassettes DIR --cassette-mode record`
  writes each item's tool observations (reputation, history, enrichment
  providers) and model replies to one JSON Lines file per item. The default
  `replay` mode runs the dataset again from them with no network call and the
  same verdicts; `replay-tools` replays the tools and calls the configured
  model, to compare a new model or prompt on the same observations. A call
  the cassette does not hold fails the item (`CassetteMiss`) instead of going
  out. Cassettes for the first synthetic and phishing items are committed;
  `make eval-cassettes` records them again.

### Security

- Cassettes are redacted with the trace digest's rules before they are
  written, so no credential reaches a cassette file.
