### Added

- Tenant setting `triage.known_scanners`: host names, IP addresses or CIDR
  ranges of your own vulnerability scanners. An alert whose host or IP
  entities include one gets the `known_scanner` false-positive signal.
- Triage recognises the EICAR anti-virus test file by hash: an alert whose
  only file hashes are EICAR's gets the `eicar_test_file` false-positive
  signal.

### Changed

- The adversarial corpus v2 gates the `title-camouflage` family: its three
  items moved from the reported-only `known-gap` split to the `adversarial`
  split, and the corpus lists its own scanner.

### Security

- Triage no longer reads benign words ("test", "update", "maintenance",
  "scheduled" ...) from alert titles. Integrations build titles from the
  names of the objects involved, and an attacker who named a scheduled task
  "Windows Update Test" could get a malicious alert closed on the rules
  alone. False-positive evidence now comes only from the detection rule's
  name (with quoted values and every attacker-named value masked out), EICAR
  hashes, the tenant's known scanners and the source id. Alerts whose only
  benign evidence was in the title now reach the model and, when needed, an
  analyst.
