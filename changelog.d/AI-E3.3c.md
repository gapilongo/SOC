### Changed

- Evidence lookups: the events listed for a busy host (AI-E3.3c, #452). The
  host lookup (`wazuh.host_activity`) lists at most 50 events. When the host
  raised more than 50 in the window, it used to list the 50 with the highest
  rule level, so whoever could raise louder alerts on the host chose the
  list. The 50 are now chosen in four parts, each from its own search: the
  newest events whose ATT&CK technique is in a class only a person may
  close (up to 20), the events of the techniques the host showed least
  often (up to 10), the events closest in time to the alert (up to 10), and
  the highest rule levels for the rest. Each listed event says which part
  kept it (`listed_for`), and the fact says whether events of a never-close
  technique were left out (`never_close_technique_truncated`). A host with
  50 events or fewer is listed whole, in the same order as before, with no
  extra search.
  - The deep model is shown such a list grouped by part, so each part is
    fitted to the prompt on its own. Fifty events with their command lines
    do not fit the prompt: within a part that does not fit, every event is
    cut alike, the cut is marked and the record says `evidence_truncated`.
  - The flag reads the ATT&CK technique only. An event that is in a
    never-close class by its tactic, by a Wazuh rule group or rule id, or
    for having no ATT&CK mapping, is not in that part.
  - If a search of the sample fails, the lookup still answers from its
    first search: the events are the highest rule levels and the flag is
    `true`. The sample's searches are sent together, so a busy host on a
    slow indexer stays inside the lookup's time limit.
- One event of a host lookup now holds at most 400 characters of its
  command template and 100 of its user and of its image name; a cut is
  noted on the fact. This applies to every host, busy or not. Process
  lineage lookups keep full command lines.
  - The fact of a busy host is still incomplete (`complete: false`): its
    counts, techniques and highest level cover every event, its list is a
    sample. A benign claim that cites it is recorded as resting on an
    incomplete fact, as before, and the indicators that can hold an AI close
    read the counts, not the list.
  - The evidence-fact schema is now 1.2.0 (two optional fields). Facts
    stored under 1.1.0 are read as before. See docs/evidence-facts.md
    ("A busy host").

### Security

- An attacker who controls how many alerts a host raises, how loud they are
  and when they happen can no longer push an event of a never-close
  technique out of the list the host fact records (what the citation check
  and the case record read), while the window holds at most 20 such events.
  With more, the newest 20 are listed and the fact says so. What the deep
  model's prompt shows of that list is still bounded by the prompt's size.
- A command line made of bare numbers no longer fails the host lookup or a
  process lineage lookup (its template outgrew the fact's limit), and 50
  events with long command lines or user names no longer make the prompt
  leave the host's observation out without saying so: when an observation
  is left out, the record says `evidence_truncated`.
