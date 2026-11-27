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
  class were left out (`never_close_class_truncated`). A host with 50 events
  or fewer is listed whole, exactly as before, with no extra search.
  - The deep model is shown such a list grouped by part. Fifty events do
    not fit its prompt, and the prompt cuts every member of a list alike;
    grouped, the part an attacker's noise fills is cut and a small part is
    shown whole.
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
  technique out of what the deep model and the citation check read, while
  the window holds at most 20 such events. With more, the newest 20 are
  listed and the fact says so.
