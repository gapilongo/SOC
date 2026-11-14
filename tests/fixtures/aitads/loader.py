"""Turn AIT-ADS Wazuh alerts into labelled ``lg-sotf eval`` items (``aitads_v1``).

Labels. The AIT-ADS release labels attack *phases*, not alerts: ``labels.csv``
gives each scenario's phases with a start and an end time. Per-alert labels
(upstream's ``event_label``) need the raw logs of AIT-LDSv2 and the network
flows of AIT-NDS, which are not part of the release. What can be mapped from
the release alone, per alert:

* ``benign``: the alert's time is outside every attack phase of its scenario
  (upstream's ``time_label`` ``false_positive``). The attacker acts only inside
  the phases, so this label is reliable.
* ``malicious``: the alert's time is inside a phase and its detection (rule id
  and description; Suricata alerts all share rule 86601) never fires outside a
  phase in any of the eight scenarios. A detection that only ever fires during
  attacks is taken as attack-caused.
* ``inconclusive``: inside a phase, but the same detection also fires outside
  the phases (ClamAV updates, Dovecot logins, web 400s during a dirb scan):
  it may be the attack or the background noise. Headline rates leave these out.

The time is ``@timestamp``, which equals upstream's own parsing of the event
time to the second in every alert checked. ``agent.name`` is the replay
client's name (``wazuh-client``) in the release; the monitored host is
restored from the agent address (the predecoder host name most often seen with
it), as a Wazuh agent on that host would report it.
"""

from __future__ import annotations

import csv
import io
import json
import random
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

SCENARIOS: Tuple[str, ...] = (
    "fox", "harrison", "russellmitchell", "santos", "shaw", "wardbeck", "wheeler", "wilson",
)
ZENODO_RECORD = "https://zenodo.org/records/8263181"
FILES: Dict[str, str] = {  # name -> md5 published by Zenodo
    "ait_ads.zip": "43db6b1f0996e0024befd617706c50e9",
    "labels.csv": "60ff33796c77fd2136c4d1a4bc841bd9",
}
LICENCE = "CC BY 4.0"
CITATION = (
    "Landauer, M., Skopik, F., Wurzenberger, M. (2024): Introducing a New Alert Data Set for Multi-Step Attack "
    "Analysis. Proceedings of the 17th Cyber Security Experimentation and Test Workshop."
)
NAME = "aitads_v1"
NO_PHASE = "none"
REPLAY_AGENT = "wazuh-client"
SUMMARY_LINE = "The average number"  # upstream's analyze.py skips these summary records too


@dataclass(frozen=True)
class Phase:
    name: str
    start: float
    end: float


def load_phases(text: str) -> Dict[str, List[Phase]]:
    """``labels.csv`` (scenario, attack, start, end in epoch seconds) as phases per scenario."""
    out: Dict[str, List[Phase]] = defaultdict(list)
    for row in csv.DictReader(io.StringIO(text)):
        out[row["scenario"]].append(Phase(row["attack"], float(row["start"]), float(row["end"])))
    return {k: sorted(v, key=lambda p: p.start) for k, v in out.items()}


def alert_time(alert: Mapping[str, Any]) -> Optional[datetime]:
    raw = alert.get("@timestamp")
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def phase_at(phases: Sequence[Phase], at: datetime) -> str:
    """The attack phase ``at`` falls in (start inclusive, end exclusive), or :data:`NO_PHASE`."""
    ts = at.timestamp()
    for phase in phases:
        if phase.start <= ts < phase.end:
            return phase.name
    return NO_PHASE


def detection(alert: Mapping[str, Any]) -> str:
    """The detection an alert comes from: rule id and description (Suricata alerts share one rule id)."""
    rule = alert.get("rule") or {}
    return f"{rule.get('id')}:{rule.get('description')}"


def agent_ip(alert: Mapping[str, Any]) -> Optional[str]:
    agent = alert.get("agent")
    return str(agent.get("ip")) if isinstance(agent, Mapping) and agent.get("ip") else None


@dataclass
class ScenarioScan:
    """What one pass over a scenario's ``*_wazuh.json`` keeps: per-stratum reservoirs, host names, detections."""

    scenario: str
    capacity: Dict[str, int]
    rng: random.Random
    seen: Counter[str] = field(default_factory=Counter)
    reservoirs: Dict[str, List[Tuple[int, str]]] = field(default_factory=lambda: defaultdict(list))
    hosts: Dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    outside: Set[str] = field(default_factory=set)
    skipped: Counter[str] = field(default_factory=Counter)

    def add(self, index: int, line: str, phases: Sequence[Phase]) -> None:
        if SUMMARY_LINE in line:
            self.skipped["summary"] += 1
            return
        alert = json.loads(line)
        at = alert_time(alert)
        if at is None:
            self.skipped["no_time"] += 1
            return
        stratum = phase_at(phases, at)
        if stratum == NO_PHASE:
            self.outside.add(detection(alert))
        host = (alert.get("predecoder") or {}).get("hostname")
        ip = agent_ip(alert)
        if ip and isinstance(host, str):
            self.hosts[ip][host] += 1
        self.seen[stratum] += 1
        # Algorithm R: a uniform sample of each stratum, as large as any allocation could ask for.
        size = self.capacity.get(stratum, self.capacity[NO_PHASE])
        pool = self.reservoirs[stratum]
        if len(pool) < size:
            pool.append((index, line))
        else:
            slot = self.rng.randrange(self.seen[stratum])
            if slot < size:
                pool[slot] = (index, line)

    def host_names(self) -> Dict[str, str]:
        return {ip: names.most_common(1)[0][0] for ip, names in self.hosts.items() if names}


def allocate(available: Mapping[str, int], total: int, attack_share: float) -> Dict[str, int]:
    """Per-stratum sample sizes: ``attack_share`` of ``total`` spread evenly over the phases, the rest benign.

    A phase with fewer alerts than its share gives the remainder to the other phases, then to the benign stratum.
    """
    phases = sorted(k for k in available if k != NO_PHASE and available[k])
    quota = {k: 0 for k in phases}
    budget = min(round(total * attack_share), sum(available[k] for k in phases))
    open_phases = list(phases)
    while budget > 0 and open_phases:
        share = max(1, budget // len(open_phases))
        for name in list(open_phases):
            take = min(share, available[name] - quota[name], budget)
            quota[name] += take
            budget -= take
            if quota[name] >= available[name]:
                open_phases.remove(name)
            if budget == 0:
                break
    quota[NO_PHASE] = min(available.get(NO_PHASE, 0), total - sum(quota.values()))
    return quota


def restore_host(alert: Dict[str, Any], hosts: Mapping[str, str]) -> Dict[str, Any]:
    """``alert`` with ``agent.name`` set to the monitored host (the release has the replay client's name)."""
    agent = alert.get("agent")
    ip = agent_ip(alert)
    if isinstance(agent, dict) and agent.get("name") == REPLAY_AGENT and ip in hosts:
        alert = {**alert, "agent": {**agent, "name": hosts[ip]}}
    return alert


def disposition(phase: str, key: str, outside: Set[str]) -> str:
    if phase == NO_PHASE:
        return "benign"
    return "inconclusive" if key in outside else "malicious"


def select(scan: ScenarioScan, per_scenario: int, attack_share: float) -> List[Tuple[Dict[str, Any], str]]:
    """The scenario's sample, ``(alert, phase)`` in event-time order, host names restored, one alert per id."""
    quota = allocate(scan.seen, per_scenario, attack_share)
    hosts = scan.host_names()
    chosen: List[Tuple[datetime, int, Dict[str, Any], str]] = []
    seen_ids: Set[str] = set()
    for stratum, size in sorted(quota.items()):
        pool = sorted(scan.reservoirs.get(stratum, []))
        picked = sorted(scan.rng.sample(pool, size)) if size < len(pool) else pool
        for index, line in picked:
            alert = json.loads(line)
            if str(alert.get("id")) in seen_ids:
                scan.skipped["duplicate_id"] += 1
                continue
            seen_ids.add(str(alert.get("id")))
            at = alert_time(alert)
            assert at is not None  # the scan kept timed alerts only
            chosen.append((at, index, restore_host(alert, hosts), stratum))
    chosen.sort(key=lambda row: (row[0], row[1]))
    return [(alert, phase) for _, _, alert, phase in chosen]


def to_item(scenario: str, n: int, alert: Mapping[str, Any], phase: str, label: str) -> Dict[str, Any]:
    rule = alert.get("rule") or {}
    groups = rule.get("groups") or []
    method = "outside-attack-phases" if phase == NO_PHASE else "attack-only-detection" if label == "malicious" \
        else "detection-also-outside-phases"
    return {
        "id": f"ait-{scenario}-{n:05d}",
        "source_type": "wazuh",
        "alert": dict(alert),
        "expected": {"disposition": label},
        "split": scenario,
        "tags": [
            "vendor:wazuh",
            "ids:suricata" if "suricata" in groups else "ids:wazuh",
            f"phase:{phase}",
            f"label:{method}",
            f"rule:{rule.get('id')}"[:64],
            f"level:{rule.get('level')}",
        ],
    }


def meta(stats: Mapping[str, Any], per_scenario: int, attack_share: float, seed: int) -> Dict[str, Any]:
    return {
        "synthetic": True,
        "version": 1,
        "name": NAME,
        "description": (
            "AIT Alert Data Set (AIT-ADS): Wazuh and Suricata alerts from the AIT-LDSv2 testbed (simulated users, "
            "multi-step attacks), a stratified sample per scenario. Labels come from the dataset's attack-phase "
            "times (see tests/fixtures/aitads/loader.py). Benign volume is realistic and repetitive; it is lab data, "
            "not a customer's."
        ),
        "source": {"record": ZENODO_RECORD, "licence": LICENCE, "citation": CITATION},
        "sampling": {"per_scenario": per_scenario, "attack_share": attack_share, "seed": seed,
                     "strata": "attack phase (or none), uniform within a stratum"},
        "composition": stats,
    }


def build(
    sources: Mapping[str, Iterable[str]],
    labels_csv: str,
    *,
    per_scenario: int = 5000,
    attack_share: float = 0.2,
    seed: int = 20261108,
) -> str:
    """The ``aitads_v1`` JSONL text from each scenario's ``*_wazuh.json`` lines (``sources``) and ``labels.csv``."""
    phases = load_phases(labels_csv)
    capacity = {NO_PHASE: max(per_scenario, 1)}
    samples: Dict[str, List[Tuple[Dict[str, Any], str]]] = {}
    outside: Set[str] = set()
    stats: Dict[str, Any] = {}
    for scenario, lines in sources.items():
        scan = ScenarioScan(scenario, capacity, random.Random(f"{seed}:{scenario}"))
        for index, line in enumerate(lines):
            if line.strip():
                scan.add(index, line, phases.get(scenario, []))
        samples[scenario] = select(scan, per_scenario, attack_share)
        outside |= scan.outside
        stats[scenario] = {"alerts": sum(scan.seen.values()), "by_phase": dict(sorted(scan.seen.items())),
                           "skipped": dict(scan.skipped)}
    # Labels last: a detection seen outside the phases in any scenario makes its in-phase alerts inconclusive.
    items: List[Dict[str, Any]] = []
    for scenario, sample in samples.items():
        chosen = [to_item(scenario, n, alert, phase, disposition(phase, detection(alert), outside))
                  for n, (alert, phase) in enumerate(sample, start=1)]
        items += chosen
        stats[scenario]["sampled"] = len(chosen)
        stats[scenario]["labels"] = dict(sorted(Counter(i["expected"]["disposition"] for i in chosen).items()))
    lines = [json.dumps({"_meta": meta(stats, per_scenario, attack_share, seed)}, ensure_ascii=False,
                        separators=(",", ":"))]
    lines += [json.dumps(item, ensure_ascii=False, separators=(",", ":")) for item in items]
    return "\n".join(lines) + "\n"
