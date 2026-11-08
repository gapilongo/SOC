"""Wazuh 4.14 alert bodies, one builder per decoder family.

Each builder returns the decoder-specific part of an alert (``decoder``,
``data``, ``full_log``, ``predecoder``, ``syscheck``, ``location``,
``previous_output``); :mod:`tests.fixtures.attack_corpus.corpus` adds
``timestamp``, ``rule``, ``agent``, ``manager`` and ``id``. Shapes follow what
a 4.14 manager writes to ``alerts.json``:

* Windows events arrive through the ``windows_eventchannel`` decoder as
  ``data.win.system`` and ``data.win.eventdata`` with camelCase names, and every
  backslash in an event value doubled (``C:\\\\Windows``), which is what the 4.x
  Sysmon rules' regular expressions match.
* syslog programs (sshd, PAM, sudo, useradd, crontab, dpkg, yum) carry
  ``full_log``, ``predecoder`` and the fields their decoders extract.
* File integrity monitoring events carry a ``syscheck`` object; auditd events
  ``data.audit``; web access logs the ``web-accesslog`` fields.

``win.system.message`` (the rendered event text, a copy of ``eventdata``) is
left out to keep the corpus small.
"""

from __future__ import annotations

import hashlib
import random
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence

from tests.fixtures.attack_corpus.fleet import DOMAIN, Host

Body = Dict[str, Any]
SYSMON_GUID = "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
SECURITY_GUID = "{54849625-5478-4994-a5ba-3e3b0328c30d}"

# PE metadata of the binaries the corpus runs: description, product, company, original file name, version.
PE: Dict[str, tuple] = {  # type: ignore[type-arg]
    "powershell.exe": ("Windows PowerShell", "Microsoft® Windows® Operating System", "Microsoft Corporation",
                       "PowerShell.EXE", "10.0.19041.3996 (WinBuild.160101.0800)"),
    "cmd.exe": ("Windows Command Processor", "Microsoft® Windows® Operating System", "Microsoft Corporation",
                "Cmd.Exe", "10.0.19041.4355 (WinBuild.160101.0800)"),
    "net.exe": ("Net Command", "Microsoft® Windows® Operating System", "Microsoft Corporation", "net.exe",
                "10.0.19041.1 (WinBuild.160101.0800)"),
    "net1.exe": ("Net Command", "Microsoft® Windows® Operating System", "Microsoft Corporation", "net1.exe",
                 "10.0.19041.1 (WinBuild.160101.0800)"),
    "reg.exe": ("Registry Console Tool", "Microsoft® Windows® Operating System", "Microsoft Corporation", "reg.exe",
                "10.0.19041.1 (WinBuild.160101.0800)"),
    "certutil.exe": ("CertUtil.exe", "Microsoft® Windows® Operating System", "Microsoft Corporation", "CertUtil.exe",
                     "10.0.19041.3636 (WinBuild.160101.0800)"),
    "mshta.exe": ("Microsoft (R) HTML Application host", "Internet Explorer", "Microsoft Corporation", "MSHTA.EXE",
                  "11.00.19041.1 (WinBuild.160101.0800)"),
    "rundll32.exe": ("Windows host process (Rundll32)", "Microsoft® Windows® Operating System",
                     "Microsoft Corporation", "RUNDLL32.EXE", "10.0.19041.3636 (WinBuild.160101.0800)"),
    "regsvr32.exe": ("Microsoft(C) Register Server", "Microsoft® Windows® Operating System", "Microsoft Corporation",
                     "REGSVR32.EXE", "10.0.19041.1 (WinBuild.160101.0800)"),
    "vssadmin.exe": ("Command Line Interface for Microsoft® Volume Shadow Copy Service ",
                     "Microsoft® Windows® Operating System", "Microsoft Corporation", "VSSADMIN.EXE",
                     "10.0.19041.1 (WinBuild.160101.0800)"),
    "wevtutil.exe": ("Eventing Command Line Utility", "Microsoft® Windows® Operating System", "Microsoft Corporation",
                     "wevtutil.exe", "10.0.19041.1 (WinBuild.160101.0800)"),
    "schtasks.exe": ("Task Scheduler Configuration Tool", "Microsoft® Windows® Operating System",
                     "Microsoft Corporation", "schtasks.exe", "10.0.19041.1 (WinBuild.160101.0800)"),
    "sc.exe": ("Service Control Manager Configuration Tool", "Microsoft® Windows® Operating System",
               "Microsoft Corporation", "sc.exe", "10.0.19041.1 (WinBuild.160101.0800)"),
    "wmic.exe": ("WMI Commandline Utility", "Microsoft® Windows® Operating System", "Microsoft Corporation",
                 "wmic.exe", "10.0.19041.3636 (WinBuild.160101.0800)"),
    "fodhelper.exe": ("Features On Demand Helper", "Microsoft® Windows® Operating System", "Microsoft Corporation",
                      "FodHelper.EXE", "10.0.19041.1 (WinBuild.160101.0800)"),
    "procdump64.exe": ("Sysinternals process dump utility", "ProcDump", "Sysinternals - www.sysinternals.com",
                       "procdump", "11.0"),
    "psexesvc.exe": ("PsExec Service", "Sysinternals PsExec", "Sysinternals - www.sysinternals.com", "psexesvc.exe",
                     "2.43"),
    "7z.exe": ("7-Zip Console", "7-Zip", "Igor Pavlov", "7z.exe", "23.01"),
    "curl.exe": ("The curl executable", "The curl executable", "curl, https://curl.se/", "curl.exe", "8.4.0"),
    "netsh.exe": ("Network Command Shell", "Microsoft® Windows® Operating System", "Microsoft Corporation",
                  "netsh.exe", "10.0.19041.1 (WinBuild.160101.0800)"),
    "msiexec.exe": ("Windows® installer", "Windows Installer - Unicode", "Microsoft Corporation", "msiexec.exe",
                    "5.0.19041.3636 (WinBuild.160101.0800)"),
    "wbadmin.exe": ("Command Line Interface for Microsoft® BLB Backup", "Microsoft® Windows® Operating System",
                    "Microsoft Corporation", "WBADMIN.EXE", "10.0.19041.1 (WinBuild.160101.0800)"),
    "sdelete64.exe": ("Secure file delete", "Sysinternals Sdelete", "Sysinternals - www.sysinternals.com",
                      "sdelete.exe", "2.05"),
    "tasklist.exe": ("Lists the current running tasks", "Microsoft® Windows® Operating System",
                     "Microsoft Corporation", "tasklist.exe", "10.0.19041.1 (WinBuild.160101.0800)"),
}


def win(value: str) -> str:
    """An event value as the eventchannel decoder writes it: every backslash doubled."""
    return value.replace("\\", "\\\\")


def basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def digest(kind: str, seed: str) -> str:
    """A stable stand-in hash for a file (the same file has the same hash across the corpus)."""
    return hashlib.new(kind, seed.encode("utf-8")).hexdigest()


def sysmon_hashes(path: str) -> str:
    key = path.lower()
    return (f"SHA1={digest('sha1', key).upper()},MD5={digest('md5', key).upper()},"
            f"SHA256={digest('sha256', key).upper()},IMPHASH={digest('md5', 'imp:' + key).upper()}")


def syslog_stamp(at: datetime) -> str:
    return f"{at:%b} {at.day:>2} {at:%H:%M:%S}"


class Ctx:
    """Random identifiers drawn from the corpus seed."""

    def __init__(self, rng: random.Random):
        self.rng = rng
        self._record = 418_000

    def guid(self) -> str:
        return "{" + str(uuid.UUID(int=self.rng.getrandbits(128), version=4)) + "}"

    def pid(self) -> str:
        return str(self.rng.randrange(400, 14_000, 4))

    def port(self) -> str:
        return str(self.rng.randrange(49_152, 65_535))

    def logon_id(self) -> str:
        return hex(self.rng.randrange(0x100000, 0xFFFFFF))

    def record_id(self) -> str:
        self._record += self.rng.randrange(1, 900)
        return str(self._record)

    def b64(self, n: int) -> str:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return "".join(self.rng.choice(alphabet) for _ in range(n))

    def hexstr(self, n: int) -> str:
        return "".join(self.rng.choice("0123456789abcdef") for _ in range(n))


# ---------------------------------------------------------------------------------------------------------------------
# Windows event channel
# ---------------------------------------------------------------------------------------------------------------------


def _system(
    ctx: Ctx, host: Host, at: datetime, *, provider: str, guid: Optional[str], event_id: int, channel: str,
    severity: str, level: str = "4", task: str = "0", keywords: str = "0x8000000000000000", version: str = "0",
) -> Dict[str, str]:
    system = {"providerName": provider}
    if guid:
        system["providerGuid"] = guid
    system.update({
        "eventID": str(event_id), "version": version, "level": level, "task": task, "opcode": "0",
        "keywords": keywords, "systemTime": at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z",
        "eventRecordID": ctx.record_id(), "processID": ctx.pid(), "threadID": ctx.pid(), "channel": channel,
        "computer": host.fqdn, "severityValue": severity,
    })
    return system


def _win_body(system: Dict[str, str], eventdata: Dict[str, str]) -> Body:
    return {
        "decoder": {"name": "windows_eventchannel"},
        "data": {"win": {"system": system, "eventdata": {k: win(v) for k, v in eventdata.items()}}},
        "location": "EventChannel",
    }


def sysmon(ctx: Ctx, host: Host, at: datetime, event_id: int, eventdata: Dict[str, str]) -> Body:
    system = _system(ctx, host, at, provider="Microsoft-Windows-Sysmon", guid=SYSMON_GUID, event_id=event_id,
                     channel="Microsoft-Windows-Sysmon/Operational", severity="INFORMATION", task=str(event_id),
                     version="5" if event_id == 1 else "2")
    data = {"ruleName": "-", "utcTime": at.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]}
    data.update(eventdata)
    return _win_body(system, data)


def user_of(host: Host, user: str) -> str:
    if user in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
        return f"NT AUTHORITY\\{user}"
    return f"{DOMAIN}\\{user}"


def process(
    ctx: Ctx, host: Host, at: datetime, *, image: str, cmd: str, parent: str, parent_cmd: str, user: str,
    integrity: str = "Medium", cwd: Optional[str] = None, original: Optional[str] = None,
) -> Body:
    """Sysmon event 1 (process creation)."""
    name = basename(image).lower()
    desc, product, company, original_name, version = PE.get(name, ("-", "-", "-", basename(image), "-"))
    return sysmon(ctx, host, at, 1, {
        "processGuid": ctx.guid(), "processId": ctx.pid(), "image": image, "fileVersion": version,
        "description": desc, "product": product, "company": company,
        "originalFileName": original or original_name, "commandLine": cmd,
        "currentDirectory": cwd or (f"C:\\Users\\{user}\\" if "\\" not in user and user != "SYSTEM"
                                    else "C:\\Windows\\system32\\"),
        "user": user_of(host, user), "logonGuid": ctx.guid(), "logonId": ctx.logon_id(),
        "terminalSessionId": "0" if user == "SYSTEM" else "1", "integrityLevel": integrity,
        "hashes": sysmon_hashes(image), "parentProcessGuid": ctx.guid(), "parentProcessId": ctx.pid(),
        "parentImage": parent, "parentCommandLine": parent_cmd, "parentUser": user_of(host, user),
    })


def network(
    ctx: Ctx, host: Host, at: datetime, *, image: str, user: str, dst_ip: str, dst_port: int,
    dst_host: str = "", port_name: str = "-",
) -> Body:
    """Sysmon event 3 (network connection)."""
    return sysmon(ctx, host, at, 3, {
        "processGuid": ctx.guid(), "processId": ctx.pid(), "image": image, "user": user_of(host, user),
        "protocol": "tcp", "initiated": "true", "sourceIsIpv6": "false", "sourceIp": host.ip,
        "sourceHostname": host.fqdn, "sourcePort": ctx.port(), "sourcePortName": "-", "destinationIsIpv6": "false",
        "destinationIp": dst_ip, "destinationHostname": dst_host or "-", "destinationPort": str(dst_port),
        "destinationPortName": port_name,
    })


def remote_thread(ctx: Ctx, host: Host, at: datetime, *, source: str, target: str, user: str) -> Body:
    """Sysmon event 8 (CreateRemoteThread)."""
    return sysmon(ctx, host, at, 8, {
        "sourceProcessGuid": ctx.guid(), "sourceProcessId": ctx.pid(), "sourceImage": source,
        "targetProcessGuid": ctx.guid(), "targetProcessId": ctx.pid(), "targetImage": target,
        "newThreadId": ctx.pid(), "startAddress": "0x" + ctx.hexstr(12).upper(), "startModule": "-",
        "startFunction": "-", "sourceUser": user_of(host, user), "targetUser": user_of(host, user),
    })


def process_access(
    ctx: Ctx, host: Host, at: datetime, *, source: str, target: str, access: str, user: str,
) -> Body:
    """Sysmon event 10 (process access)."""
    trace = ("C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+2c13e|"
             f"{source}+{ctx.hexstr(5)}")
    return sysmon(ctx, host, at, 10, {
        "sourceProcessGUID": ctx.guid(), "sourceProcessId": ctx.pid(), "sourceThreadId": ctx.pid(),
        "sourceImage": source, "targetProcessGUID": ctx.guid(), "targetProcessId": "712",
        "targetImage": target, "grantedAccess": access, "callTrace": trace,
        "sourceUser": user_of(host, user), "targetUser": "NT AUTHORITY\\SYSTEM",
    })


def file_create(ctx: Ctx, host: Host, at: datetime, *, image: str, target: str, user: str) -> Body:
    """Sysmon event 11 (file created)."""
    return sysmon(ctx, host, at, 11, {
        "processGuid": ctx.guid(), "processId": ctx.pid(), "image": image, "targetFilename": target,
        "creationUtcTime": at.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "user": user_of(host, user),
    })


def registry_set(ctx: Ctx, host: Host, at: datetime, *, image: str, key: str, details: str, user: str) -> Body:
    """Sysmon event 13 (registry value set)."""
    return sysmon(ctx, host, at, 13, {
        "eventType": "SetValue", "processGuid": ctx.guid(), "processId": ctx.pid(), "image": image,
        "targetObject": key, "details": details, "user": user_of(host, user),
    })


def wmi_consumer(ctx: Ctx, host: Host, at: datetime, *, name: str, destination: str, user: str) -> Body:
    """Sysmon event 20 (WMI event consumer registered)."""
    return sysmon(ctx, host, at, 20, {
        "eventType": "WmiConsumerEvent", "operation": "Created", "user": user_of(host, user),
        "name": f"\"{name}\"", "type": "Command Line", "destination": destination,
    })


def security(ctx: Ctx, host: Host, at: datetime, event_id: int, eventdata: Dict[str, str], *, ok: bool = True) -> Body:
    """A Security channel event (Microsoft-Windows-Security-Auditing)."""
    system = _system(ctx, host, at, provider="Microsoft-Windows-Security-Auditing", guid=SECURITY_GUID,
                     event_id=event_id, channel="Security", level="0",
                     severity="AUDIT_SUCCESS" if ok else "AUDIT_FAILURE",
                     keywords="0x8020000000000000" if ok else "0x8010000000000000",
                     task={4624: "12544", 4625: "12544", 4634: "12545", 4769: "14337", 4720: "13824",
                           4732: "13826", 4728: "13826", 4725: "13824", 4740: "13824", 4767: "13824",
                           4616: "12288"}.get(event_id, "0"))
    return _win_body(system, eventdata)


def sid(rid: int) -> str:
    return f"S-1-5-21-3623811015-3361044348-30300820-{rid}"


def logon(
    ctx: Ctx, host: Host, at: datetime, *, user: str, src_ip: str, workstation: str, logon_type: int = 3,
    ok: bool = True, kerberos: bool = False, status: str = "0xc000006d", sub_status: str = "0xc000006a",
) -> Body:
    """4624 / 4625."""
    data = {
        "subjectUserSid": "S-1-0-0", "subjectUserName": "-", "subjectDomainName": "-", "subjectLogonId": "0x0",
        "targetUserSid": sid(1100 + sum(map(ord, user)) % 800) if ok else "S-1-0-0", "targetUserName": user,
        "targetDomainName": DOMAIN, "logonType": str(logon_type),
        "logonProcessName": "Kerberos" if kerberos else "NtLmSsp ",
        "authenticationPackageName": "Kerberos" if kerberos else "NTLM", "workstationName": workstation,
        "transmittedServices": "-", "lmPackageName": "-" if kerberos else "NTLM V2", "keyLength": "0" if kerberos else "128",
        "processId": "0x0", "processName": "-", "ipAddress": src_ip, "ipPort": ctx.port(),
    }
    if ok:
        data.update(targetLogonId=ctx.logon_id(), logonGuid=ctx.guid(), impersonationLevel="%%1833",
                    virtualAccount="%%1843", elevatedToken="%%1842")
    else:
        data.update(failureReason="%%2313", status=status, subStatus=sub_status)
    return security(ctx, host, at, 4624 if ok else 4625, data, ok=ok)


def service_ticket(ctx: Ctx, host: Host, at: datetime, *, user: str, service: str, src_ip: str, rc4: bool) -> Body:
    """4769 on a domain controller."""
    return security(ctx, host, at, 4769, {
        "targetUserName": f"{user}@{DOMAIN}.EXAMPLE.COM", "targetDomainName": f"{DOMAIN}.EXAMPLE.COM",
        "serviceName": service, "serviceSid": sid(2200 + sum(map(ord, service)) % 300),
        "ticketOptions": "0x40810000" if rc4 else "0x40810010", "ticketEncryptionType": "0x17" if rc4 else "0x12",
        "ipAddress": f"::ffff:{src_ip}", "ipPort": ctx.port(), "status": "0x0", "logonGuid": ctx.guid(),
        "transmittedServices": "-",
    })


def account_event(ctx: Ctx, host: Host, at: datetime, event_id: int, *, actor: str, target: str, **extra: str) -> Body:
    """4720 / 4722 / 4725 / 4738 / 4740 / 4767 user account management."""
    data = {"targetUserName": target, "targetDomainName": host.name if host.role == "workstation" else DOMAIN,
            "targetSid": sid(1500 + sum(map(ord, target)) % 400), "subjectUserSid": sid(1001),
            "subjectUserName": actor, "subjectDomainName": DOMAIN, "subjectLogonId": ctx.logon_id()}
    data.update(extra)
    return security(ctx, host, at, event_id, data)


def group_member_added(
    ctx: Ctx, host: Host, at: datetime, *, actor: str, member: str, group: str, group_sid: str, event_id: int = 4732,
) -> Body:
    """4732 (local group) / 4728 (global group) member added."""
    return security(ctx, host, at, event_id, {
        "memberName": f"CN={member},OU=Users,DC=corp,DC=example,DC=com", "memberSid": sid(1500 + sum(map(ord, member)) % 400),
        "targetUserName": group, "targetDomainName": "Builtin" if group_sid.startswith("S-1-5-32") else DOMAIN,
        "targetSid": group_sid, "subjectUserSid": sid(1001), "subjectUserName": actor, "subjectDomainName": DOMAIN,
        "subjectLogonId": ctx.logon_id(), "privilegeList": "-",
    })


def log_cleared(ctx: Ctx, host: Host, at: datetime, *, user: str) -> Body:
    """1102: the Security log was cleared."""
    system = _system(ctx, host, at, provider="Microsoft-Windows-Eventlog",
                     guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}", event_id=1102, channel="Security",
                     severity="INFORMATION", task="104", keywords="0x4020000000000000", version="0")
    return _win_body(system, {"subjectUserSid": sid(1001), "subjectUserName": user, "subjectDomainName": DOMAIN,
                              "subjectLogonId": ctx.logon_id()})


def service_installed(
    ctx: Ctx, host: Host, at: datetime, *, name: str, image: str, start: str = "demand start",
    account: str = "LocalSystem",
) -> Body:
    """System 7045: a service was installed."""
    system = _system(ctx, host, at, provider="Service Control Manager",
                     guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}", event_id=7045, channel="System",
                     severity="INFORMATION", keywords="0x8080000000000000")
    return _win_body(system, {"serviceName": name, "imagePath": image, "serviceType": "user mode service",
                              "startType": start, "accountName": account})


def service_start_type(ctx: Ctx, host: Host, at: datetime, *, display: str, name: str, old: str, new: str) -> Body:
    """System 7040: a service start type was changed."""
    system = _system(ctx, host, at, provider="Service Control Manager",
                     guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}", event_id=7040, channel="System",
                     severity="INFORMATION", keywords="0x8080000000000000")
    return _win_body(system, {"param1": display, "param2": old, "param3": new, "param4": name})


def msi_installed(ctx: Ctx, host: Host, at: datetime, *, product: str) -> Body:
    """Application 11707 (MsiInstaller)."""
    system = _system(ctx, host, at, provider="MsiInstaller", guid=None, event_id=11707, channel="Application",
                     severity="INFORMATION", keywords="0x80000000000000")
    return _win_body(system, {"data": f"Product: {product} -- Installation completed successfully.",
                              "binary": "7B" + ctx.hexstr(14).upper() + "7D"})


def defender(ctx: Ctx, host: Host, at: datetime, event_id: int, eventdata: Dict[str, str], severity: str = "INFORMATION") -> Body:
    system = _system(ctx, host, at, provider="Microsoft-Windows-Windows Defender",
                     guid="{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}", event_id=event_id,
                     channel="Microsoft-Windows-Windows Defender/Operational", severity=severity,
                     level="4" if severity == "INFORMATION" else "3")
    return _win_body(system, {"product Name": "Microsoft Defender Antivirus", **eventdata})


def script_block(ctx: Ctx, host: Host, at: datetime, *, text: str, path: str = "", message: bool = False) -> Body:
    """PowerShell/Operational 4104 (script block logging)."""
    system = _system(ctx, host, at, provider="Microsoft-Windows-PowerShell",
                     guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", event_id=4104,
                     channel="Microsoft-Windows-PowerShell/Operational", severity="WARNING", level="5", task="2",
                     keywords="0x0", version="1")
    if message:  # rule 91803 reads the rendered message
        system["message"] = win(f"\"Creating Scriptblock text (1 of 1):\r\n{text}\r\n\r\nScriptBlock ID: -\"")
    return _win_body(system, {"messageNumber": "1", "messageTotal": "1", "scriptBlockText": text,
                              "scriptBlockId": ctx.guid()[1:-1], "path": path})


# ---------------------------------------------------------------------------------------------------------------------
# Linux: syslog programs, auditd, file integrity, web access logs
# ---------------------------------------------------------------------------------------------------------------------


def syslog(
    host: Host, at: datetime, *, program: str, pid: Optional[int], message: str, decoder: Dict[str, str],
    data: Optional[Dict[str, str]] = None, location: str = "/var/log/auth.log",
) -> Body:
    tag = f"{program}[{pid}]" if pid is not None else program
    stamp = syslog_stamp(at)
    body: Body = {
        "full_log": f"{stamp} {host.name} {tag}: {message}",
        "predecoder": {"program_name": program, "timestamp": stamp, "hostname": host.name},
        "decoder": decoder,
        "location": location,
    }
    if data:
        body["data"] = data
    return body


def sshd(host: Host, at: datetime, pid: int, message: str, data: Dict[str, str]) -> Body:
    """An sshd line; ``{port}`` in ``message`` becomes ``data["srcport"]``."""
    message = message.replace("{port}", data.get("srcport", ""))
    return syslog(host, at, program="sshd", pid=pid, message=message, decoder={"parent": "sshd", "name": "sshd"},
                  data=data)


def previous(lines: Sequence[str]) -> str:
    return "\n".join(lines)


def pam_session(host: Host, at: datetime, pid: int, user: str, uid: int, service: str = "sshd") -> Body:
    return syslog(host, at, program=service, pid=pid,
                  message=f"pam_unix({service}:session): session opened for user {user}(uid={uid}) by (uid=0)",
                  decoder={"parent": "pam", "name": "pam"}, data={"dstuser": user, "uid": str(uid)})


def sudo(host: Host, at: datetime, user: str, command: str, cwd: str, tty: str = "pts/0") -> Body:
    return syslog(host, at, program="sudo", pid=None,
                  message=f"  {user} : TTY={tty} ; PWD={cwd} ; USER=root ; COMMAND={command}",
                  decoder={"parent": "sudo", "name": "sudo"},
                  data={"srcuser": user, "tty": tty, "pwd": cwd, "dstuser": "root", "command": command})


def useradd(host: Host, at: datetime, pid: int, user: str, uid: int, shell: str = "/bin/bash") -> Body:
    return syslog(host, at, program="useradd", pid=pid,
                  message=f"new user: name={user}, UID={uid}, GID={uid}, home=/home/{user}, shell={shell}, from=/dev/pts/1",
                  decoder={"parent": "useradd", "name": "useradd"},
                  data={"dstuser": user, "uid": str(uid), "gid": str(uid), "home": f"/home/{user}", "shell": shell},
                  location="/var/log/auth.log")


def crontab(host: Host, at: datetime, pid: int, user: str) -> Body:
    return syslog(host, at, program="crontab", pid=pid, message=f"({user}) REPLACE ({user})",
                  decoder={"name": "crontab"}, data={"dstuser": user}, location="/var/log/syslog")


def dpkg(host: Host, at: datetime, package: str, version: str, arch: str = "amd64") -> Body:
    line = f"{at:%Y-%m-%d %H:%M:%S} status installed {package}:{arch} {version}"
    return {"full_log": line, "decoder": {"name": "dpkg-decoder"},
            "data": {"dpkg_status": "status installed", "package": package, "arch": arch, "version": version},
            "location": "/var/log/dpkg.log"}


def yum(host: Host, at: datetime, package: str, updated: bool) -> Body:
    verb = "Updated" if updated else "Installed"
    stamp = f"{at:%b} {at.day:02d} {at:%H:%M:%S}"
    return {"full_log": f"{stamp} {verb}: {package}", "predecoder": {"timestamp": stamp},
            "decoder": {"name": "yum"}, "location": "/var/log/yum.log"}


def audit_execve(
    ctx: Ctx, host: Host, at: datetime, *, argv: Sequence[str], exe: str, uid: int, auid: int, cwd: str,
    key: str = "audit-wazuh-c", tty: str = "pts0", success: bool = True,
) -> Body:
    """auditd SYSCALL + EXECVE for one command (the Wazuh audit rule set's ``audit-wazuh-c`` key)."""
    serial = f"{at.timestamp():.3f}:{ctx.rng.randrange(1000, 99999)}"
    pid, ppid = ctx.rng.randrange(2000, 60000), ctx.rng.randrange(1000, 60000)
    command = argv[0].rsplit("/", 1)[-1][:15]
    audit: Dict[str, Any] = {
        "type": "SYSCALL", "id": serial.split(":")[1], "syscall": "59", "exit": "0", "ppid": str(ppid),
        "pid": str(pid), "auid": str(auid), "uid": str(uid), "gid": str(uid), "euid": str(uid), "suid": str(uid),
        "fsuid": str(uid), "egid": str(uid), "sgid": str(uid), "fsgid": str(uid), "tty": tty,
        "session": str(ctx.rng.randrange(1, 400)), "command": command, "exe": exe, "key": key,
        "success": "yes" if success else "no", "cwd": cwd,
        "execve": {f"a{i}": arg for i, arg in enumerate(argv)},
    }
    args = " ".join(f'a{i}="{arg}"' for i, arg in enumerate(argv))
    full = (f"type=SYSCALL msg=audit({serial}): arch=c000003e syscall=59 success={audit['success']} exit=0 "
            f"ppid={ppid} pid={pid} auid={auid} uid={uid} gid={uid} euid={uid} suid={uid} fsuid={uid} egid={uid} "
            f"sgid={uid} fsgid={uid} tty={tty} ses={audit['session']} comm=\"{command}\" exe=\"{exe}\" "
            f"key=\"{key}\" type=EXECVE msg=audit({serial}): argc={len(argv)} {args} "
            f"type=CWD msg=audit({serial}): cwd=\"{cwd}\"")
    return {"full_log": full, "decoder": {"parent": "auditd", "name": "auditd"}, "data": {"audit": audit},
            "location": "/var/log/audit/audit.log"}


def audit_watch(
    ctx: Ctx, host: Host, at: datetime, *, path: str, exe: str, uid: int, auid: int, key: str, syscall: str = "257",
) -> Body:
    """auditd file watch hit (``-w path -p ...`` rule)."""
    serial = f"{at.timestamp():.3f}:{ctx.rng.randrange(1000, 99999)}"
    command = exe.rsplit("/", 1)[-1][:15]
    audit = {"type": "SYSCALL", "id": serial.split(":")[1], "syscall": syscall, "exit": "3", "pid": str(ctx.rng.randrange(2000, 60000)),
             "auid": str(auid), "uid": str(uid), "euid": str(uid), "command": command, "exe": exe, "key": key,
             "success": "yes", "file": {"name": path, "mode": "0100640"}, "cwd": "/root" if uid == 0 else "/tmp"}
    full = (f"type=SYSCALL msg=audit({serial}): arch=c000003e syscall={syscall} success=yes exit=3 auid={auid} "
            f"uid={uid} euid={uid} comm=\"{command}\" exe=\"{exe}\" key=\"{key}\" type=PATH msg=audit({serial}): "
            f"item=0 name=\"{path}\" mode=0100640")
    return {"full_log": full, "decoder": {"parent": "auditd", "name": "auditd"}, "data": {"audit": audit},
            "location": "/var/log/audit/audit.log"}


def fim(
    ctx: Ctx, host: Host, at: datetime, *, path: str, event: str, size: int, user: str = "root",
    changed: Sequence[str] = ("size", "mtime", "md5", "sha1", "sha256"), perm: str = "rw-r--r--",
    diff: Optional[str] = None, size_before: Optional[int] = None,
) -> Body:
    """File integrity monitoring (syscheck) event: added, modified or deleted."""
    key = f"{host.name}:{path}:{at.isoformat()}"
    sys: Dict[str, Any] = {"path": path, "mode": "realtime", "event": event}
    if event != "deleted":
        sys.update(size_after=str(size), perm_after=perm, uid_after="0" if user == "root" else "1001",
                   gid_after="0" if user == "root" else "1001", md5_after=digest("md5", key),
                   sha1_after=digest("sha1", key), sha256_after=digest("sha256", key), uname_after=user,
                   gname_after=user, mtime_after=at.strftime("%Y-%m-%dT%H:%M:%S"),
                   inode_after=ctx.rng.randrange(100_000, 9_000_000))
    if event == "modified":
        sys.update(size_before=str(size_before if size_before is not None else max(1, size - 40)),
                   md5_before=digest("md5", key + ":old"), sha256_before=digest("sha256", key + ":old"),
                   changed_attributes=list(changed))
    if diff:
        sys["diff"] = diff
    verb = {"added": "added", "modified": "modified", "deleted": "deleted"}[event]
    lines = [f"File '{path}' {verb}", "Mode: realtime"]
    if event == "modified":
        lines.append(f"Changed attributes: {','.join(changed)}")
    decoder = {"added": "syscheck_new_entry", "modified": "syscheck_integrity_changed",
               "deleted": "syscheck_deleted"}[event]
    return {"full_log": "\n".join(lines) + "\n", "decoder": {"name": decoder}, "syscheck": sys, "location": "syscheck"}


def access_log(
    host: Host, at: datetime, *, src_ip: str, method: str, url: str, status: int, size: int, agent: str,
    referer: str = "-",
) -> Body:
    """nginx combined access log line through the ``web-accesslog`` decoder."""
    stamp = at.strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'{src_ip} - - [{stamp}] "{method} {url} HTTP/1.1" {status} {size} "{referer}" "{agent}"'
    return {"full_log": line, "decoder": {"name": "web-accesslog"},
            "data": {"protocol": method, "srcip": src_ip, "id": str(status), "url": url},
            "location": "/var/log/nginx/access.log"}


def minutes(rng: random.Random, lo: float, hi: float) -> timedelta:
    return timedelta(seconds=rng.uniform(lo * 60, hi * 60))


def pick(rng: random.Random, options: Sequence[Any]) -> Any:
    return options[rng.randrange(len(options))]


def sample(rng: random.Random, options: Sequence[Any], k: int) -> List[Any]:
    return rng.sample(list(options), k)
