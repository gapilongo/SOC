#!/usr/bin/env bash
# Read-only health report of this PC as the LG-SOTF dev/uat host
# (docs/self-hosting-pc.md). Needs no sudo and changes nothing:
#
#   bash deploy/pc/check-host.sh
#   bash deploy/pc/check-host.sh --env dev --no-public
#
# It reports: the WSL version and the always-on settings (.wslconfig, the
# Windows task 'LG-SOTF WSL keepalive'); free space on C:, where the WSL disk
# lives (a loud warning under 10 GB); Docker; Tailscale (connected, tailnet
# IPv4, tags) and whether Tailscale for Windows also runs; that SSH listens
# only on the tailnet address; and per environment the Tailscale sidecar, its
# Funnel status and https://<name>/healthz from the internet side.
#
# Options:
#   --env NAME     only this environment (repeatable; default: dev and uat)
#   --no-public    skip the public https://<name>/healthz requests
#   -h, --help     show this text
#
# Exit status: 0 when nothing needs attention (warnings allowed), 1 otherwise.

set -euo pipefail

MIN_FREE_GB="${LGSOTF_MIN_FREE_GB:-10}"
C_MOUNT="${LGSOTF_C_MOUNT:-/mnt/c}"
TASK_NAME="LG-SOTF WSL keepalive"
HOST_TAG="tag:lgsotf-host"
HOST_NAME="lgsotf-pc"
ENVS=()
PUBLIC=1

usage() { awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --env)
      if [ $# -lt 2 ] || ! [[ "$2" =~ ^[a-z][a-z0-9]{0,11}$ ]]; then
        printf 'ERROR: --env needs an environment name (dev, uat)\n' >&2
        exit 64
      fi
      ENVS+=("$2"); shift 2 ;;
    --no-public) PUBLIC=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'ERROR: unknown argument: %s (see --help)\n' "$1" >&2; exit 64 ;;
  esac
done
[ "${#ENVS[@]}" -gt 0 ] || ENVS=(dev uat)
[[ "$MIN_FREE_GB" =~ ^[0-9]{1,4}$ ]] || MIN_FREE_GB=10

FAILS=0
WARNS=0
section() { printf '\n%s\n' "$*"; }
ok() { printf '  OK    %s\n' "$*"; }
note() { printf '  --    %s\n' "$*"; }
warn() { printf '  WARN  %s\n' "$*"; WARNS=$((WARNS + 1)); }
fail() { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }
have() { command -v "$1" >/dev/null 2>&1; }
gib() { awk -v b="$1" 'BEGIN { printf "%.1f GB", b / 1073741824 }'; }
avail_bytes() { df -B1 --output=avail "$1" 2>/dev/null | awk 'NR == 2 { print $1 }'; }

# ------------------------------------------------------------------ Windows side (one read-only query)
declare -A WIN=()
POWERSHELL=""
if have powershell.exe; then
  POWERSHELL="powershell.exe"
elif [ -x "$C_MOUNT/Windows/System32/WindowsPowerShell/v1.0/powershell.exe" ]; then
  POWERSHELL="$C_MOUNT/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
fi
DISTRO="${WSL_DISTRO_NAME:-Ubuntu}"
[[ "$DISTRO" =~ ^[A-Za-z0-9._-]+$ ]] || DISTRO="Ubuntu"
PS_QUERY="$(cat <<'PS'
$ErrorActionPreference = 'SilentlyContinue'
"USERPROFILE=$env:USERPROFILE"
$t = Get-ScheduledTask -TaskName '@TASK@'
if ($t) {
  $i = Get-ScheduledTaskInfo -TaskName '@TASK@'
  "TASK_STATE=$($t.State)"
  "TASK_LOGON=$($t.Principal.LogonType)"
  "TASK_LAST_RESULT=$($i.LastTaskResult)"
  if ($i.LastRunTime) { "TASK_LAST_RUN=$($i.LastRunTime.ToString('yyyy-MM-dd HH:mm'))" }
  if ($i.NextRunTime) { "TASK_NEXT_RUN=$($i.NextRunTime.ToString('yyyy-MM-dd HH:mm'))" }
} else { 'TASK_STATE=missing' }
$s = Get-Service -Name Tailscale
if ($s) { "WIN_TAILSCALE=$($s.Status)" } else { 'WIN_TAILSCALE=absent' }
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' | ForEach-Object {
  $p = Get-ItemProperty $_.PSPath
  if ($p.DistributionName -eq '@DISTRO@') {
    $vhd = 'ext4.vhdx'
    if ($p.VhdFileName) { $vhd = $p.VhdFileName }
    $path = Join-Path ($p.BasePath -replace '^\\\\\?\\', '') $vhd
    "VHD_PATH=$path"
    "VHD_BYTES=$((Get-Item -LiteralPath $path).Length)"
  }
}
PS
)"
PS_QUERY="${PS_QUERY//@TASK@/$TASK_NAME}"
PS_QUERY="${PS_QUERY//@DISTRO@/$DISTRO}"
if [ -n "$POWERSHELL" ]; then
  encoded="$(printf '%s' "$PS_QUERY" | iconv -f UTF-8 -t UTF-16LE | base64 -w 0)"
  while IFS= read -r line; do
    line="${line%$'\r'}"
    [[ "$line" =~ ^[A-Z_]+= ]] || continue
    WIN["${line%%=*}"]="${line#*=}"
  done < <(cd "$C_MOUNT" 2>/dev/null || cd /; timeout 60 "$POWERSHELL" -NoProfile -NonInteractive -EncodedCommand "$encoded" 2>/dev/null || true)
fi

# ------------------------------------------------------------------ WSL
section "WSL"
if grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then
  version="$(wslinfo --version 2>/dev/null || true)"
  case "$version" in
    3.0.1|3.0.1.*) warn "WSL $version: known session-0 regression (microsoft/WSL#41110) can break the keepalive task; use 2.5.9 or 2.7.14" ;;
    '') note "WSL version unknown (wslinfo not found)" ;;
    *) ok "WSL $version, $(wslinfo --networking-mode 2>/dev/null || echo '?') networking, up $(uptime -p 2>/dev/null | sed 's/^up //')" ;;
  esac
else
  warn "not running under WSL (kernel $(uname -r))"
fi
if [ "$(ps -p 1 -o comm= 2>/dev/null)" = "systemd" ]; then
  ok "systemd is PID 1"
else
  fail "systemd is not PID 1: set [boot] systemd=true in /etc/wsl.conf"
fi

WSLCONFIG=""
if [ -n "${WIN[USERPROFILE]:-}" ] && have wslpath; then
  WSLCONFIG="$(wslpath -u "${WIN[USERPROFILE]}" 2>/dev/null || true)/.wslconfig"
fi
if [ -z "$WSLCONFIG" ]; then
  warn "cannot reach Windows (powershell.exe) to read .wslconfig and the keepalive task"
elif [ ! -f "$WSLCONFIG" ]; then
  fail "no .wslconfig in your Windows profile: WSL stops shortly after the last terminal closes (docs step 4)"
else
  idle="$(awk '
    { line = $0; sub(/\r$/, "", line) }
    line ~ /^[ \t]*\[/ { section = tolower(line); gsub(/[][ \t]/, "", section); next }
    section == "general" {
      n = index(line, "="); if (n == 0) next
      key = tolower(substr(line, 1, n - 1)); gsub(/[ \t]/, "", key)
      val = substr(line, n + 1); gsub(/[ \t]/, "", val)
      if (key == "instanceidletimeout") print val
    }' "$WSLCONFIG" | tail -n 1)"
  if [ "$idle" = "-1" ]; then
    ok ".wslconfig: [general] instanceIdleTimeout=-1 (the distribution never idles out)"
  else
    fail ".wslconfig has no [general] instanceIdleTimeout=-1: WSL stops ~15 s after the last terminal closes"
  fi
fi
case "${WIN[TASK_STATE]:-}" in
  '') ;;
  missing) fail "Windows task '$TASK_NAME' is not registered: run deploy/pc/windows-setup.ps1 (docs step 4)" ;;
  Disabled) warn "Windows task '$TASK_NAME' is disabled (maintenance mode?): Enable-ScheduledTask in an elevated PowerShell" ;;
  *)
    result="${WIN[TASK_LAST_RESULT]:-}"
    detail="state ${WIN[TASK_STATE]}, logon ${WIN[TASK_LOGON]:-?}, last run ${WIN[TASK_LAST_RUN]:-never} (result ${result:-?}), next ${WIN[TASK_NEXT_RUN]:-?}"
    if [ "${WIN[TASK_LOGON]:-}" != "S4U" ]; then
      warn "Windows task '$TASK_NAME' does not run as S4U ($detail); re-run windows-setup.ps1"
    elif [ "$result" = "0" ] || [ "$result" = "267009" ] || [ "$result" = "267011" ]; then
      ok "Windows task '$TASK_NAME': $detail"
    else
      warn "Windows task '$TASK_NAME' last failed: $detail (docs: troubleshooting)"
    fi ;;
esac

# ------------------------------------------------------------------ disk
section "Disk"
c_free="$(avail_bytes "$C_MOUNT" || true)"
if [[ "$c_free" =~ ^[0-9]+$ ]]; then
  if [ "$c_free" -lt $((MIN_FREE_GB * 1073741824)) ]; then
    fail "C: has only $(gib "$c_free") free (keep at least $MIN_FREE_GB GB)"
    cat <<EOF
  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  !!  C: IS NEARLY FULL: $(gib "$c_free") free. The WSL disk, and with it every
  !!  database, lives on C:. When C: fills up, WSL and Docker stop and data can
  !!  be corrupted. Free space now (docs/self-hosting-pc.md, "Disk space").
  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
EOF
  else
    ok "C: has $(gib "$c_free") free (keep at least $MIN_FREE_GB GB)"
  fi
else
  warn "cannot read the free space of C: ($C_MOUNT not mounted?)"
fi
if [[ "${WIN[VHD_BYTES]:-}" =~ ^[0-9]+$ ]]; then
  note "WSL disk ${WIN[VHD_PATH]:-ext4.vhdx}: $(gib "${WIN[VHD_BYTES]}") on C: (grows with data, never shrinks by itself)"
fi
root_free="$(avail_bytes / || true)"
if [[ "$root_free" =~ ^[0-9]+$ ]]; then note "inside WSL: $(gib "$root_free") free in / (virtual; C: is the real limit)"; fi

# ------------------------------------------------------------------ Docker
section "Docker"
DOCKER_OK=0
if ! have docker; then
  fail "docker is not installed: sudo bash deploy/pc/install-docker.sh"
elif docker info >/dev/null 2>&1; then
  DOCKER_OK=1
  ok "docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?') is running, $(docker ps -q 2>/dev/null | wc -l) containers up"
  while read -r name subnets; do
    for subnet in $subnets; do
      if [[ "$subnet" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] || [[ "$subnet" =~ ^192\.168\. ]]; then
        warn "docker network $name uses $subnet, which can collide with WSL's NAT network or your LAN"
      fi
    done
  done < <(docker network ls -q 2>/dev/null | xargs -r docker network inspect \
             --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null || true)
elif systemctl is-active --quiet docker 2>/dev/null; then
  warn "docker runs but this shell cannot use it (not in the docker group yet: open a new WSL terminal)"
else
  fail "the docker service is not running: sudo systemctl start docker"
fi

# ------------------------------------------------------------------ Tailscale
section "Tailscale (this PC)"
TS_IP=""
if ! have tailscale; then
  fail "tailscale is not installed: sudo bash deploy/pc/setup-host.sh"
else
  IFS='|' read -r backend tags dnsname TS_IP <<<"$( { tailscale status --json 2>/dev/null || true; } | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    d = {}
s = d.get("Self") or {}
ipv4 = [ip for ip in (s.get("TailscaleIPs") or []) if ":" not in ip]
print("|".join([d.get("BackendState") or "stopped", ",".join(s.get("Tags") or []),
                (s.get("DNSName") or "").rstrip("."), ipv4[0] if ipv4 else ""]))
')"
  if [ "$backend" = "Running" ]; then
    ok "connected as ${dnsname:-?}, tailnet address ${TS_IP:-?}"
  else
    fail "tailscaled is not connected (state: $backend): sudo tailscale up, or re-run setup-host.sh"
  fi
  if [[ ",$tags," == *",$HOST_TAG,"* ]]; then
    ok "tagged $HOST_TAG"
  else
    fail "not tagged $HOST_TAG (tags: ${tags:-none}): GitHub's deploy job may not reach SSH"
  fi
  if [ -n "$dnsname" ] && [ "${dnsname%%.*}" != "$HOST_NAME" ]; then
    warn "machine name is ${dnsname%%.*}, not $HOST_NAME (an old $HOST_NAME exists in the admin console?)"
  fi
fi
case "${WIN[WIN_TAILSCALE]:-}" in
  Running) warn "Tailscale for Windows is RUNNING on this PC: quit it and set the 'Tailscale' service to Manual" ;;
  Stopped) ok "Tailscale for Windows is installed but not running (keep it that way)" ;;
  absent) ok "Tailscale for Windows is not installed" ;;
esac

# ------------------------------------------------------------------ SSH
section "SSH"
listeners="$(ss -Hltn 'sport = :22' 2>/dev/null | awk '{ print $4 }' | sort -u | tr '\n' ' ' || true)"
listeners="${listeners% }"
if [ -z "$listeners" ]; then
  fail "nothing listens on port 22: sudo bash deploy/pc/setup-host.sh"
elif [ -n "$TS_IP" ] && [ "$listeners" = "$TS_IP:22" ]; then
  ok "sshd listens only on $TS_IP:22"
elif [ -n "$TS_IP" ]; then
  fail "port 22 is open on $listeners; expected only $TS_IP:22 (re-run setup-host.sh)"
else
  warn "port 22 is open on $listeners (tailnet address unknown)"
fi
timer="$(systemctl is-enabled lgsotf-backup.timer 2>/dev/null || true)"
if [ "$timer" = "enabled" ]; then ok "nightly backups: lgsotf-backup.timer enabled"; else warn "lgsotf-backup.timer is not enabled (setup-host.sh installs it)"; fi

# ------------------------------------------------------------------ environments
for env in "${ENVS[@]}"; do
  section "Environment $env (compose project lgsotf-$env)"
  if [ "$DOCKER_OK" -ne 1 ]; then
    note "skipped: docker is not available to this shell"
    continue
  fi
  containers="$(docker ps -a --filter "label=com.docker.compose.project=lgsotf-$env" \
    --format '{{.Label "com.docker.compose.service"}}={{.State}}' 2>/dev/null | sort | tr '\n' ' ' || true)"
  if [ -z "$containers" ]; then
    note "not deployed"
    continue
  fi
  note "containers: ${containers% }"
  cid="$(docker ps -a -q --filter "label=com.docker.compose.project=lgsotf-$env" \
    --filter "label=com.docker.compose.service=ts" 2>/dev/null | sed -n 1p || true)"
  if [ -z "$cid" ]; then
    note "no Tailscale sidecar (this environment does not use Funnel)"
    continue
  fi
  state="$(docker inspect --format '{{.State.Status}}' "$cid" 2>/dev/null || true)"
  if [ "$state" != "running" ]; then
    fail "the ts sidecar is ${state:-missing}: docker logs $(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | tr -d /)"
    continue
  fi
  # Only TS_SOCKET is read from the container's environment (which also holds TS_AUTHKEY).
  sock="$(docker inspect --format '{{range .Config.Env}}{{if eq (index (split . "=") 0) "TS_SOCKET"}}{{index (split . "=") 1}}{{end}}{{end}}' "$cid" 2>/dev/null || true)"
  sock="${sock:-/tmp/tailscaled.sock}"
  IFS='|' read -r backend dnsname <<<"$( { docker exec "$cid" tailscale --socket="$sock" status --json 2>/dev/null || true; } | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    d = {}
print((d.get("BackendState") or "unknown") + "|" + ((d.get("Self") or {}).get("DNSName") or "").rstrip("."))
')"
  if [ "$backend" != "Running" ]; then
    fail "the ts sidecar is not logged in (state: $backend): see 'Troubleshooting' (auth key)"
    continue
  fi
  ok "ts sidecar logged in as $dnsname"
  if [ "${dnsname%%.*}" != "soc-$env" ]; then
    warn "the node is called ${dnsname%%.*}, not soc-$env: its state volume was lost (docs: troubleshooting)"
  fi
  funnel="$(docker exec "$cid" tailscale --socket="$sock" funnel status 2>&1 || true)"
  if [[ "$funnel" == *"(Funnel on)"* ]]; then
    ok "Funnel is on"
  else
    fail "Funnel is not on for this node:"
  fi
  printf '%s\n' "$funnel" | sed -e '/^[[:space:]]*$/d' -e 's/^/          /'
  if [ "$PUBLIC" -eq 1 ] && [ -n "$dnsname" ]; then
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "https://$dnsname/healthz" 2>/dev/null || true)"
    if [ "$code" = "200" ]; then
      ok "https://$dnsname/healthz answers 200 through Funnel"
    else
      warn "https://$dnsname/healthz answered '${code:-nothing}' (a new Funnel name can take ~10 minutes to resolve)"
    fi
  fi
done

section "Summary"
if [ "$FAILS" -gt 0 ]; then
  printf '  %s problem(s) and %s warning(s). See docs/self-hosting-pc.md, Troubleshooting.\n' "$FAILS" "$WARNS"
  exit 1
fi
printf '  No problems (%s warning(s)).\n' "$WARNS"
