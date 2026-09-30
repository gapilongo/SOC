#!/usr/bin/env bash
# Prepare this WSL2 Ubuntu on your Windows PC to receive LG-SOTF deploys from
# GitHub Actions over your tailnet (docs/self-hosting-pc.md, step 3). Run it
# from your normal account; it is safe to run again at any time:
#
#   sudo bash deploy/pc/setup-host.sh
#   sudo bash deploy/pc/setup-host.sh --auth-key-file ~/tskey-host   # no browser login
#
# What it does:
#   * checks that Docker Engine is installed (deploy/pc/install-docker.sh);
#   * installs Tailscale from pkgs.tailscale.com (signing key fingerprint
#     pinned), starts tailscaled and joins your tailnet as "lgsotf-pc" with the
#     tag tag:lgsotf-host and --accept-dns=false (WSL keeps its own DNS). It
#     prints a login URL to open in your Windows browser, unless you give an
#     auth key file;
#   * installs OpenSSH server and makes it listen ONLY on this machine's
#     tailnet address, for the "deploy" user only, with a key only (no
#     passwords, no root). Ubuntu starts sshd through ssh.socket; the socket
#     gets FreeBind=yes so it can bind the tailnet address at boot before
#     tailscaled has brought it up;
#   * creates the "deploy" user (no password, docker group) and /opt/lg-sotf;
#   * creates the GitHub deploy key pair in ~/.config/lg-sotf/deploy_ed25519
#     (your account, 0600) and authorizes it for the deploy user from tailnet
#     addresses only, with "restrict" (no terminal, no forwarding; it can still
#     run any command as deploy, which is root-equivalent through docker);
#   * writes ~/.config/lg-sotf/known_hosts, deploy_host and tailnet for
#     configure-github.sh, then tests the SSH login end to end;
#   * installs the nightly database backup timer (/opt/lg-sotf/bin/backup.sh,
#     installed by the first deploy) and vm.overcommit_memory=1 for Redis.
#
# Options:
#   --auth-key-file PATH   log in with a Tailscale auth key read from PATH
#                          (handed to tailscale as --auth-key=file:PATH, so the
#                          key never appears in a process list)
#   --backup-time HH:MM    nightly backup time, UTC (default 02:30)
#   -h, --help             show this text
#
# Nothing secret is printed. Do not run the Tailscale app for Windows at the
# same time: this WSL node is the PC's Tailscale node.

set -euo pipefail
umask 022

TS_TAG="tag:lgsotf-host"
TS_HOSTNAME="lgsotf-pc"
TS_KEY_FINGERPRINT="2596A99EAAB33821893C0A79458CA832957F5868"
TS_KEYRING="/usr/share/keyrings/tailscale-archive-keyring.gpg"
TS_SOURCE="/etc/apt/sources.list.d/tailscale.list"
TAILNET_CIDR="100.64.0.0/10"
DEPLOY_USER="deploy"
ROOT="/opt/lg-sotf"
KEY_COMMENT="lgsotf-github-deploy"
SSHD_DROPIN="/etc/ssh/sshd_config.d/60-lgsotf.conf"
SOCKET_DROPIN="/etc/systemd/system/ssh.socket.d/60-lgsotf.conf"
SERVICE_DROPIN="/etc/systemd/system/ssh.service.d/60-lgsotf.conf"
UBUNTU_SOCKET_SHIM="/etc/systemd/system/ssh.service.d/00-socket.conf"
SYSCTL_CONF="/etc/sysctl.d/60-lgsotf.conf"

AUTH_KEY_FILE=""
BACKUP_TIME="02:30"

step() { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
usage() { awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; }
need_value() { [ "$2" -ge 2 ] || { printf 'ERROR: %s needs a value\n' "$1" >&2; exit 64; }; }

while [ $# -gt 0 ]; do
  case "$1" in
    --auth-key-file) need_value "$1" $#; AUTH_KEY_FILE="$2"; shift 2 ;;
    --backup-time) need_value "$1" $#; BACKUP_TIME="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'ERROR: unknown argument: %s (see --help)\n' "$1" >&2; exit 64 ;;
  esac
done

# ------------------------------------------------------------------ checks
[ "$(id -u)" -eq 0 ] || die "run it with sudo from your normal account: sudo bash $0"
OWNER="${SUDO_USER:-}"
if [ -z "$OWNER" ] || [ "$OWNER" = "root" ]; then
  die "run it through sudo from your normal account (the deploy key goes to that account's ~/.config/lg-sotf)"
fi
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
OWNER_GROUP="$(id -gn "$OWNER")"
[ -d "$OWNER_HOME" ] || die "home directory of $OWNER not found"
CONFIG_DIR="$OWNER_HOME/.config/lg-sotf"
KEY="$CONFIG_DIR/deploy_ed25519"

# shellcheck source=/dev/null
. /etc/os-release
[ "${ID:-}" = "ubuntu" ] || die "this script supports Ubuntu (found ${PRETTY_NAME:-unknown})"
CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
[[ "$CODENAME" =~ ^[a-z]+$ ]] || die "cannot tell the Ubuntu release codename"
[ "$(ps -p 1 -o comm=)" = "systemd" ] \
  || die "systemd is not PID 1: set [boot] systemd=true in /etc/wsl.conf, then run 'wsl --shutdown' in Windows"
if ! grep -qi microsoft /proc/sys/kernel/osrelease; then
  warn "this does not look like WSL; continuing anyway"
fi
[[ "$BACKUP_TIME" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "--backup-time must be HH:MM (UTC)"
if [ -n "$AUTH_KEY_FILE" ]; then
  if [ ! -f "$AUTH_KEY_FILE" ] || [ ! -r "$AUTH_KEY_FILE" ]; then die "cannot read --auth-key-file $AUTH_KEY_FILE"; fi
  AUTH_KEY_FILE="$(realpath "$AUTH_KEY_FILE")"
  grep -q '^tskey-' "$AUTH_KEY_FILE" || die "$AUTH_KEY_FILE does not contain a Tailscale auth key (tskey-...)"
  case "$(stat -c %a "$AUTH_KEY_FILE")" in
    ?00) ;;
    *) warn "$AUTH_KEY_FILE is readable by other users; chmod 600 it (or delete it after this run)" ;;
  esac
fi

# write_file PATH MODE [OWNER:GROUP] < content
# Replaces PATH atomically when the content differs. Sets WROTE=1 if it did.
WROTE=0
write_file() {
  local path="$1" mode="$2" owner="${3:-root:root}" tmp
  tmp="$(mktemp "$path.XXXXXX")" || die "cannot write $path"
  cat > "$tmp" || die "cannot write $path"
  if [ -f "$path" ] && cmp -s "$tmp" "$path"; then
    rm -f "$tmp"
    WROTE=0
  else
    mv -f "$tmp" "$path" || die "cannot write $path"
    WROTE=1
  fi
  chmod "$mode" "$path"
  chown "$owner" "$path"
}

APT_UPDATED=0
apt_install() {
  local missing=() pkg
  for pkg in "$@"; do
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
      missing+=("$pkg")
    fi
  done
  [ "${#missing[@]}" -gt 0 ] || return 0
  export DEBIAN_FRONTEND=noninteractive
  if [ "$APT_UPDATED" -eq 0 ]; then
    apt-get update -q
    APT_UPDATED=1
  fi
  apt-get install -y -q "${missing[@]}"
}

# ------------------------------------------------------------------ Docker
step "Docker"
command -v docker >/dev/null || die "Docker is not installed: run  sudo bash deploy/pc/install-docker.sh  first"
getent group docker >/dev/null || die "the docker group does not exist: re-run deploy/pc/install-docker.sh"
systemctl is-active --quiet docker || die "the docker service is not running (systemctl status docker)"
docker compose version >/dev/null 2>&1 || die "the docker compose plugin is missing: re-run deploy/pc/install-docker.sh"
info "$(docker version --format 'docker {{.Server.Version}}'), $(docker compose version --short 2>/dev/null | sed 's/^/compose /')"

# ------------------------------------------------------------------ Tailscale
step "Tailscale (pkgs.tailscale.com, Ubuntu $CODENAME)"
apt_install ca-certificates curl gnupg python3

keyring_ok() {  # $1: keyring file; true when its primary key is Tailscale's
  local home fpr
  [ -s "$1" ] || return 1
  home="$(mktemp -d)"
  fpr="$(gpg --homedir "$home" --batch --quiet --show-keys --with-colons "$1" 2>/dev/null \
    | awk -F: '$1 == "fpr" { print $10; exit }')" || true
  rm -rf "$home"
  [ "$fpr" = "$TS_KEY_FINGERPRINT" ]
}

if ! keyring_ok "$TS_KEYRING"; then
  tmpdir="$(mktemp -d)"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$tmpdir/key.gpg" \
    "https://pkgs.tailscale.com/stable/ubuntu/$CODENAME.noarmor.gpg" \
    || die "cannot download the Tailscale signing key for Ubuntu $CODENAME (see https://pkgs.tailscale.com/stable/)"
  keyring_ok "$tmpdir/key.gpg" || die "the downloaded Tailscale key does not have the expected fingerprint $TS_KEY_FINGERPRINT"
  install -d -m 0755 "$(dirname "$TS_KEYRING")"
  install -m 0644 "$tmpdir/key.gpg" "$TS_KEYRING"
  rm -rf "$tmpdir"
  info "signing key installed ($TS_KEY_FINGERPRINT)"
fi
write_file "$TS_SOURCE" 0644 <<EOF
# Tailscale packages for ubuntu $CODENAME (written by LG-SOTF deploy/pc/setup-host.sh)
deb [signed-by=$TS_KEYRING] https://pkgs.tailscale.com/stable/ubuntu $CODENAME main
EOF
[ "$WROTE" -eq 0 ] || APT_UPDATED=0
apt_install tailscale
systemctl enable --now tailscaled >/dev/null
info "$(tailscale version | sed -n 1p)"

ts_state() {  # prints: backend|tags|dns name|tailnet dns suffix|tailnet IPv4
  { tailscale status --json 2>/dev/null || true; } | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    d = {}
s = d.get("Self") or {}
t = d.get("CurrentTailnet") or {}
ipv4 = [ip for ip in (s.get("TailscaleIPs") or []) if ":" not in ip]
print("|".join([
    d.get("BackendState") or "",
    ",".join(s.get("Tags") or []),
    (s.get("DNSName") or "").rstrip("."),
    t.get("MagicDNSSuffix") or d.get("MagicDNSSuffix") or "",
    ipv4[0] if ipv4 else "",
]))
'
}

IFS='|' read -r TS_BACKEND TS_TAGS TS_DNSNAME TS_SUFFIX TS_IP <<<"$(ts_state)"
if [ "$TS_BACKEND" = "Running" ] && [[ ",$TS_TAGS," == *",$TS_TAG,"* ]]; then
  info "already connected as ${TS_DNSNAME:-$TS_HOSTNAME} ($TS_TAG)"
  tailscale set --hostname="$TS_HOSTNAME" --accept-dns=false
else
  up_args=(up --reset "--advertise-tags=$TS_TAG" "--hostname=$TS_HOSTNAME" --accept-dns=false --timeout=15m)
  if [ -n "$AUTH_KEY_FILE" ]; then
    up_args+=("--auth-key=file:$AUTH_KEY_FILE")
    info "logging in with the auth key in $AUTH_KEY_FILE"
  else
    info "Open the login URL printed below in your Windows browser and sign in to your tailnet."
    info "(Your account must own $TS_TAG: paste the tailnet policy from docs/self-hosting-pc.md, step 2, first.)"
  fi
  tailscale "${up_args[@]}" \
    || die "tailscale up failed. 'requested tags are invalid or not permitted' means the tailnet policy (docs/self-hosting-pc.md, step 2) is not saved yet"
fi

TS_IP=""
for _ in $(seq 1 30); do
  IFS='|' read -r TS_BACKEND TS_TAGS TS_DNSNAME TS_SUFFIX TS_IP <<<"$(ts_state)"
  [ -z "$TS_IP" ] || break
  sleep 2
done
[[ "$TS_IP" =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}$ ]] \
  || die "no tailnet IPv4 address after 60 s (state: ${TS_BACKEND:-unknown}); check 'tailscale status'"
[[ ",$TS_TAGS," == *",$TS_TAG,"* ]] \
  || die "this node is not tagged $TS_TAG (tags: ${TS_TAGS:-none}); fix the tailnet policy and re-run"
info "tailnet address $TS_IP (${TS_DNSNAME:-no MagicDNS name})"
if [ -n "$TS_DNSNAME" ] && [ "${TS_DNSNAME%%.*}" != "$TS_HOSTNAME" ]; then
  warn "this machine is called ${TS_DNSNAME%%.*} in your tailnet because another machine already uses $TS_HOSTNAME;"
  warn "remove the old one in the admin console (Machines) and rename this one to $TS_HOSTNAME"
fi

win_tailscale_running() {
  local sc="/mnt/c/Windows/System32/sc.exe" out
  [ -x "$sc" ] || return 1
  out="$(timeout 15 "$sc" query Tailscale 2>/dev/null || true)"
  [[ "$out" == *RUNNING* ]]
}
if win_tailscale_running; then
  warn "Tailscale for Windows is running on this PC. Quit it (tray icon > Exit) and set the 'Tailscale'"
  warn "Windows service to Manual: two Tailscale nodes on one PC break the routing to this WSL node."
fi

# ------------------------------------------------------------------ deploy user
step "Deploy user ($DEPLOY_USER) and $ROOT"
if ! id "$DEPLOY_USER" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash --user-group "$DEPLOY_USER"
  info "created user $DEPLOY_USER"
fi
usermod -aG docker "$DEPLOY_USER"
passwd -l "$DEPLOY_USER" >/dev/null
DEPLOY_HOME="$(getent passwd "$DEPLOY_USER" | cut -d: -f6)"
install -d -m 0750 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$ROOT" "$ROOT/env" "$ROOT/bin" "$ROOT/backups"
info "no password, groups: $(id -nG "$DEPLOY_USER" | tr ' ' ',') (the docker group is root-equivalent: guard the deploy key)"

# ------------------------------------------------------------------ deploy key
step "GitHub deploy key ($KEY)"
[ -d "$OWNER_HOME/.config" ] || install -d -m 0700 -o "$OWNER" -g "$OWNER_GROUP" "$OWNER_HOME/.config"
install -d -m 0700 -o "$OWNER" -g "$OWNER_GROUP" "$CONFIG_DIR"
if [ ! -f "$KEY" ]; then
  rm -f "$KEY.pub"
  runuser -u "$OWNER" -- ssh-keygen -q -t ed25519 -N '' -C "$KEY_COMMENT" -f "$KEY"
  info "generated a new key pair"
fi
if [ ! -s "$KEY.pub" ]; then
  runuser -u "$OWNER" -- ssh-keygen -y -f "$KEY" > "$KEY.pub" || die "$KEY is not a readable private key"
fi
chown "$OWNER:$OWNER_GROUP" "$KEY" "$KEY.pub"
chmod 0600 "$KEY"
chmod 0644 "$KEY.pub"
PUBKEY="$(cut -d' ' -f1,2 "$KEY.pub")"
[[ "$PUBKEY" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+$ ]] || die "$KEY.pub is not an ed25519 public key"

install -d -m 0700 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$DEPLOY_HOME/.ssh"
AUTHORIZED="$DEPLOY_HOME/.ssh/authorized_keys"
touch "$AUTHORIZED"
# Replace this script's line (and any other line with the same key); keep the rest.
awk -v blob="${PUBKEY#* }" -v mark=" $KEY_COMMENT" \
  'index($0, blob) == 0 && substr($0, length($0) - length(mark) + 1) != mark' "$AUTHORIZED" \
  > "$AUTHORIZED.new"
printf 'restrict,from="%s" %s %s\n' "$TAILNET_CIDR" "$PUBKEY" "$KEY_COMMENT" >> "$AUTHORIZED.new"
write_file "$AUTHORIZED" 0600 "$DEPLOY_USER:$DEPLOY_USER" < "$AUTHORIZED.new"
rm -f "$AUTHORIZED.new"
info "authorized for $DEPLOY_USER from $TAILNET_CIDR only (restrict: no terminal, no port/agent/X11 forwarding;"
info "it can still run commands as $DEPLOY_USER, which is root-equivalent through docker)"

# ------------------------------------------------------------------ SSH
step "OpenSSH: only $TS_IP:22, only $DEPLOY_USER, keys only"
install -d -m 0755 /etc/ssh/sshd_config.d "$(dirname "$SOCKET_DROPIN")"
# Without this drop-in sshd falls back to Ubuntu's defaults (every address,
# password logins), so a rejected new version must never leave none behind.
SSHD_BACKUP=""
if [ -f "$SSHD_DROPIN" ]; then
  SSHD_BACKUP="$SSHD_DROPIN.bak"
  cp -p "$SSHD_DROPIN" "$SSHD_BACKUP"
fi
write_file "$SSHD_DROPIN" 0644 <<EOF
# Written by LG-SOTF deploy/pc/setup-host.sh (docs/self-hosting-pc.md):
# only the GitHub deploy job, over the tailnet, as the deploy user, with its key.
ListenAddress $TS_IP
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers $DEPLOY_USER@$TAILNET_CIDR
EOF
write_file "$SOCKET_DROPIN" 0644 <<'EOF'
# Written by LG-SOTF deploy/pc/setup-host.sh: bind the tailnet address even
# before tailscaled has brought it up at boot. Ubuntu's ssh.socket sets this
# too; the drop-in keeps it if the packaged unit ever stops doing so.
[Socket]
FreeBind=yes
EOF
apt_install openssh-server

# sshd -t and -T stop at a missing privilege separation directory, and systemd
# deletes /run/sshd whenever ssh.service stops.
install -d -m 0755 -o root -g root /run/sshd
if ! SSHD_CHECK="$(sshd -t 2>&1)"; then
  if [ -n "$SSHD_BACKUP" ]; then
    mv -f "$SSHD_BACKUP" "$SSHD_DROPIN"
    die "sshd -t failed: ${SSHD_CHECK:-no message} (restored the previous $SSHD_DROPIN; SSH was not restarted)"
  fi
  die "sshd -t failed: ${SSHD_CHECK:-no message} ($SSHD_DROPIN is kept, so SSH stays closed rather than open to passwords; SSH was not restarted)"
fi
[ -z "$SSHD_BACKUP" ] || rm -f "$SSHD_BACKUP"
EFFECTIVE="$(sshd -T -C "user=$DEPLOY_USER,host=github-runner,addr=100.64.0.1")" \
  || die "sshd -T could not print the effective configuration (see the message above)"
for expected in "passwordauthentication no" "kbdinteractiveauthentication no" "permitrootlogin no" \
                "allowusers $DEPLOY_USER@$TAILNET_CIDR"; do
  grep -qxF "$expected" <<<"$EFFECTIVE" \
    || die "sshd does not end up with '$expected': another file in /etc/ssh/sshd_config.d sets it first (the first value wins)"
done
LISTEN_CONFIG="$(awk '$1 == "listenaddress" { print $2 }' <<<"$EFFECTIVE" | sort -u | tr '\n' ' ')"
[ "$LISTEN_CONFIG" = "$TS_IP:22 " ] \
  || die "sshd would listen on: ${LISTEN_CONFIG:-nothing} (expected only $TS_IP:22); remove other ListenAddress lines in /etc/ssh"

listeners() { ss -Hltn 'sport = :22' | awk '{ print $4 }' | sort -u | tr '\n' ' '; }
listening_only_on_tailnet() {
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    [ "$(listeners)" != "$TS_IP:22 " ] || return 0
    sleep "$((i > 3 ? 2 : 1))"
  done
  return 1
}

use_service_mode() {
  info "running sshd as ssh.service (no socket activation)"
  systemctl disable --now ssh.socket >/dev/null 2>&1 || true
  if [ -f "$UBUNTU_SOCKET_SHIM" ]; then
    rm -f "$UBUNTU_SOCKET_SHIM"
    info "removed $UBUNTU_SOCKET_SHIM (Ubuntu's socket-activation link)"
  fi
  install -d -m 0755 "$(dirname "$SERVICE_DROPIN")"
  write_file "$SERVICE_DROPIN" 0644 <<EOF
# Written by LG-SOTF deploy/pc/setup-host.sh: sshd binds the tailnet address,
# which appears only after tailscaled has started. Wait up to 60 s for it, and
# retry every 5 s after that. The empty RestartPreventExitStatus= clears
# Ubuntu's 255, the status sshd exits with when it cannot bind, which would
# otherwise stop the retries.
[Unit]
After=tailscaled.service
Wants=tailscaled.service
StartLimitIntervalSec=0

[Service]
ExecStartPre=/usr/bin/timeout 60 /bin/sh -c 'until /usr/bin/ip -4 -o addr show | /usr/bin/grep -qF " inet $TS_IP/"; do sleep 1; done'
Restart=on-failure
RestartPreventExitStatus=
RestartSec=5s
EOF
  systemctl daemon-reload
  systemctl enable ssh.service >/dev/null 2>&1 || die "cannot enable ssh.service (systemctl status ssh.service)"
  systemctl restart ssh.service
}

SSH_MODE="socket"
if [ -f "$SERVICE_DROPIN" ] || ! systemctl cat ssh.socket >/dev/null 2>&1; then SSH_MODE="service"; fi
if [ "$SSH_MODE" = "socket" ]; then
  # The ssh.socket generator turns ListenAddress into the socket's ListenStream.
  systemctl daemon-reload
  systemctl enable ssh.socket >/dev/null 2>&1 || die "cannot enable ssh.socket (systemctl status ssh.socket)"
  systemctl stop ssh.service >/dev/null 2>&1 || true
  systemctl restart ssh.socket
  if ! listening_only_on_tailnet; then
    warn "ssh.socket listens on '$(listeners)' instead of $TS_IP:22 only; falling back to ssh.service"
    SSH_MODE="service"
    use_service_mode
  fi
else
  use_service_mode
fi
listening_only_on_tailnet \
  || die "port 22 is open on '$(listeners)' instead of $TS_IP:22 only; check 'systemctl status ssh.socket ssh.service'"
info "listening on $TS_IP:22 only (ssh.$SSH_MODE)"

# ------------------------------------------------------------------ files for configure-github.sh
step "Files for GitHub ($CONFIG_DIR)"
SCAN="$(ssh-keyscan -t ed25519 -T 10 "$TS_IP" 2>/dev/null | awk '$1 !~ /^#/ && $2 == "ssh-ed25519"' | sed -n 1p)"
[ -n "$SCAN" ] || die "ssh-keyscan got no ed25519 host key from $TS_IP:22"
[ "${SCAN#* }" = "$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)" ] \
  || die "the host key served on $TS_IP:22 is not this machine's /etc/ssh/ssh_host_ed25519_key"
write_file "$CONFIG_DIR/known_hosts" 0644 "$OWNER:$OWNER_GROUP" <<<"$SCAN"
write_file "$CONFIG_DIR/deploy_host" 0644 "$OWNER:$OWNER_GROUP" <<<"$TS_IP"
if [[ "$TS_SUFFIX" =~ ^[a-z0-9-]+\.ts\.net$ ]]; then
  write_file "$CONFIG_DIR/tailnet" 0644 "$OWNER:$OWNER_GROUP" <<<"$TS_SUFFIX"
else
  warn "MagicDNS looks off (no tailnet DNS name); enable MagicDNS and HTTPS certificates (docs step 2)"
fi

REMOTE_DOCKER="$(runuser -u "$OWNER" -- ssh -F /dev/null -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$CONFIG_DIR/known_hosts" -o ConnectTimeout=15 \
  "$DEPLOY_USER@$TS_IP" "docker version --format '{{.Server.Version}}'" 2>&1)" \
  || die "the SSH test login failed: $REMOTE_DOCKER"
info "SSH test login as $DEPLOY_USER@$TS_IP: ok (docker $REMOTE_DOCKER)"

# ------------------------------------------------------------------ backups and Redis
step "Nightly backups ($BACKUP_TIME UTC) and kernel settings"
write_file /etc/systemd/system/lgsotf-backup.service 0644 <<EOF
[Unit]
Description=LG-SOTF PostgreSQL backups (all environments)
After=docker.service
Requires=docker.service
ConditionPathExists=$ROOT/bin/backup.sh

[Service]
Type=oneshot
User=$DEPLOY_USER
Group=$DEPLOY_USER
ExecStart=$ROOT/bin/backup.sh --all --root $ROOT
Nice=10
IOSchedulingClass=idle
EOF
write_file /etc/systemd/system/lgsotf-backup.timer 0644 <<EOF
[Unit]
Description=Nightly LG-SOTF database backups

[Timer]
OnCalendar=*-*-* $BACKUP_TIME:00 UTC
RandomizedDelaySec=10m
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now lgsotf-backup.timer >/dev/null
# Redis forks for its background saves and fails them without overcommit.
write_file "$SYSCTL_CONF" 0644 <<'EOF'
vm.overcommit_memory=1
EOF
sysctl -q -p "$SYSCTL_CONF" >/dev/null || warn "could not apply $SYSCTL_CONF now; it applies at the next start"
info "lgsotf-backup.timer enabled (runs once a deploy has installed $ROOT/bin/backup.sh)"

# ------------------------------------------------------------------ summary
cat <<EOF

==> Done
    Tailnet address   $TS_IP (${TS_DNSNAME:-$TS_HOSTNAME}, $TS_TAG)
    Tailnet name      ${TS_SUFFIX:-unknown (enable MagicDNS)}
    SSH               $TS_IP:22 only, user $DEPLOY_USER, key only (ssh.$SSH_MODE)
    Deploy key        $KEY
                      (private; configure-github.sh uploads it to GitHub, never share it elsewhere)
    For GitHub        $CONFIG_DIR/known_hosts, deploy_host, tailnet

Next (docs/self-hosting-pc.md):
  4. In an elevated Windows PowerShell: deploy/pc/windows-setup.ps1, then restart WSL as it explains.
  5. gh auth login, then:
       bash deploy/pc/configure-github.sh --env dev --admin-email you@example.com
  Check the host at any time with: bash deploy/pc/check-host.sh

Do not run the Tailscale app for Windows at the same time as this WSL node.
EOF
