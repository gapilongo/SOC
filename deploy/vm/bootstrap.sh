#!/usr/bin/env bash
# One-time (and safe to re-run) preparation of an Ubuntu 22.04/24.04 VM for
# LG-SOTF deploys, e.g. an Oracle Cloud Always Free Ampere A1 instance
# (arm64) or any amd64 Ubuntu server. Run it as root; see docs/cicd.md.
#
#   curl -fsSLO https://raw.githubusercontent.com/gapilongo/SOC/main/deploy/vm/bootstrap.sh
#   less bootstrap.sh                      # read what you run as root
#   sudo bash bootstrap.sh --ssh-key "ssh-ed25519 AAAA... github-deploy" \
#        --public-host 203.0.113.10
#
# What it does:
#   * installs Docker Engine and the compose plugin from Docker's apt
#     repository (arm64 or amd64), with log rotation for containers;
#   * creates the `deploy` user (docker group, SSH key only, no password, no
#     sudo) and /opt/lg-sotf owned by it;
#   * firewall: allows only 22, 80 and 443 in. On Oracle's Ubuntu images,
#     which ship iptables rules ending in "REJECT --reject-with
#     icmp-host-prohibited" (and whose OUTPUT rules protect the boot volume),
#     it inserts ACCEPT rules for 80/443 before that REJECT and saves them with
#     netfilter-persistent instead of enabling ufw (which could drop the rules
#     the boot volume relies on). Elsewhere it configures ufw. You must ALSO open 80 and 443 in
#     the VCN security list or NSG (Oracle console), see the docs;
#   * SSH: key-only logins, no root password login;
#   * unattended security upgrades, a swap file, vm.overcommit_memory=1 for
#     Redis, optional fail2ban;
#   * a systemd timer that runs the nightly database backups (backup.sh);
#   * prints the DEPLOY_SSH_KNOWN_HOSTS value to paste into GitHub.
#
# Options:
#   --ssh-key "KEY"        public key allowed to log in as the deploy user
#                          (repeatable; or --ssh-key-file FILE)
#   --public-host HOST     the VM's public IP or hostname, for the known_hosts line
#   --deploy-user NAME     default: deploy
#   --swap-size SIZE       swap file size when the VM has no swap (default 4G; 0 = none)
#   --fail2ban             also install fail2ban (SSH jail)
#   --firewall MODE        auto (default), oracle-iptables, ufw or none
#   --backup-time HH:MM    nightly backup time, UTC (default 02:30)

set -euo pipefail

DEPLOY_USER="deploy"
SSH_KEYS=()
PUBLIC_HOST=""
SWAP_SIZE="4G"
FAIL2BAN=0
FIREWALL="auto"
BACKUP_TIME="02:30"
ROOT="/opt/lg-sotf"

while [ $# -gt 0 ]; do
  case "$1" in
    --ssh-key) SSH_KEYS+=("${2:-}"); shift 2 ;;
    --ssh-key-file) mapfile -t -O "${#SSH_KEYS[@]}" SSH_KEYS < <(grep -v '^[[:space:]]*\(#\|$\)' "${2:?}"); shift 2 ;;
    --public-host) PUBLIC_HOST="${2:-}"; shift 2 ;;
    --deploy-user) DEPLOY_USER="${2:-}"; shift 2 ;;
    --swap-size) SWAP_SIZE="${2:-}"; shift 2 ;;
    --fail2ban) FAIL2BAN=1; shift ;;
    --firewall) FIREWALL="${2:-}"; shift 2 ;;
    --backup-time) BACKUP_TIME="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,37p' "$0"; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 64 ;;
  esac
done

step() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR %s\n' "$*" >&2; exit 2; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash bootstrap.sh ...)"
# shellcheck source=/dev/null
. /etc/os-release
[ "${ID:-}" = "ubuntu" ] || die "this script supports Ubuntu 22.04/24.04 (found ${PRETTY_NAME:-unknown})"
[[ "$DEPLOY_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "bad --deploy-user"
[[ "$SWAP_SIZE" =~ ^[0-9]+[MG]?$ ]] || die "bad --swap-size (e.g. 4G)"
[[ "$FIREWALL" =~ ^(auto|oracle-iptables|ufw|none)$ ]] || die "bad --firewall"
[[ "$BACKUP_TIME" =~ ^[0-2][0-9]:[0-5][0-9]$ ]] || die "bad --backup-time (HH:MM)"
[ -z "$PUBLIC_HOST" ] || [[ "$PUBLIC_HOST" =~ ^[A-Za-z0-9.:-]+$ ]] || die "bad --public-host"
for key in "${SSH_KEYS[@]}"; do
  [[ "$key" =~ ^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa|sk-ssh-ed25519@openssh.com)\ [A-Za-z0-9+/=]+(\ .*)?$ ]] \
    || die "--ssh-key must be one public key line (ssh-ed25519 AAAA... comment)"
done
ARCH="$(dpkg --print-architecture)"
[[ "$ARCH" =~ ^(arm64|amd64)$ ]] || die "unsupported architecture $ARCH"

export DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
step "base packages"
apt-get update -q
apt-get install -y -q ca-certificates curl gnupg unattended-upgrades apt-transport-https util-linux

# ---------------------------------------------------------------------------
step "firewall"
ORACLE_RULES=/etc/iptables/rules.v4
if [ "$FIREWALL" = "auto" ]; then
  if [ -f "$ORACLE_RULES" ] && grep -q -- '-A INPUT -j REJECT --reject-with icmp-host-prohibited' "$ORACLE_RULES"; then
    FIREWALL="oracle-iptables"
  else
    FIREWALL="ufw"
  fi
fi
echo "firewall mode: $FIREWALL"

oracle_open_port() {  # $1 proto, $2 port
  local rule="-p $1 -m state --state NEW -m $1 --dport $2 -j ACCEPT"
  # Persistent: insert the rule just before the INPUT REJECT in rules.v4.
  if ! grep -q -- "-A INPUT $rule" "$ORACLE_RULES"; then
    sed -i "0,/^-A INPUT -j REJECT --reject-with icmp-host-prohibited/s//-A INPUT $rule\n&/" "$ORACLE_RULES"
  fi
  # Live: insert before the REJECT without flushing (a flush would also drop
  # Docker's chains). The rule number of the REJECT is where it goes.
  # shellcheck disable=SC2086  # $rule is a list of iptables words
  if ! iptables -C INPUT $rule 2>/dev/null; then
    local pos
    pos="$(iptables -L INPUT --line-numbers -n | awk '$2 == "REJECT" {print $1; exit}')"
    # shellcheck disable=SC2086
    if [ -n "$pos" ]; then iptables -I INPUT "$pos" $rule; else iptables -A INPUT $rule; fi
  fi
}

case "$FIREWALL" in
  oracle-iptables)
    apt-get install -y -q iptables-persistent netfilter-persistent
    cp -n "$ORACLE_RULES" "$ORACLE_RULES.lgsotf-orig" || true
    oracle_open_port tcp 80
    oracle_open_port tcp 443
    oracle_open_port udp 443
    # Docker adds its own chains at start; make sure the saved rules are
    # restored first so Docker's are never flushed by a later restore.
    mkdir -p /etc/systemd/system/docker.service.d
    printf '[Unit]\nAfter=netfilter-persistent.service\nWants=netfilter-persistent.service\n' \
      > /etc/systemd/system/docker.service.d/10-after-netfilter.conf
    echo "INPUT now accepts 22, 80, 443 (tcp) and 443 (udp); everything else is still rejected."
    ;;
  ufw)
    apt-get install -y -q ufw
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    ufw allow 22/tcp >/dev/null
    ufw allow 80/tcp >/dev/null
    ufw allow 443/tcp >/dev/null
    ufw allow 443/udp >/dev/null
    ufw --force enable >/dev/null
    ufw status verbose
    echo "Note: Docker-published ports bypass ufw; the stack publishes only Caddy's 80/443."
    ;;
  none) echo "firewall left unchanged" ;;
esac

# ---------------------------------------------------------------------------
step "Docker Engine and compose plugin (Docker's apt repository, $ARCH)"
install -d -m 0755 /etc/apt/keyrings
if [ ! -s /etc/apt/keyrings/docker.asc ]; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
fi
echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME:-$VERSION_CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -q
apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

install -d -m 0755 /etc/docker
DAEMON_JSON='{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "5" },
  "live-restore": true
}'
if [ ! -f /etc/docker/daemon.json ] || [ "$(cat /etc/docker/daemon.json)" != "$DAEMON_JSON" ]; then
  [ ! -f /etc/docker/daemon.json ] || cp /etc/docker/daemon.json "/etc/docker/daemon.json.bak.$(date +%s)"
  printf '%s\n' "$DAEMON_JSON" > /etc/docker/daemon.json
  systemctl daemon-reload
  systemctl restart docker
fi
systemctl enable --now docker >/dev/null
docker version --format 'docker {{.Server.Version}} ({{.Server.Arch}})'
docker compose version

# ---------------------------------------------------------------------------
step "deploy user ($DEPLOY_USER)"
if ! id "$DEPLOY_USER" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "$DEPLOY_USER"
fi
usermod -aG docker "$DEPLOY_USER"
passwd -l "$DEPLOY_USER" >/dev/null
HOME_DIR="$(getent passwd "$DEPLOY_USER" | cut -d: -f6)"
install -d -m 0700 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$HOME_DIR/.ssh"
AUTH="$HOME_DIR/.ssh/authorized_keys"
touch "$AUTH"
for key in "${SSH_KEYS[@]}"; do
  grep -qxF "$key" "$AUTH" || printf '%s\n' "$key" >> "$AUTH"
done
chown "$DEPLOY_USER:$DEPLOY_USER" "$AUTH"
chmod 0600 "$AUTH"
[ -s "$AUTH" ] || echo "WARNING: $AUTH is empty; re-run with --ssh-key \"<public key>\" before the first deploy"
install -d -m 0750 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$ROOT" "$ROOT/env" "$ROOT/bin" "$ROOT/backups"
echo "The docker group is root-equivalent on this host: protect the deploy key like a root key."

# ---------------------------------------------------------------------------
step "SSH: key-only logins"
cat > /etc/ssh/sshd_config.d/60-lgsotf.conf <<'EOF'
# Written by LG-SOTF bootstrap.sh
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PermitEmptyPasswords no
EOF
if sshd -t; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
else
  rm -f /etc/ssh/sshd_config.d/60-lgsotf.conf
  echo "WARNING: sshd rejected the hardening drop-in; left SSH unchanged"
fi

# ---------------------------------------------------------------------------
step "unattended security upgrades"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
echo "Security updates install daily; reboot when /var/run/reboot-required exists (not automatic)."

# ---------------------------------------------------------------------------
step "swap and kernel settings"
if [ "$SWAP_SIZE" = "0" ]; then
  echo "skipped (--swap-size 0)"
elif swapon --noheadings --show | grep -q .; then
  echo "swap already active: $(swapon --noheadings --show=NAME,SIZE | tr '\n' ' ')"
else
  if [ ! -f /swapfile ]; then
    fallocate -l "$SWAP_SIZE" /swapfile
    chmod 0600 /swapfile
    mkswap /swapfile >/dev/null
  fi
  swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo "swap on /swapfile ($SWAP_SIZE)"
fi
# Redis (AOF rewrites fork) warns and may fail background saves without overcommit.
printf 'vm.swappiness=10\nvm.overcommit_memory=1\n' > /etc/sysctl.d/60-lgsotf.conf
sysctl -q --system >/dev/null || true

# ---------------------------------------------------------------------------
if [ "$FAIL2BAN" -eq 1 ]; then
  step "fail2ban (SSH jail)"
  apt-get install -y -q fail2ban
  cat > /etc/fail2ban/jail.d/lgsotf-sshd.local <<'EOF'
[sshd]
enabled = true
maxretry = 5
findtime = 10m
bantime = 1h
EOF
  systemctl enable --now fail2ban >/dev/null
  systemctl restart fail2ban
fi

# ---------------------------------------------------------------------------
step "nightly backups (systemd timer, $BACKUP_TIME UTC)"
cat > /etc/systemd/system/lgsotf-backup.service <<EOF
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
cat > /etc/systemd/system/lgsotf-backup.timer <<EOF
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
systemctl list-timers lgsotf-backup.timer --no-pager | head -n 2

# ---------------------------------------------------------------------------
step "done"
echo "Paste this as the DEPLOY_SSH_KNOWN_HOSTS secret of each GitHub environment on this VM:"
echo
host="${PUBLIC_HOST:-<VM_PUBLIC_IP>}"
for pub in /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ecdsa_key.pub /etc/ssh/ssh_host_rsa_key.pub; do
  [ -f "$pub" ] && printf '%s %s\n' "$host" "$(cut -d' ' -f1,2 "$pub")"
done
echo
echo "Next: open 80/443 in the VCN security list, point your hostname at this VM,"
echo "create the GitHub environments and run the Deploy workflow (docs/cicd.md)."
