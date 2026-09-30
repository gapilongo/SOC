#!/usr/bin/env bash
# Install Docker Engine inside WSL2 Ubuntu for self-hosting LG-SOTF on this PC
# (docs/self-hosting-pc.md, step 1). Run once, as root:
#
#   sudo bash deploy/pc/install-docker.sh
#
# What it does (idempotent):
#   * installs docker-ce, containerd, buildx and the compose plugin from
#     Docker's official apt repository (not Docker Desktop, not get.docker.com);
#   * writes /etc/docker/daemon.json: log rotation, live-restore, and address
#     pools in 10.200.0.0/15 so Docker never collides with WSL's NAT range
#     (inside 172.16.0.0/12, changes between restarts) or a 192.168.x LAN;
#   * caps the systemd journal at 200 MB (the disk lives on the C: drive);
#   * enables docker and containerd under systemd;
#   * adds the invoking user to the docker group (root-equivalent; inside WSL
#     that user can already run `wsl -u root`, so this adds no new power).

set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run with sudo: sudo bash $0"
# shellcheck source=/dev/null
. /etc/os-release
[ "${ID:-}" = "ubuntu" ] || die "this script supports Ubuntu (found ${PRETTY_NAME:-unknown})"
grep -qi microsoft /proc/sys/kernel/osrelease || echo "note: this does not look like WSL; continuing anyway"
[ "$(ps -p 1 -o comm=)" = "systemd" ] || die "systemd is not PID 1; set [boot] systemd=true in /etc/wsl.conf and run 'wsl --shutdown'"
TARGET_USER="${SUDO_USER:-}"
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then die "run through sudo from your normal account"; fi

CODENAME="${UBUNTU_CODENAME:-$VERSION_CODENAME}"
ARCH="$(dpkg --print-architecture)"

for pkg in docker.io docker-compose docker-compose-v2 docker-doc podman-docker containerd runc; do
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    die "conflicting package '$pkg' is installed; remove it first (apt remove $pkg)"
  fi
done

echo "== Docker apt repository ($CODENAME, $ARCH)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
if [ ! -s /etc/apt/keyrings/docker.asc ]; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
fi
cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $CODENAME
Components: stable
Architectures: $ARCH
Signed-By: /etc/apt/keyrings/docker.asc
EOF
apt-get update -q
apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "== /etc/docker/daemon.json"
install -d -m 0755 /etc/docker
DAEMON_JSON='{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "5" },
  "live-restore": true,
  "bip": "10.200.0.1/24",
  "default-address-pools": [ { "base": "10.201.0.0/16", "size": 24 } ]
}'
if [ ! -f /etc/docker/daemon.json ] || [ "$(cat /etc/docker/daemon.json)" != "$DAEMON_JSON" ]; then
  [ ! -f /etc/docker/daemon.json ] || cp /etc/docker/daemon.json "/etc/docker/daemon.json.bak.$(date +%s)"
  printf '%s\n' "$DAEMON_JSON" > /etc/docker/daemon.json
  RESTART_DOCKER=1
fi

echo "== journald cap"
install -d -m 0755 /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=200M\n' > /etc/systemd/journald.conf.d/60-lgsotf.conf
systemctl restart systemd-journald

echo "== services"
systemctl enable --now containerd docker >/dev/null
[ -z "${RESTART_DOCKER:-}" ] || systemctl restart docker

echo "== docker group"
usermod -aG docker "$TARGET_USER"

echo "== check"
docker version --format 'docker {{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}})'
docker compose version
if iptables -t nat -S DOCKER >/dev/null 2>&1; then
  echo "iptables NAT chain: ok"
else
  echo "warning: no DOCKER nat chain; see docs/self-hosting-pc.md (iptables-legacy fallback)"
fi
if docker run --rm hello-world >/dev/null; then
  echo "hello-world container: ok"
else
  echo "warning: could not run the hello-world container (no internet access to Docker Hub?)"
fi

cat <<EOF

Docker is installed. '$TARGET_USER' was added to the docker group; it applies to
new WSL terminals only (open a new one; Ubuntu 26.04 has no 'newgrp' unless the
util-linux-extra package is installed).
EOF
