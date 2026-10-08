#!/usr/bin/env bash
# RC UDP Proxy installer for Debian (12 "bookworm" / 13 "trixie").
#
# Installs Docker Engine + compose plugin and git, fetches the project from
# GitHub, builds the image and starts the container. Re-running the script
# updates an existing installation to the latest code (configuration in
# <install dir>/data is kept).
#
#   curl -fsSL https://raw.githubusercontent.com/thedayowl/RC-Udp-Proxy/main/install.sh | sudo bash
#
# Optional environment variables:
#   INSTALL_DIR     install location            (default /opt/rc-udp-proxy)
#   REPO_URL        git repository              (default https://github.com/thedayowl/RC-Udp-Proxy.git)
#   BRANCH          branch to deploy            (default main)
#   ADMIN_PASSWORD  initial web UI password     (default: prompt, or generate one)
#   WEB_PORT        web UI port                 (default 8080)
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/rc-udp-proxy}"
REPO_URL="${REPO_URL:-https://github.com/thedayowl/RC-Udp-Proxy.git}"
BRANCH="${BRANCH:-main}"
WEB_PORT="${WEB_PORT:-8080}"
CONTAINER=rc-udp-proxy

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- checks
[ "$(id -u)" -eq 0 ] || die "run as root (e.g. sudo bash install.sh)"
[ -r /etc/os-release ] || die "cannot detect OS (/etc/os-release missing)"
. /etc/os-release
[ "${ID:-}" = "debian" ] || die "this installer supports Debian only (found '${ID:-unknown}')"
CODENAME="${VERSION_CODENAME:-}"
case "$CODENAME" in
  bookworm|trixie) ;;
  *) warn "untested Debian release '${CODENAME:-unknown}', continuing anyway" ;;
esac

export DEBIAN_FRONTEND=noninteractive

start_service() {
  # systemd on real hosts; SysV init script as a fallback (e.g. containers)
  if [ -d /run/systemd/system ]; then
    systemctl enable --now "$1" >/dev/null
  else
    service "$1" start >/dev/null || true
  fi
}

# ---------------------------------------------------------- prerequisites
info "Installing base packages"
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg git openssl iproute2 >/dev/null

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  info "Installing Docker Engine from download.docker.com"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian ${CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
else
  info "Docker already installed ($(docker --version))"
fi

start_service docker
for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
docker info >/dev/null 2>&1 || die "Docker daemon is not running"

# ------------------------------------------------------------ fetch code
if [ -d "$INSTALL_DIR/.git" ]; then
  info "Updating existing installation in $INSTALL_DIR"
  git -C "$INSTALL_DIR" fetch -q origin "$BRANCH"
  git -C "$INSTALL_DIR" checkout -q "$BRANCH"
  git -C "$INSTALL_DIR" reset -q --hard "origin/$BRANCH"
else
  [ -e "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ] \
    && die "$INSTALL_DIR exists and is not a git checkout; move it away or set INSTALL_DIR"
  info "Cloning $REPO_URL into $INSTALL_DIR"
  git clone -q --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"
install -d -m 0700 data

# ---------------------------------------------------------- environment
GENERATED_PW=""
if [ ! -f .env ]; then
  if [ ! -f data/config.json ]; then
    if [ -z "${ADMIN_PASSWORD:-}" ] && { : </dev/tty >/dev/tty; } 2>/dev/null; then
      while :; do
        read -r -s -p "Choose a web UI admin password (blank = generate one): " ADMIN_PASSWORD </dev/tty || true
        echo >/dev/tty
        if [ -z "$ADMIN_PASSWORD" ] || [ ${#ADMIN_PASSWORD} -ge 8 ]; then break; fi
        echo "Password must be at least 8 characters." >/dev/tty
      done
    fi
    if [ -z "${ADMIN_PASSWORD:-}" ]; then
      ADMIN_PASSWORD="$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-14)"
      GENERATED_PW="$ADMIN_PASSWORD"
    fi
  fi
  umask 077
  {
    echo "# Used only on first start; afterwards change the password in the web UI"
    echo "ADMIN_PASSWORD=${ADMIN_PASSWORD:-}"
    echo "WEB_PORT=${WEB_PORT}"
    echo "TZ=$(cat /etc/timezone 2>/dev/null || echo UTC)"
  } > .env
  umask 022
fi

# ------------------------------------------------------------ port check
ours_running=$(docker ps -q -f "name=^${CONTAINER}$")
if [ -z "$ours_running" ] && command -v ss >/dev/null 2>&1; then
  ss -lun 2>/dev/null | awk '{print $4}' | grep -qE '[:.]5060$' \
    && warn "UDP port 5060 is already in use; phones will not reach the proxy until it is freed (or change the SIP port in Settings)"
  ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${WEB_PORT}\$" \
    && die "TCP port ${WEB_PORT} is in use; set WEB_PORT to another port"
fi

# ------------------------------------------------------------- build/run
info "Building image and starting container (this can take a minute)"
docker compose up -d --build --remove-orphans

info "Waiting for the proxy to come up"
ok=""
for _ in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${WEB_PORT}/" || true)
  if [ "$code" = "401" ] || [ "$code" = "200" ]; then ok=1; break; fi
  sleep 1
done
[ -n "$ok" ] || { docker compose logs --tail=50; die "web UI did not come up on port ${WEB_PORT}"; }
docker image prune -f >/dev/null 2>&1 || true

LAN_IP=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}' || true)
LAN_IP=${LAN_IP:-$(hostname -I 2>/dev/null | awk '{print $1}' || true)}
LAN_IP=${LAN_IP:-<this-host-ip>}

cat <<EOF

RC UDP Proxy is running.

  Web UI:        http://${LAN_IP}:${WEB_PORT}/   (user: admin)
EOF
if [ -n "$GENERATED_PW" ]; then
  echo "  Password:      ${GENERATED_PW}   (generated - note it down, then change it in Settings)"
elif [ -f data/config.json ] && [ -z "${ADMIN_PASSWORD:-}" ]; then
  echo "  Password:      unchanged (existing configuration kept)"
fi
cat <<EOF
  Phones:        register to ${LAN_IP}:5060 over UDP
  Install dir:   ${INSTALL_DIR}   (configuration in ${INSTALL_DIR}/data)
  Logs:          cd ${INSTALL_DIR} && docker compose logs -f
  Update:        re-run this installer

Firewall: allow outbound TCP to the RingCentral outbound proxy and UDP for
RTP (default 20000-20999). If audio is one-way, forward that UDP range to
this host.
EOF
