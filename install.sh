#!/usr/bin/env bash
# gorecshit — one-command hardening for Remnawave VPN node servers (Debian 11+/Ubuntu 20.04+)
# Usage:
#   bash <(curl -Ls https://raw.githubusercontent.com/gorecvpn/gorecshit/main/install.sh) --panel-ip X.X.X.X
# Idempotent. No secrets. Panel IP is a required runtime parameter (never hardcoded).
set -Eeuo pipefail

VERSION="1.0.0"
SCRIPT_NAME="gorecshit"
BACKUP_ROOT="/root/hardening-backups"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TS}"
MARKER_DIR="/var/lib/gorecshit"

# Defaults
PANEL_IP=""
NODE_PORT="auto"
CLIENT_PORTS="auto"
MODE="direct"          # direct | cdn
ALLOW_SSH_FROM=""
IPV6_OFF=1
DO_BLOCKLIST=1
DO_HOSTNAME=1
TZ_OPT=""              # empty = leave; "auto" = geo; or IANA name
ASSUME_YES=0
DRY_RUN=0
DO_ROLLBACK=0

# Runtime detected
OS_ID=""
OS_VERSION=""
DETECTED_NODE_PORT=""
DETECTED_CLIENT_PORTS=()
SSH_CLIENT_IP=""
CADDY_PRESENT=0
CHANGED_DOCKER=0
QDISC="fq"

# Colors
if [[ -t 1 ]] || [[ "${FORCE_COLOR:-0}" == "1" ]]; then
  C_RESET='\033[0m'; C_RED='\033[0;31m'; C_GRN='\033[0;32m'
  C_YEL='\033[0;33m'; C_BLU='\033[0;34m'; C_CYN='\033[0;36m'; C_BOLD='\033[1m'
else
  C_RESET=''; C_RED=''; C_GRN=''; C_YEL=''; C_BLU=''; C_CYN=''; C_BOLD=''
fi

log()  { printf '%b[%s]%b %s\n' "${C_BLU}" "INFO" "${C_RESET}" "$*"; }
ok()   { printf '%b[%s]%b %s\n' "${C_GRN}" " OK " "${C_RESET}" "$*"; }
warn() { printf '%b[%s]%b %s\n' "${C_YEL}" "WARN" "${C_RESET}" "$*"; }
err()  { printf '%b[%s]%b %s\n' "${C_RED}" "ERR " "${C_RESET}" "$*" >&2; }
step() { printf '\n%b==>%b %b%s%b\n' "${C_CYN}" "${C_RESET}" "${C_BOLD}" "$*" "${C_RESET}"; }

on_error() {
  local ec=$?
  err "Failed at line ${BASH_LINENO[0]} (exit ${ec}). Backups: ${BACKUP_DIR:-n/a}"
  err "Restore with: $0 --rollback   (or run ${BACKUP_DIR}/rollback.sh if present)"
  exit "$ec"
}
trap on_error ERR

usage() {
  cat <<'EOF'
gorecshit — Remnawave VPN node hardening (Debian 11+ / Ubuntu 20.04+)

Usage:
  install.sh --panel-ip X.X.X.X [options]
  install.sh --rollback | --uninstall
  install.sh --dry-run --panel-ip X.X.X.X [options]

Required:
  --panel-ip IP              Management/panel host allowed to reach NODE_PORT

Options:
  --node-port PORT|auto      remnanode API port (default: auto from /opt/remnanode/.env)
  --client-ports LIST|auto   Comma-separated client ports (default: auto via ss)
  --mode direct|cdn          direct: open detected xray ports; cdn: open 80/443, keep internal xray closed
  --allow-ssh-from IP,...    Extra IPs always allowed (SSH ignore + never-block)
  --no-ipv6-off              Keep IPv6 enabled
  --no-blocklist             Skip scanner ipset blocklist
  --no-hostname              Do not change hostname
  --tz ZONE|auto             Set timezone (default: leave as-is). auto = IP geolocation
  --yes                      Non-interactive (still requires --panel-ip or GORECSHIT_PANEL_IP)
  --dry-run                  Print actions only; make no changes
  --rollback / --uninstall   Restore latest backup under /root/hardening-backups/
  -h, --help                 Show this help

One-liner:
  bash <(curl -Ls https://raw.githubusercontent.com/gorecvpn/gorecshit/main/install.sh) --panel-ip X.X.X.X --yes
EOF
}

is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS=.
  # shellcheck disable=SC2086
  set -- $ip
  [[ $1 -le 255 && $2 -le 255 && $3 -le 255 && $4 -le 255 ]]
}

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b %s\n' "${C_YEL}" "${C_RESET}" "$*"
    return 0
  fi
  "$@"
}

run_sh() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b sh -c %q\n' "${C_YEL}" "${C_RESET}" "$*"
    return 0
  fi
  bash -c "$*"
}

write_file() {
  # write_file <path>  (content on stdin)
  local path="$1"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b write %s (%s bytes stdin)\n' "${C_YEL}" "${C_RESET}" "$path" "$(wc -c < /dev/stdin 2>/dev/null || echo ?)"
    # consume stdin in dry-run if piped differently — caller should use write_file_content
    return 0
  fi
  local dir
  dir="$(dirname "$path")"
  mkdir -p "$dir"
  cat >"$path"
}

# Safer: content as argument via temp in real mode
write_content() {
  local path="$1"
  local content="$2"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b write %s (%d bytes)\n' "${C_YEL}" "${C_RESET}" "$path" "${#content}"
    return 0
  fi
  mkdir -p "$(dirname "$path")"
  printf '%s' "$content" >"$path"
}

backup_file() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b backup %s -> %s\n' "${C_YEL}" "${C_RESET}" "$f" "${BACKUP_DIR}${f}"
    return 0
  fi
  local dest="${BACKUP_DIR}${f}"
  mkdir -p "$(dirname "$dest")"
  cp -a "$f" "$dest"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --panel-ip) PANEL_IP="${2:-}"; shift 2 ;;
      --node-port) NODE_PORT="${2:-}"; shift 2 ;;
      --client-ports) CLIENT_PORTS="${2:-}"; shift 2 ;;
      --mode) MODE="${2:-}"; shift 2 ;;
      --allow-ssh-from) ALLOW_SSH_FROM="${2:-}"; shift 2 ;;
      --no-ipv6-off) IPV6_OFF=0; shift ;;
      --no-blocklist) DO_BLOCKLIST=0; shift ;;
      --no-hostname) DO_HOSTNAME=0; shift ;;
      --tz) TZ_OPT="${2:-}"; shift 2 ;;
      --yes|-y) ASSUME_YES=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --rollback|--uninstall) DO_ROLLBACK=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) err "Unknown option: $1"; usage; exit 2 ;;
    esac
  done
  if [[ -z "$PANEL_IP" && -n "${GORECSHIT_PANEL_IP:-}" ]]; then
    PANEL_IP="$GORECSHIT_PANEL_IP"
  fi
}

prompt_panel_ip() {
  if [[ -n "$PANEL_IP" ]]; then return 0; fi
  if [[ "$DO_ROLLBACK" -eq 1 ]]; then return 0; fi
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    err "--panel-ip is required (or set GORECSHIT_PANEL_IP). Refusing non-interactive without it."
    exit 2
  fi
  if [[ ! -t 0 ]]; then
    err "No TTY and --panel-ip missing. Pass --panel-ip X.X.X.X"
    exit 2
  fi
  local ans=""
  while true; do
    printf 'Enter panel / management IPv4 (required): '
    read -r ans || true
    if is_ipv4 "$ans"; then
      PANEL_IP="$ans"
      break
    fi
    warn "Invalid IPv4: $ans"
  done
}

detect_ssh_client() {
  SSH_CLIENT_IP=""
  if [[ -n "${SSH_CLIENT:-}" ]]; then
    SSH_CLIENT_IP="${SSH_CLIENT%% *}"
  elif [[ -n "${SSH_CONNECTION:-}" ]]; then
    SSH_CLIENT_IP="${SSH_CONNECTION%% *}"
  fi
  if [[ -n "$SSH_CLIENT_IP" ]] && ! is_ipv4 "$SSH_CLIENT_IP"; then
    SSH_CLIENT_IP=""
  fi
}

preflight() {
  step "Preflight"
  if [[ "$DRY_RUN" -eq 0 && "$(id -u)" -ne 0 ]]; then
    err "Must run as root"
    exit 1
  fi
  if [[ "$DRY_RUN" -eq 1 && "$(id -u)" -ne 0 ]]; then
    warn "Dry-run as non-root: will only print planned actions"
  fi

  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
  else
    OS_ID="unknown"; OS_VERSION="unknown"
  fi
  case "$OS_ID" in
    debian|ubuntu) ok "OS: ${OS_ID} ${OS_VERSION}" ;;
    *) warn "Untested OS: ${OS_ID} ${OS_VERSION} (script targets Debian 11+/Ubuntu 20.04+)" ;;
  esac

  detect_ssh_client
  if [[ -n "$SSH_CLIENT_IP" ]]; then
    ok "SSH client IP (anti-lockout): ${SSH_CLIENT_IP}"
  else
    warn "SSH_CLIENT not set; rely on --allow-ssh-from and panel IP"
  fi

  if [[ "$MODE" != "direct" && "$MODE" != "cdn" ]]; then
    err "--mode must be direct or cdn"; exit 2
  fi
  if [[ -n "$PANEL_IP" ]] && ! is_ipv4 "$PANEL_IP"; then
    err "Invalid --panel-ip: $PANEL_IP"; exit 2
  fi

  if [[ "$DRY_RUN" -eq 0 ]]; then
    mkdir -p "$BACKUP_DIR" "$MARKER_DIR"
    log "Backup directory: $BACKUP_DIR"
  else
    log "Backup directory (planned): $BACKUP_DIR"
  fi
}

detect_remnanode() {
  step "Detect remnanode / listeners"
  DETECTED_NODE_PORT=""
  DETECTED_CLIENT_PORTS=()

  if [[ -f /opt/remnanode/.env ]]; then
    # shellcheck disable=SC1091
    set +e
    # parse without sourcing secrets into env broadly — grep only ports
    local np
    np="$(grep -E '^(NODE_PORT|APP_PORT)=' /opt/remnanode/.env 2>/dev/null | head -1 | cut -d= -f2- | tr -d '\"\r' || true)"
    set -e
    if [[ "$np" =~ ^[0-9]+$ ]]; then
      DETECTED_NODE_PORT="$np"
      ok "Found /opt/remnanode/.env port=${DETECTED_NODE_PORT}"
    else
      warn "/opt/remnanode/.env present but NODE_PORT/APP_PORT not found"
    fi
  else
    warn "/opt/remnanode not found — will use --node-port or default 3000"
  fi

  CADDY_PRESENT=0
  if command -v caddy >/dev/null 2>&1 || [[ -d /etc/caddy ]]; then
    CADDY_PRESENT=1
  elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qi caddy; then
    CADDY_PRESENT=1
  fi
  if [[ "$CADDY_PRESENT" -eq 1 ]]; then
    ok "Caddy detected"
  fi

  # Detect client TCP ports: prefer xray/rw-core/remnanode listeners; else common VPN ports.
  local exclude_port="${DETECTED_NODE_PORT:-3000}"
  if command -v ss >/dev/null 2>&1; then
    local line addr port proc
    while IFS= read -r line; do
      addr="$(awk '{print $4}' <<<"$line")"
      port="${addr##*:}"
      if [[ ! "$port" =~ ^[0-9]+$ ]]; then continue; fi
      if [[ "$port" == "22" || "$port" == "$exclude_port" ]]; then continue; fi
      if [[ "$addr" == 127.* || "$addr" == \[::1\]* ]]; then continue; fi
      proc=""
      if [[ "$line" == *'users:(('* ]]; then
        proc="$(sed -n 's/.*users:(("\([^"]*\).*/\1/p' <<<"$line" | head -1 || true)"
      fi
      case "$proc" in
        xray|rw-core|remnanode|Xray|sing-box|singbox) DETECTED_CLIENT_PORTS+=("$port") ;;
      esac
    done < <(ss -lntp 2>/dev/null | awk 'NR>1' || true)
  fi

  # Unique sort
  if [[ ${#DETECTED_CLIENT_PORTS[@]} -gt 0 ]]; then
    mapfile -t DETECTED_CLIENT_PORTS < <(printf '%s\n' "${DETECTED_CLIENT_PORTS[@]}" | sort -n -u)
  fi

  if [[ "$NODE_PORT" == "auto" ]]; then
    NODE_PORT="${DETECTED_NODE_PORT:-3000}"
  fi
  if [[ "$CLIENT_PORTS" == "auto" ]]; then
    if [[ "$MODE" == "cdn" || "$CADDY_PRESENT" -eq 1 ]]; then
      CLIENT_PORTS="80,443"
      # Prefer cdn if caddy present and user left mode default? keep mode as user set
    elif [[ ${#DETECTED_CLIENT_PORTS[@]} -gt 0 ]]; then
      local IFS=,
      CLIENT_PORTS="${DETECTED_CLIENT_PORTS[*]}"
      IFS=$' \t\n'
    else
      CLIENT_PORTS="8443"
      warn "No client listeners detected; defaulting client ports to 8443"
    fi
  fi

  ok "NODE_PORT=${NODE_PORT}"
  ok "CLIENT_PORTS=${CLIENT_PORTS}"
  ok "MODE=${MODE}"
}

do_rollback() {
  step "Rollback / uninstall"
  local latest
  if [[ ! -d "$BACKUP_ROOT" ]]; then
    err "No backups at $BACKUP_ROOT"; exit 1
  fi
  latest="$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
  if [[ -z "$latest" ]]; then
    err "No backup directories found"; exit 1
  fi
  log "Using backup: $latest"
  if [[ -x "$latest/rollback.sh" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      printf '%b[DRY]%b run %s\n' "${C_YEL}" "${C_RESET}" "$latest/rollback.sh"
      exit 0
    fi
    # shellcheck disable=SC1090
    bash "$latest/rollback.sh"
    ok "Rollback script finished"
    exit 0
  fi
  # Generic restore: copy files back
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b restore files from %s\n' "${C_YEL}" "${C_RESET}" "$latest"
    find "$latest" -type f | sed "s|^${latest}||" | head -50
    exit 0
  fi
  while IFS= read -r -d '' f; do
    local rel="${f#"$latest"}"
    mkdir -p "$(dirname "$rel")"
    cp -a "$f" "$rel"
    log "Restored $rel"
  done < <(find "$latest" -type f ! -name 'rollback.sh' ! -name 'MANIFEST.txt' -print0)
  systemctl daemon-reload 2>/dev/null || true
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
  systemctl restart fail2ban 2>/dev/null || true
  if command -v ufw >/dev/null; then ufw --force reload 2>/dev/null || true; fi
  ok "Rollback complete from $latest"
  exit 0
}

write_rollback_script() {
  if [[ "$DRY_RUN" -eq 1 ]]; then return 0; fi
  local rb="${BACKUP_DIR}/rollback.sh"
  cat >"$rb" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
BACKUP_DIR="${BACKUP_DIR}"
echo "Restoring from \$BACKUP_DIR ..."
while IFS= read -r -d '' f; do
  rel="\${f#\$BACKUP_DIR}"
  if [[ "\$rel" == "/rollback.sh" || "\$rel" == "/MANIFEST.txt" ]]; then continue; fi
  mkdir -p "\$(dirname "\$rel")"
  cp -a "\$f" "\$rel"
  echo "restored \$rel"
done < <(find "\$BACKUP_DIR" -type f -print0)
systemctl daemon-reload 2>/dev/null || true
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
systemctl restart fail2ban 2>/dev/null || true
systemctl restart scanner-block.service 2>/dev/null || true
if command -v ufw >/dev/null; then ufw --force reload || true; fi
sysctl --system >/dev/null 2>&1 || true
echo "Rollback done."
EOF
  chmod 700 "$rb"
  {
    echo "timestamp=$TS"
    echo "panel_ip=${PANEL_IP}"
    echo "node_port=${NODE_PORT}"
    echo "client_ports=${CLIENT_PORTS}"
    echo "mode=${MODE}"
    echo "version=${VERSION}"
  } >"${BACKUP_DIR}/MANIFEST.txt"
}

install_packages() {
  step "Packages"
  if [[ "$IPV6_OFF" -eq 1 ]]; then
    backup_file /etc/apt/apt.conf.d/99force-ipv4
    write_content /etc/apt/apt.conf.d/99force-ipv4 'Acquire::ForceIPv4 "true";'$'\n'
    ok "apt ForceIPv4"
  fi

  local pkgs=(ufw fail2ban ipset chrony curl ca-certificates)
  # jq/python3 for docker json merge
  pkgs+=(python3)
  command -v jq >/dev/null 2>&1 || pkgs+=(jq)

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b apt-get install -y %s\n' "${C_YEL}" "${C_RESET}" "${pkgs[*]}"
    return 0
  fi
  export DEBIAN_FRONTEND=noninteractive
  local w=0
  while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1; do
    [ $w -eq 0 ] && warn "Waiting for apt/dpkg lock (unattended-upgrades)..."
    w=$((w+5)); [ $w -ge 900 ] && { err "apt lock held >15 min"; return 1; }; sleep 5
  done
  apt-get -o DPkg::Lock::Timeout=600 update -qq
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq "${pkgs[@]}"
  ok "Installed: ${pkgs[*]}"
  systemctl enable --now chrony 2>/dev/null || systemctl enable --now chronyd 2>/dev/null || true
}

configure_sysctl() {
  step "Sysctl (BBR + buffers)"
  backup_file /etc/sysctl.d/99-zz-bbr.conf
  backup_file /etc/sysctl.d/99-disable-ipv6.conf

  # Choose qdisc
  QDISC="fq"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    if ! modprobe sch_fq 2>/dev/null; then
      if modprobe sch_fq_codel 2>/dev/null; then
        QDISC="fq_codel"
        warn "sch_fq missing; falling back to fq_codel"
      else
        warn "Neither sch_fq nor sch_fq_codel loadable; leaving default_qdisc unset may fail"
        QDISC="fq_codel"
      fi
    fi
  else
    printf '%b[DRY]%b modprobe sch_fq (fallback sch_fq_codel)\n' "${C_YEL}" "${C_RESET}"
  fi

  local bbr
  bbr=$(cat <<EOF
# Managed by ${SCRIPT_NAME} ${VERSION} — BBR + ${QDISC}
net.core.default_qdisc = ${QDISC}
net.ipv4.tcp_congestion_control = bbr

# Longevity / throughput
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_max_syn_backlog = 65535
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
fs.file-max = 2097152
fs.nr_open = 2097152
EOF
)
  # conntrack keys only if module present
  if [[ "$DRY_RUN" -eq 1 ]] || lsmod | grep -q nf_conntrack || modprobe nf_conntrack 2>/dev/null; then
    bbr+=$'\n'"net.netfilter.nf_conntrack_max = 1048576"
    bbr+=$'\n'"net.netfilter.nf_conntrack_tcp_timeout_established = 86400"
  fi
  bbr+=$'\n'
  write_content /etc/sysctl.d/99-zz-bbr.conf "$bbr"

  if [[ "$IPV6_OFF" -eq 1 ]]; then
    write_content /etc/sysctl.d/99-disable-ipv6.conf \
"net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
"
    ok "IPv6 disable sysctl written"
  else
    if [[ "$DRY_RUN" -eq 0 && -f /etc/sysctl.d/99-disable-ipv6.conf ]]; then
      # leave existing; user asked --no-ipv6-off so do not create/overwrite aggressively
      log "Leaving IPv6 settings (--no-ipv6-off)"
    fi
  fi

  if [[ "$DRY_RUN" -eq 0 ]]; then
    sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-zz-bbr.conf >/dev/null 2>&1 || true
  else
    printf '%b[DRY]%b sysctl --system\n' "${C_YEL}" "${C_RESET}"
  fi
  ok "Sysctl applied (cc=bbr qdisc=${QDISC})"
}

configure_ssh() {
  step "SSH hardening drop-in"
  local conf="/etc/ssh/sshd_config.d/99-hardening.conf"
  backup_file "$conf"

  local body=""
  body+="Banner none"$'\n'
  body+="MaxAuthTries 3"$'\n'
  body+="LoginGraceTime 20"$'\n'
  body+="MaxStartups 10:30:60"$'\n'
  # Keep password+root as-is: only set if we want explicit — reference set them yes.
  # Do NOT disable password/root login.
  body+="PasswordAuthentication yes"$'\n'
  body+="PermitRootLogin yes"$'\n'

  # Test DebianBanner support
  local testconf
  if [[ "$DRY_RUN" -eq 0 ]]; then
    testconf="$(mktemp)"
    printf '%s\nDebianBanner no\n' "$body" >"$testconf"
    if sshd -t -f "$testconf" 2>/dev/null; then
      body="DebianBanner no"$'\n'"$body"
      ok "DebianBanner no (supported)"
    else
      warn "DebianBanner not supported by this sshd; skipping"
    fi
    rm -f "$testconf"
  else
    printf '%b[DRY]%b test sshd -t for DebianBanner\n' "${C_YEL}" "${C_RESET}"
    body="DebianBanner no"$'\n'"$body"
  fi

  write_content "$conf" "$body"

  if [[ "$DRY_RUN" -eq 0 ]]; then
    if sshd -t; then
      systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || \
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
      ok "sshd config validated and reloaded"
    else
      err "sshd -t failed; restoring previous config"
      if [[ -f "${BACKUP_DIR}${conf}" ]]; then
        cp -a "${BACKUP_DIR}${conf}" "$conf"
      else
        rm -f "$conf"
      fi
      exit 1
    fi
  else
    printf '%b[DRY]%b sshd -t && reload ssh\n' "${C_YEL}" "${C_RESET}"
  fi
}

whitelist_ips_csv() {
  # Build comma/space list of IPs for ignoreip / never-block
  local out=("127.0.0.1/8" "::1")
  if [[ -n "$PANEL_IP" ]]; then out+=("$PANEL_IP"); fi
  if [[ -n "$SSH_CLIENT_IP" ]]; then out+=("$SSH_CLIENT_IP"); fi
  if [[ -n "$ALLOW_SSH_FROM" ]]; then
    local IFS=,
    local a
    for a in $ALLOW_SSH_FROM; do
      a="$(echo "$a" | tr -d ' ')"
      if [[ -n "$a" ]]; then out+=("$a"); fi
    done
  fi
  printf '%s\n' "${out[@]}" | awk 'NF' | sort -u | tr '\n' ' ' | sed 's/ *$//'
}

configure_fail2ban() {
  step "fail2ban sshd"
  backup_file /etc/fail2ban/jail.local
  local ignore
  ignore="$(whitelist_ips_csv)"
  local jail
  jail=$(cat <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
ignoreip = ${ignore}

[sshd]
enabled = true
port = ssh
filter = sshd
maxretry = 5
EOF
)
  write_content /etc/fail2ban/jail.local "$jail"$'\n'
  if [[ "$DRY_RUN" -eq 0 ]]; then
    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban
    ok "fail2ban configured (ignoreip includes panel + SSH client)"
  else
    printf '%b[DRY]%b systemctl restart fail2ban\n' "${C_YEL}" "${C_RESET}"
  fi
}

configure_ufw() {
  step "UFW firewall"
  backup_file /etc/ufw/before.rules
  backup_file /etc/default/ufw

  if [[ "$DRY_RUN" -eq 1 ]]; then
    if [[ "$DO_BLOCKLIST" -eq 1 ]]; then
      printf '%b[DRY]%b hook ufw before.rules (panel ACCEPT + scanner-block DROP)\n' "${C_YEL}" "${C_RESET}"
    else
      printf '%b[DRY]%b hook ufw before.rules (panel ACCEPT; no blocklist DROP)\n' "${C_YEL}" "${C_RESET}"
    fi
    printf '%b[DRY]%b ufw default deny incoming / allow outgoing\n' "${C_YEL}" "${C_RESET}"
    printf '%b[DRY]%b ufw limit 22/tcp\n' "${C_YEL}" "${C_RESET}"
    printf '%b[DRY]%b ufw allow %s/tcp (client)\n' "${C_YEL}" "${C_RESET}" "$CLIENT_PORTS"
    printf '%b[DRY]%b ufw allow from %s to any port %s proto tcp (node)\n' "${C_YEL}" "${C_RESET}" "$PANEL_IP" "$NODE_PORT"
    if [[ "$MODE" == "cdn" ]]; then
      printf '%b[DRY]%b cdn mode: allow 80,443; deny external access to internal xray ports\n' "${C_YEL}" "${C_RESET}"
    fi
    printf '%b[DRY]%b ufw --force enable\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi

  # Hook scanner-block into before.rules (idempotent marker)
  hook_ufw_before_rules

  # Do NOT ufw reset (would drop unrelated rules / risk lockout). Set defaults + ensure rules.
  ufw default deny incoming
  ufw default allow outgoing

  # Anti-lockout: limit SSH, and allow from known clients explicitly
  ufw limit 22/tcp comment 'SSH rate-limit'
  if [[ -n "$SSH_CLIENT_IP" ]]; then
    ufw allow from "$SSH_CLIENT_IP" to any port 22 proto tcp comment 'SSH current client' || true
  fi
  if [[ -n "$ALLOW_SSH_FROM" ]]; then
    local IFS=,
    local a
    for a in $ALLOW_SSH_FROM; do
      a="$(echo "$a" | tr -d ' ')"
      if [[ -n "$a" ]]; then
        ufw allow from "$a" to any port 22 proto tcp comment 'SSH allow-list' || true
      fi
    done
  fi
  # Panel may need SSH too
  ufw allow from "$PANEL_IP" to any port 22 proto tcp comment 'SSH from panel' || true

  # Client ports
  local IFS=,
  local p
  for p in $CLIENT_PORTS; do
    p="$(echo "$p" | tr -d ' ')"
    [[ "$p" =~ ^[0-9]+$ ]] || continue
    ufw allow "${p}/tcp" comment "client-${p}"
  done
  IFS=$' \t\n'

  # NODE_PORT only from panel
  ufw allow from "$PANEL_IP" to any port "$NODE_PORT" proto tcp comment 'remnanode from panel'

  # In cdn mode, also ensure 80/443 open (already in CLIENT_PORTS if auto)
  if [[ "$MODE" == "cdn" ]]; then
    ufw allow 80/tcp comment 'cdn-http' || true
    ufw allow 443/tcp comment 'cdn-https' || true
    # Do not open internal xray ports detected on high ports like 4443
    for p in "${DETECTED_CLIENT_PORTS[@]:-}"; do
      if [[ "$p" == "80" || "$p" == "443" ]]; then continue; fi
      log "cdn mode: not opening internal port ${p}"
    done
  fi

  ufw --force enable
  ok "UFW enabled (SSH limited; NODE_PORT=${NODE_PORT}←panel; clients=${CLIENT_PORTS})"
}

hook_ufw_before_rules() {
  local rules="/etc/ufw/before.rules"
  [[ -f "$rules" ]] || return 0
  backup_file "$rules"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b inject scanner-block + panel ACCEPT into %s\n' "${C_YEL}" "${C_RESET}" "$rules"
    return 0
  fi

  # Remove previous gorecshit block if any
  if grep -q 'BEGIN gorecshit scanner-block' "$rules"; then
    sed -i '/# BEGIN gorecshit scanner-block/,/# END gorecshit scanner-block/d' "$rules"
  fi
  # Also remove older unmarked scanner-block lines from previous manual installs (safe-ish)
  # Do not touch unrelated rules.

  local insert=""
  insert+="# BEGIN gorecshit scanner-block"$'\n'
  insert+="# Accept management / anti-lockout hosts before blocklist DROP"$'\n'
  insert+="-A ufw-before-input -s ${PANEL_IP} -j ACCEPT"$'\n'
  if [[ -n "$SSH_CLIENT_IP" ]]; then
    insert+="-A ufw-before-input -s ${SSH_CLIENT_IP} -j ACCEPT"$'\n'
  fi
  if [[ -n "$ALLOW_SSH_FROM" ]]; then
    local IFS=,
    local a
    for a in $ALLOW_SSH_FROM; do
      a="$(echo "$a" | tr -d ' ')"
      if [[ -n "$a" ]]; then insert+="-A ufw-before-input -s ${a} -j ACCEPT"$'
'; fi
    done
    IFS=$' \t\n'
  fi
  if [[ "$DO_BLOCKLIST" -eq 1 ]]; then
    insert+="-A ufw-before-input -m set --match-set scanner-block src -j DROP"$'\n'
  fi
  insert+="# END gorecshit scanner-block"$'\n'

  # Insert after RELATED,ESTABLISHED accept on input if present, else after End required lines
  if grep -q 'ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' "$rules"; then
    local tmp
    tmp="$(mktemp)"
    awk -v block="$insert" '
      { print }
      /ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT/ && !done {
        printf "%s", block
        done=1
      }
    ' "$rules" >"$tmp"
    mv "$tmp" "$rules"
  else
    # after "# End required lines"
    local tmp
    tmp="$(mktemp)"
    awk -v block="$insert" '
      { print }
      /End required lines/ && !done {
        printf "%s", block
        done=1
      }
    ' "$rules" >"$tmp"
    mv "$tmp" "$rules"
  fi
  ok "UFW before.rules hooked"
}

install_blocklist() {
  if [[ "$DO_BLOCKLIST" -eq 0 ]]; then
    warn "Skipping scanner blocklist (--no-blocklist)"
    return 0
  fi
  step "Scanner blocklist (ipset + weekly timer)"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b install /usr/local/sbin/scanner-block-refresh.sh\n' "${C_YEL}" "${C_RESET}"
    printf '%b[DRY]%b write /etc/scanner-block/never-block.txt from panel+allow lists\n' "${C_YEL}" "${C_RESET}"
    printf '%b[DRY]%b enable scanner-block.service + weekly timer\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi

  mkdir -p /etc/scanner-block
  backup_file /usr/local/sbin/scanner-block-refresh.sh
  backup_file /etc/systemd/system/scanner-block.service
  backup_file /etc/systemd/system/scanner-block-refresh.service
  backup_file /etc/systemd/system/scanner-block-refresh.timer
  backup_file /etc/scanner-block/never-block.txt

  # never-block: panel, ssh client, allow list, private, optional CDN ranges (Yandex-like public CDN)
  {
    echo "# Managed by ${SCRIPT_NAME} — never include these in scanner-block"
    echo "$PANEL_IP"
    if [[ -n "$SSH_CLIENT_IP" ]]; then echo "$SSH_CLIENT_IP"; fi
    if [[ -n "$ALLOW_SSH_FROM" ]]; then
      local IFS=,
      local a
      for a in $ALLOW_SSH_FROM; do
        a="$(echo "$a" | tr -d ' ')"
        if [[ -n "$a" ]]; then echo "$a"; fi
      done
    fi
    # Private / link-local
    echo "10.0.0.0/8"
    echo "172.16.0.0/12"
    echo "192.168.0.0/16"
    echo "127.0.0.0/8"
    echo "169.254.0.0/16"
    # Common CDN / edge ranges sometimes used in front of nodes (harmless if unused)
    echo "5.45.192.0/18"
    echo "5.255.192.0/18"
    echo "37.9.64.0/18"
    echo "37.140.128.0/18"
    echo "77.88.0.0/18"
    echo "87.250.224.0/19"
    echo "93.158.128.0/18"
    echo "95.108.128.0/17"
    echo "141.8.128.0/18"
    echo "178.154.128.0/17"
    echo "213.180.192.0/19"
    echo "185.32.186.0/23"
    echo "185.32.184.0/22"
  } > /etc/scanner-block/never-block.txt

  cat > /usr/local/sbin/scanner-block-refresh.sh <<'REFRESH_EOF'
#!/bin/bash
set -euo pipefail
# Refresh scanner-block ipset. Safe failure: keep old list if download fails.
# --local-only: only load /etc/scanner-block/blocklist.txt (boot path)
# Sources match production Remnawave node hardening (OpenFilters, wdes.eu, Xorlent, CyberOK, traffic-guard).

LOCAL_ONLY=0
[ "${1:-}" = "--local-only" ] && LOCAL_ONLY=1

DIR=/etc/scanner-block
LIST="$DIR/blocklist.txt"
TMP="$DIR/blocklist.txt.new"
NEVER="$DIR/never-block.txt"
SET=scanner-block
mkdir -p "$DIR"

download_lists() {
  local tmpdir
  tmpdir=$(mktemp -d)
  # shellcheck disable=SC2064
  trap 'rm -rf "$tmpdir"' RETURN
  local ok=0
  BASE="https://raw.githubusercontent.com/OpenFilters/internet-scanners/main/cidr"
  for f in censys_v4.txt shodan_v4.txt binaryedge_v4.txt shadowserver_v4.txt driftnet_v4.txt \
    paloaltonetworks_v4.txt rapid7_v4.txt onyphe_v4.txt bitsight_v4.txt leakix_v4.txt cyberok_v4.txt \
    netlas_v4.txt zoomeye_v4.txt quake_v4.txt fofa_v4.txt hunter_v4.txt criminalip_v4.txt \
    internetmeasurementresearch_v4.txt researchscanner_v4.txt alphastrike_v4.txt \
    cyberresilience_v4.txt cybcube_v4.txt detectify_v4.txt hackertarget_v4.txt other_v4.txt; do
    if curl -fsSL --max-time 30 -o "$tmpdir/$f" "$BASE/$f"; then ok=1; fi
  done
  curl -fsSL --max-time 30 -o "$tmpdir/cyberok-skipa.txt" \
    "https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt" && ok=1 || true
  curl -fsSL --max-time 30 -o "$tmpdir/antiscanner.list" \
    "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/main/public/antiscanner.list" && ok=1 || true
  for n in stretchoid binaryedge shadowserver censys internet-measurement.com; do
    curl -fsSL --max-time 30 -o "$tmpdir/wdes-$n.txt" "https://security.wdes.eu/scanners/$n.txt" && ok=1 || true
  done
  for n in stretchoid censys binaryedge shadowserver; do
    curl -fsSL --max-time 30 -o "$tmpdir/xorlent-$n.txt" \
      "https://raw.githubusercontent.com/Xorlent/Internet-Scanners/main/$n.txt" && ok=1 || true
  done
  if [ "$ok" -eq 0 ]; then
    echo "DOWNLOAD_FAILED keeping old list" >&2
    return 1
  fi
  {
    cat "$tmpdir"/*_v4.txt 2>/dev/null || true
    cat "$tmpdir/cyberok-skipa.txt" 2>/dev/null || true
    grep -E '^[0-9]' "$tmpdir/antiscanner.list" 2>/dev/null || true
    for f in "$tmpdir"/wdes-*.txt "$tmpdir"/xorlent-*.txt; do
      [ -f "$f" ] || continue
      grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$f" | sed 's/\r//' | awk '{if($1!~/\//) print $1"/32"; else print $1}'
    done
  } | sed 's/\r//' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' | sort -u > "$TMP.raw"

  python3 - "$TMP.raw" "$TMP" "$NEVER" <<'PY'
import sys, ipaddress
raw, out, never_path = sys.argv[1:4]
never_nets = [
  "10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16",
]
try:
  for line in open(never_path):
    line=line.strip()
    if line and not line.startswith("#"):
      never_nets.append(line if "/" in line else line+"/32")
except FileNotFoundError:
  pass
never=[ipaddress.ip_network(n, strict=False) for n in never_nets]
kept=[]
for line in open(raw):
  line=line.strip()
  if not line: continue
  try: net=ipaddress.ip_network(line, strict=False)
  except ValueError: continue
  if net.version!=4: continue
  if net.prefixlen < 12: continue
  if any(net.overlaps(n) for n in never): continue
  kept.append(str(net))
kept=sorted(set(kept), key=lambda x: (ipaddress.ip_network(x).network_address.packed, ipaddress.ip_network(x).prefixlen))
open(out,"w").write("\n".join(kept)+"\n")
print(len(kept))
PY
  mv -f "$TMP" "$LIST"
  echo "UPDATED $(wc -l < "$LIST") entries"
}

load_ipset() {
  if [ ! -s "$LIST" ]; then
    echo "No blocklist at $LIST" >&2
    return 1
  fi
  ipset create "${SET}-new" hash:net family inet maxelem 200000 -exist
  ipset flush "${SET}-new"
  local n=0
  while read -r cidr; do
    [ -z "$cidr" ] && continue
    ipset add "${SET}-new" "$cidr" -exist 2>/dev/null && n=$((n+1)) || true
  done < "$LIST"
  if ! ipset list "$SET" >/dev/null 2>&1; then
    ipset rename "${SET}-new" "$SET"
  else
    ipset swap "${SET}-new" "$SET"
    ipset destroy "${SET}-new"
  fi
  if ! iptables -C ufw-before-input -m set --match-set "$SET" src -j DROP 2>/dev/null; then
    if iptables -L ufw-before-input -n >/dev/null 2>&1; then
      iptables -I ufw-before-input 3 -m set --match-set "$SET" src -j DROP 2>/dev/null || \
      iptables -A ufw-before-input -m set --match-set "$SET" src -j DROP 2>/dev/null || true
    fi
  fi
  echo "LOADED $n into ipset $SET (size=$(ipset list $SET 2>/dev/null | grep -c '^[0-9]' || echo 0))"
}

if [ "$LOCAL_ONLY" -eq 0 ]; then
  download_lists || echo "using existing list"
fi
load_ipset
REFRESH_EOF
  chmod 755 /usr/local/sbin/scanner-block-refresh.sh

  cat > /etc/systemd/system/scanner-block.service <<'EOF'
[Unit]
Description=Load scanner IP blocklist into ipset
DefaultDependencies=no
Before=ufw.service
After=network-pre.target systemd-modules-load.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/scanner-block-refresh.sh --local-only

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/scanner-block-refresh.service <<'EOF'
[Unit]
Description=Refresh internet scanner IP blocklist
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/scanner-block-refresh.sh
Nice=10
EOF

  cat > /etc/systemd/system/scanner-block-refresh.timer <<'EOF'
[Unit]
Description=Weekly scanner blocklist refresh

[Timer]
OnCalendar=weekly
Persistent=true
RandomizedDelaySec=3600

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable scanner-block.service >/dev/null 2>&1 || true
  systemctl enable --now scanner-block-refresh.timer >/dev/null 2>&1 || true

  # First refresh (network); keep old on failure
  /usr/local/sbin/scanner-block-refresh.sh || warn "Initial blocklist refresh failed; will retry via timer"
  systemctl start scanner-block.service || true
  ok "Scanner blocklist installed"
}

configure_hostname_tz() {
  step "Hostname / timezone"
  if [[ "$DO_HOSTNAME" -eq 1 ]]; then
    local hex newhost
    hex="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 6)"
    newhost="web-${hex}"
    if [[ "$DRY_RUN" -eq 1 ]]; then
      printf '%b[DRY]%b hostnamectl set-hostname %s\n' "${C_YEL}" "${C_RESET}" "$newhost"
    else
      backup_file /etc/hostname
      backup_file /etc/hosts
      backup_file /etc/cloud/cloud.cfg
      hostnamectl set-hostname "$newhost" 2>/dev/null || echo "$newhost" >/etc/hostname
      # Update /etc/hosts 127.0.1.1
      if grep -qE '^127\.0\.1\.1' /etc/hosts; then
        sed -i -E "s/^127\\.0\\.1\\.1.*/127.0.1.1\t${newhost}/" /etc/hosts
      else
        echo -e "127.0.1.1\t${newhost}" >>/etc/hosts
      fi
      # cloud-init preserve
      if [[ -f /etc/cloud/cloud.cfg ]]; then
        if grep -q '^preserve_hostname:' /etc/cloud/cloud.cfg; then
          sed -i 's/^preserve_hostname:.*/preserve_hostname: true/' /etc/cloud/cloud.cfg
        else
          echo 'preserve_hostname: true' >>/etc/cloud/cloud.cfg
        fi
      fi
      mkdir -p /etc/cloud/cloud.cfg.d
      echo 'preserve_hostname: true' >/etc/cloud/cloud.cfg.d/99-gorecshit-hostname.cfg
      ok "Hostname set to ${newhost}"
    fi
  else
    log "Hostname unchanged (--no-hostname)"
  fi

  if [[ -n "$TZ_OPT" ]]; then
    local tz="$TZ_OPT"
    if [[ "$tz" == "auto" ]]; then
      if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '%b[DRY]%b detect TZ via IP geolocation\n' "${C_YEL}" "${C_RESET}"
        tz="Europe/Warsaw"
      else
        tz="$(curl -fsSL --max-time 5 https://ipapi.co/timezone 2>/dev/null || \
              curl -fsSL --max-time 5 https://ipinfo.io/timezone 2>/dev/null || true)"
        tz="$(echo "$tz" | tr -d '\r\n' | head -1)"
        if [[ -z "$tz" || "$tz" == *"error"* ]]; then
          warn "TZ auto-detect failed; leaving timezone unchanged"
          tz=""
        fi
      fi
    fi
    if [[ -n "$tz" ]]; then
      if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '%b[DRY]%b timedatectl set-timezone %s\n' "${C_YEL}" "${C_RESET}" "$tz"
      else
        if timedatectl set-timezone "$tz"; then ok "Timezone: $tz"; else warn "Failed to set TZ $tz"; fi
      fi
    fi
  else
    log "Timezone left as-is (pass --tz ZONE|auto to change)"
  fi
}

configure_docker_journal() {
  step "Docker logs / journald / remnanode perms"
  backup_file /etc/docker/daemon.json
  backup_file /etc/systemd/journald.conf
  mkdir -p /etc/systemd/journald.conf.d 2>/dev/null || true
  backup_file /etc/systemd/journald.conf.d/99-gorecshit.conf

  local desired='{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"}}'
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b merge docker daemon.json log rotation\n' "${C_YEL}" "${C_RESET}"
    printf '%b[DRY]%b journald SystemMaxUse=200M\n' "${C_YEL}" "${C_RESET}"
    printf '%b[DRY]%b chmod 600 /opt/remnanode/.env compose files\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi

  write_content /etc/systemd/journald.conf.d/99-gorecshit.conf $'[Journal]\nSystemMaxUse=200M\n'
  systemctl restart systemd-journald 2>/dev/null || true

  if command -v docker >/dev/null 2>&1 || [[ -d /etc/docker ]]; then
    mkdir -p /etc/docker
    local newjson
    if [[ -f /etc/docker/daemon.json ]]; then
      newjson="$(python3 - "$desired" <<'PY'
import json,sys
desired=json.loads(sys.argv[1])
try:
  cur=json.load(open("/etc/docker/daemon.json"))
except Exception:
  cur={}
# merge log-driver / log-opts without wiping other keys
if "log-driver" not in cur:
  cur["log-driver"]=desired["log-driver"]
opts=cur.get("log-opts") or {}
if not isinstance(opts, dict):
  opts={}
for k,v in desired["log-opts"].items():
  opts.setdefault(k,v)
cur["log-opts"]=opts
if cur.get("log-driver") in (None,""):
  cur["log-driver"]=desired["log-driver"]
print(json.dumps(cur, indent=2))
PY
)" || newjson="$(printf '%s\n' "$desired" | python3 -m json.tool 2>/dev/null || echo "$desired")"
    else
      newjson="$(printf '%s\n' "$desired" | python3 -m json.tool)"
    fi
    local old=""
    if [[ -f /etc/docker/daemon.json ]]; then old="$(cat /etc/docker/daemon.json)"; fi
    printf '%s\n' "$newjson" >/etc/docker/daemon.json
    if [[ "$old" != "$(cat /etc/docker/daemon.json)" ]]; then
      CHANGED_DOCKER=1
      if systemctl is-active --quiet docker 2>/dev/null; then
        warn "Docker daemon.json changed — restarting docker (clients may briefly reconnect)"
        systemctl restart docker || warn "docker restart failed"
      fi
    else
      ok "Docker daemon.json already OK"
    fi
  else
    log "Docker not installed; wrote nothing under /etc/docker"
  fi

  if [[ -d /opt/remnanode ]]; then
    chmod 600 /opt/remnanode/.env 2>/dev/null || true
    chmod 600 /opt/remnanode/docker-compose.yml 2>/dev/null || true
    chmod 600 /opt/remnanode/compose.yml 2>/dev/null || true
    ok "Locked down /opt/remnanode env/compose permissions (600)"
  fi
}

final_verify() {
  step "Verification summary"
  echo "---- ufw ----"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "(dry-run: skipped live checks)"
    return 0
  fi
  ufw status verbose 2>/dev/null | head -40 || true
  echo "---- tcp cc / qdisc ----"
  sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc 2>/dev/null || true
  echo "---- listeners (ss -lnt) ----"
  ss -lnt 2>/dev/null | awk 'NR==1 || /:22 |:80 |:443 |:'"$NODE_PORT"' |:8443 |:4443 /' || ss -lnt | head -20
  echo "---- fail2ban ----"
  fail2ban-client status sshd 2>/dev/null | head -20 || true
  echo "---- blocklist ----"
  if command -v ipset >/dev/null; then
    ipset list scanner-block 2>/dev/null | head -5 || echo "ipset scanner-block not loaded"
    echo "blocklist lines: $(wc -l </etc/scanner-block/blocklist.txt 2>/dev/null || echo 0)"
  fi
  echo "---- remnanode container ----"
  if command -v docker >/dev/null; then
    docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null | head -20 || true
  fi
  echo "---- hostname / tz ----"
  hostname; timedatectl 2>/dev/null | head -6 || true
  if [[ "$CHANGED_DOCKER" -eq 1 ]]; then
    warn "Docker was restarted due to daemon.json change — VPN clients may have briefly reconnected"
  fi
  ok "Hardening complete. Backups: ${BACKUP_DIR}"
  ok "Rollback: bash install.sh --rollback   OR   ${BACKUP_DIR}/rollback.sh"
}

main() {
  # Re-parse PANEL_IP from env after args (GORECSHIT_PANEL_IP)
  parse_args "$@"
  if [[ -z "$PANEL_IP" && -n "${GORECSHIT_PANEL_IP:-}" ]]; then
    PANEL_IP="$GORECSHIT_PANEL_IP"
  fi

  printf '%b%s%b v%s\n' "${C_BOLD}" "$SCRIPT_NAME" "${C_RESET}" "$VERSION"

  if [[ "$DO_ROLLBACK" -eq 1 ]]; then
    if [[ "$DRY_RUN" -eq 0 && "$(id -u)" -ne 0 ]]; then err "Must run as root"; exit 1; fi
    do_rollback
  fi

  prompt_panel_ip
  preflight
  detect_remnanode
  write_rollback_script

  if [[ "$ASSUME_YES" -eq 0 && "$DRY_RUN" -eq 0 && -t 0 ]]; then
    echo
    log "Will harden this node: panel=${PANEL_IP} node_port=${NODE_PORT} clients=${CLIENT_PORTS} mode=${MODE}"
    printf 'Proceed? [y/N] '
    local ans
    read -r ans || true
    [[ "$ans" =~ ^[Yy]$ ]] || { warn "Aborted"; exit 0; }
  fi

  install_packages
  configure_sysctl
  configure_ssh
  configure_fail2ban
  install_blocklist
  configure_ufw
  configure_hostname_tz
  configure_docker_journal
  final_verify
}

main "$@"
