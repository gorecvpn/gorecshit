#!/usr/bin/env bash
# gorecshit v2.2.2 — one-command hardening for Remnawave VPN node servers (Debian 11+/Ubuntu 20.04+)
# Usage:
#   bash install.sh --panel-ip X.X.X.X [--node-port 2222] [--yes]
#   bash install.sh --check --panel-ip X.X.X.X
#   bash install.sh                      # interactive Russian menu (TTY)
# Idempotent. No secrets. Panel IP / NODE_PORT via flags or GORECSHIT_* env.
# Does NOT restart Docker while remnanode/xray is live. Does NOT deploy itself.
set -Eeuo pipefail

VERSION="2.2.2"
SCRIPT_NAME="gorecshit"
BACKUP_ROOT="/root/hardening-backups"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TS}"
MARKER_DIR="/var/lib/gorecshit"

# Defaults (override via flags or GORECSHIT_* env)
PANEL_IP=""
NODE_PORT="auto"
CLIENT_PORTS="auto"       # CSV of TCP ports, or auto
CLIENT_UDP_PORTS="auto"   # CSV of UDP ports (hysteria2 etc), or auto
MODE="direct"             # direct | cdn
ALLOW_SSH_FROM=""
# HAProxy relays — never block (scanner ipset / fail2ban / UFW ACCEPT before DROP)
RELAY_IPS="188.225.24.250,188.225.27.46"
IPV6_OFF=0
DO_BLOCKLIST=1
DO_HOSTNAME=1
DO_DOCKER_USER=1
DO_NOFILE=1
DO_RESOLV_V4=1
DO_CERTBOT_HOOKS=1
DO_UFW=1
DO_FAIL2BAN=1
DO_SYSCTL=1
DO_SSH=1
DO_HIDE_PORTS=1
DO_ANTI_PROBE=1
DO_STEALTH=1
DO_DOCKER_JOURNAL=1
DO_TCP_TIMESTAMPS_OFF=0
SSH_PORT_NEW=""           # empty = keep 22 only; --ssh-port N adds N
BLOCKLIST_FROM=""         # ssh host or URL or local path
MODULES_CSV=""            # --modules ufw,blocklist,...
TZ_OPT=""                 # empty = leave; "auto" = geo; or IANA name
ASSUME_YES=0
DRY_RUN=0
CHECK_ONLY=0
DO_ROLLBACK=0
DO_REFRESH_LISTS_ONLY=0
DO_STATUS_ONLY=0
DO_DPI_CHECK=0
DO_UPDATE_ONLY=0
INTERACTIVE=0
LOG_FILE="/var/log/gorecshit.log"

# Runtime detected
OS_ID=""
OS_VERSION=""
DETECTED_NODE_PORT=""
DETECTED_CLIENT_PORTS=()
DETECTED_CLIENT_UDP_PORTS=()
SSH_CLIENT_IP=""
CADDY_PRESENT=0
CHANGED_DOCKER=0
SKIPPED_DOCKER_RESTART=0
QDISC="fq"
NGINX_PRESENT=0

# Colors
if [[ -t 1 ]] || [[ "${FORCE_COLOR:-0}" == "1" ]]; then
  C_RESET='\033[0m'; C_RED='\033[0;31m'; C_GRN='\033[0;32m'
  C_YEL='\033[0;33m'; C_BLU='\033[0;34m'; C_CYN='\033[0;36m'; C_BOLD='\033[1m'
  C_DIM='\033[2m'; C_GREY='\033[90m'
else
  C_RESET=''; C_RED=''; C_GRN=''; C_YEL=''; C_BLU=''; C_CYN=''; C_BOLD=''
  C_DIM=''; C_GREY=''
fi

_log_ts() { date '+%Y-%m-%d %H:%M:%S %z'; }
_log_line() {
  local level="$1"; shift
  local msg="$*"
  local plain
  plain="[$(_log_ts)] [$level] $msg"
  if [[ -n "${LOG_FILE:-}" && "$DRY_RUN" -eq 0 && "$(id -u 2>/dev/null || echo 1)" -eq 0 ]]; then
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    printf '%s\n' "$plain" >>"$LOG_FILE" 2>/dev/null || true
  fi
}
log()  { _log_line INFO "$*"; printf '%b[%s]%b %s\n' "${C_BLU}" "INFO" "${C_RESET}" "$*"; }
ok()   { _log_line OK "$*";   printf '%b[%s]%b %s\n' "${C_GRN}" " OK " "${C_RESET}" "$*"; }
warn() { _log_line WARN "$*"; printf '%b[%s]%b %s\n' "${C_YEL}" "WARN" "${C_RESET}" "$*"; }
err()  { _log_line ERR "$*";  printf '%b[%s]%b %s\n' "${C_RED}" "ERR " "${C_RESET}" "$*" >&2; }
step() { _log_line STEP "$*"; printf '\n%b==>%b %b%s%b\n' "${C_CYN}" "${C_RESET}" "${C_BOLD}" "$*" "${C_RESET}"; }

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
  install.sh                         # interactive menu (Russian UI, TTY)
  gorecshit                          # same menu after install (/usr/local/bin/gorecshit)
  gorecshit --update                 # self-update from GitHub / jsDelivr
  install.sh --rollback | --uninstall
  install.sh --dry-run --panel-ip X.X.X.X [options]
  install.sh --refresh-lists         # only refresh scanner blocklist
  install.sh --status                # show hardening status
  install.sh --dpi-check             # outbound DPI / DNS / TLS checks (node egress)

Required (non-interactive apply):
  --panel-ip IP              Management/panel host allowed to reach NODE_PORT

Options:
  --node-port PORT|auto      remnanode API port (default: auto from /opt/remnanode/.env)
  --client-ports LIST|auto   Comma-separated TCP client ports (default: auto via ss xray/rw-core)
  --client-udp-ports LIST|auto  Comma-separated UDP client ports (hysteria2 etc; default: auto)
  --mode direct|cdn          direct: open detected xray ports; cdn: open 80/443, keep internal xray closed
  --allow-ssh-from IP,...    Extra IPs always allowed (SSH ignore + never-block)
  --ssh-port N               Add SSH listen port N (ufw first, sshd -t, keep 22 until confirmed)
  --blocklist-from SRC       Copy/fetch blocklist from ssh-host, URL, or local path (fallback)
  --modules LIST             Comma modules: ufw,blocklist,hide_ports,anti_probe,ssh,stealth,
                             fail2ban,sysctl,hostname,docker (default: all enabled)
  --ipv6-off                 Opt-in: disable IPv6 via sysctl (default: keep IPv6 on; safer under dual-stack xray)
  --no-ipv6-off              Keep IPv6 enabled (default; retained for compatibility)
  --no-blocklist             Skip scanner ipset blocklist
  --no-hostname              Do not change hostname
  --no-hide-ports            Skip ICMP/closed-port hiding
  --no-anti-probe            Skip client-port rate limits
  --no-stealth               Skip stealth / not-look-like-VPN tweaks
  --tcp-timestamps-off       Set net.ipv4.tcp_timestamps=0
  --tz ZONE|auto             Set timezone (default: leave as-is). auto = IP geolocation
  --yes                      Non-interactive (still requires --panel-ip or GORECSHIT_PANEL_IP)
  --relay-ips IP,...         Extra never-block / ACCEPT IPs (default: HAProxy relays)
  --no-docker-user           Skip DOCKER-USER NODE_PORT restriction (bridge publish)
  --no-nofile                Skip nofile 1048576 limits
  --no-resolv-v4             Keep IPv6 nameservers in resolv.conf even when IPv6 off
  --no-certbot-hooks         Skip certbot renew reload hooks for caddy/nginx
  --dry-run, --check         Print actions / verify plan only; make no changes
  --refresh-lists            Only run scanner-block refresh
  --status                   Show current hardening status
  --update                   Self-update from GitHub (jsDelivr fallback); installs gorecshit command
  --dpi-check                Check DPI/DNS/TLS from this node (egress diagnostics)
  --rollback / --uninstall   Restore latest backup under /root/hardening-backups/
  -h, --help                 Show this help

Env: GORECSHIT_PANEL_IP, GORECSHIT_NODE_PORT, GORECSHIT_RELAY_IPS, GORECSHIT_LOG_FILE,
     GORECSHIT_BLOCKLIST_FROM, GORECSHIT_MODULES

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

is_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 ))
}

ss_local_addr() {
  # First Local Address:Port token from an ss line (column layout varies by ss version)
  local line="$1"
  awk '{
    for (i=1; i<=NF; i++) {
      if ($i ~ /^\*:([0-9]+)$/) { print $i; exit }
      if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+%[A-Za-z0-9._-]+:[0-9]+$/) { print $i; exit }
      if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$/) { print $i; exit }
      if ($i ~ /^\[[0-9a-fA-F:]+\]:[0-9]+$/) { print $i; exit }
      if ($i ~ /^::1:[0-9]+$/) { print $i; exit }
    }
  }' <<<"$line"
}

ss_is_loopback_addr() {
  local addr="$1"
  [[ "$addr" == 127.* || "$addr" == \[::1\]:* || "$addr" == ::1:* || "$addr" == *%lo:* ]]
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

foreach_csv() {
  local csv="$1" a
  local IFS=,
  for a in $csv; do
    a="$(echo "$a" | tr -d ' ')"
    [[ -n "$a" ]] && printf '%s\n' "$a"
  done
}

foreach_csv_ip() { foreach_csv "$1"; }

apply_modules_csv() {
  local csv="$1"
  [[ -z "$csv" ]] && return 0
  # If modules specified, first disable all optional modules then enable listed
  DO_UFW=0; DO_BLOCKLIST=0; DO_HIDE_PORTS=0; DO_ANTI_PROBE=0
  DO_SSH=0; DO_STEALTH=0; DO_FAIL2BAN=0; DO_SYSCTL=0
  DO_HOSTNAME=0; DO_DOCKER_JOURNAL=0; DO_DOCKER_USER=0; DO_NOFILE=0
  DO_RESOLV_V4=0; DO_CERTBOT_HOOKS=0
  local m
  while IFS= read -r m; do
    case "$m" in
      ufw) DO_UFW=1 ;;
      blocklist|mirrors|sources) DO_BLOCKLIST=1 ;;
      hide_ports|hide|icmp) DO_HIDE_PORTS=1 ;;
      anti_probe|antiprobing|probe) DO_ANTI_PROBE=1 ;;
      ssh) DO_SSH=1 ;;
      stealth|stealthy) DO_STEALTH=1 ;;
      fail2ban|f2b) DO_FAIL2BAN=1 ;;
      sysctl|bbr) DO_SYSCTL=1; DO_NOFILE=1 ;;
      hostname|tz) DO_HOSTNAME=1 ;;
      docker|journald|journal)
        DO_DOCKER_JOURNAL=1; DO_DOCKER_USER=1; DO_RESOLV_V4=1; DO_CERTBOT_HOOKS=1; DO_NOFILE=1 ;;
      all)
        DO_UFW=1; DO_BLOCKLIST=1; DO_HIDE_PORTS=1; DO_ANTI_PROBE=1
        DO_SSH=1; DO_STEALTH=1; DO_FAIL2BAN=1; DO_SYSCTL=1
        DO_HOSTNAME=1; DO_DOCKER_JOURNAL=1; DO_DOCKER_USER=1; DO_NOFILE=1
        DO_RESOLV_V4=1; DO_CERTBOT_HOOKS=1 ;;
      minimum|min)
        DO_UFW=1; DO_SSH=1; DO_FAIL2BAN=1; DO_SYSCTL=1; DO_BLOCKLIST=1
        DO_HIDE_PORTS=1; DO_DOCKER_USER=1 ;;
      *) warn "Unknown module: $m" ;;
    esac
  done < <(foreach_csv "$csv")
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --panel-ip) PANEL_IP="${2:-}"; shift 2 ;;
      --node-port) NODE_PORT="${2:-}"; shift 2 ;;
      --client-ports) CLIENT_PORTS="${2:-}"; shift 2 ;;
      --client-udp-ports) CLIENT_UDP_PORTS="${2:-}"; shift 2 ;;
      --mode) MODE="${2:-}"; shift 2 ;;
      --allow-ssh-from) ALLOW_SSH_FROM="${2:-}"; shift 2 ;;
      --ssh-port) SSH_PORT_NEW="${2:-}"; shift 2 ;;
      --blocklist-from) BLOCKLIST_FROM="${2:-}"; shift 2 ;;
      --modules) MODULES_CSV="${2:-}"; shift 2 ;;
      --ipv6-off) IPV6_OFF=1; shift ;;
      --no-ipv6-off) IPV6_OFF=0; shift ;;
      --no-blocklist) DO_BLOCKLIST=0; shift ;;
      --no-hostname) DO_HOSTNAME=0; shift ;;
      --no-hide-ports) DO_HIDE_PORTS=0; shift ;;
      --no-anti-probe) DO_ANTI_PROBE=0; shift ;;
      --no-stealth) DO_STEALTH=0; shift ;;
      --tcp-timestamps-off) DO_TCP_TIMESTAMPS_OFF=1; shift ;;
      --tz) TZ_OPT="${2:-}"; shift 2 ;;
      --relay-ips) RELAY_IPS="${2:-}"; shift 2 ;;
      --no-docker-user) DO_DOCKER_USER=0; shift ;;
      --no-nofile) DO_NOFILE=0; shift ;;
      --no-resolv-v4) DO_RESOLV_V4=0; shift ;;
      --no-certbot-hooks) DO_CERTBOT_HOOKS=0; shift ;;
      --yes|-y) ASSUME_YES=1; shift ;;
      --dry-run|--check) DRY_RUN=1; CHECK_ONLY=1; shift ;;
      --refresh-lists) DO_REFRESH_LISTS_ONLY=1; shift ;;
      --status) DO_STATUS_ONLY=1; shift ;;
      --update) DO_UPDATE_ONLY=1; shift ;;
      --dpi-check) DO_DPI_CHECK=1; shift ;;
      --rollback|--uninstall) DO_ROLLBACK=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) err "Unknown option: $1"; usage; exit 2 ;;
    esac
  done
  if [[ -z "$PANEL_IP" && -n "${GORECSHIT_PANEL_IP:-}" ]]; then
    PANEL_IP="$GORECSHIT_PANEL_IP"
  fi
  if [[ "$NODE_PORT" == "auto" && -n "${GORECSHIT_NODE_PORT:-}" ]]; then
    NODE_PORT="$GORECSHIT_NODE_PORT"
  fi
  if [[ -n "${GORECSHIT_RELAY_IPS:-}" ]]; then
    RELAY_IPS="$GORECSHIT_RELAY_IPS"
  fi
  if [[ -n "${GORECSHIT_LOG_FILE:-}" ]]; then
    LOG_FILE="$GORECSHIT_LOG_FILE"
  fi
  if [[ -z "$BLOCKLIST_FROM" && -n "${GORECSHIT_BLOCKLIST_FROM:-}" ]]; then
    BLOCKLIST_FROM="$GORECSHIT_BLOCKLIST_FROM"
  fi
  if [[ -z "$MODULES_CSV" && -n "${GORECSHIT_MODULES:-}" ]]; then
    MODULES_CSV="$GORECSHIT_MODULES"
  fi
  if [[ -n "$MODULES_CSV" ]]; then
    apply_modules_csv "$MODULES_CSV"
  fi
  if [[ -n "$SSH_PORT_NEW" ]] && ! is_port "$SSH_PORT_NEW"; then
    err "Invalid --ssh-port: $SSH_PORT_NEW"; exit 2
  fi
}


prompt_panel_ip() {
  if [[ -n "$PANEL_IP" ]]; then return 0; fi
  if [[ "$DO_ROLLBACK" -eq 1 || "$DO_STATUS_ONLY" -eq 1 || "$DO_REFRESH_LISTS_ONLY" -eq 1 || "$DO_DPI_CHECK" -eq 1 || "$DO_UPDATE_ONLY" -eq 1 ]]; then return 0; fi
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
    printf 'Введите IPv4 панели / management (обязательно): '
    read -r ans || true
    if is_ipv4 "$ans"; then
      PANEL_IP="$ans"
      break
    fi
    warn "Некорректный IPv4: $ans"
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

whitelist_ips_csv() {
  local out=("127.0.0.1/8" "::1")
  if [[ -n "$PANEL_IP" ]]; then out+=("$PANEL_IP"); fi
  if [[ -n "$SSH_CLIENT_IP" ]]; then out+=("$SSH_CLIENT_IP"); fi
  local a
  while IFS= read -r a; do out+=("$a"); done < <(foreach_csv_ip "$ALLOW_SSH_FROM")
  while IFS= read -r a; do out+=("$a"); done < <(foreach_csv_ip "$RELAY_IPS")
  printf '%s ' "${out[@]}"
}

remnanode_running() {
  command -v docker >/dev/null 2>&1 || return 1
  docker ps --format '{{.Names}}' 2>/dev/null | grep -qiE 'remnanode|rw-core|xray' && return 0
  return 1
}

# ---------- Interactive Russian menu ----------
menu_sep() {
  printf '%b%s%b\n' "${C_DIM}" "────────────────────────────────────────" "${C_RESET}"
}

# Compact one-line status for the menu header (no secrets).
print_menu_status_line() {
  local ufw_s="ufw off" f2b_s="fail2ban off" ipset_n=0 ports="" active=1
  local marker_ok=0

  if [[ -d "$MARKER_DIR" ]] || [[ -x /usr/local/sbin/scanner-block-refresh.sh ]]; then
    marker_ok=1
  fi

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qiE 'Status:\s*active'; then
    ufw_s="ufw on"
  else
    active=0
  fi

  if command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client ping 2>/dev/null | grep -qi pong; then
    f2b_s="fail2ban on"
  else
    # also accept systemd active without ping
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
      f2b_s="fail2ban on"
    else
      active=0
    fi
  fi

  if command -v ipset >/dev/null 2>&1 && ipset list scanner-block >/dev/null 2>&1; then
    ipset_n="$(ipset list scanner-block 2>/dev/null | grep -cE '^[0-9]' || true)"
    ipset_n="${ipset_n:-0}"
  else
    active=0
  fi

  # Client ports: prefer live VPN process listeners; else UFW client-* rules; else —
  ports="$(
    { ss -lntup 2>/dev/null || true; } \
      | grep -E 'xray|rw-core|remnanode|sing-box|hysteria|xhttp' \
      | grep -oE ':[0-9]+' | tr -d ':' | sort -nu | head -8 | tr '\n' ',' | sed 's/,$//' || true
  )"
  if [[ -z "$ports" ]] && command -v ufw >/dev/null 2>&1; then
    ports="$(
      ufw status 2>/dev/null | grep -oE 'client-[0-9]+' | grep -oE '[0-9]+' | sort -nu | head -8 | tr '\n' ',' | sed 's/,$//' || true
    )"
  fi
  if [[ -z "$ports" ]]; then
    ports="—"
  fi

  if [[ "$marker_ok" -eq 0 && "$active" -eq 1 ]]; then
    # tools present but gorecshit may not have been applied
    :
  fi

  if [[ "$active" -eq 1 && "$ipset_n" -gt 0 ]]; then
    printf '%b✅ Защита: активна%b%b · %s · %s · ipset %s подсетей · порты: %s%b\n' \
      "${C_GRN}" "${C_RESET}" "${C_GREY}" "$ufw_s" "$f2b_s" "$ipset_n" "$ports" "${C_RESET}"
  elif [[ "$ufw_s" == "ufw on" ]]; then
    printf '%b⚠️  Защита: частично%b%b · %s · %s · ipset %s подсетей · порты: %s%b\n' \
      "${C_YEL}" "${C_RESET}" "${C_GREY}" "$ufw_s" "$f2b_s" "$ipset_n" "$ports" "${C_RESET}"
  else
    printf '%b❌ Защита: не активна%b%b · %s · %s · ipset %s подсетей · порты: %s%b\n' \
      "${C_RED}" "${C_RESET}" "${C_GREY}" "$ufw_s" "$f2b_s" "$ipset_n" "$ports" "${C_RESET}"
  fi
}

show_status_summary() {
  step "Статус hardening"
  echo "Версия скрипта: ${VERSION}"
  echo "Hostname: $(hostname 2>/dev/null || true)"
  print_menu_status_line
  if command -v ufw >/dev/null 2>&1; then
    echo "---- UFW ----"
    ufw status verbose 2>/dev/null | head -35 || true
  fi
  echo "---- listeners ----"
  ss -lntup 2>/dev/null | head -40 || true
  if command -v ipset >/dev/null 2>&1 && ipset list scanner-block >/dev/null 2>&1; then
    echo "---- ipset scanner-block ----"
    echo "entries: $(ipset list scanner-block 2>/dev/null | grep -cE '^[0-9]' || echo 0)"
  else
    echo "ipset scanner-block: нет"
  fi
  if command -v fail2ban-client >/dev/null 2>&1; then
    echo "---- fail2ban ----"
    fail2ban-client status 2>/dev/null || true
  fi
  if remnanode_running; then ok "remnanode/xray контейнер жив"; else warn "remnanode не найден в docker ps"; fi
  [[ -d "$BACKUP_ROOT" ]] && echo "Бэкапы: $(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l) шт. в $BACKUP_ROOT"
}

# ---------- DPI / DNS / TLS egress checks (bash + curl/openssl/timeout) ----------
# Inspired by Runnin4ik/dpi-detector, adapted for a VPN *node* (outbound path).
# No GitHub installs, no Python/rich/httpx. Never prints secrets.

_dpi_have() { command -v "$1" >/dev/null 2>&1; }

_dpi_pad() {
  # ~4KB alphanumeric pad for fat-header probes (TCP 16–20KB style)
  local n="${1:-4000}"
  if [[ -r /dev/urandom ]]; then
    head -c "$((n * 2))" /dev/urandom 2>/dev/null | base64 2>/dev/null | tr -d '\n+/=' | head -c "$n"
  else
    printf '%*s' "$n" '' | tr ' ' 'A'
  fi
}

_dpi_resolve_doh() {
  # Resolve A via Cloudflare DoH JSON (truth reference). Prints first A or empty.
  local host="$1"
  local raw
  raw="$(timeout 8 curl -fsS -H 'accept: application/dns-json' \
    "https://cloudflare-dns.com/dns-query?name=${host}&type=A" 2>/dev/null || true)"
  printf '%s' "$raw" | tr '{}' '\n' | grep -oE '"data":"[0-9.]+"' | head -1 | cut -d'"' -f4
}

_dpi_resolve_system() {
  local host="$1"
  local ip=""
  ip="$(getent ahostsv4 "$host" 2>/dev/null | awk '/STREAM|RAW|DGRAM/ {print $1; exit}')"
  if [[ -z "$ip" ]]; then
    ip="$(getent hosts "$host" 2>/dev/null | awk '{print $1; exit}')"
  fi
  printf '%s' "$ip"
}

_dpi_tls_probe() {
  # Args: host [sni] [ip]  → prints STATUS|detail
  local host="$1"
  local sni="${2:-$1}"
  local ip="${3:-}"
  local connect_to
  if [[ -n "$ip" ]]; then
    connect_to="${ip}:443"
  else
    connect_to="${host}:443"
  fi
  local out ec=0
  # -brief is OpenSSL 1.1.1+; fall back to classic output on older builds
  out="$(timeout 8 openssl s_client -connect "$connect_to" -servername "$sni" -brief </dev/null 2>&1)" || ec=$?
  if ! printf '%s' "$out" | grep -qiE 'CONNECTION ESTABLISHED|Protocol version|Cipher|Verify return code'; then
    ec=0
    out="$(timeout 8 openssl s_client -connect "$connect_to" -servername "$sni" </dev/null 2>&1)" || ec=$?
  fi
  if printf '%s' "$out" | grep -qiE 'CONNECTION ESTABLISHED|Protocol version|Cipher|Verify return code|SSL-Session'; then
    local proto cipher
    proto="$(printf '%s' "$out" | grep -iE 'Protocol version|Protocol *:' | head -1 | sed 's/.*: *//' | tr -d '\r')"
    cipher="$(printf '%s' "$out" | grep -iE 'Cipher *(|Ciphersuite|Cipher is)' | head -1 | sed 's/.*: *//;s/.*Cipher is //' | tr -d '\r')"
    printf 'OK|%s %s' "${proto:-tls}" "${cipher:-ok}"
    return 0
  fi
  if [[ "$ec" -eq 124 ]]; then
    printf 'TLS DROP|handshake timeout (возможный SNI/DPI drop)'
    return 1
  fi
  if printf '%s' "$out" | grep -qiE 'Connection reset|errno=104|ECONNRESET'; then
    printf 'TLS RST|TCP RST на ClientHello'
    return 1
  fi
  if printf '%s' "$out" | grep -qiE 'Connection refused|ECONNREFUSED'; then
    printf 'REFUSED|порт закрыт'
    return 1
  fi
  if printf '%s' "$out" | grep -qiE 'Name or service not known|getaddrinfo|NXDOMAIN'; then
    printf 'DNS FAIL|не резолвится'
    return 1
  fi
  printf 'FAIL|%s' "$(printf '%s' "$out" | tr '\n' ' ' | head -c 80)"
  return 1
}

_dpi_tcp_connect() {
  local host="$1" port="${2:-443}"
  if timeout 5 bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null; then
    printf 'OK'
    return 0
  fi
  printf 'FAIL'
  return 1
}

_dpi_fat_probe() {
  # Lightweight TCP 16–20KB style: keep-alive HTTP/1.1 HEAD with growing X-Pad.
  # Target: host:443 via curl. Returns OK|DETECTED@Nkb|TIMEOUT|FAIL
  local host="$1"
  local ip="${2:-}"
  local pad i sent_kb=0
  local resolve=()
  pad="$(_dpi_pad 4000)"
  [[ -z "$pad" ]] && pad="$(printf 'A%.0s' {1..4000})"
  if [[ -n "$ip" ]]; then
    resolve=(--resolve "${host}:443:${ip}")
  fi
  # warmup (no pad)
  if ! timeout 10 curl -fsS -o /dev/null --http1.1 --connect-timeout 5 -m 8 \
      "${resolve[@]}" "https://${host}/" -I 2>/dev/null; then
    # try without -I / allow insecure for DPI labs
    if ! timeout 10 curl -ksS -o /dev/null --http1.1 --connect-timeout 5 -m 8 \
        "${resolve[@]}" "https://${host}/" -I 2>/dev/null; then
      printf 'UNREACH|не удалось установить TLS'
      return 1
    fi
  fi
  for i in 1 2 3 4 5 6 7 8; do
    sent_kb=$((i * 4))
    if ! timeout 12 curl -ksS -o /dev/null --http1.1 --connect-timeout 5 -m 10 \
        "${resolve[@]}" -H "X-Pad: ${pad}" -H "Connection: keep-alive" \
        "https://${host}/" -I 2>/dev/null; then
      if [[ "$sent_kb" -ge 12 ]]; then
        printf 'DETECTED|обрыв около %sKB (TCP16-20 стиль)' "$sent_kb"
      else
        printf 'TIMEOUT|обрыв рано (~%sKB)' "$sent_kb"
      fi
      return 1
    fi
  done
  printf 'OK|прошли ~%sKB без обрыва' "$sent_kb"
  return 0
}

_dpi_row() {
  # printf table row: col1 col2 col3
  printf '  %-22s %-14s %s\n' "$1" "$2" "$3"
}

run_dpi_check() {
  step "Проверка DPI / DNS / TLS (egress с ноды)"
  echo "Источник идей: github.com/Runnin4ik/dpi-detector — облегчённый bash-порт для VPN-ноды."
  echo "Инструменты: bash, curl, openssl, timeout (без Python/GitHub-установок)."
  echo

  local have_curl=0 have_openssl=0
  _dpi_have curl && have_curl=1
  _dpi_have openssl && have_openssl=1
  if [[ "$have_curl" -eq 0 ]]; then
    err "нужен curl"; return 1
  fi

  # --- 1) DNS spoof / stub check ---
  echo "=== 1) DNS: систем vs DoH (Cloudflare) ==="
  _dpi_row "домен" "результат" "system → doh"
  menu_sep
  local doms=( "vk.ru" "google.com" "discord.com" "meduza.io" "instagram.com" "youtube.com" "x.com" "cloudflare.com" )
  # Known RU ISP stub / sinkhole patterns (subset; heuristic only)
  local stub_re='^(1\.1\.1\.1|0\.0\.0\.0|127\.|10\.|192\.0\.2\.|198\.18\.|198\.51\.100\.|203\.0\.113\.|255\.255\.255\.255)'
  local d sys doh verdict
  for d in "${doms[@]}"; do
    sys="$(_dpi_resolve_system "$d")"
    doh="$(_dpi_resolve_doh "$d")"
    if [[ -z "$sys" && -z "$doh" ]]; then
      verdict="DNS FAIL"
    elif [[ -z "$sys" ]]; then
      verdict="DNS FAIL (system)"
    elif [[ -n "$sys" && "$sys" =~ $stub_re ]]; then
      verdict="DNS FAKE/stub?"
    elif [[ -n "$doh" && -n "$sys" && "$sys" != "$doh" ]]; then
      # Different A is not always spoof (CDN geo); flag only if sys looks private/stub-like
      if [[ "$sys" =~ ^(100\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.) ]]; then
        verdict="DNS FAKE?"
      else
        verdict="DIFF (CDN/geo)"
      fi
    else
      verdict="OK"
    fi
    _dpi_row "$d" "$verdict" "${sys:-—} → ${doh:-—}"
  done
  echo

  # --- 2) TLS reachability to known domains ---
  echo "=== 2) TLS reachability (SNI=hostname) ==="
  _dpi_row "домен" "результат" "деталь"
  menu_sep
  local tdoms=( "vk.ru" "google.com" "cloudflare.com" "discord.com" "meduza.io" "www.instagram.com" "www.youtube.com" "github.com" )
  local res detail status
  if [[ "$have_openssl" -eq 1 ]]; then
    for d in "${tdoms[@]}"; do
      res="$(_dpi_tls_probe "$d" "$d" || true)"
      status="${res%%|*}"
      detail="${res#*|}"
      _dpi_row "$d" "$status" "$detail"
    done
  else
    warn "openssl не найден — TLS-пробы через curl -I"
    for d in "${tdoms[@]}"; do
      if timeout 8 curl -ksS -o /dev/null --connect-timeout 5 -m 8 -I "https://${d}/" 2>/dev/null; then
        _dpi_row "$d" "OK" "HTTP HEAD ok"
      else
        _dpi_row "$d" "FAIL" "curl HEAD failed"
      fi
    done
  fi
  echo

  # --- 3) SNI-based drop: same Cloudflare IP, different SNI ---
  echo "=== 3) SNI-фильтр (один IP Cloudflare, разный SNI) ==="
  local cf_ip
  cf_ip="$(_dpi_resolve_doh www.cloudflare.com)"
  [[ -z "$cf_ip" ]] && cf_ip="$(_dpi_resolve_system www.cloudflare.com)"
  [[ -z "$cf_ip" ]] && cf_ip="1.1.1.1"
  echo "IP: ${cf_ip}"
  _dpi_row "SNI" "результат" "деталь"
  menu_sep
  local snis=( "www.cloudflare.com" "discord.com" "meduza.io" "www.instagram.com" "vk.ru" )
  if [[ "$have_openssl" -eq 1 ]]; then
    for d in "${snis[@]}"; do
      res="$(_dpi_tls_probe "$cf_ip" "$d" "$cf_ip" || true)"
      status="${res%%|*}"
      detail="${res#*|}"
      # Cert mismatch on open CDN IP is normal if SNI host isn't served there —
      # distinguish handshake drop vs cert/alert.
      _dpi_row "$d" "$status" "$detail"
    done
  else
    warn "openssl нет — секция SNI пропущена"
  fi
  echo

  # --- 4) TCP 16–20KB-style fat probes on a few CDNs ---
  echo "=== 4) TCP 16–20KB-стиль (fat HEAD / X-Pad ~32KB) ==="
  _dpi_row "цель" "результат" "деталь"
  menu_sep
  # Compact targets (host + optional pin IP). Keep short for node health.
  local targets=(
    "cloudflare.com|"
    "www.cloudflare.com|"
    "discord.com|"
    "github.com|"
  )
  local t host tip
  for t in "${targets[@]}"; do
    host="${t%%|*}"
    tip="${t#*|}"
    res="$(_dpi_fat_probe "$host" "$tip" || true)"
    status="${res%%|*}"
    detail="${res#*|}"
    _dpi_row "$host" "$status" "$detail"
  done
  echo

  # --- 5) Quick TCP connect to common ports / self REALITY note ---
  echo "=== 5) Локальные слушатели (нода) ==="
  local lp
  lp="$(ss -lntH 2>/dev/null | awk '{print $4}' | grep -oE '[0-9]+$' | sort -nu | tr '\n' ' ')"
  echo "  TCP listen: ${lp:-нет данных}"
  if remnanode_running 2>/dev/null; then
    ok "remnanode/xray контейнер жив (DPI-check его не трогает)"
  else
    warn "remnanode не виден — проверьте docker ps отдельно"
  fi
  echo
  ok "DPI-check завершён. На зарубежной VPS чаще всего всё OK — это нормально (DPI у провайдера РФ)."
  echo "Если DETECTED/TLS DROP на EU-ноде — смотрите firewall/маршрут хостера, не «российский DPI»."
}

install_cli_command() {
  # Install/refresh /usr/local/sbin/gorecshit + /usr/local/bin/gorecshit symlink (no hardening).
  # Safe to call on every run when root.
  if [[ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]]; then
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b install CLI -> /usr/local/sbin/gorecshit (+ /usr/local/bin/gorecshit)\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi
  local src dest link
  src="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || realpath "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
  dest="/usr/local/sbin/gorecshit"
  link="/usr/local/bin/gorecshit"
  mkdir -p /usr/local/sbin /usr/local/bin
  if [[ ! -f "$src" ]]; then
    warn "Не удалось определить путь скрипта для установки CLI"
    return 0
  fi
  # Avoid no-op copy noise when already identical
  if ! cmp -s "$src" "$dest" 2>/dev/null; then
    local tmp
    tmp="$(mktemp "${dest}.XXXXXX")"
    cp -f "$src" "$tmp"
    chmod 755 "$tmp"
    mv -f "$tmp" "$dest"
    ok "CLI установлен: $dest (v${VERSION})"
  fi
  ln -sfn "$dest" "$link"
  # Ensure sbin is preferred; bin symlink for PATH convenience
  if [[ ! -x "$dest" ]]; then
    chmod 755 "$dest" || true
  fi
}

self_update_from_github() {
  step "Обновление gorecshit с GitHub"
  if [[ "$(id -u)" -ne 0 ]]; then
    err "Обновление требует root"; exit 1
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b curl GitHub/jsDelivr -> /usr/local/sbin/gorecshit\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi
  local urls=(
    "https://raw.githubusercontent.com/gorecvpn/gorecshit/main/install.sh"
    "https://cdn.jsdelivr.net/gh/gorecvpn/gorecshit@main/install.sh"
    "https://fastly.jsdelivr.net/gh/gorecvpn/gorecshit@main/install.sh"
  )
  local tmp dest="/usr/local/sbin/gorecshit" link="/usr/local/bin/gorecshit" ok_url=""
  tmp="$(mktemp /tmp/gorecshit-update.XXXXXX)"
  local u
  for u in "${urls[@]}"; do
    log "Пробую: $u"
    if command -v curl >/dev/null 2>&1; then
      if curl -fsSL --connect-timeout 8 --max-time 60 "$u" -o "$tmp"; then
        ok_url="$u"; break
      fi
    elif command -v wget >/dev/null 2>&1; then
      if wget -q -T 60 -O "$tmp" "$u"; then
        ok_url="$u"; break
      fi
    fi
  done
  if [[ -z "$ok_url" ]]; then
    rm -f "$tmp"
    err "Не удалось скачать install.sh (GitHub и jsDelivr недоступны). Скопируйте файл вручную."
    exit 1
  fi
  if ! head -1 "$tmp" | grep -qE '^#!.*bash'; then
    rm -f "$tmp"
    err "Скачанный файл не похож на bash-скрипт ($ok_url)"
    exit 1
  fi
  if ! bash -n "$tmp" 2>/tmp/gorecshit-bashn.err; then
    err "bash -n не прошёл для скачанного скрипта"
    cat /tmp/gorecshit-bashn.err 2>/dev/null || true
    rm -f "$tmp"
    exit 1
  fi
  mkdir -p /usr/local/sbin /usr/local/bin
  chmod 755 "$tmp"
  mv -f "$tmp" "$dest"
  ln -sfn "$dest" "$link"
  local newv
  newv="$(grep -E '^VERSION=' "$dest" | head -1 | cut -d= -f2 | tr -d '"')"
  ok "Обновлено из $ok_url → $dest (VERSION=${newv:-?})"
  ok "Запуск: gorecshit   |   gorecshit --status   |   gorecshit --update"
}

interactive_menu() {
  local choice=""
  while true; do
    echo
    print_menu_status_line
    menu_sep
    printf '%b📋 Меню:%b\n' "${C_BOLD}" "${C_RESET}"
    printf '  %b1)%b 🚀 Установить защиту (всё)\n' "${C_BOLD}" "${C_RESET}"
    printf '  %b2)%b 🧩 Выборочная установка\n' "${C_BOLD}" "${C_RESET}"
    printf '  %b3)%b 🔄 Обновить списки сканеров\n' "${C_BOLD}" "${C_RESET}"
    printf '  %b4)%b 📊 Показать статус\n' "${C_BOLD}" "${C_RESET}"
    printf '  %b5)%b 🔍 Проверка DPI/блокировок\n' "${C_BOLD}" "${C_RESET}"
    printf '  %b6)%b ↩️  Откат\n' "${C_BOLD}" "${C_RESET}"
    printf '  %b7)%b ⬆️  Обновить gorecshit (GitHub)\n' "${C_BOLD}" "${C_RESET}"
    menu_sep
    printf '  %b0)%b 🚪 Выход\n' "${C_BOLD}" "${C_RESET}"
    printf '%bCLI: gorecshit [--status|--update|--yes|--modules …]%b\n' "${C_GREY}" "${C_RESET}"
    printf '%bВыберите пункт [0-7]:%b ' "${C_BOLD}" "${C_RESET}"
    read -r choice || true
    case "$choice" in
      1)
        apply_modules_csv "all"
        prompt_panel_ip
        ASSUME_YES=1
        return 0
        ;;
      2)
        interactive_select_modules
        prompt_panel_ip
        ASSUME_YES=1
        return 0
        ;;
      3)
        DO_REFRESH_LISTS_ONLY=1
        return 0
        ;;
      4)
        show_status_summary
        ;;
      5)
        run_dpi_check
        ;;
      6)
        DO_ROLLBACK=1
        return 0
        ;;
      7)
        self_update_from_github
        # re-exec updated binary into menu
        if [[ -x /usr/local/sbin/gorecshit ]]; then
          exec /usr/local/sbin/gorecshit
        fi
        ;;
      0|q|Q)
        exit 0
        ;;
      *)
        warn "Неизвестный пункт: $choice"
        ;;
    esac
  done
}

interactive_select_modules() {
  local selected=""
  echo "Модули (введите номера через запятую, Enter = все):"
  echo "  1 ufw  2 blocklist  3 hide_ports  4 anti_probe  5 ssh"
  echo "  6 stealth  7 fail2ban  8 sysctl  9 hostname  10 docker"
  echo "  (или: minimum — UFW+SSH+fail2ban+blocklist+BBR)"
  printf 'Номера: '
  local ans
  read -r ans || true
  if [[ -z "$ans" ]]; then
    selected="all"
  elif [[ "$ans" == "minimum" || "$ans" == "min" ]]; then
    selected="minimum"
  else
    local map=( "" ufw blocklist hide_ports anti_probe ssh stealth fail2ban sysctl hostname docker )
    local n parts=()
    local IFS=,
    for n in $ans; do
      n="$(echo "$n" | tr -d ' ')"
      [[ "$n" =~ ^[0-9]+$ ]] && parts+=("${map[$n]}")
    done
    local IFS=,
    selected="${parts[*]}"
  fi
  apply_modules_csv "${selected:-all}"
  log "Выбраны модули: ufw=$DO_UFW blocklist=$DO_BLOCKLIST hide=$DO_HIDE_PORTS probe=$DO_ANTI_PROBE ssh=$DO_SSH stealth=$DO_STEALTH f2b=$DO_FAIL2BAN sysctl=$DO_SYSCTL host=$DO_HOSTNAME docker=$DO_DOCKER_JOURNAL"
}

preflight() {
  step "Preflight"
  if [[ "$DRY_RUN" -eq 0 && "$(id -u)" -ne 0 ]]; then
    err "Запускайте от root"; exit 1
  fi
  detect_ssh_client
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    # Save script VERSION — /etc/os-release defines VERSION= and would clobber it
    local _gs_ver="$VERSION"
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    VERSION="$_gs_ver"
  else
    OS_ID="unknown"; OS_VERSION="unknown"
  fi
  case "$OS_ID" in
    debian|ubuntu) ok "OS: ${OS_ID} ${OS_VERSION}" ;;
    *) warn "Непроверенная ОС: ${OS_ID} ${OS_VERSION} (цель: Debian 11+/Ubuntu 20.04+)" ;;
  esac
  if [[ -n "$SSH_CLIENT_IP" ]]; then
    ok "SSH client IP (anti-lockout): ${SSH_CLIENT_IP}"
  else
    warn "SSH_CLIENT не задан; опираемся на --allow-ssh-from и IP панели"
  fi
  if [[ -n "$PANEL_IP" ]] && ! is_ipv4 "$PANEL_IP"; then
    err "Некорректный --panel-ip: $PANEL_IP"; exit 2
  fi
  if [[ "$DRY_RUN" -eq 0 ]]; then
    mkdir -p "$BACKUP_DIR" "$MARKER_DIR"
    ok "Бэкапы: $BACKUP_DIR"
  fi
}

detect_remnanode() {
  step "Detect remnanode / listeners"
  DETECTED_NODE_PORT=""
  DETECTED_CLIENT_PORTS=()
  DETECTED_CLIENT_UDP_PORTS=()

  if [[ -f /opt/remnanode/.env ]]; then
    set +e
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
  NGINX_PRESENT=0
  if command -v caddy >/dev/null 2>&1 || [[ -d /etc/caddy ]]; then
    CADDY_PRESENT=1
  elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qi caddy; then
    CADDY_PRESENT=1
  fi
  if command -v nginx >/dev/null 2>&1 || [[ -d /etc/nginx ]]; then
    NGINX_PRESENT=1
  elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qiE 'nginx|remnawave-nginx'; then
    NGINX_PRESENT=1
  fi
  [[ "$CADDY_PRESENT" -eq 1 ]] && ok "Caddy detected"
  [[ "$NGINX_PRESENT" -eq 1 ]] && ok "nginx detected"

  if [[ -z "$DETECTED_NODE_PORT" ]]; then
    local alt np2
    for alt in /opt/remnanode-*/.env; do
      [[ -f "$alt" ]] || continue
      np2="$(grep -E '^(NODE_PORT|APP_PORT)=' "$alt" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '\"\r' || true)"
      if [[ "$np2" =~ ^[0-9]+$ ]]; then
        DETECTED_NODE_PORT="$np2"
        ok "Found $alt port=${DETECTED_NODE_PORT}"
        break
      fi
    done
  fi

  local exclude_port="${DETECTED_NODE_PORT:-3000}"
  # Detect ALL client TCP/UDP ports from xray/rw-core/remnanode/sing-box — never hardcode 443/8443
  if command -v ss >/dev/null 2>&1; then
    local line addr port proc
    while IFS= read -r line; do
      addr="$(ss_local_addr "$line")"
      port="${addr##*:}"
      port="${port%%]*}"
      if [[ ! "$port" =~ ^[0-9]+$ ]]; then continue; fi
      if [[ "$port" == "22" || "$port" == "$exclude_port" || "$port" == "${SSH_PORT_NEW:-}" ]]; then continue; fi
      if ss_is_loopback_addr "$addr"; then continue; fi
      proc=""
      if [[ "$line" == *'users:(('* ]]; then
        proc="$(sed -n 's/.*users:(("\([^"]*\).*/\1/p' <<<"$line" | head -1 || true)"
      fi
      case "$proc" in
        xray|rw-core|remnanode|rw-node|Xray|sing-box|singbox|hysteria|hysteria2|hy2)
          DETECTED_CLIENT_PORTS+=("$port")
          ;;
      esac
    done < <(ss -lntp 2>/dev/null | awk 'NR>1' || true)

    while IFS= read -r line; do
      addr="$(ss_local_addr "$line")"
      port="${addr##*:}"
      port="${port%%]*}"
      if [[ ! "$port" =~ ^[0-9]+$ ]]; then continue; fi
      if [[ "$port" == "53" || "$port" == "68" || "$port" == "323" ]]; then continue; fi
      if ss_is_loopback_addr "$addr"; then continue; fi
      proc=""
      if [[ "$line" == *'users:(('* ]]; then
        proc="$(sed -n 's/.*users:(("\([^"]*\).*/\1/p' <<<"$line" | head -1 || true)"
      fi
      case "$proc" in
        xray|rw-core|remnanode|rw-node|Xray|sing-box|singbox|hysteria|hysteria2|hy2)
          DETECTED_CLIENT_UDP_PORTS+=("$port")
          ;;
      esac
    done < <(ss -lnup 2>/dev/null | awk 'NR>1' || true)
  fi

  if [[ ${#DETECTED_CLIENT_PORTS[@]} -gt 0 ]]; then
    mapfile -t DETECTED_CLIENT_PORTS < <(printf '%s\n' "${DETECTED_CLIENT_PORTS[@]}" | sort -n -u)
  fi
  if [[ ${#DETECTED_CLIENT_UDP_PORTS[@]} -gt 0 ]]; then
    mapfile -t DETECTED_CLIENT_UDP_PORTS < <(printf '%s\n' "${DETECTED_CLIENT_UDP_PORTS[@]}" | sort -n -u)
  fi

  if [[ "$NODE_PORT" == "auto" ]]; then
    NODE_PORT="${DETECTED_NODE_PORT:-3000}"
  fi
  if [[ "$CLIENT_PORTS" == "auto" ]]; then
    if [[ "$MODE" == "cdn" || "$CADDY_PRESENT" -eq 1 ]]; then
      CLIENT_PORTS="80,443"
    elif [[ ${#DETECTED_CLIENT_PORTS[@]} -gt 0 ]]; then
      local IFS=,
      CLIENT_PORTS="${DETECTED_CLIENT_PORTS[*]}"
      IFS=$' \t\n'
    else
      CLIENT_PORTS=""
      warn "Клиентские TCP-слушатели не найдены; укажите --client-ports (порты НЕ хардкодятся)"
    fi
  fi
  if [[ "$CLIENT_UDP_PORTS" == "auto" ]]; then
    if [[ ${#DETECTED_CLIENT_UDP_PORTS[@]} -gt 0 ]]; then
      local IFS=,
      CLIENT_UDP_PORTS="${DETECTED_CLIENT_UDP_PORTS[*]}"
      IFS=$' \t\n'
    else
      CLIENT_UDP_PORTS=""
    fi
  fi

  ok "NODE_PORT=${NODE_PORT}"
  ok "CLIENT_PORTS(tcp)=${CLIENT_PORTS:-<none>}"
  ok "CLIENT_UDP_PORTS=${CLIENT_UDP_PORTS:-<none>}"
  ok "MODE=${MODE}"
}


do_rollback() {
  step "Rollback / uninstall"
  local latest
  if [[ ! -d "$BACKUP_ROOT" ]]; then
    err "Нет бэкапов в $BACKUP_ROOT"; exit 1
  fi
  latest="$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
  if [[ -z "$latest" ]]; then
    err "Каталоги бэкапов не найдены"; exit 1
  fi
  log "Используем бэкап: $latest"
  if [[ -x "$latest/rollback.sh" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      printf '%b[DRY]%b run %s\n' "${C_YEL}" "${C_RESET}" "$latest/rollback.sh"
      exit 0
    fi
    bash "$latest/rollback.sh"
    ok "Rollback script finished"
    exit 0
  fi
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
  chmod 755 "$rb"
  {
    echo "panel_ip=${PANEL_IP}"
    echo "node_port=${NODE_PORT}"
    echo "client_ports=${CLIENT_PORTS}"
    echo "client_udp_ports=${CLIENT_UDP_PORTS}"
    echo "version=${VERSION}"
    echo "ts=${TS}"
  } >"${BACKUP_DIR}/MANIFEST.txt"
}

install_packages() {
  step "Пакеты"
  local pkgs=(ufw fail2ban ipset chrony curl ca-certificates iptables)
  # hashlimit / connlimit need xtables modules usually already in iptables
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b apt-get install -y %s\n' "${C_YEL}" "${C_RESET}" "${pkgs[*]}"
    return 0
  fi
  export DEBIAN_FRONTEND=noninteractive
  if [[ "$IPV6_OFF" -eq 1 ]]; then
    mkdir -p /etc/apt/apt.conf.d
    echo 'Acquire::ForceIPv4 "true";' >/etc/apt/apt.conf.d/99force-ipv4
  fi
  apt-get update -qq || warn "apt-get update failed (продолжаем)"
  apt-get install -y -qq "${pkgs[@]}" || apt-get install -y "${pkgs[@]}"
  # optional whiptail for future interactive runs on minimal images
  apt-get install -y -qq whiptail 2>/dev/null || true
  ok "Пакеты установлены: ${pkgs[*]}"
}

configure_sysctl() {
  if [[ "$DO_SYSCTL" -eq 0 ]]; then
    log "sysctl/BBR пропущен"
    return 0
  fi
  step "sysctl BBR + буферы"
  backup_file /etc/sysctl.d/99-zz-bbr.conf
  backup_file /etc/sysctl.d/99-disable-ipv6.conf
  backup_file /etc/sysctl.d/99-gorecshit-stealth.conf

  # Pick qdisc
  if modprobe fq 2>/dev/null || [[ -d /sys/module/sch_fq ]]; then
    QDISC="fq"
  else
    QDISC="fq_codel"
  fi

  local body="# Managed by ${SCRIPT_NAME} ${VERSION} — BBR + ${QDISC} + throughput buffers
net.core.default_qdisc = ${QDISC}
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 131072 67108864
net.ipv4.tcp_wmem = 4096 131072 67108864
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
fs.file-max = 2097152
net.netfilter.nf_conntrack_max = 1048576
"
  write_content /etc/sysctl.d/99-zz-bbr.conf "$body"

  # Always liberal conntrack: UFW drops INVALID; without this, NAT/asymmetric TCP can kill live VPN flows
  write_content /etc/sysctl.d/99-conntrack-liberal.conf \
"# Managed by ${SCRIPT_NAME} ${VERSION}
net.netfilter.nf_conntrack_tcp_be_liberal = 1
"

  if [[ "$IPV6_OFF" -eq 1 ]]; then
    write_content /etc/sysctl.d/99-disable-ipv6.conf \
"net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
"
    # remove enable override if present
    if [[ "$DRY_RUN" -eq 0 && -f /etc/sysctl.d/99-enable-ipv6.conf ]]; then
      rm -f /etc/sysctl.d/99-enable-ipv6.conf
    fi
    ok "IPv6 disable sysctl written (--ipv6-off)"
  else
    # Default: keep IPv6. Remove prior disable file so re-runs heal dual-stack xray nodes.
    if [[ "$DRY_RUN" -eq 0 ]]; then
      if [[ -f /etc/sysctl.d/99-disable-ipv6.conf ]]; then
        backup_file /etc/sysctl.d/99-disable-ipv6.conf
        rm -f /etc/sysctl.d/99-disable-ipv6.conf
        ok "Removed 99-disable-ipv6.conf (IPv6 kept by default)"
      fi
      write_content /etc/sysctl.d/99-enable-ipv6.conf \
"# Managed by ${SCRIPT_NAME} ${VERSION} — xray often listens dual-stack; IPv6 off is opt-in (--ipv6-off)
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0
"
    fi
  fi

  if [[ "$DO_TCP_TIMESTAMPS_OFF" -eq 1 ]]; then
    write_content /etc/sysctl.d/99-gorecshit-tcp-timestamps.conf "net.ipv4.tcp_timestamps = 0\n"
    ok "tcp_timestamps=0"
  fi

  if [[ "$DRY_RUN" -eq 0 ]]; then
    sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-zz-bbr.conf >/dev/null 2>&1 || true
    # default_qdisc=fq only affects new devices; force fq + txqueuelen on default route iface
    local iface
    iface="$(ip -o route show default 2>/dev/null | awk '{print $5; exit}' || true)"
    if [[ -n "$iface" ]]; then
      tc qdisc replace dev "$iface" root fq 2>/dev/null || tc qdisc change dev "$iface" root fq 2>/dev/null || true
      ip link set dev "$iface" txqueuelen 10000 2>/dev/null || true
    fi
    # Persist NIC tune across reboot (no docker restart)
    write_content /usr/local/sbin/gorecshit-nic-tune.sh \
'#!/bin/bash
IFACE=$(ip -o route show default 2>/dev/null | awk '"'"'{print $5; exit}'"'"')
[ -n "$IFACE" ] || exit 0
ip link set dev "$IFACE" txqueuelen 10000 2>/dev/null || true
tc qdisc replace dev "$IFACE" root fq 2>/dev/null || true
'
    chmod 755 /usr/local/sbin/gorecshit-nic-tune.sh
    write_content /etc/systemd/system/gorecshit-nic-tune.service \
"[Unit]
Description=gorecshit NIC txqueuelen + fq
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/gorecshit-nic-tune.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"
    systemctl daemon-reload
    systemctl enable --now gorecshit-nic-tune.service >/dev/null 2>&1 || true
    # irqbalance best-effort (spreads NIC IRQs; skip quietly if unavailable)
    if ! command -v irqbalance >/dev/null 2>&1; then
      apt-get install -y -qq irqbalance >/dev/null 2>&1 || true
    fi
    if command -v irqbalance >/dev/null 2>&1; then
      systemctl enable --now irqbalance >/dev/null 2>&1 || true
      ok "irqbalance enabled"
    fi
  else
    printf '%b[DRY]%b sysctl --system + tc fq + txqueuelen 10000 + irqbalance\n' "${C_YEL}" "${C_RESET}"
  fi
  ok "Sysctl applied (cc=bbr qdisc=${QDISC}; buffers=64MB; tcp_notsent_lowat=16384; tcp_be_liberal=1; ipv6_off=${IPV6_OFF})"
}

configure_ssh() {
  if [[ "$DO_SSH" -eq 0 ]]; then
    log "SSH hardening пропущен"
    return 0
  fi
  step "SSH hardening drop-in"
  local conf="/etc/ssh/sshd_config.d/99-hardening.conf"
  backup_file "$conf"
  backup_file /etc/ssh/sshd_config

  # Optional new SSH port: open UFW first, validate, keep 22
  if [[ -n "$SSH_PORT_NEW" && "$SSH_PORT_NEW" != "22" ]]; then
    step "Добавление SSH порта ${SSH_PORT_NEW} (22 сохраняем)"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      if command -v ufw >/dev/null 2>&1; then
        ufw allow "${SSH_PORT_NEW}/tcp" comment 'SSH alt port' || true
        if [[ -n "$SSH_CLIENT_IP" ]]; then
          ufw allow from "$SSH_CLIENT_IP" to any port "$SSH_PORT_NEW" proto tcp comment 'SSH alt current client' || true
        fi
        ufw allow from "$PANEL_IP" to any port "$SSH_PORT_NEW" proto tcp comment 'SSH alt from panel' || true
      fi
      # Ensure Port directives: keep 22 + add new
      if ! grep -qE "^Port ${SSH_PORT_NEW}\b" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null; then
        echo "Port 22" >>"$conf"
        echo "Port ${SSH_PORT_NEW}" >>"$conf"
      fi
    else
      printf '%b[DRY]%b ufw allow %s/tcp; sshd Port 22 + %s\n' "${C_YEL}" "${C_RESET}" "$SSH_PORT_NEW" "$SSH_PORT_NEW"
    fi
  fi

  local body=""
  body+="Banner none"$'\n'
  body+="MaxAuthTries 3"$'\n'
  body+="LoginGraceTime 20"$'\n'
  body+="MaxStartups 10:30:60"$'\n'
  # Do NOT disable password/root login.
  body+="PasswordAuthentication yes"$'\n'
  body+="PermitRootLogin yes"$'\n'
  if [[ -n "$SSH_PORT_NEW" && "$SSH_PORT_NEW" != "22" ]]; then
    body+="Port 22"$'\n'
    body+="Port ${SSH_PORT_NEW}"$'\n'
  fi

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
      if [[ -n "$SSH_PORT_NEW" && "$SSH_PORT_NEW" != "22" ]]; then
        warn "Новый SSH порт ${SSH_PORT_NEW} добавлен; порт 22 сохранён до вашей проверки доступности"
      fi
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

configure_fail2ban() {
  if [[ "$DO_FAIL2BAN" -eq 0 ]]; then
    log "fail2ban пропущен"
    return 0
  fi
  step "fail2ban sshd + recidive"
  backup_file /etc/fail2ban/jail.local
  local ignore
  ignore="$(whitelist_ips_csv)"
  local jail="# Managed by ${SCRIPT_NAME} ${VERSION}
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
ignoreip = ${ignore}

[sshd]
enabled = true
port = ssh
filter = sshd
backend = systemd
maxretry = 5
bantime = 1h

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
banaction = iptables-multiport
bantime = 1w
findtime = 1d
maxretry = 3
"
  # Also ban scanner-set hits on SSH immediately via ignoreip inverse handled by ipset DROP already;
  # add dedicated jail action note in filter-less action using recidive above.
  write_content /etc/fail2ban/jail.local "$jail"$'\n'
  if [[ "$DRY_RUN" -eq 0 ]]; then
    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban
    ok "fail2ban configured (sshd + recidive; ignoreip includes panel + SSH client + relays)"
  else
    printf '%b[DRY]%b systemctl restart fail2ban\n' "${C_YEL}" "${C_RESET}"
  fi
}


hook_ufw_before_rules() {
  local rules="/etc/ufw/before.rules"
  backup_file "$rules"
  if [[ ! -f "$rules" ]]; then
    warn "Нет $rules — пропуск хука"
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b hook ufw before.rules (panel/relays ACCEPT + scanner DROP + ICMP)\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi

  # Remove previous gorecshit managed block if present
  if grep -q '# gorecshit-managed-begin' "$rules"; then
    sed -i '/# gorecshit-managed-begin/,/# gorecshit-managed-end/d' "$rules"
  fi

  local insert=""
  insert+="# gorecshit-managed-begin ${VERSION}"$'\n'
  insert+="# Accept management / anti-lockout / HAProxy relays before blocklist DROP"$'\n'
  insert+="-A ufw-before-input -s ${PANEL_IP} -j ACCEPT"$'\n'
  if [[ -n "$SSH_CLIENT_IP" ]]; then
    insert+="-A ufw-before-input -s ${SSH_CLIENT_IP} -j ACCEPT"$'\n'
  fi
  local a
  while IFS= read -r a; do
    insert+="-A ufw-before-input -s ${a} -j ACCEPT"$'\n'
  done < <(foreach_csv_ip "$ALLOW_SSH_FROM")
  while IFS= read -r a; do
    insert+="-A ufw-before-input -s ${a} -j ACCEPT"$'\n'
  done < <(foreach_csv_ip "$RELAY_IPS")
  if [[ "$DO_BLOCKLIST" -eq 1 ]]; then
    insert+="-A ufw-before-input -m conntrack --ctstate NEW -m set --match-set scanner-block src -j DROP"$'\n'
  fi
  insert+="# gorecshit-managed-end"$'\n'

  if grep -q 'ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' "$rules"; then
    local tmp
    tmp="$(mktemp)"
    awk -v ins="$insert" '
      /ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT/ && !done {
        print; print ins; done=1; next
      }
      { print }
    ' "$rules" >"$tmp"
    mv "$tmp" "$rules"
  else
    # fallback: prepend after *filter
    local tmp
    tmp="$(mktemp)"
    awk -v ins="$insert" '
      BEGIN{done=0}
      /^\*filter/ && !done { print; print ins; done=1; next }
      { print }
    ' "$rules" >"$tmp"
    mv "$tmp" "$rules"
  fi

  # Hide ping: echo-request DROP (not ACCEPT)
  if [[ "$DO_HIDE_PORTS" -eq 1 ]]; then
    sed -i -E 's/^(-A ufw-before-input -p icmp --icmp-type echo-request -j) ACCEPT/\1 DROP/' "$rules" || true
    sed -i -E 's/^(-A ufw-before-forward -p icmp --icmp-type echo-request -j) ACCEPT/\1 DROP/' "$rules" || true
    # Also destination-unreachable / time-exceeded stay ACCEPT for PMTU usually —
    # but for closed-port stealth we drop ICMP unreachable replies via sysctl/iptables below.
  fi
  ok "UFW before.rules hooked (panel+relays ACCEPT; scanner DROP; ping hide=${DO_HIDE_PORTS})"
}

configure_hide_ports() {
  if [[ "$DO_HIDE_PORTS" -eq 0 ]]; then
    log "Скрытие портов/ping пропущено"
    return 0
  fi
  step "Скрытие закрытых портов и ping (DROP, без RST/unreachable)"
  backup_file /etc/ufw/before.rules
  backup_file /etc/default/ufw
  backup_file /etc/sysctl.d/99-gorecshit-stealth-net.conf

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b ufw default deny incoming (DROP); logging low; ICMP echo DROP; disable RST for closed\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi

  # UFW: deny = DROP (not REJECT)
  sed -i 's/^DEFAULT_INPUT_POLICY=.*/DEFAULT_INPUT_POLICY="DROP"/' /etc/default/ufw || true
  # UFW IPv6 follows IPV6_OFF (default: keep IPv6)
  if [[ "$IPV6_OFF" -eq 1 ]]; then
    sed -i 's/^IPV6=.*/IPV6=no/' /etc/default/ufw 2>/dev/null || true
  else
    sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw 2>/dev/null || true
  fi
  ufw logging low || true
  ufw default deny incoming || true
  ufw default allow outgoing || true

  # Drop TCP RST / ICMP port-unreachable for closed ports (make them look filtered)
  # net.ipv4.icmp_echo_ignore_all is too blunt; we already DROP echo-request in before.rules
  write_content /etc/sysctl.d/99-gorecshit-stealth-net.conf \
"# Managed by ${SCRIPT_NAME} ${VERSION}
# Reduce leakage about closed ports (best-effort; UFW DROP is primary)
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
"
  sysctl -p /etc/sysctl.d/99-gorecshit-stealth-net.conf >/dev/null 2>&1 || true

  # iptables: ensure final UFW reject path uses DROP. ufw-reject-input usually REJECT — replace with DROP via after.rules tip:
  # UFW's deny uses DROP when DEFAULT_INPUT_POLICY=DROP; ufw-reject-input still may REJECT.
  # Soften: insert catch-all DROP before reject if possible.
  if iptables -L ufw-reject-input -n >/dev/null 2>&1; then
    iptables -C ufw-reject-input -j DROP 2>/dev/null || iptables -I ufw-reject-input 1 -j DROP 2>/dev/null || true
  fi
  ok "Закрытые порты/ping: DROP (без RST), logging=low"
}

configure_anti_probe() {
  if [[ "$DO_ANTI_PROBE" -eq 0 ]]; then
    log "Anti-probing пропущен"
    return 0
  fi
  step "Anti-probing на клиентских портах (hashlimit/connlimit)"
  local ports_tcp=() ports_udp=()
  local p
  while IFS= read -r p; do [[ -n "$p" ]] && ports_tcp+=("$p"); done < <(foreach_csv "$CLIENT_PORTS")
  while IFS= read -r p; do [[ -n "$p" ]] && ports_udp+=("$p"); done < <(foreach_csv "$CLIENT_UDP_PORTS")

  if [[ ${#ports_tcp[@]} -eq 0 && ${#ports_udp[@]} -eq 0 ]]; then
    warn "Нет клиентских портов для anti-probe — пропуск (задайте --client-ports / --client-udp-ports)"
    return 0
  fi

  local script="/usr/local/sbin/gorecshit-anti-probe.sh"
  local unit="/etc/systemd/system/gorecshit-anti-probe.service"
  backup_file "$script"
  backup_file "$unit"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b anti-probe TCP=%s UDP=%s (ESTABLISHED first; NEW-only hashlimit 600/min burst 1200, connlimit 2000; no recent-ban)\n' \
      "${C_YEL}" "${C_RESET}" "${CLIENT_PORTS}" "${CLIENT_UDP_PORTS}"
    return 0
  fi

  # Throughput rules:
  #  - ESTABLISHED,RELATED always bypass (never hashlimit/connlimit/ipset on hot path)
  #  - limits apply to NEW only; ceilings generous for CGNAT/home NAT
  #  - no xt_recent silent 10m ban (banned legit NAT clients after reconnect bursts)
  {
    echo '#!/bin/bash'
    echo "# Managed by ${SCRIPT_NAME} ${VERSION}"
    echo 'set -euo pipefail'
    echo 'CHAIN=GORECSHIT-ANTIPROBE'
    echo 'iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"'
    echo '# Hot path: established client traffic never rate-limited'
    echo 'iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN'
    echo '# never-block (panel / ssh client / relays)'
    echo "iptables -A \"\$CHAIN\" -s ${PANEL_IP} -j RETURN"
    [[ -n "$SSH_CLIENT_IP" ]] && echo "iptables -A \"\$CHAIN\" -s ${SSH_CLIENT_IP} -j RETURN"
    while IFS= read -r a; do
      echo "iptables -A \"\$CHAIN\" -s ${a} -j RETURN"
    done < <(foreach_csv_ip "$ALLOW_SSH_FROM")
    while IFS= read -r a; do
      echo "iptables -A \"\$CHAIN\" -s ${a} -j RETURN"
    done < <(foreach_csv_ip "$RELAY_IPS")
    for p in "${ports_tcp[@]}"; do
      echo "iptables -A \"\$CHAIN\" -p tcp --dport ${p} -m conntrack --ctstate NEW -m connlimit --connlimit-above 2000 --connlimit-mask 32 -j DROP"
      echo "iptables -A \"\$CHAIN\" -p tcp --dport ${p} -m conntrack --ctstate NEW -m hashlimit --hashlimit-name gs_ap_${p} --hashlimit-mode srcip --hashlimit-above 600/min --hashlimit-burst 1200 --hashlimit-htable-expire 120000 -j DROP"
    done
    for p in "${ports_udp[@]}"; do
      # NEW only — never limit established UDP flows (hy2/tuic data plane)
      echo "iptables -A \"\$CHAIN\" -p udp --dport ${p} -m conntrack --ctstate NEW -m hashlimit --hashlimit-name gs_apu_${p} --hashlimit-mode srcip --hashlimit-above 1200/min --hashlimit-burst 2400 --hashlimit-htable-expire 120000 -j DROP"
    done
    echo 'iptables -A "$CHAIN" -j RETURN'
    echo '# Hook into ufw-before-input if present, else INPUT (after ESTABLISHED hotpath if any)'
    echo 'if iptables -L ufw-before-input -n >/dev/null 2>&1; then'
    echo '  iptables -C ufw-before-input -j "$CHAIN" 2>/dev/null || iptables -I ufw-before-input 4 -j "$CHAIN"'
    echo 'else'
    echo '  iptables -C INPUT -j "$CHAIN" 2>/dev/null || iptables -I INPUT 1 -j "$CHAIN"'
    echo 'fi'
    echo '# INPUT hot-path: ACCEPT ESTABLISHED/RELATED before fail2ban/antiprobe jumps'
    echo 'while iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do'
    echo '  iptables -D INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || break'
    echo 'done'
    echo 'iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
  } >"$script"
  chmod 755 "$script"

  cat >"$unit" <<EOF
[Unit]
Description=gorecshit anti-probe rate limits on client ports (NEW only; ESTABLISHED first)
After=network.target ufw.service
Wants=ufw.service

[Service]
Type=oneshot
ExecStart=${script}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable gorecshit-anti-probe.service >/dev/null 2>&1 || true
  "$script" || warn "anti-probe apply returned non-zero"
  ok "Anti-probe TCP=[${CLIENT_PORTS}] UDP=[${CLIENT_UDP_PORTS}] (ESTABLISHED bypass; NEW-only NAT-friendly limits; no recent-ban)"
}

configure_ufw() {
  if [[ "$DO_UFW" -eq 0 ]]; then
    log "UFW пропущен"
    return 0
  fi
  step "UFW"
  backup_file /etc/ufw/before.rules
  backup_file /etc/default/ufw

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b ufw default deny incoming / allow outgoing; limit 22; clients; NODE_PORT from panel\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi

  hook_ufw_before_rules
  configure_hide_ports

  ufw default deny incoming
  ufw default allow outgoing

  # SSH
  ufw limit 22/tcp comment 'SSH rate-limit' || true
  if [[ -n "$SSH_CLIENT_IP" ]]; then
    ufw allow from "$SSH_CLIENT_IP" to any port 22 proto tcp comment 'SSH current client' || true
  fi
  if [[ -n "$ALLOW_SSH_FROM" ]]; then
    local a
    while IFS= read -r a; do
      ufw allow from "$a" to any port 22 proto tcp comment 'SSH allow-list' || true
    done < <(foreach_csv_ip "$ALLOW_SSH_FROM")
  fi
  ufw allow from "$PANEL_IP" to any port 22 proto tcp comment 'SSH from panel' || true
  if [[ -n "$SSH_PORT_NEW" && "$SSH_PORT_NEW" != "22" ]]; then
    ufw allow "${SSH_PORT_NEW}/tcp" comment 'SSH alt port' || true
  fi

  # Relays ACCEPT on client ports
  local p a
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    ufw allow "${p}/tcp" comment "client-${p}" || true
    while IFS= read -r a; do
      ufw allow from "$a" to any port "$p" proto tcp comment "relay-client-${p}" || true
    done < <(foreach_csv_ip "$RELAY_IPS")
  done < <(foreach_csv "$CLIENT_PORTS")

  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    ufw allow "${p}/udp" comment "client-udp-${p}" || true
  done < <(foreach_csv "$CLIENT_UDP_PORTS")

  # NODE_PORT only from panel
  ufw allow from "$PANEL_IP" to any port "$NODE_PORT" proto tcp comment 'remnanode from panel' || true
  # Deny public NODE_PORT if somehow open (idempotent deny after allow-from)
  # ufw processes first match — allow from panel already added

  if [[ "$MODE" == "cdn" || "$CADDY_PRESENT" -eq 1 ]]; then
    ufw allow 80/tcp comment 'cdn-http' || true
    ufw allow 443/tcp comment 'cdn-https' || true
  fi

  # Deny common internal xray if present and not in CLIENT_PORTS
  ufw deny 4443/tcp comment 'deny-public-xray-4443' || true

  ufw --force enable
  ok "UFW enabled (SSH limited; NODE_PORT=${NODE_PORT}←panel; clients tcp=${CLIENT_PORTS} udp=${CLIENT_UDP_PORTS})"
}


install_blocklist() {
  if [[ "$DO_BLOCKLIST" -eq 0 ]]; then
    warn "Skipping scanner blocklist (--no-blocklist)"
    return 0
  fi
  step "Scanner blocklist (ipset + mirrors + weekly timer)"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b install /usr/local/sbin/scanner-block-refresh.sh (mirrors + parallel)\n' "${C_YEL}" "${C_RESET}"
    printf '%b[DRY]%b never-block + --blocklist-from fallback\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi

  mkdir -p /etc/scanner-block
  backup_file /usr/local/sbin/scanner-block-refresh.sh
  backup_file /etc/systemd/system/scanner-block.service
  backup_file /etc/systemd/system/scanner-block-refresh.service
  backup_file /etc/systemd/system/scanner-block-refresh.timer
  backup_file /etc/scanner-block/never-block.txt
  if [[ -n "$BLOCKLIST_FROM" ]]; then
    printf '%s\n' "$BLOCKLIST_FROM" >/etc/scanner-block/blocklist-from.conf
  fi

  {
    echo "# Managed by ${SCRIPT_NAME} — never include these in scanner-block"
    echo "$PANEL_IP"
    if [[ -n "$SSH_CLIENT_IP" ]]; then echo "$SSH_CLIENT_IP"; fi
    local a
    while IFS= read -r a; do echo "$a"; done < <(foreach_csv_ip "$ALLOW_SSH_FROM")
    while IFS= read -r a; do echo "$a"; done < <(foreach_csv_ip "$RELAY_IPS")
    echo "10.0.0.0/8"
    echo "172.16.0.0/12"
    echo "192.168.0.0/16"
    echo "127.0.0.0/8"
    echo "169.254.0.0/16"
    # Yandex / common CDN edge (harmless if unused)
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
  } >/etc/scanner-block/never-block.txt

  cat >/usr/local/sbin/scanner-block-refresh.sh <<'REFRESH_EOF'
#!/bin/bash
set -euo pipefail
# Refresh scanner-block ipset. Safe failure: keep old list if download fails.
# Mirrors: raw.githubusercontent.com → cdn.jsdelivr.net/gh → fastly.jsdelivr.net/gh
# Timeouts: connect 8s, max 20s. Parallel downloads. --blocklist-from fallback.
# --local-only: only load /etc/scanner-block/blocklist.txt (boot path)

LOCAL_ONLY=0
[ "${1:-}" = "--local-only" ] && LOCAL_ONLY=1

DIR=/etc/scanner-block
LIST="$DIR/blocklist.txt"
TMP="$DIR/blocklist.txt.new"
NEVER="$DIR/never-block.txt"
FROM_CONF="$DIR/blocklist-from.conf"
SET=scanner-block
CONNECT_TIMEOUT=8
MAX_TIME=20
mkdir -p "$DIR"

js_mirrors() {
  # js_mirrors <github_raw_url> → prints mirror URLs (jsdelivr) then original
  local url="$1"
  local owner repo ref path
  if [[ "$url" =~ ^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.*)$ ]]; then
    owner="${BASH_REMATCH[1]}"; repo="${BASH_REMATCH[2]}"; ref="${BASH_REMATCH[3]}"; path="${BASH_REMATCH[4]}"
    echo "https://cdn.jsdelivr.net/gh/${owner}/${repo}@${ref}/${path}"
    echo "https://fastly.jsdelivr.net/gh/${owner}/${repo}@${ref}/${path}"
  fi
  echo "$url"
}

fetch_one() {
  # fetch_one <outdir> <name> <url...>  (tries each URL)
  local outdir="$1" name="$2"; shift 2
  local u
  for u in "$@"; do
    if curl -fsSL --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" -o "${outdir}/${name}" "$u" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

fetch_gh() {
  # fetch_gh <outdir> <name> <raw_github_url>
  local outdir="$1" name="$2" raw="$3"
  local urls
  mapfile -t urls < <(js_mirrors "$raw")
  fetch_one "$outdir" "$name" "${urls[@]}"
}

import_from_source() {
  # import_from_source <src> → writes LIST if successful
  local src="$1"
  local dest="$LIST.from"
  if [[ -z "$src" ]]; then return 1; fi
  if [[ "$src" =~ ^https?:// ]]; then
    curl -fsSL --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" -o "$dest" "$src" || return 1
  elif [[ -f "$src" ]]; then
    cp -a "$src" "$dest" || return 1
  else
    # treat as SSH host: copy remote /etc/scanner-block/blocklist.txt
    scp -o ConnectTimeout=12 -o StrictHostKeyChecking=accept-new \
      "root@${src}:/etc/scanner-block/blocklist.txt" "$dest" 2>/dev/null || \
    scp -o ConnectTimeout=12 -o StrictHostKeyChecking=accept-new \
      "${src}:/etc/scanner-block/blocklist.txt" "$dest" 2>/dev/null || return 1
  fi
  if [[ -s "$dest" ]]; then
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' "$dest" | sort -u >"$TMP.raw" || true
    if [[ -s "$TMP.raw" ]]; then
      echo "IMPORTED from $src ($(wc -l <"$TMP.raw") lines)"
      return 0
    fi
  fi
  return 1
}

download_lists() {
  local tmpdir
  tmpdir=$(mktemp -d)
  # shellcheck disable=SC2064
  trap 'rm -rf "$tmpdir"' RETURN
  local ok=0
  local pids=()

  download_job() {
    local name="$1"; shift
    if fetch_one "$tmpdir" "$name" "$@"; then
      echo OK >"${tmpdir}/${name}.ok"
    fi
  }

  # OpenFilters scanner CIDRs (GitHub + jsDelivr mirrors)
  local BASE_RAW="https://raw.githubusercontent.com/OpenFilters/internet-scanners/main/cidr"
  local f
  for f in censys_v4.txt shodan_v4.txt binaryedge_v4.txt shadowserver_v4.txt driftnet_v4.txt \
    paloaltonetworks_v4.txt rapid7_v4.txt onyphe_v4.txt bitsight_v4.txt leakix_v4.txt cyberok_v4.txt \
    netlas_v4.txt zoomeye_v4.txt quake_v4.txt fofa_v4.txt hunter_v4.txt criminalip_v4.txt \
    internetmeasurementresearch_v4.txt researchscanner_v4.txt alphastrike_v4.txt \
    cyberresilience_v4.txt cybcube_v4.txt detectify_v4.txt hackertarget_v4.txt other_v4.txt; do
    (
      mapfile -t urls < <(js_mirrors "$BASE_RAW/$f")
      fetch_one "$tmpdir" "$f" "${urls[@]}" && echo OK >"${tmpdir}/${f}.ok"
    ) &
    pids+=($!)
  done

  # Extra verified sources (2026-11-01 curl-checked; 404s dropped)
  (
    mapfile -t urls < <(js_mirrors "https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt")
    fetch_one "$tmpdir" "cyberok-skipa.txt" "${urls[@]}" && echo OK >"${tmpdir}/cyberok-skipa.txt.ok"
  ) &
  pids+=($!)
  (
    mapfile -t urls < <(js_mirrors "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/main/public/antiscanner.list")
    fetch_one "$tmpdir" "antiscanner.list" "${urls[@]}" && echo OK >"${tmpdir}/antiscanner.list.ok"
  ) &
  pids+=($!)
  (
    mapfile -t urls < <(js_mirrors "https://raw.githubusercontent.com/Xorlent/Internet-Scanners/main/censys.txt")
    fetch_one "$tmpdir" "xorlent-censys.txt" "${urls[@]}" && echo OK >"${tmpdir}/xorlent-censys.txt.ok"
  ) &
  pids+=($!)
  for n in stretchoid binaryedge shadowserver censys internet-measurement.com; do
    (
      fetch_one "$tmpdir" "wdes-$n.txt" "https://security.wdes.eu/scanners/$n.txt" && echo OK >"${tmpdir}/wdes-$n.txt.ok"
    ) &
    pids+=($!)
  done
  for n in stretchoid censys binaryedge shadowserver; do
    (
      mapfile -t urls < <(js_mirrors "https://raw.githubusercontent.com/Xorlent/Internet-Scanners/main/$n.txt")
      fetch_one "$tmpdir" "xorlent-$n.txt" "${urls[@]}" && echo OK >"${tmpdir}/xorlent-$n.txt.ok"
    ) &
    pids+=($!)
  done

  # FireHOL level1/level2 (iplists + github mirrors). Filtered by never-block + prefixlen.
  (
    fetch_one "$tmpdir" "firehol_level1.netset" \
      "https://iplists.firehol.org/files/firehol_level1.netset" \
      "https://cdn.jsdelivr.net/gh/firehol/blocklist-ipsets@master/firehol_level1.netset" \
      "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" \
      && echo OK >"${tmpdir}/firehol_level1.netset.ok"
  ) &
  pids+=($!)
  (
    fetch_one "$tmpdir" "firehol_level2.netset" \
      "https://iplists.firehol.org/files/firehol_level2.netset" \
      "https://cdn.jsdelivr.net/gh/firehol/blocklist-ipsets@master/firehol_level2.netset" \
      "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset" \
      && echo OK >"${tmpdir}/firehol_level2.netset.ok"
  ) &
  pids+=($!)

  # Spamhaus DROP/EDROP (official + github mirror)
  (
    fetch_one "$tmpdir" "spamhaus_drop.txt" \
      "https://www.spamhaus.org/drop/drop.txt" \
      "https://cdn.jsdelivr.net/gh/firehol/blocklist-ipsets@master/spamhaus_drop.netset" \
      "https://raw.githubusercontent.com/SecOps-Institute/SpamhausIPLists/master/drop.txt" \
      && echo OK >"${tmpdir}/spamhaus_drop.txt.ok"
  ) &
  pids+=($!)
  (
    fetch_one "$tmpdir" "spamhaus_edrop.txt" \
      "https://www.spamhaus.org/drop/edrop.txt" \
      "https://cdn.jsdelivr.net/gh/firehol/blocklist-ipsets@master/spamhaus_edrop.netset" \
      "https://raw.githubusercontent.com/SecOps-Institute/SpamhausIPLists/master/edrop.txt" \
      && echo OK >"${tmpdir}/spamhaus_edrop.txt.ok"
  ) &
  pids+=($!)

  # blocklist.de
  (
    fetch_one "$tmpdir" "blocklist_de_ssh.txt" "https://lists.blocklist.de/lists/ssh.txt" \
      "https://cdn.jsdelivr.net/gh/firehol/blocklist-ipsets@master/blocklist_de_ssh.ipset" \
      && echo OK >"${tmpdir}/blocklist_de_ssh.txt.ok"
  ) &
  pids+=($!)
  (
    fetch_one "$tmpdir" "blocklist_de_all.txt" "https://lists.blocklist.de/lists/all.txt" \
      && echo OK >"${tmpdir}/blocklist_de_all.txt.ok"
  ) &
  pids+=($!)

  # CINS army
  (
    fetch_one "$tmpdir" "cins_army.txt" "https://cinsscore.com/list/ci-badguys.txt" \
      && echo OK >"${tmpdir}/cins_army.txt.ok"
  ) &
  pids+=($!)

  # ipsum level 3 (reputation)
  (
    mapfile -t urls < <(js_mirrors "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt")
    fetch_one "$tmpdir" "ipsum3.txt" "${urls[@]}" && echo OK >"${tmpdir}/ipsum3.txt.ok"
  ) &
  pids+=($!)

  # Russian state scanner ranges: CyberOK Skipa (already) + C24Be AS_Network_List blacklist-v4
  (
    mapfile -t urls < <(js_mirrors "https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist-v4.txt")
    fetch_one "$tmpdir" "c24be_v4.txt" "${urls[@]}" && echo OK >"${tmpdir}/c24be_v4.txt.ok"
  ) &
  pids+=($!)

  for pid in "${pids[@]}"; do
    wait "$pid" || true
  done

  ok=0
  for marker in "$tmpdir"/*.ok; do
    [ -f "$marker" ] || continue
    ok=1
    break
  done

  if [ "$ok" -eq 0 ]; then
    echo "DOWNLOAD_FAILED all mirrors" >&2
    # fallback: --blocklist-from / existing list
    local src=""
    if [ -f "$FROM_CONF" ]; then
      src="$(head -1 "$FROM_CONF" | tr -d '\r')"
    fi
    if [ -n "${GORECSHIT_BLOCKLIST_FROM:-}" ]; then
      src="${GORECSHIT_BLOCKLIST_FROM}"
    fi
    if import_from_source "$src"; then
      :
    elif [ -s "$LIST" ]; then
      echo "KEEPING existing $LIST" >&2
      return 1
    else
      echo "EMPTY blocklist — no sources reachable" >&2
      return 1
    fi
  else
    {
      cat "$tmpdir"/*_v4.txt 2>/dev/null || true
      cat "$tmpdir/cyberok-skipa.txt" 2>/dev/null || true
      grep -E '^[0-9]' "$tmpdir/antiscanner.list" 2>/dev/null || true
      for f in "$tmpdir"/wdes-*.txt "$tmpdir"/xorlent-*.txt; do
        [ -f "$f" ] || continue
        grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$f" | sed 's/\r//' | awk '{if($1!~/\//) print $1"/32"; else print $1}'
      done
      # firehol / spamhaus / blocklist.de / cins / ipsum / c24be — extract CIDRs/IPs
      for f in "$tmpdir"/firehol_level1.netset "$tmpdir"/firehol_level2.netset \
               "$tmpdir"/spamhaus_drop.txt "$tmpdir"/spamhaus_edrop.txt \
               "$tmpdir"/blocklist_de_ssh.txt "$tmpdir"/blocklist_de_all.txt \
               "$tmpdir"/cins_army.txt "$tmpdir"/ipsum3.txt "$tmpdir"/c24be_v4.txt; do
        [ -f "$f" ] || continue
        # Spamhaus DROP format: CIDR ; SBL...
        sed 's/\r//' "$f" | sed 's/[;#].*//' | awk '
          /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+/ {print $1; next}
          /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1"/32"; next}
        '
      done
    } | sed 's/\r//' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' | sort -u >"$TMP.raw"
  fi

  if [ ! -s "$TMP.raw" ]; then
    echo "RAW empty after parse" >&2
    if [ -s "$LIST" ]; then return 1; fi
    # last chance: blocklist-from
    local src=""
    [ -f "$FROM_CONF" ] && src="$(head -1 "$FROM_CONF" | tr -d '\r')"
    import_from_source "$src" || return 1
  fi

  python3 - "$TMP.raw" "$TMP" "$NEVER" <<'PY'
import sys, ipaddress
raw, out, never_path = sys.argv[1:4]
never_nets = [
  "10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16",
  "0.0.0.0/8","100.64.0.0/10","192.0.0.0/24","192.0.2.0/24","198.18.0.0/15",
  "198.51.100.0/24","203.0.113.0/24","224.0.0.0/4","240.0.0.0/4","255.255.255.255/32",
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
  # Skip huge aggregates (bogons / whole continents) that could hit infra
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
  ipset create "${SET}-new" hash:net family inet maxelem 500000 -exist
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
  # Immediate ban path for scanner IPs hitting SSH is the ipset DROP itself (before UFW user rules).
  echo "LOADED $n into ipset $SET (size=$(ipset list $SET 2>/dev/null | grep -cE '^[0-9]' || echo 0))"
}

if [ "$LOCAL_ONLY" -eq 0 ]; then
  download_lists || echo "using existing list"
fi
load_ipset
REFRESH_EOF
  chmod 755 /usr/local/sbin/scanner-block-refresh.sh

  cat >/etc/systemd/system/scanner-block.service <<'EOF'
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

  cat >/etc/systemd/system/scanner-block-refresh.service <<'EOF'
[Unit]
Description=Refresh internet scanner IP blocklist
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/scanner-block-refresh.sh
Nice=10
EOF

  cat >/etc/systemd/system/scanner-block-refresh.timer <<'EOF'
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

  # If --blocklist-from set and current list empty / first run preference
  if [[ -n "$BLOCKLIST_FROM" && ! -s /etc/scanner-block/blocklist.txt ]]; then
    log "Пробуем --blocklist-from=${BLOCKLIST_FROM} до сетевой загрузки"
  fi

  /usr/local/sbin/scanner-block-refresh.sh || warn "Initial blocklist refresh failed; will retry via timer / --blocklist-from"
  systemctl start scanner-block.service || true
  local cnt
  cnt="$(ipset list scanner-block 2>/dev/null | grep -cE '^[0-9]' || echo 0)"
  if [[ "${cnt:-0}" -eq 0 ]]; then
    warn "ipset scanner-block пуст после refresh — проверьте сеть/зеркала/--blocklist-from"
  else
    ok "Scanner blocklist установлен (${cnt} entries)"
  fi
}


configure_stealth() {
  if [[ "$DO_STEALTH" -eq 0 ]]; then
    log "Stealth-модуль пропущен"
    return 0
  fi
  step "Стелс: не выглядеть как VPN-нода"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b hide banners; disable default nginx/caddy pages; warn extra listeners; tcp_timestamps optional\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi

  # SSH banners already Banner none / DebianBanner no in configure_ssh
  # Disable nginx default site if present (do not restart docker)
  if [[ -d /etc/nginx ]]; then
    backup_file /etc/nginx/sites-enabled/default
    if [[ -L /etc/nginx/sites-enabled/default || -f /etc/nginx/sites-enabled/default ]]; then
      rm -f /etc/nginx/sites-enabled/default
      if command -v nginx >/dev/null 2>&1 && nginx -t 2>/dev/null; then
        systemctl reload nginx 2>/dev/null || true
      fi
      ok "nginx default site disabled"
    fi
  fi
  # Caddy: if a trivial respond-only default exists on host, leave config but warn — do not break reverse proxy
  if [[ -f /etc/caddy/Caddyfile ]]; then
    if grep -qE '^\s*:80\s*\{' /etc/caddy/Caddyfile 2>/dev/null && grep -qiE 'respond|hello|welcome' /etc/caddy/Caddyfile 2>/dev/null; then
      warn "Обнаружен простой Caddy default/respond — проверьте вручную (не трогаем live proxy)"
    fi
  fi

  # Extra public listeners warning (not client/node/ssh)
  local allow_ports=("22" "$NODE_PORT")
  [[ -n "$SSH_PORT_NEW" ]] && allow_ports+=("$SSH_PORT_NEW")
  local p
  while IFS= read -r p; do [[ -n "$p" ]] && allow_ports+=("$p"); done < <(foreach_csv "$CLIENT_PORTS")
  while IFS= read -r p; do [[ -n "$p" ]] && allow_ports+=("$p"); done < <(foreach_csv "$CLIENT_UDP_PORTS")
  if [[ "$MODE" == "cdn" || "$CADDY_PRESENT" -eq 1 ]]; then
    allow_ports+=("80" "443")
  fi
  if command -v ss >/dev/null 2>&1; then
    local line addr port
    while IFS= read -r line; do
      addr="$(ss_local_addr "$line")"
      port="${addr##*:}"; port="${port%%]*}"
      [[ "$port" =~ ^[0-9]+$ ]] || continue
      ss_is_loopback_addr "$addr" && continue
      local okp=0 ap
      for ap in "${allow_ports[@]}"; do
        [[ "$port" == "$ap" ]] && okp=1 && break
      done
      if [[ "$okp" -eq 0 ]]; then
        warn "Лишний слушатель :${port} — ${line}"
      fi
    done < <(ss -lntup 2>/dev/null | awk 'NR>1' || true)
  fi

  # NODE_PORT already panel-only via UFW/DOCKER-USER — reaffirm
  ok "Stealth checks done (banners/default pages/extra ports). NODE_PORT остаётся panel-only."
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
      if grep -qE '^127\.0\.1\.1' /etc/hosts; then
        sed -i -E "s/^127\\.0\\.1\\.1.*/127.0.1.1\t${newhost}/" /etc/hosts
      else
        echo -e "127.0.1.1\t${newhost}" >>/etc/hosts
      fi
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
        printf '%b[DRY]%b timedatectl set-timezone (auto via IP)\n' "${C_YEL}" "${C_RESET}"
      else
        tz="$(curl -fsSL --connect-timeout 5 --max-time 10 https://ipapi.co/timezone 2>/dev/null || true)"
        if [[ -z "$tz" ]]; then
          tz="$(curl -fsSL --connect-timeout 5 --max-time 10 https://worldtimeapi.org/api/ip 2>/dev/null | sed -n 's/.*"timezone":"\([^"]*\)".*/\1/p' || true)"
        fi
        [[ -z "$tz" ]] && tz="UTC"
        timedatectl set-timezone "$tz" 2>/dev/null || ln -sf "/usr/share/zoneinfo/$tz" /etc/localtime
        ok "Timezone set to $tz (auto)"
      fi
    else
      if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '%b[DRY]%b timedatectl set-timezone %s\n' "${C_YEL}" "${C_RESET}" "$tz"
      else
        timedatectl set-timezone "$tz" 2>/dev/null || ln -sf "/usr/share/zoneinfo/$tz" /etc/localtime
        ok "Timezone set to $tz"
      fi
    fi
  else
    log "Timezone left as-is (pass --tz ZONE|auto to change)"
  fi
}

configure_docker_journal() {
  if [[ "$DO_DOCKER_JOURNAL" -eq 0 ]]; then
    log "Docker/journald пропущен"
    return 0
  fi
  step "Docker logs / journald / remnanode perms"
  backup_file /etc/docker/daemon.json
  backup_file /etc/systemd/journald.conf
  mkdir -p /etc/systemd/journald.conf.d 2>/dev/null || true
  backup_file /etc/systemd/journald.conf.d/99-gorecshit.conf

  local desired='{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"}}'
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b merge docker daemon.json log rotation\n' "${C_YEL}" "${C_RESET}"
    printf '%b[DRY]%b journald SystemMaxUse=200M\n' "${C_YEL}" "${C_RESET}"
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
)" || newjson="$desired"
    else
      newjson="$(printf '%s\n' "$desired" | python3 -m json.tool)"
    fi
    local old=""
    if [[ -f /etc/docker/daemon.json ]]; then old="$(cat /etc/docker/daemon.json)"; fi
    printf '%s\n' "$newjson" >/etc/docker/daemon.json
    if [[ "$old" != "$(cat /etc/docker/daemon.json)" ]]; then
      CHANGED_DOCKER=1
      if remnanode_running; then
        SKIPPED_DOCKER_RESTART=1
        warn "Docker daemon.json changed but remnanode/xray is live — NOT restarting docker"
      elif systemctl is-active --quiet docker 2>/dev/null; then
        warn "Docker daemon.json changed and no remnanode running — restarting docker"
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

configure_nofile() {
  if [[ "$DO_NOFILE" -eq 0 ]]; then
    log "nofile limits skipped (--no-nofile)"
    return 0
  fi
  step "nofile 1048576 (limits + systemd)"
  backup_file /etc/security/limits.d/99-gorecshit-nofile.conf
  backup_file /etc/systemd/system.conf.d/99-gorecshit-nofile.conf

  local limits="# Managed by ${SCRIPT_NAME} ${VERSION}
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
"
  local sysd="# Managed by ${SCRIPT_NAME} ${VERSION}
[Manager]
DefaultLimitNOFILE=1048576:1048576
"
  write_content /etc/security/limits.d/99-gorecshit-nofile.conf "$limits"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b write systemd DefaultLimitNOFILE=1048576\n' "${C_YEL}" "${C_RESET}"
  else
    mkdir -p /etc/systemd/system.conf.d
    write_content /etc/systemd/system.conf.d/99-gorecshit-nofile.conf "$sysd"
    systemctl daemon-reload 2>/dev/null || true
    ok "nofile soft/hard 1048576 written (applies to new sessions/services)"
  fi
}

configure_resolv_v4() {
  if [[ "$IPV6_OFF" -eq 0 || "$DO_RESOLV_V4" -eq 0 ]]; then
    log "resolv.conf IPv4-only skipped"
    return 0
  fi
  step "resolv.conf IPv4-only (IPv6 disabled)"
  backup_file /etc/resolv.conf
  backup_file /etc/systemd/resolved.conf
  backup_file /etc/systemd/resolved.conf.d/99-gorecshit-dns.conf

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b force IPv4 DNS (1.1.1.1/1.0.0.1)\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi

  mkdir -p /etc/systemd/resolved.conf.d
  write_content /etc/systemd/resolved.conf.d/99-gorecshit-dns.conf \
"# Managed by ${SCRIPT_NAME} ${VERSION}
[Resolve]
DNS=1.1.1.1 1.0.0.1
FallbackDNS=8.8.8.8 8.8.4.4
DNSOverTLS=no
DNSStubListener=yes
"

  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    systemctl restart systemd-resolved 2>/dev/null || true
    if [[ -f /etc/resolv.conf ]] && ! [[ -L /etc/resolv.conf ]]; then
      {
        grep -E '^\s*(search|domain|options)\b' /etc/resolv.conf 2>/dev/null || true
        grep -E '^\s*nameserver\s+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' /etc/resolv.conf 2>/dev/null || true
        if ! grep -qE '^\s*nameserver\s+1\.1\.1\.1' /etc/resolv.conf 2>/dev/null; then
          echo 'nameserver 1.1.1.1'
          echo 'nameserver 1.0.0.1'
        fi
      } >/etc/resolv.conf.tmp
      awk 'NF && !seen[$0]++' /etc/resolv.conf.tmp >/etc/resolv.conf
      rm -f /etc/resolv.conf.tmp
    fi
    ok "systemd-resolved DNS set to IPv4-only upstreams"
  else
    write_content /etc/resolv.conf \
"nameserver 1.1.1.1
nameserver 1.0.0.1
nameserver 8.8.8.8
options timeout:2 attempts:2
"
    ok "Wrote IPv4-only /etc/resolv.conf"
  fi
}

configure_docker_user() {
  if [[ "$DO_DOCKER_USER" -eq 0 ]]; then
    log "DOCKER-USER NODE_PORT rule skipped (--no-docker-user)"
    return 0
  fi
  if ! command -v docker >/dev/null 2>&1 && [[ ! -d /etc/docker ]]; then
    log "Docker not present — skip DOCKER-USER rule"
    return 0
  fi
  # host-network remnanode does not need DOCKER-USER for NODE_PORT; still harmless
  step "DOCKER-USER: NODE_PORT ${NODE_PORT} only from panel (ctdir REPLY RETURN first)"

  local script="/usr/local/sbin/docker-user-${NODE_PORT}.sh"
  local unit="/etc/systemd/system/docker-user-${NODE_PORT}.service"
  backup_file "$script"
  backup_file "$unit"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b install %s + %s\n' "${C_YEL}" "${C_RESET}" "$script" "$unit"
    return 0
  fi

  cat >"$script" <<EOF
#!/bin/sh
# Managed by ${SCRIPT_NAME} ${VERSION} — DOCKER-USER guard for NODE_PORT=${NODE_PORT}
PANEL_IP="${PANEL_IP}"
NODE_PORT="${NODE_PORT}"
iptables -C DOCKER-USER -m conntrack --ctdir REPLY -j RETURN 2>/dev/null \\
  || iptables -I DOCKER-USER 1 -m conntrack --ctdir REPLY -j RETURN
iptables -C DOCKER-USER ! -s "\${PANEL_IP}/32" -p tcp -m conntrack --ctorigdstport "\$NODE_PORT" -j DROP 2>/dev/null \\
  || iptables -A DOCKER-USER ! -s "\${PANEL_IP}/32" -p tcp -m conntrack --ctorigdstport "\$NODE_PORT" -j DROP
EOF
  chmod 755 "$script"

  cat >"$unit" <<EOF
[Unit]
Description=Restrict docker-published NODE_PORT ${NODE_PORT} to panel ${PANEL_IP}
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=${script}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "docker-user-${NODE_PORT}.service" >/dev/null 2>&1 || true
  if systemctl is-active --quiet docker 2>/dev/null || iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    "$script" || warn "DOCKER-USER apply returned non-zero (chain may appear after first container publish)"
  else
    log "DOCKER-USER chain not ready yet; unit will apply after docker starts"
  fi
  ok "DOCKER-USER rule persisted (panel=${PANEL_IP} port=${NODE_PORT}; no docker restart)"
}

configure_certbot_hooks() {
  if [[ "$DO_CERTBOT_HOOKS" -eq 0 ]]; then
    log "certbot hooks skipped"
    return 0
  fi
  if ! command -v certbot >/dev/null 2>&1 && [[ ! -d /etc/letsencrypt ]]; then
    log "certbot/letsencrypt not present — skip renew hooks"
    return 0
  fi
  if [[ "$CADDY_PRESENT" -eq 0 && "$NGINX_PRESENT" -eq 0 ]]; then
    log "No caddy/nginx detected — skip certbot renew hooks"
    return 0
  fi
  step "certbot renew hooks (reload caddy/nginx)"
  local hook="/etc/letsencrypt/renewal-hooks/deploy/99-gorecshit-reload.sh"
  backup_file "$hook"
  local body
  body="#!/bin/bash
# Managed by ${SCRIPT_NAME} ${VERSION}
set -euo pipefail
if systemctl is-active --quiet caddy 2>/dev/null; then
  systemctl reload caddy || systemctl restart caddy || true
fi
if systemctl is-active --quiet nginx 2>/dev/null; then
  nginx -t 2>/dev/null && systemctl reload nginx || true
fi
if command -v docker >/dev/null 2>&1; then
  for c in \$(docker ps --format '{{.Names}}' 2>/dev/null | grep -iE 'caddy|nginx' || true); do
    docker exec \"\$c\" caddy reload --config /etc/caddy/Caddyfile 2>/dev/null \\
      || docker exec \"\$c\" nginx -s reload 2>/dev/null \\
      || docker restart \"\$c\" 2>/dev/null \\
      || true
  done
fi
"
  write_content "$hook" "$body"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    mkdir -p "$(dirname "$hook")"
    chmod 755 "$hook"
    ok "Installed $hook"
  fi
}

final_verify() {
  step "Итог / verification"
  echo "==== gorecshit ${VERSION} summary ===="
  echo "panel=${PANEL_IP} node_port=${NODE_PORT}"
  echo "clients_tcp=${CLIENT_PORTS:-none} clients_udp=${CLIENT_UDP_PORTS:-none} mode=${MODE}"
  echo "modules: ufw=$DO_UFW blocklist=$DO_BLOCKLIST hide=$DO_HIDE_PORTS probe=$DO_ANTI_PROBE ssh=$DO_SSH stealth=$DO_STEALTH f2b=$DO_FAIL2BAN sysctl=$DO_SYSCTL host=$DO_HOSTNAME docker=$DO_DOCKER_JOURNAL"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "(dry-run / --check: live checks skipped)"
    return 0
  fi
  echo "---- ufw ----"
  ufw status verbose 2>/dev/null | head -40 || true
  echo "---- tcp cc / qdisc ----"
  sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc 2>/dev/null || true
  echo "---- listeners (ss -lntup) ----"
  ss -lntup 2>/dev/null | head -40 || true
  echo "---- fail2ban ----"
  fail2ban-client status 2>/dev/null || true
  echo "---- ipset scanner-block ----"
  if ipset list scanner-block >/dev/null 2>&1; then
    echo "entries: $(ipset list scanner-block 2>/dev/null | grep -cE '^[0-9]' || echo 0)"
  else
    echo "not loaded"
  fi
  echo "---- remnanode ----"
  if remnanode_running; then ok "remnanode/xray жив"; else warn "remnanode не виден в docker ps"; fi
  hostname; timedatectl 2>/dev/null | head -6 || true
  if [[ "$SKIPPED_DOCKER_RESTART" -eq 1 ]]; then
    warn "daemon.json updated without docker restart (remnanode live)."
  elif [[ "$CHANGED_DOCKER" -eq 1 ]]; then
    warn "Docker was restarted due to daemon.json change"
  fi
  ok "Hardening complete. Backups: ${BACKUP_DIR}"
  ok "Rollback: bash install.sh --rollback   OR   ${BACKUP_DIR}/rollback.sh"
}

run_hardening() {
  install_packages
  configure_sysctl
  configure_nofile
  configure_resolv_v4
  configure_ssh
  configure_fail2ban
  install_blocklist
  configure_ufw
  configure_anti_probe
  configure_docker_user
  configure_stealth
  configure_hostname_tz
  configure_docker_journal
  configure_certbot_hooks
  final_verify
}

main() {
  parse_args "$@"
  if [[ -z "$PANEL_IP" && -n "${GORECSHIT_PANEL_IP:-}" ]]; then
    PANEL_IP="$GORECSHIT_PANEL_IP"
  fi

  printf '%b%s%b v%s\n' "${C_BOLD}" "$SCRIPT_NAME" "${C_RESET}" "$VERSION"

  # Always refresh CLI entrypoint when root (does not re-run hardening)
  install_cli_command

  if [[ "$DO_UPDATE_ONLY" -eq 1 ]]; then
    self_update_from_github
    exit 0
  fi

  # Interactive menu when TTY and no --yes and not a one-shot action flag
  # Also open menu when invoked as `gorecshit` with zero args (even if not a TTY? require TTY)
  if [[ "$ASSUME_YES" -eq 0 && "$DO_ROLLBACK" -eq 0 && "$CHECK_ONLY" -eq 0 \
        && "$DO_REFRESH_LISTS_ONLY" -eq 0 && "$DO_STATUS_ONLY" -eq 0 && "$DO_DPI_CHECK" -eq 0 \
        && "$DO_UPDATE_ONLY" -eq 0 \
        && -t 0 && -t 1 ]]; then
    interactive_menu
  fi

  if [[ "$DO_STATUS_ONLY" -eq 1 ]]; then
    show_status_summary
    exit 0
  fi

  if [[ "$DO_DPI_CHECK" -eq 1 ]]; then
    run_dpi_check
    exit 0
  fi

  if [[ "$DO_REFRESH_LISTS_ONLY" -eq 1 ]]; then
    if [[ "$(id -u)" -ne 0 ]]; then err "Must run as root"; exit 1; fi
    if [[ -x /usr/local/sbin/scanner-block-refresh.sh ]]; then
      /usr/local/sbin/scanner-block-refresh.sh
    else
      err "scanner-block-refresh.sh не установлен — сначала выполните полный install"
      exit 1
    fi
    exit 0
  fi

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
    log "Будет применён hardening: panel=${PANEL_IP} node_port=${NODE_PORT} clients=${CLIENT_PORTS} udp=${CLIENT_UDP_PORTS} mode=${MODE} relays=${RELAY_IPS}"
    printf 'Продолжить? [y/N] '
    local ans
    read -r ans || true
    [[ "$ans" =~ ^[Yy]$ ]] || { warn "Отменено"; exit 0; }
  fi

  run_hardening
}

main "$@"
