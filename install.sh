#!/usr/bin/env bash
# gorecshit v2.7.0 — one-command hardening for Remnawave VPN node servers (Debian 11+/Ubuntu 20.04+)
# Usage:
#   bash install.sh --panel-ip X.X.X.X [--node-port 2222] [--yes]
#   bash install.sh --check --panel-ip X.X.X.X
#   bash install.sh                      # interactive Russian menu (TTY)
# Idempotent. No secrets. Panel IP / NODE_PORT via flags or GORECSHIT_* env.
# Does NOT restart Docker while remnanode/xray is live. Does NOT deploy itself.
set -Eeuo pipefail

VERSION="2.7.0"
SCRIPT_NAME="gorecshit"
BACKUP_ROOT="/root/hardening-backups"

# Optional snapshot only when BASH_SOURCE is a seekable regular file under /dev/fd
# (NOT a pipe — reading a pipe would consume the script for bash <(curl|cat …)).
_GORECSHIT_SELF_SNAPSHOT=""
_gorecshit_early_snapshot_self() {
  local raw="${BASH_SOURCE[0]:-$0}"
  case "$raw" in
    /dev/fd/*|/proc/self/fd/*|/proc/[0-9]*/fd/*)
      # -f is false for pipes; only snapshot seekable fd-backed files
      [[ -f "$raw" ]] || return 0
      _GORECSHIT_SELF_SNAPSHOT="$(mktemp /tmp/gorecshit-self.XXXXXX 2>/dev/null || mktemp 2>/dev/null || true)"
      [[ -n "$_GORECSHIT_SELF_SNAPSHOT" ]] || return 0
      if ! cp -f "$raw" "$_GORECSHIT_SELF_SNAPSHOT" 2>/dev/null; then
        rm -f "$_GORECSHIT_SELF_SNAPSHOT" 2>/dev/null || true
        _GORECSHIT_SELF_SNAPSHOT=""
        return 0
      fi
      if ! head -1 "$_GORECSHIT_SELF_SNAPSHOT" 2>/dev/null | grep -q '^#!'; then
        rm -f "$_GORECSHIT_SELF_SNAPSHOT" 2>/dev/null || true
        _GORECSHIT_SELF_SNAPSHOT=""
      fi
      ;;
  esac
}
_gorecshit_early_snapshot_self
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
DO_EGRESS_GUARD=1        # --no-egress-guard: skip outbound SMTP block
EGRESS_BLOCK_PORTS="25"   # --egress-block-ports LIST (e.g. 25,465,587)
# v2.7.0 netguard (outbound abuse / snitch / P2P) — see configure_netguard
DO_NETGUARD=1            # --no-netguard: skip the whole outbound guard
DO_P2P_BLOCK=1           # --no-p2p-block: BitTorrent/DHT/tracker drop at netfilter level (backup for xray rule)
DO_ABUSE_LIMIT=1         # --no-abuse-limit: outbound scan/brute rate-limit + SMB/NetBIOS block
DO_PRIVATE_EGRESS=1      # --no-private-egress: block client access to RFC1918/CGNAT (hoster LAN)
DO_SNITCH_GUARD=1        # --no-snitch-guard: block outbound to VK/MAX networks (they report VPN IPs)
EGRESS_BLOCK_METADATA=0  # --egress-block-metadata: also block 169.254.0.0/16 (cloud metadata; opt-in)
DO_IP_CHECK=0            # --ip-check: blacklist / VPN-detection self-check (read-only)
DO_ABUSE_REPORT=0        # --abuse-report: what clients tried (P2P/scan/SMTP/snitch) — read-only
NET_OFFLINE=0            # set by ensure_network_dns when there is no internet
DO_DECOY_WEB=0           # --decoy-web: :80 → 301 https via existing nginx (else asks via /dev/tty, default no)
AUDIT_PUB_IP=""
AUDIT_RU_NODES=()
AUDIT_FOREIGN_NODES=()
AUDIT_UFW_PUB4=" "
AUDIT_UFW_PUB6=" "
FORCE_DOCKER_RESTART=0   # --docker-restart: restart even with --yes / non-interactive
NO_DOCKER_RESTART=0      # --no-docker-restart: never restart
DO_TCP_TIMESTAMPS_OFF=0
SSH_PORT_NEW=""           # empty = keep 22 only; --ssh-port N adds N
BLOCKLIST_FROM=""         # ssh host or URL or local path
MODULES_CSV=""            # --modules ufw,blocklist,...
TZ_OPT=""                 # empty = leave; "auto" = geo; or IANA name
NO_UPGRADE=0              # --no-upgrade / GORECSHIT_NO_UPGRADE=1: skip apt full-upgrade
APT_TIMERS_PAUSED=0       # set when we stop apt-daily* / unattended-upgrades for the run
ASSUME_YES=0
CLI_ASSUME_YES=0          # set only by --yes / -y (not by menu)
FROM_MENU=0               # set when menu item 1/2 starts install
DRY_RUN=0
CHECK_ONLY=0
DO_ROLLBACK=0
DO_REFRESH_LISTS_ONLY=0
DO_STATUS_ONLY=0
DO_DPI_CHECK=0
DO_AUDIT=0
DO_FINGERPRINT_ONLY=0
DO_UPDATE_ONLY=0
# audit reachability side-channel (ICMP via check-host)
AUDIT_PING_DONE=0
AUDIT_PING_RU_OK=0
AUDIT_PING_RU_TOT=0
AUDIT_PING_FR_OK=0
AUDIT_PING_FR_TOT=0
AUDIT_XRAY_STDIN_CONFIG=0
AUDIT_XRAY_PID=""

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

# Interactive I/O: under `curl|bash` / `bash <(curl)` stdin is the script; use /dev/tty.
can_prompt_user() {
  [[ "$ASSUME_YES" -eq 0 ]] || return 1
  _tty_usable && return 0
  [[ -t 0 && -t 1 ]] && return 0
  return 1
}

read_user_input() {
  # read_user_input VAR — reads one line from /dev/tty if available, else stdin
  local __ru_var="$1"
  if _tty_usable; then
    IFS= read -r "$__ru_var" < /dev/tty || true
  else
    IFS= read -r "$__ru_var" || true
  fi
}

prompt_user() {
  # prompt_user "text" VAR — print prompt (to tty if possible) and read answer
  local __msg="$1" __var="$2"
  if _tty_usable; then
    printf '%s' "$__msg" > /dev/tty
  else
    printf '%s' "$__msg"
  fi
  read_user_input "$__var"
}

rollback_hint_cmd() {
  # Prefer installed CLI; avoid printing /dev/fd/63 from bash <(curl)
  if [[ -x /usr/local/sbin/gorecshit ]] || command -v gorecshit >/dev/null 2>&1; then
    printf 'gorecshit --rollback'
  elif [[ -f /usr/local/sbin/gorecshit ]]; then
    printf 'bash /usr/local/sbin/gorecshit --rollback'
  else
    local src="${BASH_SOURCE[0]:-$0}"
    case "$src" in
      /dev/fd/*|/proc/self/fd/*|/proc/*/fd/*|-|'')
        printf 'bash install.sh --rollback   # или: curl … | bash — затем gorecshit --rollback'
        ;;
      *)
        printf 'bash %q --rollback' "$src"
        ;;
    esac
  fi
}

on_error() {
  local ec=$?
  err "Failed at line ${BASH_LINENO[0]} (exit ${ec}). Backups: ${BACKUP_DIR:-n/a}"
  err "Откат: $(rollback_hint_cmd)   (или ${BACKUP_DIR:-/root/hardening-backups/<ts>}/rollback.sh)"
  exit "$ec"
}
on_exit() {
  # Always put apt-daily / unattended-upgrades back if we paused them.
  restore_apt_timers 2>/dev/null || true
}
trap on_error ERR
trap on_exit EXIT

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
  install.sh --version               # print version
  install.sh --dpi-check             # outbound DPI / DNS / TLS checks (node egress)
  install.sh --audit                 # RU reachability + detectability self-audit (read-only)
  install.sh --stealth               # hide server fingerprints (banners/MOTD/ICMP FP/…)
  install.sh --ip-check              # is this IP in blacklists / VPN-detection DBs (read-only)
  install.sh --abuse-report          # what clients tried: P2P / scans / SMTP / snitch (read-only)

Required (non-interactive apply):
  --panel-ip IP              Management/panel host allowed to reach NODE_PORT

Options:
  --node-port PORT|auto      remnanode API port (default: auto from /opt/remnanode/.env)
  --client-ports LIST|auto   TCP client ports (default: auto from xray inbounds / LISTEN ss, not ephemeral)
  --client-udp-ports LIST|auto  UDP client ports (default: auto from xray inbounds; ss fallback excludes ephemeral)
  --mode direct|cdn          direct: open detected xray ports; cdn: open 80/443, keep internal xray closed
  --allow-ssh-from IP,...    Extra IPs always allowed (SSH ignore + never-block)
  --ssh-port N               Add SSH listen port N (ufw first, sshd -t, keep 22 until confirmed)
  --blocklist-from SRC       Copy/fetch blocklist from ssh-host, URL, or local path (fallback)
  --modules LIST             Comma modules: ufw,blocklist,hide_ports,anti_probe,ssh,stealth,
                             fail2ban,sysctl,hostname,docker,egress_guard,netguard,decoy_web
                             (default: all enabled except decoy_web)
  --ipv6-off                 Opt-in: disable IPv6 via sysctl (default: keep IPv6 on; safer under dual-stack xray)
  --no-ipv6-off              Keep IPv6 enabled (default; retained for compatibility)
  --no-blocklist             Skip scanner ipset blocklist
  --no-hostname              Do not change hostname
  --no-hide-ports            Skip ICMP/closed-port hiding
  --no-anti-probe            Skip client-port rate limits
  --no-stealth               Skip stealth / not-look-like-VPN tweaks
  --no-egress-guard          Skip outbound SMTP block (abuse guard) for host + docker
  --egress-block-ports LIST  Outbound TCP ports to block (default: 25; e.g. 25,465,587)
  --no-netguard              Skip outbound guard (P2P/scan/brute/private-LAN/snitch) entirely
  --no-p2p-block             Keep BitTorrent/DHT netfilter drop off (xray rule only)
  --no-abuse-limit           No outbound scan/brute rate-limit and no SMB/NetBIOS block
  --no-private-egress        Allow clients to reach RFC1918/CGNAT (hoster LAN) through the node
  --no-snitch-guard          Allow outbound to VK/MAX networks (they report VPN server IPs to RKN)
  --egress-block-metadata    Also block 169.254.0.0/16 cloud metadata for clients (opt-in)
  --decoy-web                Port 80 → 301 https via existing nginx (only if safe; else skip)
  --tcp-timestamps-off       Set net.ipv4.tcp_timestamps=0
  --tz ZONE|auto             Set timezone (default: leave as-is). auto = IP geolocation
  --yes                      Non-interactive (still requires --panel-ip or GORECSHIT_PANEL_IP)
  --relay-ips IP,...         Extra never-block / ACCEPT IPs (default: HAProxy relays)
  --no-docker-user           Skip DOCKER-USER NODE_PORT restriction (bridge publish)
  --docker-restart          After daemon.json change, restart Docker even with --yes (non-interactive)
  --no-docker-restart       Never restart Docker for daemon.json (skip apply)
  --no-nofile                Skip nofile 1048576 limits
  --no-resolv-v4             Keep IPv6 nameservers in resolv.conf even when IPv6 off
  --no-certbot-hooks         Skip certbot renew reload hooks for caddy/nginx
  --no-upgrade               Skip system apt full-upgrade before installing packages
  --dry-run, --check         Print actions / verify plan only; make no changes
  --refresh-lists            Only run scanner-block refresh
  --status                   Show current hardening status
  --update                   Self-update from GitHub by commit SHA (jsDelivr / cache-buster fallback)
  --version                  Print script version and exit
  --dpi-check                Check DPI/DNS/TLS from this node (egress diagnostics)
  --audit                    RU block check + Shodan InternetDB + port/IPv6 exposure + active
                             REALITY probe + giveaways (PTR/banners/MTU/egress) — read-only
  --stealth                  Hide server fingerprints (SSH banner/MOTD/TTL/ICMP FP; ask before risky)
  --rollback / --uninstall   Restore latest backup under /root/hardening-backups/
  -h, --help                 Show this help

Env: GORECSHIT_PANEL_IP, GORECSHIT_NODE_PORT, GORECSHIT_RELAY_IPS, GORECSHIT_LOG_FILE,
     GORECSHIT_BLOCKLIST_FROM, GORECSHIT_MODULES, GORECSHIT_NO_UPGRADE=1

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
  [[ -e "$dest" ]] && return 0   # v2.7.0: keep the ORIGINAL (file may be backed up twice in one run)
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
  DO_RESOLV_V4=0; DO_CERTBOT_HOOKS=0; DO_EGRESS_GUARD=0; DO_NETGUARD=0
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
      egress_guard|egress|smtp) DO_EGRESS_GUARD=1 ;;
      decoy_web|decoy) DO_DECOY_WEB=1 ;;
      netguard|abuse|p2p|snitch) DO_NETGUARD=1 ;;
      docker|journald|journal)
        DO_DOCKER_JOURNAL=1; DO_DOCKER_USER=1; DO_RESOLV_V4=1; DO_CERTBOT_HOOKS=1; DO_NOFILE=1 ;;
      all)
        DO_UFW=1; DO_BLOCKLIST=1; DO_HIDE_PORTS=1; DO_ANTI_PROBE=1
        DO_SSH=1; DO_STEALTH=1; DO_FAIL2BAN=1; DO_SYSCTL=1
        DO_HOSTNAME=1; DO_DOCKER_JOURNAL=1; DO_DOCKER_USER=1; DO_NOFILE=1
        DO_RESOLV_V4=1; DO_CERTBOT_HOOKS=1; DO_EGRESS_GUARD=1; DO_NETGUARD=1 ;;
      minimum|min)
        DO_UFW=1; DO_SSH=1; DO_FAIL2BAN=1; DO_SYSCTL=1; DO_BLOCKLIST=1
        DO_HIDE_PORTS=1; DO_DOCKER_USER=1; DO_EGRESS_GUARD=1; DO_NETGUARD=1 ;;
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
      --no-egress-guard) DO_EGRESS_GUARD=0; shift ;;
      --egress-block-ports) EGRESS_BLOCK_PORTS="${2:-}"; shift 2 ;;
      --decoy-web) DO_DECOY_WEB=1; shift ;;
      --no-netguard) DO_NETGUARD=0; shift ;;
      --no-p2p-block) DO_P2P_BLOCK=0; shift ;;
      --no-abuse-limit) DO_ABUSE_LIMIT=0; shift ;;
      --no-private-egress) DO_PRIVATE_EGRESS=0; shift ;;
      --no-snitch-guard) DO_SNITCH_GUARD=0; shift ;;
      --egress-block-metadata) EGRESS_BLOCK_METADATA=1; shift ;;
      --ip-check) DO_IP_CHECK=1; shift ;;
      --abuse-report) DO_ABUSE_REPORT=1; shift ;;
      --tcp-timestamps-off) DO_TCP_TIMESTAMPS_OFF=1; shift ;;
      --tz) TZ_OPT="${2:-}"; shift 2 ;;
      --relay-ips) RELAY_IPS="${2:-}"; shift 2 ;;
      --no-docker-user) DO_DOCKER_USER=0; shift ;;
      --docker-restart) FORCE_DOCKER_RESTART=1; shift ;;
      --no-docker-restart) NO_DOCKER_RESTART=1; shift ;;
      --no-nofile) DO_NOFILE=0; shift ;;
      --no-resolv-v4) DO_RESOLV_V4=0; shift ;;
      --no-certbot-hooks) DO_CERTBOT_HOOKS=0; shift ;;
      --no-upgrade) NO_UPGRADE=1; shift ;;
      --yes|-y) ASSUME_YES=1; CLI_ASSUME_YES=1; shift ;;
      --dry-run|--check) DRY_RUN=1; CHECK_ONLY=1; shift ;;
      --refresh-lists) DO_REFRESH_LISTS_ONLY=1; shift ;;
      --status) DO_STATUS_ONLY=1; shift ;;
      --update) DO_UPDATE_ONLY=1; shift ;;
      --version|-V) printf '%s\n' "$VERSION"; exit 0 ;;
      --dpi-check) DO_DPI_CHECK=1; shift ;;
      --audit) DO_AUDIT=1; shift ;;
      --stealth) DO_FINGERPRINT_ONLY=1; shift ;;
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
  case "${GORECSHIT_NO_UPGRADE:-}" in
    1|true|TRUE|yes|YES|on|ON) NO_UPGRADE=1 ;;
  esac
  if [[ -n "$SSH_PORT_NEW" ]] && ! is_port "$SSH_PORT_NEW"; then
    err "Invalid --ssh-port: $SSH_PORT_NEW"; exit 2
  fi
}


prompt_panel_ip() {
  if [[ -n "$PANEL_IP" ]]; then return 0; fi
  if [[ "$DO_ROLLBACK" -eq 1 || "$DO_STATUS_ONLY" -eq 1 || "$DO_REFRESH_LISTS_ONLY" -eq 1 || "$DO_DPI_CHECK" -eq 1 || "$DO_AUDIT" -eq 1 || "$DO_FINGERPRINT_ONLY" -eq 1 || "$DO_UPDATE_ONLY" -eq 1 || "$DO_IP_CHECK" -eq 1 || "$DO_ABUSE_REPORT" -eq 1 ]]; then return 0; fi
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    err "--panel-ip is required (or set GORECSHIT_PANEL_IP). Refusing non-interactive without it."
    exit 2
  fi
  if ! can_prompt_user; then
    err "Нет интерактива (/dev/tty) и --panel-ip не задан. Передайте --panel-ip X.X.X.X"
    exit 2
  fi
  local ans=""
  while true; do
    prompt_user 'Введите IPv4 панели / management (обязательно): ' ans
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

  # Client ports: same filters as install (exclude ephemeral ip_local_port_range + service ports)
  load_ephemeral_port_range
  local node_ex=3000 np line addr port proc
  if [[ -n "${NODE_PORT:-}" && "${NODE_PORT}" =~ ^[0-9]+$ ]]; then
    node_ex="$NODE_PORT"
  elif [[ -f /opt/remnanode/.env ]]; then
    np="$(grep -E '^(NODE_PORT|APP_PORT)=' /opt/remnanode/.env 2>/dev/null | head -1 | cut -d= -f2- | tr -d '\"\r' || true)"
    [[ "$np" =~ ^[0-9]+$ ]] && node_ex="$np"
  fi
  local -a _menu_ports=()
  if command -v ss >/dev/null 2>&1; then
    while IFS= read -r line; do
      addr="$(ss_local_addr "$line")"
      port="${addr##*:}"; port="${port%%]*}"
      [[ "$port" =~ ^[0-9]+$ ]] || continue
      is_excluded_service_port "$port" "$node_ex" && continue
      ss_is_loopback_addr "$addr" && continue
      is_ephemeral_port "$port" && continue
      proc=""
      if [[ "$line" == *'users:(('* ]]; then
        proc="$(sed -n 's/.*users:(("\([^"]*\).*/\1/p' <<<"$line" | head -1 || true)"
      fi
      case "$proc" in
        xray|rw-core|remnanode|rw-node|Xray|sing-box|singbox|hysteria|hysteria2|hy2|xhttp)
          _menu_ports+=("$port") ;;
      esac
    done < <(ss -lntp 2>/dev/null | awk 'NR>1' || true)
  fi
  if [[ ${#_menu_ports[@]} -gt 0 ]]; then
    ports="$(printf '%s\n' "${_menu_ports[@]}" | sort -n -u | head -8 | paste -sd, -)"
  elif command -v ufw >/dev/null 2>&1; then
    ports="$(
      ufw status 2>/dev/null | grep -oE 'client-[0-9]+' | grep -oE '[0-9]+' | sort -nu | head -8 | paste -sd, - || true
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
  if command -v ipset >/dev/null 2>&1 && ipset list -n scanner-block >/dev/null 2>&1; then
    echo "---- ipsets ----"
    local _set _n
    for _set in scanner-block scanner-block6 gorecshit-rep gorecshit-snitch gorecshit-snitch6 gorecshit-cdn; do
      _n="$(ipset list "$_set" -t 2>/dev/null | awk -F': ' '/Number of entries/{print $2}')"
      [[ -n "$_n" ]] && printf '  %-18s %s\n' "$_set" "$_n"
    done
  else
    echo "ipset scanner-block: нет"
  fi
  if iptables -nL GS-NETGUARD >/dev/null 2>&1; then
    echo "---- netguard ----"
    echo "  активен · подробности: gorecshit --abuse-report"
  else
    echo "netguard: не установлен"
  fi
  if command -v fail2ban-client >/dev/null 2>&1; then
    echo "---- fail2ban ----"
    fail2ban-client status 2>/dev/null || true
  fi
  if remnanode_running; then ok "remnanode/xray контейнер жив"; else warn "remnanode не найден в docker ps"; fi
  if [[ -d "$BACKUP_ROOT" ]]; then
    echo "Бэкапы: $(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l) шт. в $BACKUP_ROOT"
  fi
  return 0
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

# ---------- Node block / detectability audit (read-only; --audit / menu 8) ----------
# Uses public check-host.net API + local xray config. Changes nothing (no UFW/iptables/sysctl).

_audit_ok()   { printf '  %b✅%b %s\n' "${C_GRN}" "${C_RESET}" "$*"; }
_audit_warn() { printf '  %b⚠️%b  %s\n' "${C_YEL}" "${C_RESET}" "$*"; }
_audit_info() { printf '  %b•%b  %s\n' "${C_CYN}" "${C_RESET}" "$*"; }
_audit_err()  { printf '  %b❌%b %s\n' "${C_RED}" "${C_RESET}" "$*"; }

_audit_http_get() {
  # usage: _audit_http_get URL [timeout_sec]
  local url="$1" t="${2:-15}"
  curl -fsS --connect-timeout 5 --max-time "$t" \
    -H 'Accept: application/json' -A 'gorecshit-audit/2.4.0' \
    "$url" 2>/dev/null || true
}

_audit_detect_public_ipv4() {
  local ip="" src
  for src in \
    'https://api.ipify.org' \
    'https://ifconfig.me/ip' \
    'https://ipv4.icanhazip.com' \
    'https://checkip.amazonaws.com'; do
    ip="$(curl -fsS --connect-timeout 4 --max-time 8 -A 'gorecshit-audit/2.4.0' "$src" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      printf '%s\n' "$ip"
      return 0
    fi
  done
  # last resort: default route iface
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      printf '%s\n' "$ip"
      return 0
    fi
  fi
  return 1
}

_audit_ensure_client_ports() {
  # Fill DETECTED_CLIENT_PORTS if empty (reuse existing detectors; read-only).
  if [[ ${#DETECTED_CLIENT_PORTS[@]} -gt 0 ]]; then
    return 0
  fi
  load_ephemeral_port_range
  local exclude_port=3000 np
  if [[ -n "${NODE_PORT:-}" && "${NODE_PORT}" =~ ^[0-9]+$ && "${NODE_PORT}" != "auto" ]]; then
    exclude_port="$NODE_PORT"
  elif [[ -f /opt/remnanode/.env ]]; then
    np="$(grep -E '^(NODE_PORT|APP_PORT)=' /opt/remnanode/.env 2>/dev/null | head -1 | cut -d= -f2- | tr -d '\"\r' || true)"
    [[ "$np" =~ ^[0-9]+$ ]] && exclude_port="$np"
  fi
  DETECTED_NODE_PORT="${DETECTED_NODE_PORT:-$exclude_port}"
  DETECTED_CLIENT_PORTS=()
  DETECTED_CLIENT_UDP_PORTS=()
  detect_ports_from_inbounds_config || true
  if [[ ${#DETECTED_CLIENT_PORTS[@]} -eq 0 ]]; then
    detect_ports_from_ss_filtered "$exclude_port" 0 || true
  fi
  if [[ ${#DETECTED_CLIENT_PORTS[@]} -gt 0 ]]; then
    mapfile -t DETECTED_CLIENT_PORTS < <(printf '%s\n' "${DETECTED_CLIENT_PORTS[@]}" | sort -n -u)
  fi
  if [[ ${#DETECTED_CLIENT_PORTS[@]} -eq 0 && -n "${CLIENT_PORTS:-}" && "${CLIENT_PORTS}" != "auto" ]]; then
    local p
    IFS=',' read -ra _ap <<< "$CLIENT_PORTS"
    for p in "${_ap[@]}"; do
      p="$(echo "$p" | tr -d '[:space:]')"
      [[ "$p" =~ ^[0-9]+$ ]] && DETECTED_CLIENT_PORTS+=("$p")
    done
  fi
}

_audit_json_get() {
  # Very small JSON helpers: prefer python3, then jq, then grep/sed.
  # _audit_json_get FIELD_PATH stdin — prints value or empty
  local expr="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 -c '
import json,sys
raw=sys.stdin.read()
try:
  d=json.loads(raw)
except Exception:
  sys.exit(0)
path=sys.argv[1].split(".")
cur=d
for p in path:
  if isinstance(cur, dict) and p in cur:
    cur=cur[p]
  else:
    sys.exit(0)
if cur is None:
  sys.exit(0)
if isinstance(cur,(dict,list)):
  print(json.dumps(cur,ensure_ascii=False))
else:
  print(cur)
' "$expr" 2>/dev/null || true
  elif command -v jq >/dev/null 2>&1; then
    jq -r ".$expr // empty" 2>/dev/null || true
  else
    # crude fallback for request_id / ok
    case "$expr" in
      request_id) grep -oE '"request_id"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"/\1/' ;;
      ok) grep -oE '"ok"[[:space:]]*:[[:space:]]*[0-9]+' | head -1 | sed -E 's/.*://;s/ //g' ;;
      *) return 0 ;;
    esac
  fi
}

_audit_pick_checkhost_nodes() {
  # Sets AUDIT_RU_NODES and AUDIT_FOREIGN_NODES (bash arrays) from nodes/hosts
  AUDIT_RU_NODES=()
  AUDIT_FOREIGN_NODES=()
  local body
  body="$(_audit_http_get 'https://check-host.net/nodes/hosts' 20)"
  [[ -n "$body" ]] || return 1
  if command -v python3 >/dev/null 2>&1; then
    local picked
    picked="$(printf '%s' "$body" | python3 -c '
import json,sys
d=json.load(sys.stdin)
nodes=d.get("nodes") or {}
ru=[]; foreign=[]
pref=["de","nl","fi","pl","se","fr","gb","uk","us","cz","at","ch"]
for k,v in nodes.items():
  loc=v.get("location") if isinstance(v,dict) else None
  if not (isinstance(loc,list) and loc):
    continue
  cc=str(loc[0]).lower()
  if cc=="ru":
    ru.append(k)
# foreign: prefer western EU/US, skip ir/ru
seen=set()
for cc in pref:
  for k,v in nodes.items():
    loc=v.get("location") if isinstance(v,dict) else None
    if not (isinstance(loc,list) and loc):
      continue
    if str(loc[0]).lower()!=cc: continue
    if k in seen: continue
    foreign.append(k); seen.add(k)
    if len(foreign)>=3: break
  if len(foreign)>=3: break
if len(foreign)<2:
  for k,v in nodes.items():
    loc=v.get("location") if isinstance(v,dict) else None
    if not (isinstance(loc,list) and loc): continue
    cc=str(loc[0]).lower()
    if cc in ("ru","ir"): continue
    if k in seen: continue
    foreign.append(k); seen.add(k)
    if len(foreign)>=3: break
print("RU "+(" ".join(ru)))
print("FR "+(" ".join(foreign[:3])))
' 2>/dev/null || true)"
    local line
    while IFS= read -r line; do
      case "$line" in
        RU\ *) read -ra AUDIT_RU_NODES <<< "${line#RU }" ;;
        FR\ *) read -ra AUDIT_FOREIGN_NODES <<< "${line#FR }" ;;
      esac
    done <<<"$picked"
  else
    # grep fallback: node names start with country code
    mapfile -t AUDIT_RU_NODES < <(printf '%s' "$body" | grep -oE '"ru[0-9]+\.node\.check-host\.net"' | tr -d '"' | sort -u)
    mapfile -t AUDIT_FOREIGN_NODES < <(printf '%s' "$body" | grep -oE '"(de|nl|pl|se|fr|us)[0-9]+\.node\.check-host\.net"' | tr -d '"' | sort -u | head -3)
  fi
  [[ ${#AUDIT_RU_NODES[@]} -gt 0 || ${#AUDIT_FOREIGN_NODES[@]} -gt 0 ]]
}

_audit_checkhost_start() {
  # _audit_checkhost_start KIND TARGET  where KIND=tcp|ping, TARGET=ip:port or ip
  # prints request_id or empty
  local kind="$1" target="$2"
  shift 2
  local -a nodes=("$@")
  local qs="" n url body
  for n in "${nodes[@]}"; do
    [[ -n "$n" ]] || continue
    qs="${qs}&node=${n}"
  done
  [[ -n "$qs" ]] || return 1
  case "$kind" in
    tcp) url="https://check-host.net/check-tcp?host=${target}${qs}" ;;
    ping) url="https://check-host.net/check-ping?host=${target}${qs}" ;;
    *) return 1 ;;
  esac
  body="$(_audit_http_get "$url" 20)"
  [[ -n "$body" ]] || return 1
  if printf '%s' "$body" | grep -q 'limit_exceeded\|"error"'; then
    if printf '%s' "$body" | grep -q 'limit_exceeded'; then
      echo "LIMIT" >&2
    fi
    # still try to extract request_id if present
  fi
  local rid
  rid="$(printf '%s' "$body" | _audit_json_get request_id)"
  [[ -z "$rid" ]] && rid="$(printf '%s' "$body" | grep -oE '"request_id"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"/\1/')"
  [[ -n "$rid" ]] || return 1
  printf '%s\n' "$rid"
}

_audit_checkhost_poll() {
  # _audit_checkhost_poll REQUEST_ID DEADLINE_EPOCH
  # prints raw JSON result (may still contain nulls if timed out)
  local rid="$1" deadline="$2"
  local body="" now
  while true; do
    now="$(date +%s)"
    (( now >= deadline )) && break
    body="$(_audit_http_get "https://check-host.net/check-result/${rid}" 10)"
    if [[ -n "$body" && "$body" != "null" ]]; then
      # unfinished nodes are null values — wait until none left or deadline
      if command -v python3 >/dev/null 2>&1; then
        if printf '%s' "$body" | python3 -c '
import json,sys
try:
  d=json.load(sys.stdin)
except Exception:
  raise SystemExit(1)
if not isinstance(d,dict) or not d:
  raise SystemExit(1)
# pending if any value is null
for v in d.values():
  if v is None:
    raise SystemExit(2)
raise SystemExit(0)
' 2>/dev/null; then
          printf '%s\n' "$body"
          return 0
        fi
      else
        # no python: if no ":null" left, done
        if ! printf '%s' "$body" | grep -qE '":\s*null'; then
          printf '%s\n' "$body"
          return 0
        fi
      fi
    fi
    sleep 1
  done
  [[ -n "$body" && "$body" != "null" ]] && printf '%s\n' "$body"
  return 0
}

_audit_summarize_tcp_result() {
  # stdin: check-result JSON; args: space-separated RU nodes, then --, then foreign nodes
  # prints: ru_ok ru_total foreign_ok foreign_total
  local -a ru_nodes=() fr_nodes=()
  local mode=ru
  local a
  for a in "$@"; do
    if [[ "$a" == "--" ]]; then mode=fr; continue; fi
    if [[ "$mode" == "ru" ]]; then ru_nodes+=("$a"); else fr_nodes+=("$a"); fi
  done
  if command -v python3 >/dev/null 2>&1; then
    python3 -c '
import json,sys
raw=sys.stdin.read()
try:
  d=json.loads(raw) if raw.strip() else {}
except Exception:
  d={}
ru=sys.argv[1].split(",") if sys.argv[1] else []
fr=sys.argv[2].split(",") if sys.argv[2] else []
def ok(v):
  if v is None: return None  # pending/unknown
  if isinstance(v,list) and v:
    item=v[0]
    if isinstance(item,dict):
      if "error" in item: return False
      if "time" in item or "address" in item: return True
      return False
    if isinstance(item,list) and item:
      # ping: ["OK", latency, addr] / ["TIMEOUT", ...]
      return str(item[0]).upper() in ("OK","OK!")
  return False
def count(keys):
  o=t=0
  for k in keys:
    if not k or k not in d: continue
    r=ok(d.get(k))
    if r is None: continue
    t+=1
    if r: o+=1
  return o,t
ro,rt=count(ru); fo,ft=count(fr)
print(f"{ro} {rt} {fo} {ft}")
' "$(IFS=,; echo "${ru_nodes[*]}")" "$(IFS=,; echo "${fr_nodes[*]}")" 2>/dev/null || echo "0 0 0 0"
  else
    # crude: count nodes without "error" near their key — best-effort
    echo "0 0 0 0"
  fi
}

_audit_reachability_from_russia() {
  local pub_ip="$1"
  shift
  local -a ports=("$@")
  local deadline=$(( $(date +%s) + 55 ))
  local started_at
  started_at="$(date +%s)"

  AUDIT_PING_DONE=0
  AUDIT_PING_RU_OK=0; AUDIT_PING_RU_TOT=0
  AUDIT_PING_FR_OK=0; AUDIT_PING_FR_TOT=0
  step "Доступность IP из России (check-host.net)"
  _audit_info "Публичный IPv4: ${pub_ip}"
  if [[ ${#ports[@]} -eq 0 ]]; then
    _audit_warn "Клиентские TCP-порты не найдены — TCP-проверку пропускаем (задайте --client-ports)"
  else
    _audit_info "Клиентские TCP-порты: $(IFS=,; echo "${ports[*]}")"
  fi

  if ! _audit_pick_checkhost_nodes; then
    _audit_err "Не удалось получить список узлов check-host.net — пропускаем внешнюю проверку"
    return 0
  fi
  _audit_info "Узлы РФ: ${AUDIT_RU_NODES[*]:-—}"
  _audit_info "Узлы зарубежье: ${AUDIT_FOREIGN_NODES[*]:-—}"

  local -a all_nodes=("${AUDIT_RU_NODES[@]}" "${AUDIT_FOREIGN_NODES[@]}")
  local port rid body ru_ok ru_tot fr_ok fr_tot verdict
  local any_ru_fail=0 any_fr_ok=0 limit_hit=0

  for port in "${ports[@]}"; do
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    now="$(date +%s)"
    if (( now >= deadline )); then
      _audit_warn "Лимит времени (~60с) — остальные порты не проверяем"
      break
    fi
    echo
    printf '%bПорт %s/tcp:%b\n' "${C_BOLD}" "$port" "${C_RESET}"
    rid="$(_audit_checkhost_start tcp "${pub_ip}:${port}" "${all_nodes[@]}" 2>/tmp/gorecshit-audit-ch.err || true)"
    if grep -q LIMIT /tmp/gorecshit-audit-ch.err 2>/dev/null; then
      limit_hit=1
    fi
    if [[ -z "$rid" ]]; then
      if [[ "$limit_hit" -eq 1 ]]; then
        _audit_warn "API check-host.net: limit_exceeded — повторите позже"
      else
        _audit_warn "Не удалось запустить check-tcp для ${pub_ip}:${port}"
      fi
      continue
    fi
    body="$(_audit_checkhost_poll "$rid" "$deadline")"
    if [[ -z "$body" ]]; then
      _audit_warn "Нет результата check-tcp (таймаут/ошибка API)"
      continue
    fi
    read -r ru_ok ru_tot fr_ok fr_tot < <(printf '%s' "$body" | _audit_summarize_tcp_result "${AUDIT_RU_NODES[@]}" -- "${AUDIT_FOREIGN_NODES[@]}")
    ru_ok="${ru_ok:-0}"; ru_tot="${ru_tot:-0}"; fr_ok="${fr_ok:-0}"; fr_tot="${fr_tot:-0}"
    _audit_info "из России: доступен ${ru_ok}/${ru_tot} узлов"
    _audit_info "из-за рубежа: доступен ${fr_ok}/${fr_tot} узлов"
    verdict=""
    if (( fr_tot > 0 && fr_ok > 0 && ru_tot > 0 && ru_ok == 0 )); then
      verdict="IP, вероятно, заблокирован в РФ (ТСПУ)"
      any_ru_fail=1
      any_fr_ok=1
      _audit_warn "$verdict"
    elif (( ru_tot > 0 && ru_ok > 0 )); then
      _audit_ok "из России порт отвечает (не похоже на полную блокировку IP/порта)"
    elif (( fr_tot > 0 && fr_ok == 0 && ru_tot > 0 && ru_ok == 0 )); then
      _audit_warn "Порт недоступен ни из РФ, ни из-за рубежа (фильтр/не слушает/файрвол хостера?)"
    else
      _audit_warn "Недостаточно данных для вердикта по порту ${port}"
    fi
    (( fr_ok > 0 )) && any_fr_ok=1
    (( ru_tot > 0 && ru_ok == 0 && fr_ok > 0 )) && any_ru_fail=1
  done

  # Ping comparison (one shot) if time left
  now="$(date +%s)"
  if (( now + 8 < deadline )) && [[ "$limit_hit" -eq 0 ]]; then
    echo
    printf '%bICMP ping (check-host):%b\n' "${C_BOLD}" "${C_RESET}"
    rid="$(_audit_checkhost_start ping "${pub_ip}" "${all_nodes[@]}" 2>/tmp/gorecshit-audit-ch.err || true)"
    if [[ -n "$rid" ]]; then
      body="$(_audit_checkhost_poll "$rid" "$deadline")"
      if [[ -n "$body" ]]; then
        read -r ru_ok ru_tot fr_ok fr_tot < <(printf '%s' "$body" | _audit_summarize_tcp_result "${AUDIT_RU_NODES[@]}" -- "${AUDIT_FOREIGN_NODES[@]}")
        AUDIT_PING_RU_OK="${ru_ok:-0}"
        AUDIT_PING_RU_TOT="${ru_tot:-0}"
        AUDIT_PING_FR_OK="${fr_ok:-0}"
        AUDIT_PING_FR_TOT="${fr_tot:-0}"
        AUDIT_PING_DONE=1
        _audit_info "ping из России: ${AUDIT_PING_RU_OK}/${AUDIT_PING_RU_TOT} узлов"
        _audit_info "ping из-за рубежа: ${AUDIT_PING_FR_OK}/${AUDIT_PING_FR_TOT} узлов"
      else
        _audit_warn "Нет результата check-ping"
      fi
    else
      if grep -q LIMIT /tmp/gorecshit-audit-ch.err 2>/dev/null; then
        _audit_warn "API check-host.net: limit_exceeded на ping — пропуск"
      else
        _audit_warn "Не удалось запустить check-ping"
      fi
    fi
  fi

  echo
  if (( any_ru_fail == 1 && any_fr_ok == 1 )); then
    _audit_warn "Итог доступности: зарубежье видит ноду, РФ — нет → вероятна блокировка IP в РФ (ТСПУ). Смените IP/хостера или используйте CDN/relay."
  fi
  local elapsed=$(( $(date +%s) - started_at ))
  _audit_info "Внешняя проверка заняла ~${elapsed}с (лимит ~60с)"
}

_audit_reality_dest_quality() {
  # stdin unused; args: serverNames/dest strings — prints good|ru|small|unknown
  local s="$1"
  s="$(printf '%s' "$s" | tr '[:upper:]' '[:lower:]')"
  case "$s" in
    *cdn-apple.com*|*mzstatic.com*|*gstatic.com*|*googleapis.com*|*google.com*|*microsoftonline.com*|*edge.microsoft*|*windows.net*|*office.com*|*microsoft.com*|*icloud.com*|*apple.com*|*cloudflare-dns.com*|*cloudflare.com*|*amazonaws.com*|*amazon.com*|*fbcdn.net*|*facebook.com*|*yimg.com*|*yahoo.com*|*bing.com*|*live.com*|*akamai*)
      echo good; return ;;
  esac
  case "$s" in
    *.ru|*.su|*.xn--p1ai|*mail.ru*|*yandex.*|*vk.com*|*ok.ru*|*sber*|*rt.ru*|*mts.ru*|*megafon*)
      echo ru; return ;;
  esac
  # short / odd looking host
  local host="${s%%/*}"
  host="${host#*://}"
  host="${host%%:*}"
  if [[ ${#host} -le 8 || "$host" =~ ^[0-9.]+$ ]]; then
    echo small; return
  fi
  echo unknown
}

_audit_openssl_dest() {
  # Check dest reachable via TLS1.3 + h2 from this server. Args: host [port=443]
  local host="$1" port="${2:-443}"
  host="${host%%/*}"; host="${host#*://}"; host="${host%%:*}"
  [[ -n "$host" ]] || { echo fail; return; }
  command -v openssl >/dev/null 2>&1 || { echo no_openssl; return; }
  local out
  out="$(timeout 8 openssl s_client -connect "${host}:${port}" -servername "$host" -tls1_3 -alpn h2 </dev/null 2>/dev/null | tr -d '\0' || true)"
  if printf '%s' "$out" | grep -qiE 'ALPN[[:space:]]+protocol:[[:space:]]*h2|Protocol[[:space:]]*:[[:space:]]*TLSv1\.3'; then
    if printf '%s' "$out" | grep -q 'ALPN' && printf '%s' "$out" | grep -qi 'h2'; then
      echo ok
      return
    fi
    # TLS1.3 without confirmed h2 — still partial ok
    if printf '%s' "$out" | grep -qi 'Protocol.*TLSv1\.3'; then
      echo tls13
      return
    fi
  fi
  # retry without forcing alpn to see any TLS
  out="$(timeout 8 openssl s_client -connect "${host}:${port}" -servername "$host" -tls1_3 </dev/null 2>/dev/null | tr -d '\0' || true)"
  if printf '%s' "$out" | grep -qi 'Protocol.*TLSv1\.3'; then
    echo tls13
  else
    echo fail
  fi
}


_audit_passive_reality_probe() {
  # Fallback when xray config is not readable: probe local client ports with openssl.
  # REALITY typically falls through to dest cert for unauthenticated probes.
  step "Пассивный REALITY/TLS-зонд (конфиг xray недоступен)"
  _audit_info "Конфиг из панели в runtime часто без файла — смотрим сертификат/ALPN на локальных клиентских портах (read-only)"
  command -v openssl >/dev/null 2>&1 || {
    _audit_warn "openssl нет — пассивный зонд невозможен"
    return 0
  }
  local -a ports=()
  if [[ ${#DETECTED_CLIENT_PORTS[@]} -gt 0 ]]; then
    ports=("${DETECTED_CLIENT_PORTS[@]}")
  fi
  if [[ ${#ports[@]} -eq 0 ]]; then
    _audit_warn "Нет клиентских портов для зонда (задайте --client-ports)"
    return 0
  fi
  local -a snis=(
    www.microsoft.com www.cloudflare.com www.google.com dl.google.com
    www.apple.com www.yahoo.com www.bing.com gateway.icloud.com
  )
  local port sni out proto alpn subj sans cn masked q
  local any=0
  for port in "${ports[@]}"; do
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    any=1
    echo
    printf '%bПорт %s (локальный TLS-зонд):%b\n' "${C_BOLD}" "$port" "${C_RESET}"
    if [[ "$port" == "443" ]]; then
      _audit_ok "Порт 443 — хорошо маскируется под HTTPS"
    else
      _audit_warn "Порт ${port} ≠ 443 — для REALITY лучше 443 (меньше палевности)"
    fi
    out=""
    masked=""
    proto=""
    alpn=""
    for sni in "${snis[@]}" ""; do
      if [[ -n "$sni" ]]; then
        out="$(timeout 6 openssl s_client -connect "127.0.0.1:${port}" -servername "$sni" -tls1_3 -alpn h2 </dev/null 2>/dev/null | tr -d '\0' || true)"
      else
        out="$(timeout 6 openssl s_client -connect "127.0.0.1:${port}" -tls1_3 -alpn h2 </dev/null 2>/dev/null | tr -d '\0' || true)"
      fi
      if printf '%s' "$out" | grep -qiE 'BEGIN CERTIFICATE|subject=|Protocol  *:'; then
        break
      fi
      out=""
    done
    if [[ -z "$out" ]]; then
      # retry without forcing tls1.3
      out="$(timeout 6 openssl s_client -connect "127.0.0.1:${port}" -servername www.microsoft.com -alpn h2 </dev/null 2>/dev/null | tr -d '\0' || true)"
    fi
    if [[ -z "$out" ]] || ! printf '%s' "$out" | grep -qiE 'BEGIN CERTIFICATE|subject='; then
      _audit_warn "TLS-ответ на 127.0.0.1:${port} не получен — порт не TLS/закрыт локально или нужен REALITY shortId"
      continue
    fi
    proto="$(printf '%s' "$out" | grep -iE '^[[:space:]]*Protocol[[:space:]]*:' | head -1 | sed -E 's/.*:[[:space:]]*//' | tr -d '\r')"
    alpn="$(printf '%s' "$out" | grep -iE 'ALPN[[:space:]]+protocol:' | head -1 | sed -E 's/.*:[[:space:]]*//' | tr -d '\r')"
    subj="$(printf '%s' "$out" | grep -iE '^subject=' | head -1 | tr -d '\r')"
    cn="$(printf '%s' "$subj" | sed -nE 's/.*CN[[:space:]]*=[[:space:]]*([^/,]+).*/\1/p' | head -1)"
    sans="$(printf '%s' "$out" | grep -i 'DNS:' | head -3 | tr '\n' ' ' | tr -d '\r')"
    masked="${cn:-}"
    if [[ -z "$masked" && -n "$sans" ]]; then
      masked="$(printf '%s' "$sans" | grep -oE 'DNS:[^, ]+' | head -1 | sed 's/DNS://')"
    fi
    if [[ -n "$masked" ]]; then
      _audit_info "Маскировочный сертификат/домен: ${masked}"
      [[ -n "$sans" ]] && _audit_info "SAN: ${sans}"
      q="$(_audit_reality_dest_quality "$masked")"
      case "$q" in
        good) _audit_ok "CN/SAN похож на крупный зарубежный сайт — хорошо для REALITY" ;;
        ru)   _audit_warn "CN/SAN российский (${masked}) — лучше gstatic/microsoft/apple" ;;
        small) _audit_warn "CN/SAN мелкий/подозрительный (${masked})" ;;
        *)    _audit_warn "CN/SAN «${masked}» — предпочтительны крупные зарубежные домены" ;;
      esac
      # dest reachability from this server
      local tls_res
      tls_res="$(_audit_openssl_dest "$masked" 443)"
      case "$tls_res" in
        ok) _audit_ok "Маскировочный домен ${masked}:443 доступен (TLS1.3 + h2) с ноды" ;;
        tls13) _audit_warn "Маскировочный домен ${masked}:443 — TLS1.3 есть, h2 не подтверждён" ;;
        no_openssl) : ;;
        *) _audit_warn "Маскировочный домен ${masked}:443 не открылся по TLS1.3/h2 с ноды" ;;
      esac
      _audit_active_probe_reality "$port" "$masked" "$masked" 443
    else
      _audit_warn "Не удалось извлечь CN/SAN из сертификата на порту ${port}"
    fi
    if printf '%s' "$proto" | grep -qi 'TLSv1\.3'; then
      _audit_ok "TLS ${proto:-1.3}"
    else
      _audit_warn "Протокол «${proto:-unknown}» — для REALITY ожидается TLS1.3"
    fi
    if printf '%s' "$alpn" | grep -qi 'h2'; then
      _audit_ok "ALPN h2"
    else
      _audit_warn "ALPN «${alpn:-нет}» — желателен h2 (как у обычного HTTPS)"
    fi
  done
  [[ "$any" -eq 1 ]] || _audit_warn "Нечего зондировать"
  _audit_info "Полный разбор flow/shortIds/bittorrent без конфига недоступен — настройки панели не трогаем"
}

_audit_report_inbounds_from_json() {
  # Shared reporter used when JSON config is available (stdin: json).
  local json="$1"
  if ! command -v python3 >/dev/null 2>&1; then
    _audit_warn "python3 нет — детальный разбор inbounds ограничен"
    if printf '%s' "$json" | grep -qi 'xtls-rprx-vision'; then
      _audit_ok "Встречается flow xtls-rprx-vision"
    else
      _audit_warn "flow xtls-rprx-vision не найден — для VLESS+REALITY лучше vision"
    fi
    if printf '%s' "$json" | grep -qi 'bittorrent\|BitTorrent\|protocol.*bittorrent'; then
      _audit_ok "Похоже есть правило блокировки bittorrent"
    else
      _audit_warn "Нет явного block bittorrent в routing — добавьте block torrent (меньше жалоб хостеру)"
    fi
    return 0
  fi

  local report
  report="$(printf '%s' "$json" | python3 -c '
import json,sys,re
cfg=json.load(sys.stdin)
inbounds=cfg.get("inbounds") or []
if isinstance(inbounds,dict):
  inbounds=list(inbounds.values())
# API lsi sometimes returns {"inbounds":[...]} or a bare list
if isinstance(cfg,list):
  inbounds=cfg
routing=cfg.get("routing") or {} if isinstance(cfg,dict) else {}
rules=routing.get("rules") or []
bt=False
for r in rules:
  if not isinstance(r,dict):
    continue
  proto=r.get("protocol") or r.get("protocols") or []
  if isinstance(proto,str): proto=[proto]
  joined=" ".join(str(x).lower() for x in proto)
  if "bittorrent" in joined or "bit torrent" in joined:
    bt=True
  outbound=(r.get("outboundTag") or r.get("outbound_tag") or "")
  s=json.dumps(r).lower()
  if "bittorrent" in s and ("blocked" in str(outbound).lower() or "blackhole" in str(outbound).lower() or r.get("type")=="field"):
    bt=True
print("BT", "yes" if bt else "no")
idx=0
for ib in inbounds:
  if not isinstance(ib,dict):
    continue
  tag=str(ib.get("tag") or "")
  if tag.lower() in ("api","metrics","stats"):
    continue
  proto=(ib.get("protocol") or "").lower()
  if proto not in ("vless","vmess","trojan","shadowsocks"):
    continue
  port=ib.get("port")
  ss=ib.get("streamSettings") or ib.get("stream_settings") or {}
  security=(ss.get("security") or "").lower()
  network=(ss.get("network") or ib.get("network") or "tcp").lower()
  rs=ss.get("realitySettings") or ss.get("reality_settings") or {}
  ts=ss.get("tlsSettings") or ss.get("tls_settings") or {}
  clients=((ib.get("settings") or {}).get("clients")) or []
  flows=[]
  for c in clients:
    if isinstance(c,dict) and c.get("flow"):
      flows.append(str(c.get("flow")))
  flow=",".join(flows) if flows else ""
  sni=""
  dest=""
  short_ids=[]
  if security=="reality" or rs:
    sni=",".join(str(x) for x in (rs.get("serverNames") or rs.get("server_names") or [])[:6])
    dest=str(rs.get("dest") or rs.get("target") or "")
    short_ids=rs.get("shortIds") or rs.get("short_ids") or []
  elif security in ("tls","xtls"):
    sni=",".join(str(x) for x in (ts.get("serverName") or ts.get("serverNames") or [])[:6] if x) if isinstance(ts.get("serverNames"),list) else str(ts.get("serverName") or "")
  idx+=1
  sid_empty = (not short_ids) or (isinstance(short_ids,list) and all(not str(x) for x in short_ids))
  print("|".join([
    "IB", str(idx), proto, str(port or ""), security or "none", network,
    flow or "-", sni or "-", dest or "-",
    "sid_empty" if sid_empty else "sid_ok",
    "reality" if (security=="reality" or rs) else "other",
  ]))
' 2>/dev/null || true)"

  if [[ -z "$report" ]]; then
    _audit_warn "Не удалось разобрать JSON inbounds"
    _audit_passive_reality_probe
    return 0
  fi

  local bt_line ib_count=0
  bt_line="$(printf '%s\n' "$report" | grep '^BT ' | head -1 || true)"
  if [[ "$bt_line" == "BT yes" ]]; then
    _audit_ok "Есть routing-правило блокировки bittorrent"
  else
    _audit_warn "Нет block bittorrent в routing — рекомендуется blackhole/blocked для protocol bittorrent"
  fi

  local line _tag idx proto port security network flow sni dest sid_flag kind
  local dest_host dest_port q tls_res
  while IFS= read -r line; do
    case "$line" in IB\|*) ;; *) continue ;; esac
    ib_count=$((ib_count+1))
    IFS="|" read -r _tag idx proto port security network flow sni dest sid_flag kind <<<"$line"
    echo
    printf '%bInbound #%s (%s port %s):%b\n' "${C_BOLD}" "${idx}" "$proto" "${port:-?}" "${C_RESET}"

    if [[ "$kind" == "reality" ]]; then
      if [[ "$port" == "443" ]]; then
        _audit_ok "Порт 443 — хорошо маскируется под HTTPS"
      else
        _audit_warn "Порт ${port:-?} ≠ 443 — для REALITY лучше слушать 443 (меньше палевности)"
      fi
      if [[ "$flow" == *xtls-rprx-vision* ]]; then
        _audit_ok "flow=xtls-rprx-vision"
      else
        _audit_warn "flow «${flow}» — для VLESS+REALITY рекомендуют xtls-rprx-vision"
      fi
      if [[ "$sid_flag" == "sid_empty" ]]; then
        _audit_warn "shortIds пустые — задайте несколько shortId (сложнее зондировать REALITY)"
      else
        _audit_ok "shortIds заданы"
      fi
      q="$(_audit_reality_dest_quality "${dest}|${sni}")"
      case "$q" in
        good) _audit_ok "dest/serverNames выглядят как крупный зарубежный сайт (${dest:-$sni}) — хорошо" ;;
        ru)   _audit_warn "dest/SNI российский (${dest:-$sni}) — лучше gstatic/microsoft/apple/cloudflare" ;;
        small) _audit_warn "dest/SNI мелкий/подозрительный (${dest:-$sni}) — возьмите крупный зарубежный домен" ;;
        *)    _audit_warn "dest/SNI «${dest:-$sni}» — предпочтительны gstatic.com / www.microsoft.com / apple.com" ;;
      esac
      dest_host="${dest%%:*}"
      dest_port=443
      if [[ "$dest" == *:* ]]; then
        dest_port="${dest##*:}"
        [[ "$dest_port" =~ ^[0-9]+$ ]] || dest_port=443
      fi
      _audit_active_probe_reality "$port" "$sni" "$dest_host" "$dest_port"
      if [[ -n "$dest_host" && "$dest_host" != "-" ]]; then
        tls_res="$(_audit_openssl_dest "$dest_host" "$dest_port")"
        case "$tls_res" in
          ok) _audit_ok "dest ${dest_host}:${dest_port} доступен (TLS1.3 + h2) с этой ноды" ;;
          tls13) _audit_warn "dest ${dest_host}:${dest_port} отвечает TLS1.3, но ALPN h2 не подтверждён — проверьте dest" ;;
          no_openssl) _audit_warn "openssl нет — проверку dest TLS пропустили" ;;
          *) _audit_warn "dest ${dest_host}:${dest_port} не открылся по TLS1.3/h2 с ноды — смените dest на живой сайт" ;;
        esac
      fi
    else
      if [[ "$security" == "none" || "$security" == "-" || -z "$security" ]]; then
        _audit_warn "Нет REALITY/TLS (${proto}/${network}) — трафик легче классифицировать как VPN"
      elif [[ "$network" == "ws" || "$network" == "websocket" ]]; then
        _audit_warn "Обычный TLS/WS без CDN — для РФ лучше REALITY или CDN (Cloudflare) перед нодой"
      else
        _audit_warn "Не REALITY (security=${security}, network=${network}) — выше риск палевности без CDN"
      fi
      if [[ "$port" != "443" && "$port" != "80" ]]; then
        _audit_warn "Порт ${port:-?} не 443/80 — заметнее для сканеров"
      fi
    fi
  done <<<"$report"

  if [[ "$ib_count" -eq 0 ]]; then
    _audit_warn "VLESS/VMESS/Trojan inbounds не найдены в конфиге — пробуем пассивный зонд"
    _audit_passive_reality_probe
  fi
}


_audit_xray_self() {
  step "Самоаудит палевности (локальный xray / REALITY)"
  local json
  json="$(collect_xray_config_json 2>/dev/null || true)"
  if [[ -n "$json" ]] && printf '%s' "$json" | grep -q '"inbounds"'; then
    _audit_ok "Конфиг xray прочитан (только чтение)"
    _audit_report_inbounds_from_json "$json"
    return 0
  fi
  _audit_warn "Статический конфиг xray недоступен (Remnawave часто отдаёт конфиг из панели в runtime / stdin)"
  if [[ "${AUDIT_XRAY_STDIN_CONFIG:-0}" -eq 1 ]]; then
    _audit_info "Обнаружен запуск xray с -config stdin: — пробуем API/зонд"
  fi
  # one more API attempt after discovery side-effects
  local cname cjson
  cname="$(_find_remnanode_container 2>/dev/null || true)"
  cjson="$(_try_xray_api_inbounds_json "${cname:-}" "${AUDIT_XRAY_PID:-}" 2>/dev/null || true)"
  if [[ -n "$cjson" ]] && printf '%s' "$cjson" | grep -q '"inbounds"'; then
    _audit_ok "Конфиг получен через xray API (read-only)"
    _audit_report_inbounds_from_json "$cjson"
    return 0
  fi
  _audit_passive_reality_probe
}


_audit_server_level() {
  step "Сервер: признаки «палевной» ноды (только проверка)"
  # Prefer external check-host ping (ground truth from the internet). Local heuristics only as fallback.
  local icmp_hidden=-1  # -1 unknown, 1 hidden, 0 visible
  if [[ "${AUDIT_PING_DONE:-0}" -eq 1 ]]; then
    local _ptot=$(( ${AUDIT_PING_RU_TOT:-0} + ${AUDIT_PING_FR_TOT:-0} ))
    local _pok=$(( ${AUDIT_PING_RU_OK:-0} + ${AUDIT_PING_FR_OK:-0} ))
    if (( _ptot > 0 )); then
      if (( _pok == 0 )); then
        icmp_hidden=1
        _audit_ok "ICMP снаружи скрыт (check-host ping ${_pok}/${_ptot} узлов) — нода не светится ping'ом"
      else
        icmp_hidden=0
        _audit_warn "ICMP снаружи отвечает (check-host ping ${_pok}/${_ptot}) — для стелса лучше DROP echo-request (не трогаем сами)"
      fi
    fi
  fi
  if [[ "$icmp_hidden" -eq -1 ]]; then
    local icmp_drop=0 ignore=0
    if [[ -r /proc/sys/net/ipv4/icmp_echo_ignore_all ]] && [[ "$(cat /proc/sys/net/ipv4/icmp_echo_ignore_all 2>/dev/null)" == "1" ]]; then
      ignore=1
      icmp_drop=1
    fi
    if command -v iptables >/dev/null 2>&1; then
      if iptables -S 2>/dev/null | grep -qiE 'icmp-type[[:space:]]*8.*DROP|DROP.*icmp-type[[:space:]]*8|icmp[[:space:]]+--icmp-type[[:space:]]+8[[:space:]]+-j[[:space:]]+DROP'; then
        icmp_drop=1
      fi
      if iptables -S INPUT 2>/dev/null | grep -qiE '\-p icmp .*(-j DROP|-j REJECT)'; then
        icmp_drop=1
      fi
    fi
    if command -v nft >/dev/null 2>&1; then
      if nft list ruleset 2>/dev/null | grep -qiE 'icmp.*(type[[:space:]]*)?(echo-request|8).*drop|drop.*icmp.*(echo-request|type 8)'; then
        icmp_drop=1
      fi
    fi
    if [[ -f /etc/ufw/before.rules ]]; then
      if grep -A2 -E 'ECHO REQUEST|icmp-type 8|icmp --icmp-type 8' /etc/ufw/before.rules 2>/dev/null | grep -qiE 'DROP|REJECT'; then
        icmp_drop=1
      fi
    fi
    if [[ -f /etc/ufw/before6.rules ]]; then
      if grep -A2 -E 'ECHO REQUEST|icmpv6-type.*(128|echo-request)' /etc/ufw/before6.rules 2>/dev/null | grep -qiE 'DROP|REJECT'; then
        icmp_drop=1
      fi
    fi
    if [[ "$icmp_drop" -eq 1 || "$ignore" -eq 1 ]]; then
      _audit_ok "ICMP echo-request, похоже, режется локально (iptables/nft/ufw/sysctl) — внешний check-host ping недоступен для подтверждения"
    else
      _audit_warn "Локально ICMP echo не выглядит отключённым (и нет данных check-host) — для стелса лучше DROP echo-request (не трогаем сами)"
    fi
  fi

  # SSH on 22
  local ssh22=0
  if command -v ss >/dev/null 2>&1; then
    if ss -lntp 2>/dev/null | awk 'NR>1' | grep -E ':22\b' | grep -qiE 'sshd|ssh'; then
      ssh22=1
    elif ss -lntp 2>/dev/null | awk 'NR>1' | grep -qE '[:.]22\s'; then
      # port 22 listen even without process name
      if ss -lntp '( sport = :22 )' 2>/dev/null | awk 'NR>1{print; exit}' | grep -q .; then
        ssh22=1
      fi
    fi
  fi
  if [[ "$ssh22" -eq 1 ]]; then
    _audit_warn "SSH слушает порт 22 — классический маркер; лучше --ssh-port N (оставив 22 до проверки)"
  else
    _audit_ok "SSH не на 22 (или не обнаружен) — меньше шаблонности"
  fi

  # ufw inactive
  local ufw_active=0
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qiE 'Status:\s*active'; then
    ufw_active=1
  fi
  if [[ "$ufw_active" -eq 1 ]]; then
    _audit_ok "UFW активен"
  else
    _audit_warn "UFW неактивен — защита gorecshit не установлена/выключена; публичная поверхность шире (пункт меню 1)"
  fi

  # Extra public listeners (v4+v6, UFW/Docker aware): see _audit_exposure_listeners (v2.6.0)

  # ---- Fingerprint / stealth markers (read-only) ----
  step "Отпечатки сервера (аудит)"
  local host_now ttl_now
  host_now="$(hostname -s 2>/dev/null || hostname 2>/dev/null || true)"
  if declare -F _fp_hostname_suspicious >/dev/null 2>&1 && _fp_hostname_suspicious "$host_now"; then
    _audit_warn "Hostname «${host_now}» похож на шаблон VPN/провайдера — меню «9» / --stealth"
  else
    _audit_ok "Hostname «${host_now}»"
  fi
  if [[ -f /etc/ssh/sshd_config.d/99-gorecshit-fingerprint.conf ]] || grep -RqiE '^\s*DebianBanner\s+no' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null; then
    _audit_ok "SSH Banner/DebianBanner скрытия настроены"
  else
    _audit_warn "SSH Banner/DebianBanner не скрыты — gorecshit --stealth"
  fi
  if [[ -f /etc/default/motd-news ]] && grep -qE '^ENABLED=0' /etc/default/motd-news 2>/dev/null; then
    _audit_ok "motd-news выключен"
  elif [[ -x /etc/update-motd.d/10-help-text || -x /etc/update-motd.d/50-motd-news ]]; then
    _audit_warn "update-motd help/news ещё исполняемые"
  else
    _audit_ok "motd ads не активны (или отсутствуют)"
  fi
  ttl_now="$(sysctl -n net.ipv4.ip_default_ttl 2>/dev/null || echo '?')"
  if [[ "$ttl_now" == "64" ]]; then
    _audit_ok "ip_default_ttl=${ttl_now}"
  else
    _audit_warn "ip_default_ttl=${ttl_now} (обычно 64)"
  fi
  if [[ "$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null || echo 1)" == "0" ]]; then
    _audit_ok "send_redirects=0"
  else
    _audit_warn "send_redirects включены"
  fi
  if [[ "$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null || echo 0)" == "1" ]]; then
    _audit_ok "icmp_echo_ignore_broadcasts=1"
  else
    _audit_warn "icmp_echo_ignore_broadcasts не 1"
  fi
  if command -v iptables >/dev/null 2>&1 && iptables -L GORECSHIT-FP -n >/dev/null 2>&1; then
    _audit_ok "Цепочка GORECSHIT-FP (ICMP timestamp/mask DROP) есть"
  else
    _audit_warn "Нет GORECSHIT-FP — ICMP timestamp/address-mask могут отвечать (--stealth)"
  fi
  if [[ -f /var/lib/gorecshit/fingerprint.done ]]; then
    _audit_ok "Маркер fingerprint.done есть"
  else
    _audit_warn "fingerprint.done нет — «Скрыть отпечатки» ещё не запускали"
  fi
  if ss -lntp 2>/dev/null | grep -qE '[:.]2375[[:space:]]|[:.]2376[[:space:]]'; then
    _audit_warn "Docker API на 2375/2376 слушает — закройте"
  else
    _audit_ok "Docker 2375/2376 не слушает"
  fi
  local _svc
  for _svc in rpcbind avahi-daemon cups snmpd; do
    if systemctl is-active --quiet "${_svc}.service" 2>/dev/null; then
      _audit_warn "Сервис ${_svc} активен — светит ОС"
    fi
  done
  if [[ -d /etc/nginx ]] && grep -RqiE '^\s*server_tokens\s+off' /etc/nginx 2>/dev/null; then
    _audit_ok "nginx server_tokens off"
  elif [[ -d /etc/nginx ]]; then
    _audit_warn "nginx есть, server_tokens off не найден"
  fi

}

# ---------- v2.6.0: exposure / active-probe / giveaway audit helpers (read-only) ----------

# Known "palevnye" ports: label shown when such a port is visible from outside.
_audit_port_label() {
  case "$1" in
    2222) echo "дефолтный NODE_PORT Remnawave" ;;
    3000|3001|6767) echo "порты панели/подписки Remnawave" ;;
    62050|62051) echo "дефолтный порт Marzban-node" ;;
    10085|62789|8080) echo "часто xray API / stats / прокси" ;;
    2053|2083|2087|2096|8880) echo "типичный порт xray (CF-порты) / 3x-ui" ;;
    54321|2095) echo "дефолт 3x-ui / x-ui" ;;
    1080|3128|8118|9050) echo "SOCKS/HTTP-прокси / Tor" ;;
    8388|8389) echo "Shadowsocks по умолчанию" ;;
    51820|51821) echo "WireGuard / wg-easy" ;;
    1194|1723|500|4500|1701) echo "OpenVPN / PPTP / IPsec / L2TP" ;;
    2375|2376) echo "Docker API" ;;
    9100|9090|9091|19999) echo "мониторинг (node_exporter/Prometheus/netdata)" ;;
    *) echo "" ;;
  esac
}

_audit_in_list() {
  # _audit_in_list needle item...
  local n="$1" x
  shift
  for x in "$@"; do [[ "$x" == "$n" ]] && return 0; done
  return 1
}

_audit_node_port() {
  local np="${DETECTED_NODE_PORT:-}"
  if [[ -z "$np" && -n "${NODE_PORT:-}" && "${NODE_PORT}" =~ ^[0-9]+$ ]]; then np="$NODE_PORT"; fi
  if [[ -f /opt/remnanode/.env ]]; then
    local e
    e="$(grep -E '^(NODE_PORT|APP_PORT)=' /opt/remnanode/.env 2>/dev/null | head -1 | cut -d= -f2- | tr -d '\"\r' || true)"
    [[ "$e" =~ ^[0-9]+$ ]] && np="$e"
  fi
  printf '%s' "${np:-3000}"
}

_audit_ssh_ports() {
  # SSH ports from ss (sshd process) + 22 + --ssh-port
  local -a out=(22)
  [[ -n "${SSH_PORT_NEW:-}" ]] && out+=("$SSH_PORT_NEW")
  local line addr port
  while IFS= read -r line; do
    [[ "$line" == *'"sshd"'* ]] || continue
    addr="$(ss_local_addr "$line")"
    port="${addr##*:}"
    [[ "$port" =~ ^[0-9]+$ ]] && out+=("$port")
  done < <(ss -Hlntp 2>/dev/null || true)
  printf '%s\n' "${out[@]}" | sort -nu
}

_audit_detect_public_ipv6() {
  local ip6=""
  ip6="$(curl -6 -fsS --connect-timeout 4 --max-time 8 -A "gorecshit-audit/${VERSION}" https://api64.ipify.org 2>/dev/null | tr -d '[:space:]' || true)"
  if [[ "$ip6" == *:* ]]; then printf '%s\n' "$ip6"; return 0; fi
  ip6="$(ip -6 addr show scope global 2>/dev/null | awk '/inet6/ && !/deprecated/ {sub(/\/.*/,"",$2); print $2; exit}' || true)"
  if [[ "$ip6" == *:* && "$ip6" != fd* && "$ip6" != fc* ]]; then printf '%s\n' "$ip6"; return 0; fi
  return 1
}

_audit_internetdb() {
  # Shodan InternetDB (free, no key): what the internet already sees on this IP.
  local ip="$1"
  [[ -n "$ip" ]] || return 0
  local raw code body _try
  for _try in 1 2; do
    raw="$(curl -sS --connect-timeout 6 --max-time 12 -A "gorecshit-audit/${VERSION}" \
      -w '\n%{http_code}' "https://internetdb.shodan.io/${ip}" 2>/dev/null || true)"
    code="${raw##*$'\n'}"
    body="${raw%$'\n'*}"
    [[ "$code" == 200 || "$code" == 404 ]] && break
    sleep 2
  done
  echo
  printf '%bShodan InternetDB — %s:%b\n' "${C_BOLD}" "$ip" "${C_RESET}"
  case "$code" in
    200) ;;
    404)
      _audit_ok "Shodan про этот IP ничего не знает — сканеры его пока не каталогизировали"
      return 0 ;;
    *)
      _audit_warn "InternetDB недоступен (HTTP ${code:-нет ответа}) — пропуск, это не ошибка ноды"
      return 0 ;;
  esac
  local idb_ports="" tags="" cpes="" vulns="" hosts=""
  if command -v python3 >/dev/null 2>&1; then
    local parsed
    parsed="$(printf '%s' "$body" | python3 -c '
import json,sys
try:
  d=json.load(sys.stdin)
except Exception:
  sys.exit(0)
def j(k): return ",".join(str(x) for x in (d.get(k) or []))
print("P "+j("ports")); print("T "+j("tags")); print("C "+j("cpes")); print("V "+j("vulns")); print("H "+j("hostnames"))
' 2>/dev/null || true)"
    idb_ports="$(sed -n 's/^P //p' <<<"$parsed")"
    tags="$(sed -n 's/^T //p' <<<"$parsed")"
    cpes="$(sed -n 's/^C //p' <<<"$parsed")"
    vulns="$(sed -n 's/^V //p' <<<"$parsed")"
    hosts="$(sed -n 's/^H //p' <<<"$parsed")"
  else
    idb_ports="$(grep -oE '"ports":\[[^]]*\]' <<<"$body" | sed -E 's/.*\[//;s/\]//' || true)"
    tags="$(grep -oE '"tags":\[[^]]*\]' <<<"$body" | sed -E 's/.*\[//;s/\]//;s/"//g' || true)"
    cpes="$(grep -oE '"cpes":\[[^]]*\]' <<<"$body" | sed -E 's/.*\[//;s/\]//;s/"//g' || true)"
    vulns="$(grep -oE '"vulns":\[[^]]*\]' <<<"$body" | sed -E 's/.*\[//;s/\]//;s/"//g' || true)"
    hosts="$(grep -oE '"hostnames":\[[^]]*\]' <<<"$body" | sed -E 's/.*\[//;s/\]//;s/"//g' || true)"
  fi
  _audit_info "Порты, которые видит интернет: ${idb_ports:-нет}"
  [[ -n "$tags" ]] && _audit_info "Теги: ${tags}"
  [[ -n "$cpes" ]] && _audit_info "CPE (софт/версии): ${cpes}"
  [[ -n "$hosts" ]] && _audit_info "Hostnames: ${hosts}"

  local np t p lbl bad=0
  np="$(_audit_node_port)"
  local -a ssh_ports=()
  mapfile -t ssh_ports < <(_audit_ssh_ports)
  local IFS_OLD="$IFS"
  IFS=','
  for p in $idb_ports; do
    IFS="$IFS_OLD"
    [[ "$p" =~ ^[0-9]+$ ]] || continue
    if [[ "$p" == "$np" ]]; then
      _audit_err "Shodan видел NODE_PORT ${p} открытым — порт управления нодой светился в интернет (сейчас проверим ниже)"
      bad=1
    elif _audit_in_list "$p" "${DETECTED_CLIENT_PORTS[@]:-}" "${DETECTED_CLIENT_UDP_PORTS[@]:-}"; then
      if [[ "$p" != "443" ]]; then
        _audit_info "Клиентский порт ${p} виден сканерам (нормально; на 443 он менее заметен)"
      fi
    elif _audit_in_list "$p" "${ssh_ports[@]}"; then
      :
    else
      lbl="$(_audit_port_label "$p")"
      if [[ -n "$lbl" ]]; then
        _audit_warn "Порт ${p} виден снаружи — ${lbl}"
      else
        _audit_warn "Порт ${p} виден снаружи и не является клиентским/SSH — лишний сервис?"
      fi
      bad=1
    fi
    IFS=','
  done
  IFS="$IFS_OLD"
  for t in ${tags//,/ }; do
    case "$t" in
      vpn|proxy|tor|self-signed|compromised|malware|c2|honeypot|scanner|spam)
        _audit_warn "Тег Shodan «${t}» — IP уже помечен; это видят все, кто ищет VPN-ноды"
        bad=1 ;;
    esac
  done
  if [[ -n "$vulns" ]]; then
    local vn
    vn="$(tr ',' '\n' <<<"$vulns" | grep -c . || true)"
    _audit_warn "Shodan сопоставил ${vn} CVE (по версиям софта): $(tr ',' ' ' <<<"$vulns" | cut -d' ' -f1-5) — обновите систему (пункт 1 делает full-upgrade)"
  fi
  if [[ -n "$hosts" ]] && grep -qiE 'vpn|proxy|xray|vless|reality|remna|v2ray|tunnel|node' <<<"$hosts"; then
    _audit_warn "Hostname/PTR в Shodan содержит VPN-слова: ${hosts}"
    bad=1
  fi
  [[ "$bad" -eq 0 ]] && _audit_ok "В Shodan нет признаков VPN-ноды"
  _audit_info "Shodan обновляет данные раз в несколько дней — после закрытия портов они исчезнут не сразу"
  return 0
}

_audit_ufw_public_sets() {
  # Fills AUDIT_UFW_PUB4 / AUDIT_UFW_PUB6 with " port/proto " tokens open to Anywhere.
  AUDIT_UFW_PUB4=" "
  AUDIT_UFW_PUB6=" "
  command -v ufw >/dev/null 2>&1 || return 0
  local line to action from v6 port proto
  while IFS= read -r line; do
    [[ "$line" == *ALLOW* || "$line" == *LIMIT* ]] || continue
    v6=0
    [[ "$line" == *"(v6)"* ]] && v6=1
    line="${line//(v6)/}"
    # columns: To  Action  From
    to="$(awk '{print $1}' <<<"$line")"
    action="$(awk '{print $2}' <<<"$line")"
    from="$(awk '{for(i=3;i<=NF;i++){ if($i!="IN") {print $i; exit} }}' <<<"$line")"
    [[ "$action" == ALLOW || "$action" == LIMIT ]] || continue
    [[ "$from" == Anywhere ]] || continue
    port="${to%%/*}"
    proto="${to#*/}"
    [[ "$to" == */* ]] || proto="any"
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    if [[ "$proto" == any ]]; then
      if [[ "$v6" -eq 1 ]]; then AUDIT_UFW_PUB6+="${port}/tcp ${port}/udp "; else AUDIT_UFW_PUB4+="${port}/tcp ${port}/udp "; fi
    else
      if [[ "$v6" -eq 1 ]]; then AUDIT_UFW_PUB6+="${port}/${proto} "; else AUDIT_UFW_PUB4+="${port}/${proto} "; fi
    fi
  done < <(ufw status 2>/dev/null | awk 'NR>4' || true)
  return 0
}

_audit_exposure_listeners() {
  step "Внешняя поверхность: кто слушает порты (IPv4 + IPv6)"
  load_ephemeral_port_range
  local np ufw_on=0 ufw_v6="no" has_v6=0 v6_enabled=0
  np="$(_audit_node_port)"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qiE 'Status:\s*active'; then ufw_on=1; fi
  if [[ -f /etc/default/ufw ]]; then
    ufw_v6="$(sed -n 's/^IPV6=//p' /etc/default/ufw 2>/dev/null | tr -d '"' | head -1 || true)"
  fi
  if [[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" == "0" ]]; then v6_enabled=1; fi
  if [[ "$v6_enabled" -eq 1 ]] && ip -6 addr show scope global 2>/dev/null | grep -q inet6; then has_v6=1; fi
  _audit_ufw_public_sets

  local -a ssh_ports=() docker_pub=()
  mapfile -t ssh_ports < <(_audit_ssh_ports)
  if command -v docker >/dev/null 2>&1; then
    mapfile -t docker_pub < <(docker ps --format '{{.Ports}}' 2>/dev/null | tr ',' '\n' | grep -oE '(0\.0\.0\.0|\[?::\]?):[0-9]+' | grep -oE '[0-9]+$' | sort -nu || true)
  fi

  local line proto addr port fam proc lbl shown=0 issues=0
  local -A seen=()
  while IFS= read -r line; do
    proto="$(awk '{print $1}' <<<"$line")"
    addr="$(ss_local_addr "$line")"
    [[ -n "$addr" ]] || continue
    port="${addr##*:}"
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    ss_is_loopback_addr "$addr" && continue
    case "$addr" in \[fe80*|fe80*) continue ;; esac
    if [[ "$addr" == \[* ]]; then fam=6; elif [[ "$addr" == \*:* ]]; then fam=46; else fam=4; fi
    if [[ "$proto" == udp ]]; then
      case "$port" in 68|546|5353|323) continue ;; esac
      # ephemeral UDP "listeners" are mostly outbound sockets (xray UDP relay, DNS); show only known service ports
      if is_ephemeral_port "$port" && ! _audit_in_list "$port" "${DETECTED_CLIENT_UDP_PORTS[@]:-}" \
         && [[ -z "$(_audit_port_label "$port")" ]]; then continue; fi
    fi
    [[ -n "${seen[$proto/$port/$fam]:-}" ]] && continue
    seen[$proto/$port/$fam]=1
    proc="$(sed -n 's/.*users:(("\([^"]*\).*/\1/p' <<<"$line" | head -1 || true)"
    shown=$((shown+1))
    local famtxt="IPv4"
    [[ "$fam" == 6 ]] && famtxt="IPv6"
    [[ "$fam" == 46 ]] && famtxt="IPv4+IPv6"
    local tag="${port}/${proto} (${proc:-?}, ${famtxt})"
    # classify
    if [[ "$proto" == tcp ]] && _audit_in_list "$port" "${DETECTED_CLIENT_PORTS[@]:-}"; then
      _audit_ok "${tag} — клиентский порт"
      continue
    fi
    if [[ "$proto" == udp ]] && _audit_in_list "$port" "${DETECTED_CLIENT_UDP_PORTS[@]:-}"; then
      _audit_ok "${tag} — клиентский UDP-порт"
      continue
    fi
    if [[ "$proto" == tcp ]] && _audit_in_list "$port" "${ssh_ports[@]}"; then
      _audit_ok "${tag} — SSH"
      continue
    fi
    local pub4=0 pub6=0 via_docker=0
    if [[ "$ufw_on" -eq 0 ]]; then
      pub4=1; pub6=1
    else
      [[ "$AUDIT_UFW_PUB4" == *" ${port}/${proto} "* ]] && pub4=1
      [[ "$AUDIT_UFW_PUB6" == *" ${port}/${proto} "* ]] && pub6=1
      [[ "$ufw_v6" != "yes" ]] && pub6=1
    fi
    [[ "$fam" == 4 ]] && pub6=0
    [[ "$fam" == 6 ]] && pub4=0
    [[ "$has_v6" -eq 0 ]] && pub6=0
    _audit_in_list "$port" "${docker_pub[@]:-}" && via_docker=1
    lbl="$(_audit_port_label "$port")"
    if [[ "$port" == "$np" && "$proto" == tcp ]]; then
      if (( pub4 == 1 || pub6 == 1 )); then
        _audit_err "${tag} — NODE_PORT открыт всем ($( ((pub4)) && echo IPv4)$( ((pub6)) && echo ' IPv6')) — главный признак ноды! Пункт 1 закроет его (только IP панели)"
        issues=$((issues+1))
      elif (( via_docker == 1 )); then
        _audit_warn "${tag} — NODE_PORT опубликован Docker (обходит UFW); проверьте цепочку DOCKER-USER"
      else
        _audit_ok "${tag} — NODE_PORT, снаружи закрыт UFW (только панель)"
      fi
      continue
    fi
    if (( via_docker == 1 )); then
      _audit_warn "${tag} — Docker publish 0.0.0.0 обходит UFW, порт виден снаружи${lbl:+ (${lbl})}; привяжите к 127.0.0.1 в compose"
      issues=$((issues+1))
    elif (( pub4 == 1 || pub6 == 1 )); then
      _audit_warn "${tag} — открыт наружу ($( ((pub4)) && echo IPv4)$( ((pub6)) && echo ' IPv6'))${lbl:+ — ${lbl}}: лишний признак, закройте или привяжите к 127.0.0.1"
      issues=$((issues+1))
    else
      _audit_info "${tag} — слушает, но UFW его закрывает (снаружи не виден)${lbl:+ — ${lbl}}"
    fi
  done < <(ss -Hlntup 2>/dev/null || true)
  [[ "$shown" -eq 0 ]] && _audit_info "ss не вернул слушателей (нет прав root?)"
  [[ "$issues" -eq 0 ]] && _audit_ok "Лишних открытых наружу портов не найдено"

  # ---- IPv6 parity ----
  echo
  printf '%bIPv6 (сканеры всё чаще проверяют и v6):%b\n' "${C_BOLD}" "${C_RESET}"
  if [[ "$has_v6" -eq 0 ]]; then
    _audit_info "Глобального IPv6 нет (или IPv6 выключен) — v6-поверхности нет"
  elif [[ "$ufw_on" -eq 1 && "$ufw_v6" != "yes" ]]; then
    _audit_err "У сервера есть IPv6, но UFW IPV6=${ufw_v6:-?} — по IPv6 открыты ВСЕ порты (включая NODE_PORT). Пункт 1 включит IPV6=yes"
  elif [[ "$ufw_on" -eq 1 ]]; then
    _audit_ok "UFW управляет и IPv6 (IPV6=yes)"
    if [[ "$AUDIT_UFW_PUB6" == *" ${np}/tcp "* ]]; then
      _audit_err "NODE_PORT ${np} разрешён всем по IPv6 — пункт 1 уберёт это правило (если панель не ходит по IPv6)"
    fi
    if [[ -f /etc/ufw/before6.rules ]] && grep -qE '^-A ufw6-before-input -p icmpv6 --icmpv6-type echo-request -j ACCEPT' /etc/ufw/before6.rules 2>/dev/null; then
      _audit_warn "ping по IPv6 отвечает (before6.rules echo-request ACCEPT) — пункт 1 (hide_ports) закроет"
    else
      _audit_ok "ping по IPv6 скрыт"
    fi
  else
    if command -v ip6tables >/dev/null 2>&1 && ip6tables -S INPUT 2>/dev/null | head -1 | grep -qE -- '-P INPUT (DROP|REJECT)'; then
      _audit_ok "ip6tables INPUT policy DROP"
    else
      _audit_warn "IPv6 есть, а фаервол v6 не настроен — все слушатели доступны по IPv6"
    fi
  fi
  return 0
}

_audit_nodeport_external() {
  # Ground truth from the internet: NODE_PORT must NOT answer anyone except the panel.
  local pub_ip="$1" np
  np="$(_audit_node_port)"
  [[ -n "$pub_ip" && "$np" =~ ^[0-9]+$ ]] || return 0
  echo
  printf '%bNODE_PORT %s снаружи (check-host, не с IP панели):%b\n' "${C_BOLD}" "$np" "${C_RESET}"
  if [[ ${#AUDIT_RU_NODES[@]} -eq 0 && ${#AUDIT_FOREIGN_NODES[@]} -eq 0 ]]; then
    _audit_pick_checkhost_nodes || { _audit_warn "check-host недоступен — пропуск"; return 0; }
  fi
  local -a nodes=("${AUDIT_FOREIGN_NODES[@]}" "${AUDIT_RU_NODES[@]:0:2}")
  local rid body ro rt fo ft
  rid="$(_audit_checkhost_start tcp "${pub_ip}:${np}" "${nodes[@]}" 2>/dev/null || true)"
  if [[ -z "$rid" ]]; then
    _audit_warn "Не удалось запустить check-tcp (лимит API?) — пропуск"
    return 0
  fi
  body="$(_audit_checkhost_poll "$rid" "$(( $(date +%s) + 20 ))")"
  [[ -n "$body" ]] || { _audit_warn "Нет результата check-tcp"; return 0; }
  read -r ro rt fo ft < <(printf '%s' "$body" | _audit_summarize_tcp_result "${AUDIT_RU_NODES[@]:0:2}" -- "${AUDIT_FOREIGN_NODES[@]}")
  if (( ${ro:-0} + ${fo:-0} > 0 )); then
    _audit_err "NODE_PORT ${np} отвечает из интернета ($(( ro + fo ))/$(( rt + ft )) узлов) — любой сканер найдёт API ноды. Закройте: пункт 1"
  elif (( ${rt:-0} + ${ft:-0} > 0 )); then
    _audit_ok "NODE_PORT ${np} снаружи не отвечает (0/$(( rt + ft )) узлов) — API ноды скрыт"
  else
    _audit_warn "Недостаточно данных check-host по NODE_PORT"
  fi
  return 0
}

# ---- Active probing (like ТСПУ/GFW probers): node without REALITY auth vs real dest ----
_audit_tls_fp() {
  # _audit_tls_fp HOST PORT SNI [extra openssl args...] -> "OK|fp|subject|issuer|alpn|proto" or "ERR|reason"
  local host="$1" port="$2" sni="$3"
  shift 3
  local -a sn=()
  if [[ -n "$sni" ]]; then sn=(-servername "$sni"); else sn=(-noservername); fi
  local out ec=0 cert fp subj iss alpn proto
  out="$(timeout 7 openssl s_client -connect "${host}:${port}" "${sn[@]}" "$@" </dev/null 2>&1 | tr -d '\0')" || ec=$?
  if printf '%s' "$out" | grep -q 'BEGIN CERTIFICATE'; then
    cert="$(printf '%s\n' "$out" | openssl x509 -noout -fingerprint -sha256 -subject -issuer 2>/dev/null || true)"
    fp="$(grep -i 'fingerprint' <<<"$cert" | sed 's/.*=//' | tr -d ':' | cut -c1-16 || true)"
    subj="$(grep -i '^subject' <<<"$cert" | sed -E 's/^subject= ?//' | tr -d '\r' || true)"
    iss="$(grep -i '^issuer' <<<"$cert" | sed -E 's/^issuer= ?//' | tr -d '\r' || true)"
    alpn="$(printf '%s' "$out" | grep -iE '^ALPN protocol:|No ALPN negotiated' | head -1 | sed -E 's/ALPN protocol: *//;s/No ALPN negotiated/none/' | tr -d '\r' || true)"
    proto="$(printf '%s' "$out" | grep -oE 'TLSv1(\.[0-3])?' | head -1 || true)"
    printf 'OK|%s|%s|%s|%s|%s' "${fp:-?}" "${subj:-?}" "${iss:-?}" "${alpn:-none}" "${proto:-?}"
    return 0
  fi
  if [[ "$ec" -eq 124 ]]; then printf 'ERR|timeout'; return 0; fi
  if printf '%s' "$out" | grep -qiE 'reset by peer|errno=104'; then printf 'ERR|reset'; return 0; fi
  if printf '%s' "$out" | grep -qiE 'refused'; then printf 'ERR|refused'; return 0; fi
  local al
  al="$(printf '%s' "$out" | grep -oiE 'alert [a-z ]+' | head -1 || true)"
  if [[ -n "$al" ]]; then printf 'ERR|%s' "$al"; return 0; fi
  if printf '%s' "$out" | grep -qiE 'unexpected eof|write:errno|no peer certificate'; then printf 'ERR|eof'; return 0; fi
  printf 'ERR|fail'
  return 0
}

_audit_http_status() {
  # _audit_http_status URL [curl args...] -> "CODE server" or "ERR curlN"
  local url="$1"
  shift
  local hdr ec=0 code srv
  hdr="$(curl -sk -o /dev/null -D - --connect-timeout 5 -m 10 -A 'Mozilla/5.0' "$@" "$url" 2>/dev/null)" || ec=$?
  code="$(printf '%s' "$hdr" | grep -m1 -oE '^HTTP/[0-9.]+ [0-9]{3}' | awk '{print $2}' || true)"
  if [[ -z "$code" ]]; then
    case "$ec" in
      52) printf 'ERR empty' ;;
      56|35) printf 'ERR reset' ;;
      28) printf 'ERR timeout' ;;
      7) printf 'ERR refused' ;;
      *) printf 'ERR curl%s' "$ec" ;;
    esac
    return 0
  fi
  srv="$(printf '%s' "$hdr" | grep -i -m1 '^server:' | sed 's/^[Ss]erver: *//' | tr -d '\r' || true)"
  printf '%s %s' "$code" "${srv:--}"
  return 0
}

_audit_cmp_line() {
  # _audit_cmp_line LABEL NODE_RESULT DEST_RESULT SAME(0/1/2=inconclusive)
  if [[ "$4" -eq 2 ]]; then
    _audit_info "$1: одна из сторон не ответила вовремя — сравнение пропущено (нода «${2:0:40}», сайт «${3:0:40}»)"
  elif [[ "$4" -eq 1 ]]; then
    _audit_ok "$1: совпадает с настоящим сайтом (${2:0:70})"
  else
    _audit_warn "$1: нода «${2:0:60}» ≠ сайт «${3:0:60}»"
  fi
}

_audit_active_probe_reality() {
  # _audit_active_probe_reality PORT SNI DEST_HOST DEST_PORT
  local port="$1" sni="$2" dhost="$3" dport="${4:-443}"
  command -v openssl >/dev/null 2>&1 || { _audit_warn "openssl нет — активный зонд пропущен"; return 0; }
  [[ "$port" =~ ^[0-9]+$ ]] || return 0
  sni="${sni%%,*}"
  [[ "$sni" == "-" ]] && sni=""
  [[ "$dhost" == "-" ]] && dhost=""
  [[ -z "$dhost" ]] && dhost="$sni"
  [[ -z "$sni" ]] && sni="$dhost"
  if [[ -z "$sni" ]]; then
    _audit_warn "Нет SNI/dest для активного зонда порта ${port}"
    return 0
  fi
  case "$dhost" in
    /*|@*) _audit_info "dest — unix-сокет (${dhost}), selfsteal: сравнение с внешним сайтом не применимо"; return 0 ;;
  esac
  local tgt=""
  if timeout 3 bash -c "</dev/tcp/127.0.0.1/${port}" 2>/dev/null; then
    tgt="127.0.0.1"
  elif [[ -n "${AUDIT_PUB_IP:-}" ]] && timeout 3 bash -c "</dev/tcp/${AUDIT_PUB_IP}/${port}" 2>/dev/null; then
    tgt="$AUDIT_PUB_IP"
  else
    _audit_warn "Порт ${port} не принимает TCP локально — активный зонд пропущен"
    return 0
  fi
  echo
  printf '%bАктивный зонд порта %s без ключа REALITY (как это делает ТСПУ/сканер) vs %s:%s:%b\n' \
    "${C_BOLD}" "$port" "$dhost" "$dport" "${C_RESET}"
  case "$dhost" in
    127.*|localhost|::1) _audit_info "dest локальный (${dhost}) — selfsteal; домен ${sni} виден в Certificate Transparency (crt.sh), это нормально для selfsteal" ;;
  esac
  local mism=0 n d same rnd
  # 1) TLS with configured SNI
  n="$(_audit_tls_fp "$tgt" "$port" "$sni" -alpn h2,http/1.1)"
  d="$(_audit_tls_fp "$dhost" "$dport" "$sni" -alpn h2,http/1.1)"
  same=0
  if [[ "$n" == OK* && "$d" == OK* ]]; then
    local nf nsub nalpn df dsub dalpn _r niss
    IFS='|' read -r _r nf nsub niss nalpn _r <<<"$n"
    IFS='|' read -r _r df dsub _r dalpn _r <<<"$d"
    if [[ "$nf" == "$df" ]] || [[ "$nsub" == "$dsub" && "$nalpn" == "$dalpn" ]]; then same=1; fi
    _audit_cmp_line "TLS (SNI=${sni}) сертификат/ALPN" "${nsub} alpn=${nalpn}" "${dsub} alpn=${dalpn}" "$same"
    if [[ "$nsub" == "$niss" ]]; then
      _audit_warn "Сертификат на ноде самоподписанный (subject=issuer) — это видят все сканеры"
      mism=$((mism+1))
    fi
  else
    [[ "${n%%|*}" == "${d%%|*}" && "$n" == "$d" ]] && same=1
    _audit_cmp_line "TLS (SNI=${sni})" "$n" "$d" "$same"
  fi
  (( same == 0 )) && mism=$((mism+1))

  # 2) HTTPS request through node (unauthenticated -> must be proxied to dest)
  n="$(_audit_http_status "https://${sni}/" --connect-to "${sni}:443:${tgt}:${port}")"
  d="$(_audit_http_status "https://${sni}/" --connect-to "${sni}:443:${dhost}:${dport}")"
  same=0
  [[ "${n%% *}" == "${d%% *}" ]] && same=1
  [[ "$same" -eq 0 && ( "$n" == "ERR timeout" || "$d" == "ERR timeout" ) ]] && same=2
  _audit_cmp_line "HTTPS GET / (код + Server)" "$n" "$d" "$same"
  (( same == 0 )) && mism=$((mism+1))

  # 3) plain HTTP to the TLS port
  n="$(_audit_http_status "http://${tgt}:${port}/" -H "Host: ${sni}")"
  d="$(_audit_http_status "http://${dhost}:${dport}/" -H "Host: ${sni}")"
  same=0
  [[ "${n%% *}" == "${d%% *}" ]] && same=1
  [[ "$same" -eq 0 && ( "$n" == "ERR timeout" || "$d" == "ERR timeout" ) ]] && same=2
  _audit_cmp_line "Обычный HTTP на TLS-порт" "$n" "$d" "$same"
  (( same == 0 )) && mism=$((mism+1))

  # 4) random SNI
  rnd="$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 10).com"
  n="$(_audit_tls_fp "$tgt" "$port" "$rnd")"
  d="$(_audit_tls_fp "$dhost" "$dport" "$rnd")"
  same=0
  if [[ "$n" == OK* && "$d" == OK* ]]; then
    [[ "$(cut -d'|' -f3 <<<"$n")" == "$(cut -d'|' -f3 <<<"$d")" ]] && same=1
  elif [[ "$n" != OK* && "$d" != OK* ]]; then
    same=1
  fi
  _audit_cmp_line "Случайный SNI (${rnd})" "$(cut -d'|' -f1-3 <<<"$n")" "$(cut -d'|' -f1-3 <<<"$d")" "$same"
  (( same == 0 )) && mism=$((mism+1))

  # 5) TLS 1.2 only (Iran-style probes used TLS1.0–1.2)
  n="$(_audit_tls_fp "$tgt" "$port" "$sni" -tls1_2)"
  d="$(_audit_tls_fp "$dhost" "$dport" "$sni" -tls1_2)"
  same=0
  if [[ "$n" != OK* && "$d" != OK* ]]; then
    same=1
  elif [[ "$n" == OK* && "$d" == OK* && "$(cut -d'|' -f3 <<<"$n")" == "$(cut -d'|' -f3 <<<"$d")" ]]; then
    same=1
  fi
  _audit_cmp_line "Только TLS 1.2" "$(cut -d'|' -f1,3 <<<"$n")" "$(cut -d'|' -f1,3 <<<"$d")" "$same"
  (( same == 0 )) && mism=$((mism+1))

  if (( mism == 0 )); then
    _audit_ok "Активное зондирование: порт ${port} отвечает как настоящий ${dhost} — маскировка хорошая"
  else
    _audit_warn "Найдено расхождений: ${mism}. Небольшие отличия (разные edge-серверы CDN) бывают; стабильное расхождение = нода палится зондом"
    _audit_info "Что сделать в панели: REALITY на порту 443, dest = крупный зарубежный сайт с TLS1.3+h2 на том же ASN/рядом (проверьте RealiTLScanner), serverNames = домены этого dest, обновить xray ≥ 25.6.8"
  fi
  if [[ "$port" != "443" ]]; then
    _audit_warn "REALITY на порту ${port} — сайт ${sni} на нестандартном порту выглядит странно; лучше 443"
  fi
  return 0
}

_audit_xray_version() {
  local cname ver
  cname="$(_find_remnanode_container 2>/dev/null || true)"
  [[ -n "$cname" ]] || return 0
  ver="$(timeout 6 docker exec "$cname" xray version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  if [[ -z "$ver" ]]; then
    ver="$(timeout 6 docker exec "$cname" /usr/local/bin/xray version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  fi
  [[ -n "$ver" ]] || { _audit_info "Версию xray в контейнере ${cname} определить не удалось"; return 0; }
  if [[ "$(printf '%s\n%s\n' "25.6.8" "$ver" | sort -V | head -1)" == "25.6.8" ]]; then
    _audit_ok "xray ${ver} (≥ 25.6.8: есть защита от детекта REALITY по post-handshake/NewSessionTicket)"
  else
    _audit_warn "xray ${ver} < 25.6.8 — старый REALITY детектится по NewSessionTicket (Aparecium). Обновите образ remnanode в окне обслуживания"
  fi
  return 0
}

_audit_giveaways() {
  step "Мелкие признаки (баннеры, PTR, MTU, исходящий трафик)"
  local pub_ip="${AUDIT_PUB_IP:-}"
  # SSH banner as the internet sees it
  local p banner
  for p in $(_audit_ssh_ports); do
    banner="$(timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/${p}; head -1 <&3" 2>/dev/null | tr -d '\r' || true)"
    [[ -n "$banner" ]] || continue
    if grep -qiE 'ubuntu|debian|raspbian' <<<"$banner"; then
      _audit_warn "SSH-баннер :${p} «${banner}» выдаёт ОС/версию — меню 9 (DebianBanner no)"
    else
      _audit_ok "SSH-баннер :${p} «${banner}»"
    fi
    break
  done
  # PTR
  if [[ -n "$pub_ip" ]]; then
    local ptr=""
    if command -v python3 >/dev/null 2>&1; then
      ptr="$(timeout 6 python3 -c 'import socket,sys
try: print(socket.gethostbyaddr(sys.argv[1])[0])
except Exception: pass' "$pub_ip" 2>/dev/null || true)"
    else
      ptr="$(timeout 6 getent hosts "$pub_ip" 2>/dev/null | awk '{print $2; exit}' || true)"
    fi
    if [[ -z "$ptr" ]]; then
      _audit_info "PTR (обратный DNS) для ${pub_ip} не задан — допустимо; нейтральный PTR (как у обычного сайта) выглядит естественнее"
    elif grep -qiE 'vpn|proxy|xray|vless|reality|remna|v2ray|tunnel|wireguard|node|exit|relay' <<<"$ptr"; then
      _audit_err "PTR ${pub_ip} → ${ptr} — содержит VPN-слова. Смените PTR в панели хостера на нейтральный (например mail/web/имя сайта)"
    elif grep -qE '[0-9]+[-.][0-9]+[-.][0-9]+[-.][0-9]+' <<<"$ptr"; then
      _audit_info "PTR ${ptr} — дефолтный хостерский (норм; нейтральное имя домена выглядит лучше)"
    else
      _audit_ok "PTR ${pub_ip} → ${ptr}"
    fi
  fi
  # motd / issue words
  local f
  for f in /etc/motd /etc/issue /etc/issue.net; do
    [[ -s "$f" ]] || continue
    if grep -qiE 'vpn|xray|remna|vless|reality|v2ray|proxy|marzban' "$f" 2>/dev/null; then
      _audit_warn "${f} содержит VPN-слова — меню 9 очистит"
    fi
  done
  # HTTP Server headers on non-client web ports
  local wp res
  for wp in 80 8080 443 8443; do
    _audit_in_list "$wp" "${DETECTED_CLIENT_PORTS[@]:-}" && continue
    ss -Hltn "( sport = :${wp} )" 2>/dev/null | grep -q . || continue
    if [[ "$wp" == 443 || "$wp" == 8443 ]]; then
      res="$(_audit_http_status "https://127.0.0.1:${wp}/")"
    else
      res="$(_audit_http_status "http://127.0.0.1:${wp}/")"
    fi
    if grep -qE '/[0-9]' <<<"${res#* }"; then
      _audit_warn "HTTP :${wp} Server «${res#* }» — версия видна (server_tokens off / меню 9)"
    elif grep -qiE 'caddy|xray|v2ray' <<<"${res#* }"; then
      _audit_info "HTTP :${wp} Server «${res#* }»"
    else
      _audit_ok "HTTP :${wp} ответ «${res}»"
    fi
  done
  # MTU / MSS
  local iface mtu
  iface="$(ip -o route show default 2>/dev/null | awk '{print $5; exit}' || true)"
  if [[ -n "$iface" ]]; then
    mtu="$(cat "/sys/class/net/${iface}/mtu" 2>/dev/null || true)"
    if [[ "$mtu" == 1500 || -z "$mtu" ]]; then
      _audit_ok "MTU ${iface}=${mtu:-?} (MSS 1460 — обычный сервер)"
    else
      _audit_info "MTU ${iface}=${mtu} → MSS $((mtu-40)) — нестандартный MSS заметен для пассивного TCP-отпечатка (JA4T); у некоторых облаков это норма, менять не нужно"
    fi
  fi
  if command -v iptables >/dev/null 2>&1 && iptables -t mangle -S 2>/dev/null | grep -q 'TCPMSS'; then
    _audit_info "Есть правила TCPMSS в mangle — MSS клиентам отличается от обычного сервера: $(iptables -t mangle -S 2>/dev/null | grep -m1 TCPMSS)"
  fi
  _audit_info "tcp_timestamps=$(sysctl -n net.ipv4.tcp_timestamps 2>/dev/null || echo '?') (оставляем как у обычного Linux; отключение само по себе выделяет сервер)"
  # Egress guard
  if command -v iptables >/dev/null 2>&1 && iptables -S GORECSHIT-EGRESS 2>/dev/null | grep -q -- '--dport 25'; then
    _audit_ok "Исходящий SMTP 25 заблокирован (спам с ноды → abuse хостеру невозможен)"
  else
    _audit_warn "Исходящий SMTP 25 не закрыт — через ноду можно слать спам → abuse-жалоба хостеру с вашим IP. Пункт 1 (egress_guard)"
  fi
  if command -v iptables >/dev/null 2>&1 && iptables -S GORECSHIT-EGRESS 2>/dev/null | grep -q 'port-unreachable'; then
    _audit_ok "Исходящие ICMP port-unreachable/time-exceeded режутся (закрытые UDP-порты не отвечают)"
  else
    _audit_info "Исходящие ICMP unreachable не режутся (UFW DROP уже скрывает большинство; пункт 1 добавит)"
  fi
  return 0
}

# ---------- v2.7.0: IP reputation / VPN-detection self-check (read-only, no API keys) ----------
_json_field() {
  # _json_field JSON dotted.path → prints value (python3; empty if absent)
  command -v python3 >/dev/null 2>&1 || return 0
  python3 -c '
import json,sys
try:
    d=json.loads(sys.argv[1])
    for k in sys.argv[2].split("."):
        d=d[k]
    print(d if not isinstance(d,bool) else ("true" if d else "false"))
except Exception:
    pass' "$1" "$2" 2>/dev/null || true
}

_ip_rev() { awk -F. '{print $4"."$3"."$2"."$1}' <<<"$1"; }

_audit_ip_reputation() {
  local ip="$1" rev z res listed=0
  [[ -n "$ip" ]] || return 0
  step "Репутация IP ${ip}: DNSBL, списки атакующих, базы «VPN/прокси» (read-only)"
  rev="$(_ip_rev "$ip")"
  # sanity: 1.0.0.127.<zone> must NOT resolve; if it does, the resolver rewrites answers (fake-DNS / NXDOMAIN hijack)
  local wild
  wild="$(timeout 6 getent ahostsv4 "1.0.0.127.zen.spamhaus.org" 2>/dev/null | awk '{print $1}' | head -1 || true)"
  if [[ -n "$wild" && ! "$wild" =~ ^127\. ]]; then
    _audit_warn "DNSBL пропущены: резолвер подменяет ответы (${wild}) — результат был бы ложным"
  else
  for z in zen.spamhaus.org bl.spamcop.net b.barracudacentral.org dnsbl-1.uceprotect.net psbl.surriel.com bl.blocklist.de all.s5h.net dnsbl.dronebl.org; do
    res="$(timeout 6 getent ahostsv4 "${rev}.${z}" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd, - || true)"
    if [[ -z "$res" ]]; then
      _audit_ok "${z}: чисто"
    elif [[ "$res" =~ 127\.255\.255\. ]]; then
      _audit_info "${z}: ответ ${res} — список не отвечает публичным резолверам (1.1.1.1/8.8.8.8); проверьте вручную: https://check.spamhaus.org/ / https://mxtoolbox.com/blacklists.aspx"
    elif [[ ! "$res" =~ ^127\. ]]; then
      _audit_info "${z}: нестандартный ответ ${res} — пропущено"
    else
      listed=$((listed+1))
      _audit_err "${z}: В СПИСКЕ (${res}) — хостеры и почтовики видят IP как «грязный»"
    fi
  done
  fi
  # attackers feeds
  local bd
  bd="$(curl -fsS --connect-timeout 5 --max-time 10 "https://api.blocklist.de/api.php?ip=${ip}" 2>/dev/null | tr -d '\r' | tr '\n' ' ' || true)"
  if [[ "$bd" =~ attacks:[[:space:]]*([0-9]+) ]] && [[ "${BASH_REMATCH[1]}" -gt 0 ]]; then
    listed=$((listed+1)); _audit_err "blocklist.de: ${BASH_REMATCH[1]} атак с этого IP (абуз-репорты хостеру!)"
  elif [[ -n "$bd" ]]; then
    _audit_ok "blocklist.de: атак не зафиксировано"
  fi
  local ips
  ips="$(curl -fsS --connect-timeout 5 --max-time 20 https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt 2>/dev/null \
        | awk -v ip="$ip" '$1==ip{print $2}' || true)"
  if [[ -n "$ips" ]]; then
    listed=$((listed+1)); _audit_err "IPsum: IP в ${ips} чёрных списках атакующих"
  else
    _audit_ok "IPsum (агрегатор ~30 списков атакующих): не найден"
  fi
  # VPN/proxy detection DBs (used by банки/маркетплейсы/стриминги и «методички» по выявлению VPN)
  local pc pi
  pc="$(_audit_http_get "https://proxycheck.io/v2/${ip}?vpn=1&asn=1" 12)"
  if [[ -n "$pc" ]]; then
    local pxy typ prov
    pxy="$(_json_field "$pc" "${ip}.proxy")"; typ="$(_json_field "$pc" "${ip}.type")"; prov="$(_json_field "$pc" "${ip}.provider")"
    if [[ "$pxy" == "yes" ]]; then
      _audit_warn "proxycheck.io: помечен как ${typ:-proxy} (провайдер: ${prov:-?}) — сервисы видят VPN"
    elif [[ -n "$pxy" ]]; then
      _audit_ok "proxycheck.io: не VPN/proxy (тип: ${typ:-?}, ${prov:-?})"
    fi
  fi
  pi="$(_audit_http_get "https://api.ipapi.is/?q=${ip}" 12)"
  if [[ -n "$pi" ]]; then
    local vpn dc ab org
    vpn="$(_json_field "$pi" is_vpn)"; dc="$(_json_field "$pi" is_datacenter)"; ab="$(_json_field "$pi" is_abuser)"; org="$(_json_field "$pi" asn.org)"
    [[ "$vpn" == "true" ]] && _audit_warn "ipapi.is: is_vpn=true (${org:-?}) — IP уже в VPN-базах"
    [[ "$vpn" == "false" ]] && _audit_ok "ipapi.is: is_vpn=false"
    [[ "$ab" == "true" ]] && { listed=$((listed+1)); _audit_err "ipapi.is: is_abuser=true — с IP шёл абуз"; }
    [[ "$dc" == "true" ]] && _audit_info "ipapi.is: датацентр (${org:-?}) — для ТСПУ «подозрительная подсеть» определяется по ASN, это не исправить скриптом"
  fi
  _audit_info "AbuseIPDB (без ключа не проверить автоматически): https://www.abuseipdb.com/check/${ip}"
  if [[ "$listed" -gt 0 ]]; then
    _audit_err "Итог: IP в ${listed} списках. Смотрите gorecshit --abuse-report (что делали клиенты), чистите причину, пишите делист."
  else
    _audit_ok "Итог: в проверенных чёрных списках IP не найден"
  fi
  return 0
}

run_ip_check() {
  local ip=""
  if ! ip="$(_audit_detect_public_ipv4)"; then
    err "Не удалось определить публичный IPv4 (нет интернета/DNS?)"
    return 0
  fi
  _audit_ip_reputation "$ip"
  echo
  _audit_info "Блокировку из РФ (ТСПУ/белые списки) проверяет пункт 8 (--audit, check-host из РФ)."
  return 0
}

# ---------- v2.7.0: abuse report — what clients tried through this node (read-only) ----------
_ipt_hits() {
  # _ipt_hits IPT CHAIN → packets hitting verdict rules (excludes LOG lines)
  "$1" -nvxL "$2" 2>/dev/null | awk 'NR>2 && $3!="LOG"{s+=$1} END{print s+0}'
}

run_abuse_report() {
  step "Что клиенты пытались делать через ноду (с момента загрузки правил; read-only)"
  if ! iptables -nL GS-NETGUARD >/dev/null 2>&1; then
    warn "Netguard не установлен — пункт 1 (или --modules netguard) включит учёт и защиту"
  fi
  local smtp=0
  smtp="$(iptables -nvxL GORECSHIT-EGRESS 2>/dev/null | awk '$3=="REJECT" && /dpt:(25|465|587)/{s+=$1} END{print s+0}')"
  local p2p abuse smb priv snitch
  p2p=$(( $(_ipt_hits iptables GS-HIT-P2P) + $(_ipt_hits ip6tables GS-HIT-P2P) ))
  abuse=$(( $(_ipt_hits iptables GS-HIT-ABUSE) + $(_ipt_hits ip6tables GS-HIT-ABUSE) ))
  smb=$(( $(_ipt_hits iptables GS-HIT-SMB) + $(_ipt_hits ip6tables GS-HIT-SMB) ))
  priv="$(_ipt_hits iptables GS-HIT-PRIV)"
  snitch=$(( $(_ipt_hits iptables GS-HIT-SNITCH) + $(_ipt_hits ip6tables GS-HIT-SNITCH) ))
  printf '  %-44s %s\n' "Торренты (DHT/handshake/трекеры) — DROP:" "$p2p" \
    "Сканы/брутфорс SSH/RDP/БД — REJECT:" "$abuse" "SMB/NetBIOS наружу — REJECT:" "$smb" \
    "Доступ в LAN хостера (10/172/192/100.64):" "$priv" "VK/MAX/mail.ru («стукачи») — REJECT:" "$snitch" \
    "Исходящий SMTP (спам) — REJECT:" "$smtp"
  echo
  if command -v journalctl >/dev/null 2>&1; then
    local pref
    for pref in GS-P2P GS-ABUSE GS-SMB GS-PRIV GS-SNITCH; do
      local lines
      lines="$(journalctl -k --since '-24h' --no-pager 2>/dev/null | grep -F "[${pref}]" || true)"
      [[ -n "$lines" ]] || continue
      echo "  ${pref}: $(grep -c . <<<"$lines") записей за 24ч (лог ограничен 6/мин). Топ направлений:"
      grep -oE 'DST=[^ ]+ .*DPT=[0-9]+' <<<"$lines" | awk '{d=$1; for(i=1;i<=NF;i++) if($i ~ /^DPT=/) p=$i; print d" "p}' \
        | sed 's/DST=//; s/DPT=/:/; s/ //' | sort | uniq -c | sort -rn | head -5 | sed 's/^/      /'
    done
  fi
  # Map to Remnawave users when xray access log is available (best effort, nothing is changed)
  local c logsrc=""
  c="$(_find_remnanode_container 2>/dev/null || true)"
  if [[ -n "$c" ]]; then
    logsrc="$(docker logs --since 24h "$c" 2>&1 | grep -E 'accepted (tcp|udp):' | tail -n 200000 || true)"
  fi
  local f
  for f in /var/log/remnanode/access.log /var/log/xray/access.log; do
    [[ -r "$f" ]] && logsrc+=$'\n'"$(tail -n 200000 "$f" 2>/dev/null)"
  done
  if [[ -n "${logsrc//[[:space:]]/}" ]] && command -v journalctl >/dev/null 2>&1; then
    local dsts
    dsts="$(journalctl -k --since '-24h' --no-pager 2>/dev/null | grep -E '\[GS-(P2P|ABUSE|SMB|PRIV)\]' \
           | grep -oE 'DST=[0-9.]+' | cut -d= -f2 | sort | uniq -c | sort -rn | head -5 | awk '{print $2}' || true)"
    if [[ -n "$dsts" ]]; then
      echo
      echo "  Кто из пользователей ходил на эти адреса (access-лог xray):"
      local d
      while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        local who
        who="$(grep -F ":${d}:" <<<"$logsrc" | grep -oE 'email: *[^ ]+' | sort | uniq -c | sort -rn | head -3 | tr -s ' ' | paste -sd';' - || true)"
        printf '      %-16s %s\n' "$d" "${who:-нет в логе}"
      done <<<"$dsts"
    fi
  else
    _audit_info "Access-лог xray недоступен — сопоставить с пользователями нельзя (включите access log в профиле панели при расследовании)."
  fi
  echo
  _audit_info "Торренты гасятся и тут, и правилом xray (рекомендуется в профиле: protocol bittorrent → block + Torrent Blocker в панели)."
  return 0
}

_audit_antiban_advice() {
  step "Анти-бан: что сдаёт IP ноды и что уже закрыто"
  if iptables -nL GS-NETGUARD >/dev/null 2>&1; then
    _audit_ok "Netguard активен (торренты/сканы/SMB/LAN/VK-MAX — см. gorecshit --abuse-report)"
  else
    _audit_warn "Netguard не активен — торренты/сканы клиентов = абузы хостеру, MAX/VK видят IP ноды"
  fi
  if iptables -nL GS-HIT-SNITCH >/dev/null 2>&1; then
    _audit_ok "VK/MAX/mail.ru через ноду закрыты (MAX HOST_REACHABILITY не отправит IP ноды)"
  else
    _audit_warn "VK/MAX через ноду открыты: MAX/VK-приложения у клиентов с полным туннелем сообщают IP ноды"
  fi
  if ipset list -n gorecshit-rep >/dev/null 2>&1; then
    _audit_ok "Репутационные списки — только на SSH (мобильные CGNAT-адреса клиентов не режутся)"
  fi
  local json
  json="$(collect_xray_config_json 2>/dev/null || true)"
  if [[ -n "$json" ]] && grep -q '"routing"' <<<"$json"; then
    grep -q '"bittorrent"' <<<"$json" && _audit_ok "xray routing: bittorrent → блок есть" \
      || _audit_warn "xray routing: нет правила protocol bittorrent → block (профиль в панели)"
    grep -q 'geoip:private' <<<"$json" && _audit_ok "xray routing: geoip:private есть" \
      || _audit_warn "xray routing: нет geoip:private → block (клиенты видят LAN хостера/метаданные)"
    grep -qE 'oneme\.ru|max\.ru' <<<"$json" && _audit_ok "xray routing: домены MAX блокируются" \
      || _audit_info "xray routing: добавьте domain:oneme.ru, domain:max.ru, full:ip.mail.ru → block (дублирует netguard по доменам)"
  fi
  _audit_info "Клиенты (Happ/подписка): РФ-сайты и приложения — НАПРЯМУЮ (geoip:ru, geosite:category-ru → direct), иначе банки/маркетплейсы/MAX видят IP ноды"
  _audit_info "Отпечаток клиента: firefox (chrome/safari/ios в июне 2026 считались подозрительными); меньше параллельных TLS (mux/xmux), >3 за ~100 мс → заморозка"
  _audit_info "Не публикуйте ссылки-подписки и IP нод; одна утечка конфига = IP в списке"
}

run_node_audit() {
  step "Проверка на блокировку и палевность ноды (read-only)"
  echo "Ничего не меняем: без правок firewall/sysctl/docker, без влияния на скорость клиентов."
  menu_sep

  local pub_ip=""
  if ! pub_ip="$(_audit_detect_public_ipv4)"; then
    _audit_err "Не удалось определить публичный IPv4 — внешнюю проверку пропускаем"
    pub_ip=""
  fi

  _audit_ensure_client_ports
  local -a ports=()
  if [[ ${#DETECTED_CLIENT_PORTS[@]} -gt 0 ]]; then
    ports=("${DETECTED_CLIENT_PORTS[@]}")
  fi

  AUDIT_PUB_IP="$pub_ip"
  if [[ -n "$pub_ip" ]]; then
    _audit_reachability_from_russia "$pub_ip" "${ports[@]}"
  fi

  # What the internet already knows about this IP (Shodan InternetDB, no key)
  step "Что о сервере уже знает интернет (Shodan InternetDB)"
  local pub_ip6=""
  if [[ -n "$pub_ip" ]]; then _audit_internetdb "$pub_ip"; fi
  if pub_ip6="$(_audit_detect_public_ipv6)"; then _audit_internetdb "$pub_ip6"; fi
  [[ -z "$pub_ip" && -z "$pub_ip6" ]] && _audit_warn "Публичный IP не определён — пропуск"

  echo
  _audit_exposure_listeners
  if [[ -n "$pub_ip" ]]; then _audit_nodeport_external "$pub_ip"; fi

  echo
  _audit_xray_self
  _audit_xray_version
  echo
  _audit_server_level
  echo
  _audit_giveaways
  echo
  if [[ -n "$pub_ip" ]]; then _audit_ip_reputation "$pub_ip"; fi
  echo
  _audit_antiban_advice

  echo
  menu_sep
  ok "Аудит завершён (read-only). Рекомендации выше — применяйте вручную / пунктом установки защиты."
  echo "Полная карта способов вычислить ноду и что закрывает gorecshit: docs/detection-vectors.md (GitHub)"
  echo "Повтор: gorecshit --audit   |   пункт меню «Проверка на блокировку и палевность ноды»"
}

_cli_script_looks_valid() {
  # $1 = path; require shebang+bash and bash -n
  local f="$1" first
  [[ -n "$f" && -r "$f" ]] || return 1
  first="$(head -1 "$f" 2>/dev/null || true)"
  [[ "$first" == "#!"*bash* || "$first" == "#!/usr/bin/env bash" || "$first" == "#!/bin/bash" ]] || return 1
  # reject old symlink stub
  if [[ "$(wc -c <"$f" 2>/dev/null || echo 0)" -lt 200 ]]; then
    return 1
  fi
  bash -n "$f" 2>/dev/null || return 1
  return 0
}

_http_get_to() {
  # _http_get_to URL OUT — curl/wget; return 0 on HTTP success
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 8 --max-time 60 \
      -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' \
      -A 'gorecshit-updater' \
      "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 60 --no-cache -U 'gorecshit-updater' -O "$out" "$url"
  else
    return 1
  fi
}

_http_get_body() {
  # stdout body; empty on failure
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 8 --max-time 20 \
      -H 'Accept: application/vnd.github+json' -A 'gorecshit-updater' "$url" 2>/dev/null || true
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 20 -U 'gorecshit-updater' -O - "$url" 2>/dev/null || true
  fi
}

github_main_sha() {
  # Resolve tip of main via GitHub API (no jq). Prints 40-hex SHA or empty.
  local body sha
  body="$(_http_get_body 'https://api.github.com/repos/gorecvpn/gorecshit/commits/main')"
  [[ -n "$body" ]] || return 1
  sha="$(printf '%s' "$body" | grep -oE '"sha"[[:space:]]*:[[:space:]]*"[0-9a-f]{40}"' | head -1 | grep -oE '[0-9a-f]{40}' || true)"
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || return 1
  printf '%s\n' "$sha"
}

_latest_script_urls() {
  # Prints candidate URLs (newest-first): raw/<sha>, jsDelivr@sha, raw main?cachebust, @main mirrors
  local sha="${1:-}" bust
  bust="$(date +%s 2>/dev/null || echo 0)"
  if [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "https://raw.githubusercontent.com/gorecvpn/gorecshit/${sha}/install.sh"
    echo "https://cdn.jsdelivr.net/gh/gorecvpn/gorecshit@${sha}/install.sh"
    echo "https://fastly.jsdelivr.net/gh/gorecvpn/gorecshit@${sha}/install.sh"
    echo "https://raw.githubusercontent.com/gorecvpn/gorecshit/${sha}/gorecshit.sh"
    echo "https://cdn.jsdelivr.net/gh/gorecvpn/gorecshit@${sha}/gorecshit.sh"
    echo "https://fastly.jsdelivr.net/gh/gorecvpn/gorecshit@${sha}/gorecshit.sh"
  fi
  echo "https://raw.githubusercontent.com/gorecvpn/gorecshit/main/install.sh?t=${bust}"
  echo "https://raw.githubusercontent.com/gorecvpn/gorecshit/main/gorecshit.sh?t=${bust}"
  echo "https://cdn.jsdelivr.net/gh/gorecvpn/gorecshit@main/install.sh"
  echo "https://fastly.jsdelivr.net/gh/gorecvpn/gorecshit@main/install.sh"
  echo "https://cdn.jsdelivr.net/gh/gorecvpn/gorecshit@main/gorecshit.sh"
  echo "https://fastly.jsdelivr.net/gh/gorecvpn/gorecshit@main/gorecshit.sh"
}

_cli_download_full_script_to() {
  # Download full install.sh into $1 (tmp path). Sets global _CLI_DL_URL on success
  local out="$1" u sha=""
  _CLI_DL_URL=""
  sha="$(github_main_sha 2>/dev/null || true)"
  while IFS= read -r u; do
    [[ -n "$u" ]] || continue
    rm -f "$out"
    if _http_get_to "$u" "$out" 2>/dev/null && _cli_script_looks_valid "$out"; then
      _CLI_DL_URL="$u"
      return 0
    fi
    rm -f "$out"
  done < <(_latest_script_urls "$sha")
  return 1
}

install_cli_command() {
  # Install/refresh /usr/local/sbin/gorecshit (FULL script body) + /usr/local/bin/gorecshit symlink.
  # Works for: /path/script, bash <(curl …), curl | bash. Does NOT re-apply hardening.
  if [[ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]]; then
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b install CLI -> /usr/local/sbin/gorecshit (+ /usr/local/bin/gorecshit)\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi
  local raw src dest link tmp how="file"
  raw="${BASH_SOURCE[0]:-$0}"
  dest="/usr/local/sbin/gorecshit"
  link="/usr/local/bin/gorecshit"
  mkdir -p /usr/local/sbin /usr/local/bin
  tmp="$(mktemp /usr/local/sbin/gorecshit.XXXXXX)"

  # Classify source: regular on-disk file vs process-substitution / pipe fd
  src=""
  if [[ -n "$raw" && "$raw" != "-" && "$raw" != "/dev/stdin" && "$raw" != "stdin" \
        && "$raw" != /dev/fd/* && "$raw" != /proc/self/fd/* && "$raw" != /proc/*/fd/* ]]; then
    # On-disk path — resolve symlinks only for real files
    if [[ -f "$raw" ]]; then
      src="$raw"
      if command -v readlink >/dev/null 2>&1; then
        src="$(readlink -f "$raw" 2>/dev/null || echo "$raw")"
      fi
    fi
  fi

  if [[ -n "$src" && -f "$src" ]] && _cli_script_looks_valid "$src"; then
    cp -f "$src" "$tmp"
    how="file:$src"
  else
    # Prefer early process-substitution snapshot (taken at script start)
    if [[ -n "${_GORECSHIT_SELF_SNAPSHOT:-}" && -f "${_GORECSHIT_SELF_SNAPSHOT}" ]] \
        && _cli_script_looks_valid "${_GORECSHIT_SELF_SNAPSHOT}"; then
      cp -f "${_GORECSHIT_SELF_SNAPSHOT}" "$tmp"
      how="snapshot:${_GORECSHIT_SELF_SNAPSHOT}"
    else
      # Try copying from BASH_SOURCE only if seekable regular file (never read a pipe — would break running script)
      local fd_src="$raw"
      if [[ -n "$fd_src" && "$fd_src" != "-" && -f "$fd_src" && -r "$fd_src" ]] \
          && [[ "$fd_src" == /dev/fd/* || "$fd_src" == /proc/self/fd/* ]]; then
        if cp -f "$fd_src" "$tmp" 2>/dev/null && _cli_script_looks_valid "$tmp"; then
          how="fd:$fd_src"
        else
          : >"$tmp"
        fi
      fi
    fi
    if ! _cli_script_looks_valid "$tmp"; then
      log "Источник не файл на диске (BASH_SOURCE=${raw:-?}) — скачиваю полный скрипт для установки команды"
      if _cli_download_full_script_to "$tmp"; then
        how="download:${_CLI_DL_URL}"
      else
        rm -f "$tmp"
        warn "Не удалось установить команду gorecshit (нет локального файла и не скачалось с GitHub/jsDelivr). BASH_SOURCE=${raw:-?}"
        return 0
      fi
    fi
  fi

  chmod 755 "$tmp"
  mv -f "$tmp" "$dest"
  chmod 755 "$dest"
  ln -sfn "$dest" "$link"
  hash -r 2>/dev/null || true
  ok "Команда gorecshit установлена ($dest → v${VERSION}; symlink $link; via ${how})"
}

self_update_from_github() {
  step "Обновление gorecshit с GitHub"
  if [[ "$(id -u)" -ne 0 ]]; then
    err "Обновление требует root"; exit 1
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b curl GitHub API SHA → raw/<sha>/install.sh → /usr/local/sbin/gorecshit\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi
  local oldv="$VERSION" newv="" sha="" u ok_url=""
  local tmp dest="/usr/local/sbin/gorecshit" link="/usr/local/bin/gorecshit"
  tmp="$(mktemp /tmp/gorecshit-update.XXXXXX)"

  sha="$(github_main_sha 2>/dev/null || true)"
  if [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then
    log "Последний commit main: ${sha:0:12}…"
  else
    warn "Не удалось получить SHA с api.github.com — fallback raw/main + cache-buster / jsDelivr"
    sha=""
  fi

  while IFS= read -r u; do
    [[ -n "$u" ]] || continue
    log "Пробую: $u"
    rm -f "$tmp"
    if _http_get_to "$u" "$tmp" 2>/dev/null; then
      if head -1 "$tmp" | grep -qE '^#!.*bash' && bash -n "$tmp" 2>/tmp/gorecshit-bashn.err; then
        ok_url="$u"
        break
      fi
    fi
  done < <(_latest_script_urls "$sha")

  if [[ -z "$ok_url" ]]; then
    rm -f "$tmp"
    err "Не удалось скачать install.sh (GitHub API/raw и jsDelivr недоступны). Скопируйте файл вручную."
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

  newv="$(grep -E '^VERSION=' "$tmp" | head -1 | cut -d= -f2 | tr -d '"')"
  newv="${newv:-?}"

  mkdir -p /usr/local/sbin /usr/local/bin
  chmod 755 "$tmp"
  mv -f "$tmp" "$dest"
  chmod 755 "$dest"
  ln -sfn "$dest" "$link"
  hash -r 2>/dev/null || true

  if [[ "$newv" == "$oldv" ]]; then
    ok "Уже последняя версия (${oldv}) ← $ok_url"
  else
    ok "Обновлено: ${oldv} → ${newv} ← $ok_url"
  fi
  ok "Команда gorecshit установлена ($dest → v${newv}; symlink $link)"
  ok "Запуск: gorecshit   |   gorecshit --status   |   gorecshit --update   |   gorecshit --version"
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
    printf '  %b8)%b 🛡️  Проверка на блокировку и палевность ноды\n' "${C_BOLD}" "${C_RESET}"
    printf '  %b9)%b 🕵️  Скрыть отпечатки сервера\n' "${C_BOLD}" "${C_RESET}"
    printf '  %b10)%b 🧾 IP в чёрных списках / VPN-базах?\n' "${C_BOLD}" "${C_RESET}"
    printf '  %b11)%b 🚨 Что делали клиенты (торренты/сканы/спам/«стукачи»)\n' "${C_BOLD}" "${C_RESET}"
    menu_sep
    printf '  %b0)%b 🚪 Выход\n' "${C_BOLD}" "${C_RESET}"
    printf '%bCLI: gorecshit [--status|--update|--audit|--stealth|--ip-check|--abuse-report|--yes|--modules …]%b\n' "${C_GREY}" "${C_RESET}"
    if [[ -w /dev/tty ]]; then
      printf '%bВыберите пункт [0-11]:%b ' "${C_BOLD}" "${C_RESET}" > /dev/tty
    else
      printf '%bВыберите пункт [0-11]:%b ' "${C_BOLD}" "${C_RESET}"
    fi
    read_user_input choice
    case "$choice" in
      1)
        apply_modules_csv "all"
        prompt_panel_ip
        FROM_MENU=1
        ASSUME_YES=1   # skip "Продолжить?"; does NOT imply CLI --yes
        return 0
        ;;
      2)
        interactive_select_modules
        prompt_panel_ip
        FROM_MENU=1
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
        # re-exec NEW script into menu (fresh VERSION / status line)
        if [[ -x /usr/local/sbin/gorecshit ]]; then
          exec /usr/local/sbin/gorecshit
        elif command -v gorecshit >/dev/null 2>&1; then
          exec gorecshit
        fi
        warn "Обновление записано, но re-exec не удался — перезапустите: gorecshit"
        ;;
      8)
        run_node_audit
        ;;
      9)
        DO_FINGERPRINT_ONLY=1
        return 0
        ;;
      10)
        run_ip_check
        ;;
      11)
        run_abuse_report
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
  echo "  11 egress_guard (исходящий SMTP)  12 decoy_web (:80 → https, опц.)"
  echo "  13 netguard (торренты/сканы/брутфорс/LAN хостера/VK-MAX «стукачи»)"
  echo "  (или: minimum — UFW+SSH+fail2ban+blocklist+BBR)"
  local ans
  prompt_user 'Номера: ' ans
  if [[ -z "$ans" ]]; then
    selected="all"
  elif [[ "$ans" == "minimum" || "$ans" == "min" ]]; then
    selected="minimum"
  else
    local map=( "" ufw blocklist hide_ports anti_probe ssh stealth fail2ban sysctl hostname docker egress_guard decoy_web netguard )
    local n parts=()
    local IFS=,
    for n in $ans; do
      n="$(echo "$n" | tr -d ' ')"
      [[ "$n" =~ ^[0-9]+$ && "$n" -ge 1 && "$n" -le 13 ]] && parts+=("${map[$n]}")
    done
    local IFS=,
    selected="${parts[*]}"
  fi
  apply_modules_csv "${selected:-all}"
  log "Выбраны модули: ufw=$DO_UFW blocklist=$DO_BLOCKLIST hide=$DO_HIDE_PORTS probe=$DO_ANTI_PROBE ssh=$DO_SSH stealth=$DO_STEALTH f2b=$DO_FAIL2BAN sysctl=$DO_SYSCTL host=$DO_HOSTNAME docker=$DO_DOCKER_JOURNAL egress=$DO_EGRESS_GUARD netguard=$DO_NETGUARD decoy=$DO_DECOY_WEB"
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

# --- client port detection (inbounds over ephemeral ss noise) ---
EPHEMERAL_LO=32768
EPHEMERAL_HI=60999

load_ephemeral_port_range() {
  EPHEMERAL_LO=32768
  EPHEMERAL_HI=60999
  if [[ -r /proc/sys/net/ipv4/ip_local_port_range ]]; then
    read -r EPHEMERAL_LO EPHEMERAL_HI < /proc/sys/net/ipv4/ip_local_port_range || true
  fi
  [[ "$EPHEMERAL_LO" =~ ^[0-9]+$ ]] || EPHEMERAL_LO=32768
  [[ "$EPHEMERAL_HI" =~ ^[0-9]+$ ]] || EPHEMERAL_HI=60999
}

is_ephemeral_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p >= EPHEMERAL_LO && p <= EPHEMERAL_HI ))
}

is_excluded_service_port() {
  local p="$1" node="${2:-}"
  case "$p" in
    22|53|68|323|2222|3000|4430|62789) return 0 ;;
  esac
  [[ -n "$node" && "$p" == "$node" ]] && return 0
  [[ -n "${SSH_PORT_NEW:-}" && "$p" == "$SSH_PORT_NEW" ]] && return 0
  return 1
}

parse_inbound_ports_from_json() {
  # JSON on stdin -> lines "tcp PORT" / "udp PORT"
  python3 -c '
import json, sys, re

def add_port(bucket, p):
    if p is None or isinstance(p, bool):
        return
    if isinstance(p, int):
        if 1 <= p <= 65535:
            bucket.append(p)
        return
    s = str(p).strip()
    if not s:
        return
    for part in re.split(r"[,\s]+", s):
        if not part:
            continue
        if "-" in part and not part.startswith("-"):
            a, b = part.split("-", 1)
            if a.isdigit() and b.isdigit():
                lo, hi = int(a), int(b)
                if 0 < lo <= hi <= 65535 and hi - lo <= 64:
                    bucket.extend(range(lo, hi + 1))
            continue
        if part.isdigit():
            x = int(part)
            if 1 <= x <= 65535:
                bucket.append(x)

def network_of(ib):
    ss = ib.get("streamSettings") or ib.get("stream_settings") or {}
    return (ss.get("network") or ib.get("network") or "").lower()

def proto_family(ib):
    p = (ib.get("protocol") or ib.get("type") or "").lower()
    net = network_of(ib)
    if p in ("hysteria", "hysteria2", "hy2", "tuic", "wireguard"):
        return "udp"
    if p in ("shadowsocks", "dokodemo-door"):
        return "both"
    if p in ("vless", "vmess", "trojan", "http", "socks"):
        if net in ("quic", "kcp"):
            return "udp"
        return "tcp"
    if net in ("quic", "http3", "kcp"):
        return "udp"
    return "tcp"

raw = sys.stdin.read()
if not raw.strip():
    raise SystemExit(0)
try:
    cfg = json.loads(raw)
except Exception:
    raise SystemExit(0)
if not isinstance(cfg, dict):
    raise SystemExit(0)
inbounds = cfg.get("inbounds") or cfg.get("inbound") or []
if isinstance(inbounds, dict):
    inbounds = list(inbounds.values())
if not isinstance(inbounds, list):
    raise SystemExit(0)
seen = set()
for ib in inbounds:
    if not isinstance(ib, dict):
        continue
    tag = str(ib.get("tag") or "").lower()
    if tag in ("api", "metrics", "stats"):
        continue
    fam = proto_family(ib)
    ports = []
    add_port(ports, ib.get("port"))
    add_port(ports, ib.get("listen_port"))
    for pr in ports:
        for f in (("tcp", "udp") if fam == "both" else (fam,)):
            key = (f, pr)
            if key in seen:
                continue
            seen.add(key)
            print("%s %s" % (f, pr))
' 2>/dev/null || true
}

_find_remnanode_container() {
  # Print best-effort running container name/id for Remnawave node (read-only).
  command -v docker >/dev/null 2>&1 || return 1
  local line id image names
  # Prefer image remnawave/node, then name remnanode / *node*
  while IFS=$'\t' read -r id image names; do
    [[ -n "$image" ]] || continue
    if printf '%s' "$image" | grep -qiE 'remnawave/node|remnanode'; then
      printf '%s\n' "${names%%,*}"
      return 0
    fi
  done < <(docker ps --format '{{.ID}}\t{{.Image}}\t{{.Names}}' 2>/dev/null || true)
  while IFS=$'\t' read -r id image names; do
    [[ -n "$names" ]] || continue
    if printf '%s' "$names" | grep -qiE 'remnanode|remnawave'; then
      printf '%s\n' "${names%%,*}"
      return 0
    fi
  done < <(docker ps --format '{{.ID}}\t{{.Image}}\t{{.Names}}' 2>/dev/null || true)
  while IFS=$'\t' read -r id image names; do
    [[ -n "$names" ]] || continue
    if printf '%s' "$names" | grep -qiE '(^|[-_])node($|[-_,])' \
      && ! printf '%s' "$names" | grep -qiE 'watchtower|portainer|nginx|caddy|postgres|redis|mariadb'; then
      printf '%s\n' "${names%%,*}"
      return 0
    fi
    if printf '%s' "$image" | grep -qiE 'remnawave'; then
      printf '%s\n' "${names%%,*}"
      return 0
    fi
  done < <(docker ps --format '{{.ID}}\t{{.Image}}\t{{.Names}}' 2>/dev/null || true)
  return 1
}

_xray_json_looks_valid() {
  local s="$1"
  [[ -n "$s" ]] || return 1
  printf '%s' "$s" | grep -q '"inbounds"' || return 1
  # reject tiny stubs
  [[ ${#s} -gt 40 ]] || return 1
  return 0
}

_read_config_via_proc_cmdline() {
  # Find xray/rw-core pid, parse -config / --config=, read file (host or /proc/pid/root).
  local pid cmdline arg next="" cfg="" cand
  for pid in $(pgrep -f 'xray|rw-core' 2>/dev/null || true); do
    [[ -r "/proc/$pid/cmdline" ]] || continue
    cmdline="$(tr '\0' '\n' <"/proc/$pid/cmdline" 2>/dev/null || true)"
    next=""
    while IFS= read -r arg; do
      if [[ -n "$next" ]]; then
        cfg="$arg"
        next=""
        break
      fi
      case "$arg" in
        -config|--config)
          next=1
          ;;
        -config=*|--config=*)
          cfg="${arg#*=}"
          break
          ;;
      esac
    done <<<"$cmdline"
    [[ -n "$cfg" ]] || continue
    case "$cfg" in
      stdin:|stdin|/dev/stdin|-|"" )
        # signal stdin-config via special return text on fd3? use global
        AUDIT_XRAY_STDIN_CONFIG=1
        AUDIT_XRAY_PID="$pid"
        continue
        ;;
    esac
    for cand in "$cfg" "/proc/$pid/root$cfg" "/proc/$pid/root/${cfg#/}"; do
      if [[ -f "$cand" ]] && grep -q '"inbounds"' "$cand" 2>/dev/null; then
        cat "$cand"
        return 0
      fi
    done
  done
  return 1
}

_try_xray_api_inbounds_json() {
  # Best-effort: docker exec xray api / curl local API. Prints JSON with inbounds or fails.
  local cname="${1:-}" pid="${2:-}" 
  local api_addr="" envline out cmd bin
  # Discover API listen from env / cmdline
  if [[ -n "$cname" ]]; then
    envline="$(docker exec "$cname" sh -c 'printenv | grep -iE "XRAY_API|API_PORT|XRAY_API_PORT|API_HOST" 2>/dev/null' 2>/dev/null || true)"
    if printf '%s' "$envline" | grep -qoE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+'; then
      api_addr="$(printf '%s' "$envline" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | head -1)"
    elif printf '%s' "$envline" | grep -qoE '(^|[^0-9])([1-9][0-9]{3,4})([^0-9]|$)'; then
      api_addr="127.0.0.1:$(printf '%s' "$envline" | grep -oE '[1-9][0-9]{3,4}' | head -1)"
    fi
    # cmdline inside container
    if [[ -z "$api_addr" ]]; then
      local cm
      cm="$(docker exec "$cname" sh -c 'tr "\0" " " < /proc/1/cmdline 2>/dev/null; for p in /proc/[0-9]*; do tr "\0" " " < $p/cmdline 2>/dev/null; echo; done | grep -iE "xray|rw-core" | head -3' 2>/dev/null || true)"
      if printf '%s' "$cm" | grep -qoE '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:)?[1-9][0-9]{3,4}'; then
        # look specifically for api flag patterns
        api_addr="$(printf '%s' "$cm" | grep -oE '\-api[= ][^ ]+' | head -1 | sed -E 's/^-api[= ]//')"
      fi
    fi
    # common remnawave/xray local API ports
    local try_addr
    for try_addr in ${api_addr:+$api_addr} 127.0.0.1:8080 127.0.0.1:10085 127.0.0.1:11111 127.0.0.1:62789; do
      [[ -n "$try_addr" ]] || continue
      for bin in xray /usr/local/bin/xray /usr/bin/xray rw-core; do
        out="$(docker exec "$cname" sh -c "command -v $bin >/dev/null 2>&1 && $bin api lsi --server=$try_addr 2>/dev/null" 2>/dev/null || true)"
        if _xray_json_looks_valid "$out"; then
          printf '%s\n' "$out"
          return 0
        fi
        out="$(docker exec "$cname" sh -c "command -v $bin >/dev/null 2>&1 && $bin api inbound --server=$try_addr 2>/dev/null" 2>/dev/null || true)"
        if _xray_json_looks_valid "$out"; then
          printf '%s\n' "$out"
          return 0
        fi
        out="$(docker exec "$cname" sh -c "command -v $bin >/dev/null 2>&1 && $bin api adi --server=$try_addr 2>/dev/null" 2>/dev/null || true)"
        # adi may not be full config; skip unless inbounds present
        if _xray_json_looks_valid "$out"; then
          printf '%s\n' "$out"
          return 0
        fi
      done
    done
    # dump running config if binary supports it
    out="$(docker exec "$cname" sh -c 'command -v xray >/dev/null && xray run -test -c /dev/null 2>/dev/null; ls /tmp /run /var/tmp 2>/dev/null | head' 2>/dev/null || true)"
  fi
  if [[ -n "$pid" && -r "/proc/$pid/cmdline" ]]; then
    :
  fi
  return 1
}

collect_xray_config_json() {
  local cjson="" cand cname f pid
  AUDIT_XRAY_STDIN_CONFIG="${AUDIT_XRAY_STDIN_CONFIG:-0}"
  AUDIT_XRAY_PID="${AUDIT_XRAY_PID:-}"

  if command -v docker >/dev/null 2>&1; then
    cname="$(_find_remnanode_container || true)"
    if [[ -z "$cname" ]]; then
      cname="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -iE 'remnanode' | head -1 || true)"
    fi
    if [[ -n "$cname" ]]; then
      for cand in \
        /var/lib/remnanode/xray/config.json \
        /var/lib/remnanode/config.json \
        /etc/xray/config.json \
        /usr/local/etc/xray/config.json \
        /tmp/xray/config.json \
        /tmp/config.json \
        /run/xray/config.json \
        /opt/xray/config.json \
        /app/config.json \
        /app/xray/config.json; do
        cjson="$(docker exec "$cname" sh -c "test -f '$cand' && cat '$cand'" 2>/dev/null || true)"
        if _xray_json_looks_valid "$cjson"; then
          printf '%s\n' "$cjson"
          return 0
        fi
      done
      # limited-depth find for any json with inbounds
      cand="$(docker exec "$cname" sh -c 'find /var/lib /etc /tmp /run /opt /app /usr/local/etc -maxdepth 4 -type f \( -name "config.json" -o -name "*.json" \) 2>/dev/null | head -40' 2>/dev/null || true)"
      while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        cjson="$(docker exec "$cname" sh -c "grep -l '\"inbounds\"' '$f' >/dev/null 2>&1 && cat '$f'" 2>/dev/null || true)"
        if _xray_json_looks_valid "$cjson"; then
          printf '%s\n' "$cjson"
          return 0
        fi
      done <<<"$cand"
      # xray API inside container (stdin-config case)
      cjson="$(_try_xray_api_inbounds_json "$cname" || true)"
      if _xray_json_looks_valid "$cjson"; then
        printf '%s\n' "$cjson"
        return 0
      fi
    fi
  fi

  for cand in \
    /var/lib/remnanode/xray/config.json \
    /var/lib/remnanode/config.json \
    /usr/local/etc/xray/config.json \
    /etc/xray/config.json \
    /tmp/xray/config.json \
    /run/xray/config.json; do
    if [[ -f "$cand" ]] && grep -q '"inbounds"' "$cand" 2>/dev/null; then
      cat "$cand"
      return 0
    fi
  done

  # /proc cmdline -config
  if cjson="$(_read_config_via_proc_cmdline)"; then
    if _xray_json_looks_valid "$cjson"; then
      printf '%s\n' "$cjson"
      return 0
    fi
  fi

  pid="$(pgrep -n rw-core 2>/dev/null || pgrep -n xray 2>/dev/null || true)"
  if [[ -n "$pid" && -d "/proc/$pid/root" ]]; then
    for cand in \
      "/proc/$pid/root/var/lib/remnanode/xray/config.json" \
      "/proc/$pid/root/var/lib/remnanode/config.json" \
      "/proc/$pid/root/etc/xray/config.json" \
      "/proc/$pid/root/usr/local/etc/xray/config.json" \
      "/proc/$pid/root/tmp/xray/config.json" \
      "/proc/$pid/root/run/xray/config.json"; do
      if [[ -f "$cand" ]] && grep -q '"inbounds"' "$cand" 2>/dev/null; then
        cat "$cand"
        return 0
      fi
    done
    # limited find under proc root
    while IFS= read -r f; do
      [[ -n "$f" ]] || continue
      if grep -q '"inbounds"' "$f" 2>/dev/null; then
        cat "$f"
        return 0
      fi
    done < <(find "/proc/$pid/root/var/lib" "/proc/$pid/root/etc" "/proc/$pid/root/tmp" "/proc/$pid/root/run" -maxdepth 4 -type f -name '*.json' 2>/dev/null | head -40 || true)
  fi

  # last: API without known container (host xray)
  if [[ "${AUDIT_XRAY_STDIN_CONFIG:-0}" -eq 1 ]]; then
    cname="$(_find_remnanode_container || true)"
    cjson="$(_try_xray_api_inbounds_json "${cname:-}" "${AUDIT_XRAY_PID:-}" || true)"
    if _xray_json_looks_valid "$cjson"; then
      printf '%s\n' "$cjson"
      return 0
    fi
  fi
  return 1
}

detect_ports_from_inbounds_config() {
  local json line fam port found=0
  json="$(collect_xray_config_json || true)"
  [[ -n "$json" ]] || return 1
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    fam="${line%% *}"
    port="${line##* }"
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    if is_excluded_service_port "$port" "${DETECTED_NODE_PORT:-}"; then
      continue
    fi
    if [[ "$fam" == "tcp" ]]; then
      DETECTED_CLIENT_PORTS+=("$port"); found=1
    elif [[ "$fam" == "udp" ]]; then
      DETECTED_CLIENT_UDP_PORTS+=("$port"); found=1
    fi
  done < <(printf '%s\n' "$json" | parse_inbound_ports_from_json)
  [[ "$found" -eq 1 ]]
}

detect_ports_from_ss_filtered() {
  local line addr port proc node_ex="${1:-3000}" have_cfg_udp="${2:-0}"
  command -v ss >/dev/null 2>&1 || return 0
  while IFS= read -r line; do
    addr="$(ss_local_addr "$line")"
    port="${addr##*:}"; port="${port%%]*}"
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    is_excluded_service_port "$port" "$node_ex" && continue
    ss_is_loopback_addr "$addr" && continue
    is_ephemeral_port "$port" && continue
    proc=""
    if [[ "$line" == *'users:(('* ]]; then
      proc="$(sed -n 's/.*users:(("\([^"]*\).*/\1/p' <<<"$line" | head -1 || true)"
    fi
    case "$proc" in
      xray|rw-core|remnanode|rw-node|Xray|sing-box|singbox|hysteria|hysteria2|hy2)
        DETECTED_CLIENT_PORTS+=("$port") ;;
    esac
  done < <(ss -lntp 2>/dev/null | awk 'NR>1' || true)

  [[ "$have_cfg_udp" -eq 1 ]] && return 0
  while IFS= read -r line; do
    addr="$(ss_local_addr "$line")"
    port="${addr##*:}"; port="${port%%]*}"
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    is_excluded_service_port "$port" "$node_ex" && continue
    ss_is_loopback_addr "$addr" && continue
    is_ephemeral_port "$port" && continue
    proc=""
    if [[ "$line" == *'users:(('* ]]; then
      proc="$(sed -n 's/.*users:(("\([^"]*\).*/\1/p' <<<"$line" | head -1 || true)"
    fi
    case "$proc" in
      xray|rw-core|remnanode|rw-node|Xray|sing-box|singbox|hysteria|hysteria2|hy2)
        DETECTED_CLIENT_UDP_PORTS+=("$port") ;;
    esac
  done < <(ss -lnup 2>/dev/null | awk 'NR>1' || true)
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
  load_ephemeral_port_range
  log "Эфемерный диапазон: ${EPHEMERAL_LO}-${EPHEMERAL_HI} (исключаем из auto-detect)"

  local cfg_ok=0 have_cfg_udp=0
  DETECTED_CLIENT_PORTS=()
  DETECTED_CLIENT_UDP_PORTS=()
  if detect_ports_from_inbounds_config; then
    cfg_ok=1
    if [[ ${#DETECTED_CLIENT_UDP_PORTS[@]} -gt 0 ]]; then
      have_cfg_udp=1
    fi
    ok "Порты из xray inbounds: tcp=[${DETECTED_CLIENT_PORTS[*]:-}] udp=[${DETECTED_CLIENT_UDP_PORTS[*]:-}]"
  else
    log "Конфиг inbounds недоступен — fallback ss (без ephemeral ${EPHEMERAL_LO}-${EPHEMERAL_HI})"
  fi

  detect_ports_from_ss_filtered "$exclude_port" "$have_cfg_udp"

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
  ok "MODE=${MODE} ephemeral_excluded=${EPHEMERAL_LO}-${EPHEMERAL_HI}"
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


# True only for a real unattended-upgrade job.
# Ubuntu keeps unattended-upgrade-shutdown running forever; both truncate to
# comm "unattended-upgr" (15 chars), so pgrep -x unattended-upgr is a false positive.
_apt_real_unattended_running() {
  local pid cmd
  for pid in $(pgrep -f 'unattended-upgrade' 2>/dev/null || true); do
    [[ -r "/proc/${pid}/cmdline" ]] || continue
    cmd="$(tr '\0' ' ' <"/proc/${pid}/cmdline" 2>/dev/null || true)"
    case "$cmd" in
      *unattended-upgrade-shutdown*) continue ;;
      */usr/bin/unattended-upgrade*) return 0 ;;
    esac
  done
  return 1
}

_apt_lock_holders_reason() {
  # Prefer lock-file holders (fuser/lsof) over process-name matching.
  local locks=(
    /var/lib/dpkg/lock-frontend
    /var/lib/dpkg/lock
    /var/lib/apt/lists/lock
    /var/cache/apt/archives/lock
  )
  local lk
  for lk in "${locks[@]}"; do
    [[ -e "$lk" ]] || continue
    if command -v fuser >/dev/null 2>&1; then
      if fuser "$lk" >/dev/null 2>&1; then
        printf 'lock %s' "$lk"
        return 0
      fi
    elif command -v lsof >/dev/null 2>&1; then
      if lsof "$lk" >/dev/null 2>&1; then
        printf 'lock %s' "$lk"
        return 0
      fi
    fi
  done
  if [[ "$(id -u 2>/dev/null || echo 1)" -eq 0 ]] \
      && [[ -e /var/lib/dpkg/lock-frontend ]] && command -v flock >/dev/null 2>&1; then
    # Root-only flock probe (non-root gets EACCES → false busy)
    if ! flock -n /var/lib/dpkg/lock-frontend -c true 2>/dev/null; then
      printf 'flock /var/lib/dpkg/lock-frontend'
      return 0
    fi
  fi
  if pgrep -x apt-get >/dev/null 2>&1 \
    || pgrep -x apt >/dev/null 2>&1 \
    || pgrep -x dpkg >/dev/null 2>&1; then
    printf 'процесс apt/dpkg'
    return 0
  fi
  if _apt_real_unattended_running; then
    printf 'процесс unattended-upgrades'
    return 0
  fi
  return 1
}

wait_for_apt_locks() {
  # Wait until dpkg/apt locks are free. Ignores idle unattended-upgrade-shutdown.
  local timeout="${1:-600}" elapsed=0 next_msg=0
  local reason=""
  while (( elapsed < timeout )); do
    if reason="$(_apt_lock_holders_reason)"; then
      :
    else
      if (( elapsed > 0 )); then
        ok "apt/dpkg свободен (ждали ${elapsed}с)"
      fi
      return 0
    fi
    if (( elapsed >= next_msg )); then
      log "Ожидание apt/dpkg (${reason}; ${elapsed}/${timeout}с) — часто unattended-upgrades на свежей Ubuntu…"
      next_msg=$((elapsed + 15))
    fi
    sleep 5
    elapsed=$((elapsed + 5))
  done
  warn "Таймаут ${timeout}с ожидания apt/dpkg (${reason:-busy}) — пробуем всё равно"
  return 1
}

pause_apt_timers() {
  # Stop apt-daily* so they don't grab locks mid-run; ask unattended-upgrades to finish.
  # Never kill dpkg mid-install — systemctl stop waits for the current job.
  [[ "$DRY_RUN" -eq 1 ]] && return 0
  [[ "$(id -u 2>/dev/null || echo 1)" -eq 0 ]] || return 0
  command -v systemctl >/dev/null 2>&1 || return 0
  local u
  for u in apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service; do
    systemctl stop "$u" 2>/dev/null || true
  done
  if systemctl is-active --quiet unattended-upgrades.service 2>/dev/null \
      || systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
    log "Останавливаем unattended-upgrades (дождётся завершения текущей установки)…"
    # ExecStop of this unit waits for an in-progress unattended-upgrade to finish.
    systemctl stop unattended-upgrades.service 2>/dev/null \
      || systemctl stop unattended-upgrades 2>/dev/null \
      || true
  fi
  APT_TIMERS_PAUSED=1
}

restore_apt_timers() {
  # Re-enable automatic security updates after our apt work.
  [[ "${APT_TIMERS_PAUSED:-0}" -eq 1 ]] || return 0
  APT_TIMERS_PAUSED=0
  [[ "$(id -u 2>/dev/null || echo 1)" -eq 0 ]] || return 0
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl start apt-daily.timer 2>/dev/null || true
  systemctl start apt-daily-upgrade.timer 2>/dev/null || true
  # Restart the shutdown helper so reboot still waits for upgrades.
  systemctl start unattended-upgrades.service 2>/dev/null \
    || systemctl start unattended-upgrades 2>/dev/null \
    || true
}

system_upgrade() {
  # Update the OS before installing packages. Skippable via --no-upgrade.
  if [[ "$NO_UPGRADE" -eq 1 ]]; then
    log "Обновление системы пропущено (--no-upgrade / GORECSHIT_NO_UPGRADE)"
    pause_apt_timers
    wait_for_apt_locks 600 || true
    return 0
  fi
  step "Обновление системы"
  if [[ "$NET_OFFLINE" -eq 1 ]]; then
    warn "Офлайн (нет интернета/DNS) — обновление системы пропущено"
    pause_apt_timers
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b stop apt-daily*; dpkg --configure -a; apt-get update; apt-get full-upgrade -y (force-confold)\n' \
      "${C_YEL}" "${C_RESET}"
    return 0
  fi
  export DEBIAN_FRONTEND=noninteractive
  pause_apt_timers
  wait_for_apt_locks 600 || true

  log "dpkg --configure -a…"
  if ! dpkg --configure -a; then
    warn "dpkg --configure -a вернул ошибку (продолжаем)"
  fi
  wait_for_apt_locks 120 || true

  if [[ "$IPV6_OFF" -eq 1 ]]; then
    mkdir -p /etc/apt/apt.conf.d
    echo 'Acquire::ForceIPv4 "true";' >/etc/apt/apt.conf.d/99force-ipv4
  fi

  apt_get_retry update -qq || warn "apt-get update не удался (продолжаем)"

  log "apt-get full-upgrade (сохраняем локальные конфиги)…"
  local upgrade_opts=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
  if ! apt_get_retry "${upgrade_opts[@]}" full-upgrade; then
    warn "full-upgrade не удался — пробуем upgrade…"
    apt_get_retry "${upgrade_opts[@]}" upgrade \
      || warn "upgrade тоже не удался (продолжаем установку пакетов)"
  fi

  apt_get_retry -y autoremove --purge -qq 2>/dev/null || true

  if [[ -f /var/run/reboot-required ]]; then
    warn "Требуется перезагрузка (/var/run/reboot-required) — НЕ перезагружаем автоматически"
    if [[ -f /var/run/reboot-required.pkgs ]]; then
      log "Пакеты, требующие reboot: $(tr '\\n' ' ' </var/run/reboot-required.pkgs | head -c 300)"
    fi
  else
    ok "Перезагрузка не требуется"
  fi
  ok "Система обновлена"
}

apt_get_cmd() {
  # apt-get with lock timeout option (APT 2.x / Ubuntu 24.04+)
  apt-get -o DPkg::Lock::Timeout=600 "$@"
}

apt_get_retry() {
  # apt_get_retry [apt-get args...]  — wait locks, up to 3 attempts
  local attempt=1 max=3 rc=0
  wait_for_apt_locks 600 || true
  while (( attempt <= max )); do
    if apt_get_cmd "$@"; then
      return 0
    fi
    rc=$?
    warn "apt-get не удался (попытка ${attempt}/${max}, exit ${rc})"
    if (( attempt < max )); then
      wait_for_apt_locks 120 || true
      sleep $(( attempt * 5 ))
    fi
    attempt=$((attempt + 1))
  done
  return "$rc"
}

install_packages() {
  step "Пакеты"
  local pkgs=(ufw fail2ban ipset chrony curl ca-certificates iptables python3)
  # hashlimit / connlimit need xtables modules usually already in iptables
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b apt-get install -y %s\n' "${C_YEL}" "${C_RESET}" "${pkgs[*]}"
    return 0
  fi
  export DEBIAN_FRONTEND=noninteractive
  local missing=()
  mapfile -t missing < <(_pkgs_missing "${pkgs[@]}")
  if [[ ${#missing[@]} -eq 0 ]]; then
    ok "Пакеты уже стоят: ${pkgs[*]}"
    return 0
  fi
  if [[ "$NET_OFFLINE" -eq 1 ]]; then
    err "Не хватает пакетов: ${missing[*]} — а интернета/DNS нет, apt не сработает."
    err "Почините сеть (ip r, панель хостера) или DNS (nameserver 1.1.1.1 в /etc/resolv.conf) и запустите снова."
    return 1
  fi
  if [[ "$IPV6_OFF" -eq 1 ]]; then
    mkdir -p /etc/apt/apt.conf.d
    echo 'Acquire::ForceIPv4 "true";' >/etc/apt/apt.conf.d/99force-ipv4
  fi
  wait_for_apt_locks 600 || true
  apt_get_retry update -qq || warn "apt-get update failed (продолжаем)"
  if ! apt_get_retry install -y -qq "${pkgs[@]}"; then
    apt_get_retry install -y "${pkgs[@]}" || {
      err "Не удалось установить пакеты (apt lock / сеть). Повторите позже: gorecshit …"
      return 1
    }
  fi
  # optional whiptail for future interactive runs on minimal images
  apt_get_retry install -y -qq whiptail 2>/dev/null || true
  ok "Пакеты установлены: ${pkgs[*]}"
}

# ---------- v2.7.0: network / DNS self-heal (servers without DNS are a real-world case) ----------
_net_ip_ok() {
  # Raw IP connectivity (no DNS needed): TCP to well-known anycast resolvers, then ICMP.
  local ip port
  for ip in 1.1.1.1 8.8.8.8 77.88.8.8; do
    for port in 443 53; do
      if timeout 4 bash -c "exec 3<>/dev/tcp/${ip}/${port}" 2>/dev/null; then
        return 0
      fi
    done
  done
  ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && return 0
  ping -c1 -W2 77.88.8.8 >/dev/null 2>&1 && return 0
  return 1
}

_dns_ok() {
  local h
  for h in github.com deb.debian.org archive.ubuntu.com ya.ru; do
    if timeout 6 getent ahostsv4 "$h" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

ensure_network_dns() {
  # Make apt/curl work on servers with broken resolv.conf; clear message when there is no internet at all.
  [[ "$DRY_RUN" -eq 1 ]] && { printf '%b[DRY]%b check DNS; if broken but IP works → nameserver 1.1.1.1/8.8.8.8/77.88.8.8\n' "${C_YEL}" "${C_RESET}"; return 0; }
  step "Сеть и DNS"
  if _dns_ok; then
    if _net_ip_ok; then
      ok "DNS работает"
    else
      NET_OFFLINE=1
      warn "DNS отвечает (кэш?), но 1.1.1.1 / 8.8.8.8 / 77.88.8.8 недоступны по IP — работаю офлайн (без apt, встроенные/сохранённые списки)"
    fi
    return 0
  fi
  if ! _net_ip_ok; then
    NET_OFFLINE=1
    err "Нет выхода в интернет: не отвечают 1.1.1.1 / 8.8.8.8 / 77.88.8.8 даже по IP — это не DNS, а сеть/шлюз."
    warn "Проверьте: ip a; ip r (должна быть строка 'default via …'), сеть/IP в панели хостера."
    warn "Продолжаю офлайн: apt пропускаю, списки сканеров — встроенные в скрипт."
    return 0
  fi
  warn "DNS не работает (интернет по IP есть) — прописываю резолверы 1.1.1.1 / 8.8.8.8 / 77.88.8.8"
  local dropin="/etc/systemd/resolved.conf.d/99-gorecshit-dns.conf" created_dropin=0
  backup_file /etc/resolv.conf
  [[ -e "$dropin" ]] || created_dropin=1
  backup_file "$dropin"
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    mkdir -p /etc/systemd/resolved.conf.d
    printf '# Managed by %s %s (DNS self-heal)\n[Resolve]\nDNS=1.1.1.1 8.8.8.8\nFallbackDNS=1.0.0.1 8.8.4.4 77.88.8.8\n' \
      "$SCRIPT_NAME" "$VERSION" >"$dropin"
    systemctl restart systemd-resolved 2>/dev/null || true
    sleep 2
  fi
  if ! _dns_ok; then
    # Replace resolv.conf (a symlink to the resolved stub is common) with static resolvers
    local keep=""
    keep="$(grep -E '^\s*(search|domain|options)\b' /etc/resolv.conf 2>/dev/null || true)"
    rm -f /etc/resolv.conf
    {
      echo "# Managed by ${SCRIPT_NAME} ${VERSION} (DNS self-heal; original in ${BACKUP_DIR}/etc/resolv.conf)"
      [[ -n "$keep" ]] && printf '%s\n' "$keep"
      echo "nameserver 1.1.1.1"
      echo "nameserver 8.8.8.8"
      echo "nameserver 77.88.8.8"
      echo "options timeout:2 attempts:2"
    } >/etc/resolv.conf
  fi
  if [[ "$created_dropin" -eq 1 && -e "$dropin" ]]; then
    : >"${BACKUP_DIR}/dns-dropin.created"
    # shellcheck disable=SC2016  # literal rollback code
    _rb_append_block "gorecshit-dns-restore" '
if [[ -f "$BACKUP_DIR/dns-dropin.created" ]]; then
  rm -f /etc/systemd/resolved.conf.d/99-gorecshit-dns.conf
  systemctl restart systemd-resolved 2>/dev/null || true
fi'
  fi
  if _dns_ok; then
    ok "DNS починен (1.1.1.1 / 8.8.8.8 / 77.88.8.8). Откат вернёт прежний resolv.conf"
  else
    NET_OFFLINE=1
    err "DNS всё ещё не работает (возможно, хостер режет UDP/TCP 53). Продолжаю офлайн: без apt, встроенные списки."
  fi
}

_pkgs_missing() {
  # prints missing packages from args
  local p
  for p in "$@"; do
    dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || printf '%s\n' "$p"
  done
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
      wait_for_apt_locks 120 || true
      apt_get_retry install -y -qq irqbalance >/dev/null 2>&1 || true
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
  local sshp
  sshp="$(_ssh_ports_csv)"
  if [[ "$DO_BLOCKLIST" -eq 1 ]] && ipset list -n scanner-block >/dev/null 2>&1; then
    insert+="-A ufw-before-input -m conntrack --ctstate NEW -m set --match-set scanner-block src -j DROP"$'\n'
  fi
  # v2.7.0: reputation lists (brute-forcers; contain mobile CGNAT IPs) — SSH only, never client ports
  if [[ "$DO_BLOCKLIST" -eq 1 ]] && ipset list -n gorecshit-rep >/dev/null 2>&1; then
    insert+="-A ufw-before-input -p tcp -m multiport --dports ${sshp} -m conntrack --ctstate NEW -m set --match-set gorecshit-rep src -j DROP"$'\n'
  fi
  # v2.7.0: SSH rate-limit with silent DROP (ufw limit answers REJECT/icmp-port-unreachable = fingerprint)
  insert+="-A ufw-before-input -p tcp -m multiport --dports ${sshp} -m conntrack --ctstate NEW -m recent --name gs_ssh --set"$'\n'
  insert+="-A ufw-before-input -p tcp -m multiport --dports ${sshp} -m conntrack --ctstate NEW -m recent --name gs_ssh --update --seconds 60 --hitcount 10 -j DROP"$'\n'
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
    # IPv6 ping too (v2.6.0): only echo-request; NDP / packet-too-big untouched
    if [[ -f /etc/ufw/before6.rules ]]; then
      backup_file /etc/ufw/before6.rules
      sed -i -E 's/^(-A ufw6-before-input -p icmpv6 --icmpv6-type echo-request -j) ACCEPT/\1 DROP/' /etc/ufw/before6.rules || true
      sed -i -E 's/^(-A ufw6-before-forward -p icmpv6 --icmpv6-type echo-request -j) ACCEPT/\1 DROP/' /etc/ufw/before6.rules || true
    fi
    # Also destination-unreachable / time-exceeded stay ACCEPT for PMTU usually —
    # but for closed-port stealth we drop ICMP unreachable replies via sysctl/iptables below.
  fi
  _hook_ufw_before6_rules "$sshp"
  ok "UFW before.rules hooked (panel+relays ACCEPT; scanner DROP; reputation→SSH only; SSH limit DROP; ping hide=${DO_HIDE_PORTS})"
}

_ssh_ports_csv() {
  # 22 + --ssh-port + whatever sshd really listens on (max 15 for multiport)
  local ports=(22) p
  [[ -n "$SSH_PORT_NEW" ]] && ports+=("$SSH_PORT_NEW")
  if command -v sshd >/dev/null 2>&1; then
    while IFS= read -r p; do is_port "$p" && ports+=("$p"); done < <(sshd -T 2>/dev/null | awk '$1=="port"{print $2}')
  fi
  printf '%s\n' "${ports[@]}" | sort -n -u | head -15 | paste -sd, -
}

_hook_ufw_before6_rules() {
  # IPv6 parity: scanner DROP + SSH silent rate-limit in before6.rules (managed block, idempotent)
  local rules6="/etc/ufw/before6.rules" sshp="$1"
  [[ -f "$rules6" ]] || return 0
  backup_file "$rules6"
  if grep -q '# gorecshit-managed-begin' "$rules6"; then
    sed -i '/# gorecshit-managed-begin/,/# gorecshit-managed-end/d' "$rules6"
  fi
  local ins="# gorecshit-managed-begin ${VERSION}"$'\n'
  if [[ "$DO_BLOCKLIST" -eq 1 ]] && ipset list -n scanner-block6 >/dev/null 2>&1; then
    ins+="-A ufw6-before-input -m conntrack --ctstate NEW -m set --match-set scanner-block6 src -j DROP"$'\n'
  fi
  ins+="-A ufw6-before-input -p tcp -m multiport --dports ${sshp} -m conntrack --ctstate NEW -m recent --name gs_ssh6 --set"$'\n'
  ins+="-A ufw6-before-input -p tcp -m multiport --dports ${sshp} -m conntrack --ctstate NEW -m recent --name gs_ssh6 --update --seconds 60 --hitcount 10 -j DROP"$'\n'
  ins+="# gorecshit-managed-end"$'\n'
  if grep -q 'ufw6-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' "$rules6"; then
    local tmp; tmp="$(mktemp)"
    awk -v ins="$ins" '
      /ufw6-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT/ && !done { print; print ins; done=1; next }
      { print }
    ' "$rules6" >"$tmp"
    cat "$tmp" >"$rules6"; rm -f "$tmp"
  fi
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
    echo '# v2.7.0: CDN edges (Yandex Cloud CDN / Cloudflare) aggregate thousands of users — never per-IP limit them'
    echo 'ipset list -n gorecshit-cdn >/dev/null 2>&1 && iptables -A "$CHAIN" -m set --match-set gorecshit-cdn src -j RETURN'
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
  backup_file /etc/ufw/before6.rules
  backup_file /etc/default/ufw
  backup_file /etc/ufw/user.rules     # v2.7.0: rollback restores ufw allow/limit rules too
  backup_file /etc/ufw/user6.rules

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b ufw default deny incoming / allow outgoing; limit 22; clients; NODE_PORT from panel\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi

  hook_ufw_before_rules
  configure_hide_ports

  # IPv6 parity (v2.6.0): with IPv6 on, UFW must manage ip6tables too — else every port is open over v6
  if [[ "$IPV6_OFF" -eq 0 && -f /etc/default/ufw ]] && grep -qE '^IPV6=' /etc/default/ufw \
     && ! grep -qE '^IPV6=yes' /etc/default/ufw; then
    sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw || true
    ok "UFW IPV6=yes — правила зеркалируются на IPv6"
  fi

  ufw default deny incoming
  ufw default allow outgoing

  # SSH
  # v2.7.0: plain allow + silent DROP rate-limit in before.rules (ufw limit = REJECT → visible fingerprint)
  ufw allow 22/tcp comment 'SSH (rate-limit DROP in before.rules)' || true
  ufw delete limit 22/tcp >/dev/null 2>&1 || true
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
  # Public "NODE_PORT ALLOW Anywhere" (v4/v6) = main node giveaway; panel-only allow above covers the link
  ufw_remove_public_node_port || true
  # Deny public NODE_PORT if somehow open (idempotent deny after allow-from)
  # ufw processes first match — allow from panel already added

  if [[ "$MODE" == "cdn" || "$CADDY_PRESENT" -eq 1 ]]; then
    ufw allow 80/tcp comment 'cdn-http' || true
    ufw allow 443/tcp comment 'cdn-https' || true
  fi

  # Deny common internal xray if present and not in CLIENT_PORTS
  ufw deny 4443/tcp comment 'deny-public-xray-4443' || true

  ufw --force enable
  ok "UFW enabled (SSH: silent DROP rate-limit; NODE_PORT=${NODE_PORT}←panel; clients tcp=${CLIENT_PORTS} udp=${CLIENT_UDP_PORTS})"
}


# ---------- v2.7.0 built-in lists (offline fallback; snapshot 2026-11-14) ----------
# Sources: OpenFilters/internet-scanners (small/medium feeds), CyberOK Skipa, traffic-guard antiscanner,
# RIPEstat announced prefixes of scanner ASNs (Modat 209334, Censys 398324/398705, Driftnet 211298,
# ONYPHE 213412, IP Volume 202425, Pfcloud 51396). Pre-filtered: no Yandex/Cloudflare, no RU mobile.
_write_builtin_lists() {
  local d="/etc/scanner-block"
  mkdir -p "$d"
  tr ' ' '\n' >"$d/builtin-scanners.txt" <<'GS_BUILTIN_SCANNERS'
2.31.155.11/32 2.57.17.0/24 2.59.21.51/32 2.59.22.234/32 2.59.255.74/32 3.7.157.159/32 3.7.173.162/32 3.9.159.128/25 3.14.73.254/32 3.14.82.245/32
3.14.84.197/32 3.14.86.234/32 3.15.169.123/32 3.15.179.241/32 3.15.180.31/32 3.16.148.58/32 3.16.213.130/32 3.17.72.122/32 3.17.73.23/32
3.17.206.73/32 3.17.207.148/32 3.18.101.236/32 3.18.108.78/32 3.19.14.190/32 3.19.14.223/32 3.19.223.104/32 3.19.240.76/32 3.21.171.90/32
3.22.234.7/32 3.23.59.18/32 3.23.104.96/32 3.26.100.0/24 3.31.100.0/24 3.32.43.0/27 3.42.1.0/26 3.42.1.64/30 3.42.1.68/31 3.64.4.229/32 3.67.7.128/25
3.97.253.250/32 3.98.92.0/25 3.98.168.45/32 3.101.216.65/32 3.101.216.66/31 3.101.216.68/30 3.101.216.72/29 3.101.216.80/31 3.101.216.82/32
3.101.216.88/29 3.101.216.96/29 3.101.216.104/30 3.101.216.108/31 3.101.216.111/32 3.101.216.114/32 3.101.216.119/32 3.101.216.120/30
3.101.216.124/31 3.101.216.126/32 3.101.226.128/26 3.101.230.128/25 3.101.239.64/26 3.101.240.0/25 3.101.240.128/26 3.106.118.128/25 3.108.37.0/24
3.115.120.212/32 3.124.123.128/25 3.129.92.250/32 3.130.96.91/32 3.131.215.38/32 3.132.23.201/32 3.132.217.0/25 3.133.84.157/32 3.134.93.22/32
3.134.100.58/32 3.134.101.147/32 3.134.148.59/32 3.136.67.107/32 3.136.208.236/32 3.137.73.221/32 3.137.132.216/32 3.137.136.201/32 3.137.141.123/32
3.137.146.232/32 3.137.148.99/32 3.137.151.234/32 3.138.185.30/32 3.138.190.72/32 3.139.58.65/32 3.139.191.225/32 3.141.153.201/32 3.141.168.125/32
3.142.97.232/32 3.142.219.55/32 3.143.33.63/32 3.143.152.247/32 3.144.44.57/32 3.144.77.222/32 3.144.120.14/32 3.144.120.21/32 3.144.192.36/32
3.144.236.65/32 3.144.239.16/32 3.144.245.141/32 3.146.111.124/32 3.148.147.222/32 3.149.59.26/32 3.151.181.143/32 3.208.140.122/32 3.211.92.239/32
3.232.81.89/32 3.233.59.216/32 3.234.180.95/32 3.251.224.0/24 5.63.151.96/27 5.101.64.6/32 5.143.224.100/30 5.143.224.104/30 5.159.97.203/32
5.178.87.167/32 5.181.20.206/32 5.182.36.155/32 5.188.159.228/32 5.189.167.246/32 5.226.140.0/25 5.252.83.0/24 8.34.210.32/27 8.208.10.94/32
8.209.96.179/32 8.210.123.17/32 8.211.162.45/32 13.37.76.130/32 13.49.36.97/32 13.51.103.193/32 13.56.21.128/25 13.58.84.198/32 13.58.114.74/32
13.58.203.73/32 13.59.16.128/32 13.59.59.233/32 13.59.120.77/32 13.59.132.170/32 13.59.242.100/32 13.59.252.0/25 13.62.142.172/32 13.62.143.68/32
13.113.254.122/32 13.115.104.128/25 13.125.155.228/32 13.126.5.12/32 13.204.242.170/32 13.209.164.77/32 13.210.1.64/26 13.213.79.0/24 13.215.44.86/32
13.219.121.241/32 13.234.214.153/32 13.237.51.211/32 15.175.17.253/32 15.175.179.151/32 15.200.117.191/32 15.204.109.96/31 15.204.109.103/32
15.204.109.224/32 15.224.61.208/32 15.228.125.0/24 15.236.61.7/32 16.60.94.233/32 16.192.194.110/32 18.97.5.0/25 18.97.19.128/25 18.97.26.0/24
18.98.162.96/29 18.116.198.0/24 18.116.202.164/32 18.116.239.38/32 18.117.57.162/32 18.117.109.14/32 18.117.218.107/32 18.118.100.31/32
18.118.107.228/32 18.119.11.223/32 18.119.13.69/32 18.135.209.62/32 18.135.221.73/32 18.139.37.197/32 18.139.204.0/25 18.168.180.128/25
18.168.224.128/25 18.188.53.152/32 18.188.134.51/32 18.188.229.2/32 18.189.28.87/32 18.190.152.179/32 18.190.163.148/32 18.191.16.102/32
18.191.69.170/32 18.191.84.177/32 18.191.173.38/32 18.191.255.164/32 18.194.95.64/26 18.199.138.76/32 18.200.155.2/32 18.217.102.23/32
18.217.128.63/32 18.217.194.148/32 18.218.94.172/32 18.218.168.5/32 18.218.230.153/32 18.219.11.104/32 18.219.37.54/32 18.219.47.173/32
18.219.56.153/32 18.219.157.186/32 18.219.193.156/32 18.220.248.172/32 18.221.18.194/32 18.221.100.43/32 18.221.137.47/32 18.221.180.165/32
18.221.214.151/32 18.222.192.238/32 18.222.201.82/32 18.222.255.237/32 18.223.2.197/32 18.223.104.85/32 18.224.39.133/32 18.224.93.149/32
18.224.184.103/32 18.225.7.162/32 18.225.206.49/32 18.229.34.49/32 18.235.110.182/32 23.92.31.220/32 23.111.14.183/32 23.111.14.184/29
23.111.14.192/32 23.176.184.0/24 23.239.4.252/32 23.239.12.138/32 23.239.14.238/32 23.239.15.172/32 23.239.21.238/32 24.144.104.6/32 31.14.32.4/30
31.14.32.8/32 31.14.254.0/25 31.40.201.0/24 31.57.185.0/24 31.131.251.106/32 31.131.251.235/32 31.131.255.205/32 31.131.255.206/31 31.131.255.208/30
31.131.255.212/32 31.131.255.240/32 32.189.238.195/32 32.193.229.248/32 32.196.38.110/32 32.236.69.187/32 34.19.116.48/28 34.19.127.160/27
34.19.127.192/27 34.68.34.64/27 34.201.223.128/25 34.223.64.0/25 34.234.144.84/32 34.234.177.119/32 35.73.219.128/25 35.75.73.253/32 35.82.51.128/25
35.86.126.0/24 35.93.174.0/24 35.177.219.0/26 35.182.14.64/26 35.203.210.0/23 35.216.140.3/32 35.216.140.175/32 35.216.144.195/32 35.216.149.150/32
35.216.150.3/32 35.216.156.249/32 35.216.172.131/32 35.216.183.140/32 35.216.185.210/32 35.216.188.37/32 35.216.189.16/32 35.216.195.77/32
35.216.196.110/32 35.216.197.176/32 35.216.200.253/32 35.216.201.9/32 35.216.216.242/32 35.216.217.192/32 35.216.231.117/32 35.216.236.0/32
35.216.247.217/32 35.216.254.237/32 36.156.22.4/32 37.9.13.54/32 37.9.13.84/32 37.9.13.105/32 37.9.13.217/32 37.10.113.208/28 44.192.244.0/24
44.193.87.188/32 44.206.3.0/24 44.220.185.0/24 44.220.188.0/24 44.237.114.33/32 44.242.181.128/25 45.12.129.166/32 45.12.129.173/32 45.12.136.73/32
45.12.136.79/32 45.12.146.245/32 45.33.28.47/32 45.33.50.24/32 45.33.65.249/32 45.33.69.253/32 45.33.73.58/32 45.33.78.24/32 45.33.78.70/32
45.33.80.243/32 45.33.83.115/32 45.33.84.124/32 45.33.89.53/32 45.33.94.76/32 45.33.95.64/32 45.55.151.3/32 45.55.153.86/32 45.55.158.168/32
45.55.185.224/32 45.55.186.92/32 45.56.101.170/32 45.56.103.133/32 45.56.103.154/32 45.56.111.60/32 45.58.168.128/32 45.58.168.141/32
45.58.168.180/32 45.58.168.195/32 45.58.168.253/32 45.79.38.219/32 45.79.102.191/32 45.79.128.205/32 45.79.132.41/32 45.79.133.252/32 45.79.153.51/32
45.79.153.72/32 45.79.156.130/32 45.79.162.88/32 45.79.172.21/32 45.79.177.245/32 45.79.181.94/32 45.79.181.104/32 45.79.181.179/32 45.79.181.223/32
45.79.181.251/32 45.79.186.176/32 45.79.190.10/32 45.79.190.208/32 45.79.190.216/32 45.79.191.178/32 45.83.64.0/22 45.90.57.150/32 45.91.64.6/31
45.91.64.8/32 45.92.176.94/32 45.92.176.129/32 45.92.176.143/32 45.92.176.144/31 45.92.176.205/32 45.92.177.113/32 45.92.177.127/32 45.92.177.237/32
45.93.20.45/32 45.93.20.79/32 45.93.20.103/32 45.93.20.104/32 45.93.20.109/32 45.93.20.126/32 45.93.20.148/32 45.93.20.229/32 45.133.173.0/24
45.135.193.0/24 45.135.194.0/24 45.140.222.0/24 45.141.86.171/32 45.144.212.0/24 45.146.167.56/32 45.146.167.68/32 45.146.167.105/32
45.146.167.237/32 45.148.144.0/24 45.156.128.0/22 46.101.1.225/32 46.101.111.185/32 46.101.126.116/32 46.101.232.106/32 46.105.132.32/27
46.161.50.108/31 47.89.154.16/32 47.91.125.252/32 47.253.116.19/32 50.116.30.197/32 50.116.47.129/32 51.15.34.47/32 51.15.44.6/32 51.15.56.200/32
51.15.98.45/32 51.15.115.141/32 51.15.164.26/32 51.15.164.149/32 51.24.112.219/32 51.24.186.244/32 51.38.12.12/30 51.38.12.20/30 51.45.55.60/32
51.102.108.215/32 51.112.93.0/24 51.158.173.123/32 51.158.173.124/32 51.159.110.167/32 51.159.125.104/32 51.159.125.199/32 51.159.125.200/32
51.159.125.208/32 51.159.149.103/32 51.254.49.96/28 51.254.59.112/28 52.14.58.0/32 52.14.122.207/32 52.14.197.136/32 52.14.202.153/32 52.15.76.227/32
52.15.78.25/32 52.15.85.154/32 52.16.213.65/32 52.17.9.21/32 52.17.98.131/32 52.20.29.198/32 52.29.203.240/32 52.33.46.232/32 52.60.84.222/32
52.61.37.84/32 52.73.169.169/32 52.192.76.61/32 52.208.235.127/32 52.209.13.240/32 54.37.81.238/32 54.73.182.190/32 54.77.111.234/32 54.86.115.253/32
54.93.254.128/26 54.149.204.90/32 54.175.125.192/26 54.207.105.3/32 54.212.169.44/32 54.233.128.86/32 54.253.208.103/32 54.255.254.0/26
56.125.84.114/32 56.126.23.58/32 57.129.64.10/32 57.129.64.219/32 57.129.64.237/32 57.182.57.78/32 62.76.98.0/24 62.113.99.65/32 62.210.142.21/32
62.210.142.39/32 62.210.142.61/32 62.210.142.62/32 62.210.142.65/32 62.210.142.148/32 62.210.142.159/32 62.210.142.160/28 62.210.142.176/30
62.210.145.219/32 62.210.245.60/32 62.210.245.66/32 62.233.57.30/32 63.32.130.39/32 63.179.48.119/32 64.23.159.209/32 64.23.218.208/32 64.52.19.0/24
64.62.156.0/24 64.62.195.152/29 64.62.197.0/24 64.94.153.0/24 64.94.156.0/24 64.94.159.0/24 64.95.9.0/24 64.95.14.0/24 64.205.72.0/24
64.225.74.178/32 64.225.75.131/32 64.225.75.246/32 64.225.78.34/32 64.226.64.124/32 64.226.65.160/32 64.226.78.121/32 64.226.86.7/32
64.226.108.113/32 64.227.10.52/32 64.227.11.241/32 64.227.18.98/32 64.227.32.66/32 64.227.70.2/32 64.227.90.185/32 64.227.97.195/32 64.227.99.138/32
64.227.99.233/32 64.227.106.112/32 64.227.108.146/32 64.227.109.89/32 64.227.110.161/32 65.49.1.0/24 65.49.20.64/26 66.94.119.243/32 66.132.148.0/24
66.132.153.0/24 66.132.159.0/24 66.132.172.0/24 66.132.175.0/24 66.132.180.0/24 66.132.186.0/24 66.132.195.0/24 66.132.198.0/24 66.132.209.0/24
66.132.224.0/24 66.132.228.0/24 66.175.208.166/32 66.175.212.77/32 66.175.213.4/32 66.228.40.98/32 66.228.41.127/32 66.234.1.0/24 66.240.192.138/32
66.240.205.34/32 66.240.219.133/32 66.240.219.146/32 66.240.223.214/32 66.240.223.240/32 66.240.236.109/32 66.240.236.116/32 66.240.236.119/32
67.21.68.60/32 67.21.68.237/32 67.207.95.230/32 67.215.228.63/32 68.69.177.0/24 68.183.3.153/32 68.183.9.16/32 68.183.11.224/32 68.183.16.131/32
68.183.96.213/32 68.183.105.175/32 68.183.180.73/32 69.5.169.0/24 69.164.207.173/32 69.164.213.157/32 69.164.214.243/32 70.39.95.20/32 70.39.95.36/32
70.39.95.67/32 70.39.95.72/32 70.39.95.129/32 71.6.135.131/32 71.6.142.213/32 71.6.146.130/32 71.6.146.185/32 71.6.146.186/32 71.6.147.198/32
71.6.147.254/32 71.6.154.144/32 71.6.158.166/32 71.6.165.200/32 71.6.167.142/32 71.6.199.23/32 71.6.199.65/32 71.6.199.87/32 71.6.202.219/32
71.6.233.0/24 74.82.47.0/26 77.67.26.0/24 77.83.207.0/24 77.223.102.84/32 77.223.102.101/32 77.223.102.191/32 77.223.103.45/32 77.223.103.53/32
77.223.120.227/32 78.232.50.178/32 79.124.58.134/32 79.124.62.10/32 80.82.64.0/22 80.82.68.0/23 80.82.70.0/24 80.82.76.0/22 80.85.152.96/32
80.93.187.17/32 80.249.131.92/32 81.19.216.64/26 81.19.219.192/26 82.117.255.125/32 82.148.21.205/32 84.75.255.71/32 85.25.43.94/32 85.25.103.50/32
85.142.100.0/24 85.175.69.50/32 85.175.147.234/32 85.208.84.0/24 85.217.140.0/24 85.217.149.0/24 86.38.187.0/24 86.54.31.32/28 87.236.176.0/24
88.80.189.24/32 88.202.190.128/27 88.214.50.0/24 89.21.67.128/26 89.37.172.128/27 89.45.35.0/24 89.169.28.191/32 89.169.28.210/32 89.169.28.214/32
89.248.160.0/21 89.248.168.0/22 89.248.172.0/23 89.248.174.0/24 91.122.177.241/32 91.196.152.0/24 91.230.168.0/24 91.231.89.0/24 92.38.135.119/32
92.38.153.0/24 92.63.196.0/24 92.124.109.218/32 92.223.103.144/32 93.120.27.62/32 93.123.109.17/32 93.123.109.18/31 93.123.109.20/30 93.123.109.24/29
93.123.109.32/30 93.123.109.36/31 93.123.109.39/32 93.123.109.40/31 93.123.109.120/30 93.123.109.124/31 93.123.109.219/32 93.174.88.0/21
94.25.46.114/32 94.26.228.18/32 94.26.228.205/32 94.102.48.0/20 94.183.174.0/24 94.231.206.0/24 95.143.190.169/32 95.143.190.179/32 95.143.191.147/32
95.143.191.223/32 95.143.191.245/32 95.167.62.66/32 95.167.62.82/32 95.167.82.26/32 95.167.87.66/32 95.167.133.10/32 95.167.148.18/32 95.167.186.2/32
95.167.197.242/32 95.167.198.186/32 95.167.199.34/32 95.167.199.90/32 95.167.200.10/32 95.189.36.106/32 95.215.0.144/31 96.126.110.54/32
96.126.112.111/32 96.126.117.80/32 97.107.133.213/32 97.107.136.165/32 97.107.140.120/32 97.107.141.150/32 98.80.4.0/25 98.84.1.175/32
98.85.37.217/32 98.85.103.176/32 98.88.137.2/32 100.52.158.15/32 101.132.145.132/32 103.16.130.243/32 103.16.131.136/32 103.29.69.181/32
103.29.70.204/32 103.66.28.0/22 103.203.56.0/22 103.230.157.150/32 104.128.144.201/32 104.128.144.202/31 104.128.144.204/30 104.128.144.208/29
104.128.144.216/30 104.128.144.220/32 104.152.52.0/24 104.156.155.0/24 104.237.130.38/32 104.237.150.176/32 104.237.151.205/32 104.237.151.244/32
104.248.206.108/32 107.20.158.220/32 107.21.48.111/32 107.170.65.169/32 107.170.75.78/32 108.132.249.171/32 109.105.208.0/21 109.123.117.224/27
112.74.38.239/32 128.199.8.140/32 128.199.44.215/32 128.199.182.55/32 128.199.182.77/32 128.199.182.152/32 130.193.25.11/32 134.122.28.88/32
134.209.25.199/32 134.209.95.237/32 134.209.252.42/32 137.184.13.100/32 137.184.31.185/32 137.184.75.34/32 137.184.78.203/32 137.184.95.216/32
137.184.112.103/32 137.184.112.192/32 137.184.190.194/32 137.184.190.205/32 137.184.190.246/32 138.68.73.85/32 138.68.82.23/32 138.68.86.32/32
138.68.144.227/32 138.68.249.116/32 138.197.90.201/32 138.197.101.95/32 138.197.118.33/32 138.197.191.87/32 138.249.120.0/23 138.249.122.0/24
138.249.124.0/23 139.59.132.8/32 139.59.136.184/32 139.59.143.102/32 139.59.170.85/32 139.59.231.238/32 139.144.235.132/32 139.144.239.72/32
139.144.239.74/32 139.162.3.141/32 139.162.3.144/32 139.162.8.186/32 139.162.31.7/32 139.162.66.65/32 139.162.70.53/32 139.162.70.102/32
139.162.71.210/32 139.162.78.6/32 139.162.87.250/32 139.162.96.14/32 139.162.96.81/32 139.162.99.58/32 139.162.109.245/32 139.162.113.212/32
139.162.116.22/32 139.162.117.40/32 139.162.119.12/32 139.162.119.49/32 139.162.119.51/32 139.162.119.61/32 139.162.119.94/32 139.162.119.146/32
139.162.119.196/32 139.162.124.188/32 139.162.141.82/32 139.162.155.225/32 139.162.173.209/32 139.162.189.5/32 139.162.251.127/32 142.91.102.186/31
142.93.0.66/32 142.93.49.93/32 142.93.129.190/32 142.93.135.91/32 142.93.135.160/32 142.93.143.8/32 142.93.146.198/32 143.110.213.72/32
143.110.217.244/32 143.110.239.2/32 143.198.68.20/32 143.198.115.76/32 143.198.179.104/32 143.198.225.197/32 143.198.238.87/32 143.244.168.161/32
144.86.173.0/24 144.202.82.88/32 145.220.91.19/32 146.88.240.0/23 146.185.25.160/27 146.190.21.73/32 146.190.63.48/32 146.190.63.248/32
146.190.69.241/32 146.190.103.103/32 146.190.242.161/32 147.182.149.75/32 147.182.200.94/32 147.182.202.179/32 147.182.225.86/32 147.182.240.244/31
147.182.240.247/32 147.182.241.81/32 147.182.247.10/32 147.185.132.0/22 148.59.129.0/24 148.153.56.170/32 148.153.56.174/32 148.153.188.246/32
148.153.188.254/32 148.153.189.62/32 150.107.36.236/32 150.107.38.251/32 151.245.151.0/24 152.32.142.86/32 152.42.136.22/32 154.16.44.0/24
154.30.3.68/32 154.53.40.98/32 154.70.207.100/32 154.197.56.163/32 157.230.19.140/32 157.230.178.76/32 157.230.220.136/32 157.245.36.108/32
157.245.72.120/32 157.245.77.56/32 157.245.105.107/32 157.245.113.227/32 157.245.176.143/32 157.245.204.205/32 157.245.222.108/32 157.245.243.118/32
157.245.245.246/32 157.245.252.5/32 158.94.187.0/24 158.94.218.0/24 159.65.18.197/32 159.65.144.72/32 159.65.193.17/32 159.65.204.129/32
159.65.206.235/32 159.65.216.50/32 159.65.219.252/32 159.65.224.182/32 159.65.237.176/32 159.89.1.53/32 159.89.12.166/32 159.89.124.112/32
159.89.127.165/32 159.89.174.87/32 159.195.79.176/32 159.203.96.42/32 159.223.0.20/32 159.223.98.198/32 159.223.132.86/32 159.223.179.74/32
159.223.203.97/32 159.223.217.240/32 159.223.231.254/32 160.119.70.0/24 160.119.76.40/32 160.119.76.42/32 161.35.51.104/32 161.35.56.30/32
161.35.70.45/32 161.35.74.94/32 161.35.108.63/32 161.35.145.35/32 161.35.230.3/32 161.35.230.183/32 161.35.236.116/32 161.35.236.158/32
161.35.238.241/32 162.142.125.0/24 162.216.18.113/32 162.216.148.0/22 162.243.114.171/32 162.243.116.182/32 162.243.208.127/32 163.172.99.21/32
163.172.99.35/32 163.172.99.60/32 163.172.99.85/32 163.172.99.98/32 163.172.109.18/32 164.68.102.233/32 164.90.176.216/32 164.90.208.56/32
164.90.228.79/32 164.92.106.15/32 164.92.107.174/32 164.92.114.247/32 164.92.148.118/32 164.92.159.100/32 164.92.182.157/32 164.92.215.178/32
164.92.219.121/32 164.92.244.132/32 165.22.27.186/32 165.22.34.189/32 165.22.193.223/32 165.22.235.3/32 165.154.23.177/32 165.154.163.10/32
165.227.39.235/32 165.227.55.4/32 165.227.62.247/32 165.227.84.14/32 165.227.84.134/32 165.227.110.45/32 165.227.172.206/32 165.227.173.41/32
165.227.188.42/32 165.232.118.73/32 167.71.48.103/32 167.71.81.114/32 167.71.102.95/32 167.71.102.181/32 167.71.110.14/32 167.71.175.236/32
167.94.138.0/24 167.94.145.0/24 167.94.146.0/24 167.99.1.98/32 167.99.107.57/32 167.99.119.168/32 167.99.181.249/32 167.99.182.39/32
167.99.210.137/32 167.99.211.88/32 167.99.225.143/32 167.99.234.119/32 167.172.40.9/32 167.172.47.74/32 167.172.148.206/32 167.172.158.128/32
167.172.183.39/32 167.172.232.142/32 167.248.133.0/24 170.187.163.90/32 170.187.163.117/32 170.187.163.133/32 170.187.165.134/32 170.187.165.139/32
170.187.165.218/31 170.187.165.242/32 170.231.236.98/32 170.231.237.214/32 172.104.11.4/32 172.104.11.34/32 172.104.11.46/32 172.104.11.51/32
172.104.19.160/32 172.104.23.19/32 172.104.94.121/32 172.104.94.242/32 172.104.100.117/32 172.104.210.143/32 172.104.211.111/32 172.104.241.92/32
172.104.241.98/32 172.105.16.34/32 172.105.16.40/32 172.105.16.105/32 172.105.16.117/32 172.105.16.131/32 172.105.102.10/32 172.105.102.42/32
172.105.128.11/32 172.105.128.12/31 172.105.147.0/24 172.105.158.219/32 172.105.169.180/32 172.105.197.151/32 172.105.208.132/32 172.105.212.74/32
172.105.218.179/32 172.105.224.72/32 172.105.229.64/32 172.232.20.149/32 172.232.188.177/32 172.232.232.10/32 172.232.232.48/32 172.232.232.169/32
172.232.232.179/32 172.233.16.50/32 172.233.20.117/32 172.233.28.142/32 172.233.29.203/32 172.233.74.207/32 172.233.135.159/32 172.233.172.43/32
172.233.190.104/32 172.233.195.143/32 172.234.162.31/32 172.234.162.56/32 172.234.207.202/32 172.234.218.10/32 172.234.246.109/32 172.235.173.150/32
172.235.181.217/32 172.235.181.226/32 172.236.137.159/32 172.236.233.65/32 172.237.28.61/32 172.237.132.117/32 172.239.4.138/32 172.255.209.23/32
173.230.145.103/32 173.255.214.145/32 173.255.225.139/32 174.138.40.30/32 175.6.54.250/32 176.9.9.142/32 176.65.134.0/24 176.65.148.0/22
176.100.243.247/32 176.208.65.146/32 176.208.67.114/32 176.208.69.226/32 176.208.70.162/32 176.208.79.82/32 176.210.118.218/32 176.211.46.130/32
176.211.47.122/32 176.211.48.242/32 176.211.51.218/32 176.211.56.130/32 176.211.103.178/32 176.211.103.202/32 176.223.188.0/24 178.62.212.177/32
178.79.148.58/32 178.128.32.203/32 178.128.66.56/32 178.128.66.109/32 178.128.207.138/32 178.128.250.218/32 178.185.133.251/32 178.185.170.42/32
178.185.202.130/32 178.185.202.162/32 178.185.216.114/32 178.185.228.58/32 178.185.234.162/32 178.185.235.58/32 178.185.235.74/32 178.185.238.154/32
178.185.238.178/32 178.185.239.50/32 178.185.239.58/32 178.185.241.98/32 178.185.241.114/32 184.105.139.64/26 184.105.247.192/26 184.192.173.246/32
184.192.188.55/32 184.193.157.254/32 185.2.80.252/31 185.94.111.1/32 185.107.80.93/32 185.114.175.0/24 185.117.225.0/24 185.142.236.34/31
185.142.236.36/32 185.142.236.38/32 185.142.236.40/31 185.142.236.43/32 185.142.239.16/32 185.154.110.22/32 185.165.190.17/32 185.165.190.34/32
185.165.191.26/31 185.180.140.0/22 185.191.236.38/32 185.197.182.0/24 185.200.118.32/32 185.200.118.34/31 185.200.118.36/30 185.200.118.40/29
185.200.118.48/29 185.200.118.56/30 185.200.118.60/32 185.200.118.63/32 185.200.118.64/32 185.200.118.66/31 185.200.118.68/30 185.200.118.72/29
185.200.118.80/29 185.200.118.88/30 185.200.118.92/32 185.216.145.160/27 185.218.100.133/32 185.223.235.0/26 185.224.228.0/22 185.226.196.0/22
185.230.223.46/32 185.235.167.0/24 185.238.75.248/32 185.242.226.0/24 185.247.137.0/24 188.68.217.207/32 188.138.9.50/32 188.166.25.133/32
188.166.75.16/32 188.166.108.93/32 188.240.59.0/26 188.246.224.80/32 190.114.255.238/32 192.46.211.230/32 192.46.221.9/32 192.155.90.118/32
192.155.90.220/32 192.158.140.0/24 192.165.198.0/24 192.241.179.235/32 193.32.209.224/27 193.47.62.90/31 193.47.62.92/31 193.47.62.110/31
193.47.62.187/32 193.124.20.224/27 193.163.125.0/24 193.168.46.143/32 193.176.29.0/27 193.176.31.144/28 193.176.31.192/26 193.181.177.0/24
193.235.193.0/24 194.26.25.137/32 194.50.235.128/27 194.55.238.32/32 194.88.98.80/28 194.88.98.96/27 194.187.176.0/22 195.96.139.0/24
195.123.244.73/32 195.140.214.16/28 195.144.21.56/32 195.154.107.13/32 195.154.107.191/32 195.154.208.62/32 195.178.110.162/32 195.184.76.0/24
195.206.182.192/27 195.206.182.224/32 195.209.120.0/22 195.216.154.0/24 198.20.69.74/32 198.20.69.98/32 198.20.70.114/32 198.20.99.130/32
198.46.182.214/32 198.74.57.47/32 198.74.58.148/32 198.199.123.141/32 198.211.109.100/32 198.235.24.0/24 199.45.154.0/23 199.85.8.144/32
199.165.159.0/24 199.195.248.205/32 200.138.46.0/24 202.112.47.54/32 202.112.47.150/32 204.44.125.237/32 204.48.24.63/32 204.76.203.0/24
204.130.133.143/32 204.130.133.193/32 204.188.219.9/32 204.188.254.145/32 204.188.254.146/32 204.188.254.228/32 204.188.254.231/32 205.210.31.0/24
206.81.12.187/32 206.81.24.74/32 206.81.24.227/32 206.168.32.0/22 206.189.2.13/32 206.189.5.249/32 206.189.19.19/32 206.189.95.232/32
206.189.225.181/32 206.189.233.36/32 207.90.244.0/24 207.154.197.113/32 207.154.212.47/32 207.244.234.126/32 207.244.235.11/32 207.244.236.30/32
207.244.249.143/32 207.244.251.12/32 207.244.251.14/32 207.244.251.16/32 208.98.38.114/32 208.98.38.173/32 208.98.38.223/32 208.98.38.229/32
208.98.38.234/32 209.38.96.38/32 209.38.111.38/32 209.38.208.202/32 209.38.208.214/32 209.38.248.17/32 209.58.160.54/32 209.97.180.8/32
209.126.86.45/32 209.126.86.46/32 209.126.87.66/32 209.126.87.68/32 209.126.87.70/32 209.126.87.72/31 209.126.87.112/32 209.126.151.114/31
209.126.151.116/30 209.126.151.120/30 209.126.151.124/31 209.145.53.57/32 209.145.58.124/32 209.145.59.230/32 209.188.108.0/24 209.237.154.0/24
212.41.10.41/32 212.41.12.45/32 212.41.12.46/31 212.41.12.48/32 212.41.13.23/32 212.41.13.24/31 212.41.26.138/32 212.67.10.218/32 212.67.11.37/32
212.67.11.128/32 212.67.11.136/32 212.67.11.167/32 212.67.11.227/32 212.67.11.233/32 212.67.11.234/32 212.73.148.0/24 212.83.184.12/30
212.83.184.16/31 212.83.184.18/32 212.129.7.56/32 212.129.7.154/32 212.129.9.141/32 212.129.10.138/32 212.129.10.245/32 212.129.53.181/32
212.164.59.250/32 212.192.156.0/22 213.32.122.80/28 213.59.217.242/32 213.166.84.32/27 213.219.38.113/32 216.25.88.0/21 216.25.124.0/24
216.31.0.17/32 216.31.13.40/30 216.117.2.176/28 216.180.246.0/24 216.218.206.64/26 217.12.206.132/32 217.21.193.74/32 217.60.197.0/24 217.60.241.0/24
217.60.250.0/24 217.65.82.18/32 217.146.80.96/27 222.186.13.130/32
GS_BUILTIN_SCANNERS
  # Never block: Yandex (AS13238), Yandex.Cloud (AS200350), Yandex Cloud CDN edges (AS215013), Cloudflare
  tr ' ' '\n' >"$d/builtin-never.txt" <<'GS_BUILTIN_NEVER'
5.45.192.0/18 5.255.192.0/18 31.44.8.0/21 37.9.64.0/18 37.140.128.0/18 37.230.168.0/23 37.230.172.0/22 46.21.244.0/22 46.243.210.0/23 51.250.0.0/17
62.84.112.0/20 77.88.0.0/18 81.26.176.0/20 84.201.128.0/18 84.252.128.0/20 84.252.160.0/19 87.250.224.0/19 89.104.112.0/23 89.169.128.0/18
89.223.9.0/24 89.232.188.0/23 92.255.1.0/24 92.255.3.0/24 92.255.13.0/24 92.255.15.0/24 92.255.112.0/20 93.77.160.0/19 93.158.128.0/18
94.131.190.0/23 95.108.128.0/17 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 103.76.52.0/22 104.16.0.0/13 104.24.0.0/14 108.162.192.0/18
111.88.144.0/20 111.88.240.0/20 130.193.32.0/19 131.0.72.0/22 141.8.128.0/18 141.101.64.0/18 153.51.32.0/19 153.51.96.0/19 153.51.160.0/19
158.160.0.0/16 162.158.0.0/15 172.64.0.0/13 173.245.48.0/20 178.154.128.0/17 185.32.187.0/24 185.206.164.0/22 188.72.103.0/24 188.72.104.0/23
188.72.110.0/23 188.72.112.0/23 188.114.96.0/20 190.93.240.0/20 193.32.216.0/22 194.247.51.0/24 197.234.240.0/22 198.41.128.0/17 213.130.80.0/21
213.165.192.0/19 213.180.192.0/19 217.28.224.0/20 217.198.168.0/21
GS_BUILTIN_NEVER
  # RU mobile operators (MTS 8359, MegaFon 31133/25159/31213/31163, Beeline 16345/3216, T2 15378/12958):
  # reputation lists often contain their CGNAT addresses → thousands of real clients behind one IP.
  tr ' ' '\n' >"$d/builtin-mobile-ru.txt" <<'GS_BUILTIN_MOBILE'
2.95.0.0/16 5.144.96.0/19 5.189.208.0/21 5.227.0.0/17 5.227.160.0/23 5.227.162.0/24 5.227.164.0/22 5.227.170.0/23 31.13.144.0/21 31.15.80.0/20
31.29.144.0/23 31.29.146.0/24 31.29.150.0/23 31.29.177.0/24 31.40.112.0/20 31.131.92.0/22 31.173.0.0/16 37.9.240.0/22 37.9.244.0/23 37.9.247.0/24
37.28.160.0/19 37.29.0.0/17 37.139.192.0/18 37.208.96.0/21 37.208.120.0/21 37.230.245.0/24 45.141.92.0/24 46.16.64.0/21 46.16.96.0/21 46.20.176.0/20
46.23.184.0/21 46.42.128.0/18 46.148.240.0/20 46.229.128.0/20 46.232.164.0/22 46.232.200.0/21 46.237.40.0/22 46.250.52.0/22 46.250.64.0/19
62.5.128.0/17 62.64.0.0/19 62.89.194.0/24 62.105.44.0/22 62.105.48.0/20 62.105.128.0/19 62.113.88.0/24 62.118.0.0/16 62.141.64.0/18 62.152.64.0/19
62.168.224.0/19 62.182.136.0/21 62.220.48.0/21 62.231.0.0/19 66.90.90.0/23 66.90.92.0/23 66.90.95.0/24 66.90.96.0/24 66.90.108.0/23 66.90.121.0/24
66.90.122.0/24 77.41.142.0/23 77.41.144.0/20 77.41.160.0/19 77.41.248.0/21 77.43.128.0/17 77.66.128.0/17 77.105.187.0/24 77.106.196.0/23
77.220.60.0/22 77.239.192.0/19 78.25.64.0/18 78.107.56.0/24 78.107.67.0/24 78.107.124.0/24 78.109.47.0/24 78.153.0.0/19 78.159.239.0/24 79.104.0.0/17
79.104.192.0/19 79.111.120.0/24 79.111.122.0/24 79.120.30.0/24 79.120.102.0/24 79.120.104.0/24 79.120.106.0/24 79.120.112.0/24 79.143.238.0/23
79.171.115.0/24 79.171.208.0/24 80.80.96.0/19 80.83.225.0/24 80.83.228.0/22 80.83.232.0/23 80.83.234.0/24 80.83.236.0/22 80.243.73.0/24
80.243.78.0/23 80.253.10.0/24 80.253.12.0/22 80.255.129.0/24 80.255.130.0/23 80.255.132.0/23 80.255.134.0/24 80.255.136.0/21 80.255.144.0/23
80.255.147.0/24 80.255.148.0/22 80.255.153.0/24 80.255.154.0/23 80.255.158.0/24 81.9.0.0/17 81.23.160.0/20 81.91.32.0/19 81.177.72.0/21 81.195.0.0/16
81.201.16.0/20 81.211.0.0/17 81.222.0.0/17 81.222.129.0/24 81.222.144.0/20 81.222.176.0/22 81.222.180.0/23 81.222.182.0/24 81.222.184.0/21
81.222.196.0/23 81.222.202.0/24 81.222.204.0/23 81.222.218.0/23 81.222.221.0/24 81.222.228.0/24 81.222.244.0/23 81.222.249.0/24 82.96.192.0/18
82.142.128.0/18 82.149.128.0/19 82.204.128.0/17 83.102.132.0/24 83.102.160.0/24 83.136.24.0/21 83.149.0.0/18 83.169.192.0/18 83.220.224.0/22
83.220.232.0/21 83.220.240.0/20 83.222.212.0/22 83.222.216.0/21 83.229.211.0/24 83.237.0.0/16 83.242.128.0/17 84.17.0.0/19 84.204.0.0/16
85.21.54.0/24 85.21.223.0/24 85.26.128.0/17 85.115.236.0/22 85.115.243.0/24 85.115.246.0/24 85.115.248.0/23 85.115.252.0/22 85.140.0.0/15
85.235.32.0/19 85.235.160.0/19 85.249.16.0/20 85.249.128.0/19 85.249.160.0/20 85.249.230.0/24 85.249.244.0/23 85.249.252.0/23 87.229.142.0/23
87.229.144.0/23 87.229.176.0/21 87.229.186.0/23 87.229.192.0/21 87.229.204.0/22 87.229.208.0/20 87.229.224.0/19 87.254.132.0/23 89.22.188.0/22
89.31.184.0/21 89.106.192.0/21 89.107.194.0/23 89.112.128.0/17 89.113.0.0/20 89.113.24.0/21 89.113.32.0/19 89.113.96.0/21 89.113.120.0/21
89.113.144.0/20 89.113.192.0/18 89.169.80.0/20 89.175.0.0/16 89.178.203.0/24 89.178.236.0/24 89.249.144.0/20 89.251.111.0/24 91.76.0.0/18
91.76.215.0/24 91.76.216.0/21 91.77.0.0/16 91.78.0.0/15 91.143.48.0/20 91.185.76.0/22 91.185.87.0/24 91.193.176.0/22 91.195.210.0/23 91.205.168.0/22
91.216.147.0/24 91.223.226.0/24 92.36.0.0/17 92.38.42.0/24 92.39.64.0/20 92.39.208.0/20 92.43.184.0/21 92.246.200.0/22 92.246.216.0/22
92.246.222.0/23 93.90.224.0/20 93.189.48.0/21 94.25.128.0/17 94.72.0.0/18 94.77.128.0/18 94.140.128.0/19 94.229.232.0/24 94.232.11.0/24
94.232.14.0/23 94.243.0.0/19 94.243.32.0/20 94.243.48.0/22 94.243.52.0/23 94.243.56.0/23 95.25.120.0/21 95.25.128.0/18 95.25.204.0/22 95.25.208.0/21
95.26.0.0/21 95.26.8.0/22 95.26.160.0/21 95.26.168.0/22 95.26.174.0/23 95.26.176.0/21 95.26.184.0/23 95.26.192.0/22 95.26.208.0/21 95.26.228.0/22
95.26.232.0/22 95.26.236.0/23 95.27.0.0/21 95.27.8.0/22 95.27.68.0/22 95.27.72.0/21 95.27.80.0/22 95.27.84.0/23 95.27.188.0/22 95.30.0.0/16
95.31.56.0/22 95.31.64.0/22 95.31.119.0/24 95.31.120.0/22 95.64.128.0/17 95.104.128.0/17 95.139.0.0/17 95.141.225.0/24 95.141.227.0/24
95.141.228.0/22 95.141.232.0/21 95.153.128.0/17 95.169.128.0/19 95.215.248.0/22 95.220.224.0/21 95.221.0.0/20 109.71.200.0/21 109.94.176.0/20
109.95.160.0/21 109.95.228.0/23 109.105.64.0/19 109.106.192.0/19 109.161.56.0/24 109.170.68.0/24 109.170.92.0/24 109.170.96.0/23 109.170.98.0/24
109.170.107.0/24 109.188.0.0/16 109.196.16.0/20 109.196.192.0/20 109.197.200.0/21 109.198.224.0/19 109.201.64.0/21 109.236.96.0/20 128.70.0.0/15
128.74.248.0/22 128.75.224.0/19 128.140.164.0/24 128.140.166.0/24 128.204.64.0/23 128.204.66.0/24 128.204.70.0/23 128.204.72.0/21 130.49.216.0/23
139.181.32.0/24 141.101.232.0/24 141.105.24.0/21 176.14.0.0/16 176.15.0.0/17 176.15.128.0/21 176.15.136.0/23 176.15.140.0/22 176.15.144.0/24
176.15.148.0/22 176.15.161.0/24 176.15.162.0/23 176.15.164.0/22 176.15.168.0/21 176.15.176.0/21 176.15.185.0/24 176.15.186.0/23 176.15.188.0/22
176.15.192.0/20 176.15.208.0/21 176.15.216.0/23 176.15.220.0/22 176.15.240.0/20 176.52.52.0/22 176.52.56.0/22 176.52.80.0/21 176.59.0.0/18
176.59.160.0/19 176.118.8.0/21 176.118.16.0/20 176.192.22.0/24 176.192.50.0/24 176.192.75.0/24 176.192.116.0/24 176.193.72.0/21 176.222.16.0/23
176.222.200.0/21 176.241.96.0/21 178.72.64.0/18 178.141.0.0/16 178.155.0.0/17 178.157.128.0/18 178.159.16.0/20 178.176.0.0/14 178.216.216.0/21
178.217.40.0/21 185.3.32.0/22 185.4.144.0/22 185.12.208.0/23 185.35.192.0/22 185.59.137.0/24 185.59.138.0/23 185.103.26.0/23 185.132.20.0/22
185.138.206.0/23 185.168.236.0/22 185.190.166.0/24 185.210.140.0/23 185.224.96.0/22 185.242.16.0/22 188.65.241.0/24 188.65.242.0/23 188.65.244.0/22
188.66.32.0/22 188.66.38.0/23 188.75.192.0/18 188.94.168.0/21 188.162.0.0/16 188.170.0.0/16 188.191.86.0/23 188.191.240.0/21 192.162.0.0/22
193.8.211.0/24 193.22.148.0/22 193.104.128.0/24 193.169.118.0/23 193.189.68.0/23 193.201.228.0/22 193.228.164.0/22 193.232.55.0/24 194.32.223.0/24
194.33.81.0/24 194.67.0.0/18 194.85.128.0/19 194.126.203.0/24 194.154.64.0/19 194.186.0.0/16 195.7.160.0/19 195.16.32.0/19 195.16.96.0/19
195.19.217.0/24 195.34.0.0/18 195.42.64.0/19 195.46.160.0/19 195.58.3.0/24 195.62.54.0/23 195.68.128.0/18 195.96.64.0/19 195.122.224.0/19
195.131.128.0/18 195.151.22.0/24 195.190.96.0/19 195.191.18.0/23 195.209.160.0/20 195.210.128.0/18 195.218.128.0/17 195.222.160.0/19 195.230.70.0/23
195.230.91.0/24 195.230.92.0/24 195.239.0.0/16 212.13.26.0/24 212.30.128.0/18 212.44.128.0/19 212.45.247.0/24 212.46.192.0/18 212.48.32.0/19
212.48.135.0/24 212.48.144.0/23 212.48.150.0/24 212.48.152.0/23 212.48.154.0/24 212.48.158.0/23 212.69.96.0/19 212.77.128.0/19 212.109.208.0/21
212.119.192.0/18 212.188.0.0/17 212.248.0.0/17 213.27.0.0/17 213.33.128.0/17 213.87.0.0/16 213.108.128.0/23 213.147.32.0/19 213.154.160.0/19
213.176.228.0/22 213.221.0.0/18 213.242.220.0/24 213.243.109.0/24 213.243.116.0/24 217.8.224.0/20 217.15.137.0/24 217.15.156.0/24 217.19.112.0/20
217.20.64.0/20 217.66.148.0/22 217.66.152.0/21 217.69.192.0/19 217.74.240.0/20 217.118.64.0/24 217.118.66.0/24 217.118.68.0/22 217.118.72.0/21
217.118.81.0/24 217.118.82.0/23 217.118.84.0/22 217.118.88.0/22 217.118.92.0/23 217.118.95.0/24 217.169.82.0/23 217.169.84.0/22 217.169.88.0/21
217.173.24.0/22 217.195.212.0/23 217.195.216.0/23 217.195.219.0/24
GS_BUILTIN_MOBILE
  # VK / MAX / OK / mail.ru networks (C24Be blacklist-vk + AS47541/47764/28709/49797/60863):
  # MAX «HOST_REACHABILITY» reports the exit IP of VPN users → RKN. Outbound NEW only (snitch guard).
  tr ' ' '\n' >"$d/builtin-snitch.txt" <<'GS_BUILTIN_SNITCH'
5.61.16.0/21 5.61.232.0/21 5.101.40.0/22 5.181.60.0/22 5.188.140.0/22 31.177.104.0/22 37.139.32.0/22 37.139.40.0/22 45.84.128.0/22 45.136.20.0/22
62.217.160.0/20 79.137.132.0/24 79.137.139.0/24 79.137.142.0/24 79.137.157.0/24 79.137.164.0/24 79.137.167.0/24 79.137.174.0/23 79.137.180.0/24
79.137.183.0/24 79.137.240.0/21 81.177.12.0/24 81.177.31.64/26 83.166.232.0/21 83.166.248.0/21 83.217.216.0/22 83.222.28.0/22 84.23.52.0/22
85.114.31.108/30 85.142.115.0/24 85.192.32.0/22 85.198.106.0/23 87.239.104.0/21 87.240.128.0/18 87.242.112.0/22 89.208.84.0/22 89.208.196.0/22
89.208.208.0/22 89.208.216.0/21 89.208.228.0/22 89.221.228.0/22 89.221.232.0/21 90.156.148.0/22 90.156.212.0/22 90.156.216.0/22 90.156.232.0/21
91.219.224.0/22 91.231.132.0/22 91.237.76.0/24 92.38.217.0/24 93.153.255.84/30 93.186.224.0/20 94.100.176.0/20 94.139.244.0/22 95.142.192.0/20
95.163.32.0/19 95.163.133.0/24 95.163.180.0/22 95.163.208.0/21 95.163.216.0/22 95.163.248.0/21 95.213.0.0/17 109.120.180.0/22 109.120.188.0/22
128.140.168.0/21 130.49.224.0/19 138.16.192.0/20 138.16.240.0/20 146.185.208.0/22 146.185.240.0/22 155.212.192.0/20 160.5.208.0/20 161.104.104.0/21
168.113.128.0/20 176.112.168.0/21 178.22.88.0/21 178.237.16.0/20 185.5.136.0/22 185.6.244.0/22 185.16.148.0/22 185.16.244.0/22 185.29.128.0/22
185.32.248.0/22 185.86.144.0/22 185.100.104.0/22 185.130.112.0/22 185.131.68.0/22 185.180.200.0/22 185.187.63.0/24 185.226.52.0/22 185.241.192.0/22
188.93.56.0/21 193.203.40.0/22 194.84.16.12/30 194.186.63.0/24 195.211.20.0/22 195.218.190.0/23 195.239.247.0/24 212.111.84.0/22 212.233.72.0/21
212.233.88.0/21 212.233.96.0/22 212.233.120.0/22 213.219.212.0/22 217.16.16.0/20 217.20.144.0/20 217.69.128.0/20 217.174.188.0/22
GS_BUILTIN_SNITCH
  sed -i '/^$/d' "$d"/builtin-*.txt 2>/dev/null || true
}

install_blocklist() {
  if [[ "$DO_BLOCKLIST" -eq 0 ]]; then
    warn "Skipping scanner blocklist (--no-blocklist)"
    return 0
  fi
  step "Списки: сканеры (все порты) · репутация (только SSH) · VK/MAX (исходящие) — ipset + ежедневное обновление"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b install /usr/local/sbin/scanner-block-refresh.sh (OpenFilters all feeds + Skipa + scanner ASNs; builtin offline fallback)\n' "${C_YEL}" "${C_RESET}"
    printf '%b[DRY]%b ipsets: scanner-block(+6) all ports · gorecshit-rep SSH only · gorecshit-snitch outbound; never-block Yandex/CF/RU-mobile\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi

  mkdir -p /etc/scanner-block
  local f
  for f in /usr/local/sbin/scanner-block-refresh.sh /etc/systemd/system/scanner-block.service \
           /etc/systemd/system/scanner-block-refresh.service /etc/systemd/system/scanner-block-refresh.timer \
           /etc/scanner-block/never-block.txt; do
    backup_file "$f"
  done
  if [[ -n "$BLOCKLIST_FROM" ]]; then
    printf '%s\n' "$BLOCKLIST_FROM" >/etc/scanner-block/blocklist-from.conf
  fi
  _write_builtin_lists

  {
    echo "# Managed by ${SCRIPT_NAME} ${VERSION} — never include these in any gorecshit ipset"
    echo "$PANEL_IP"
    if [[ -n "$SSH_CLIENT_IP" ]]; then echo "$SSH_CLIENT_IP"; fi
    local a
    while IFS= read -r a; do echo "$a"; done < <(foreach_csv_ip "$ALLOW_SSH_FROM")
    while IFS= read -r a; do echo "$a"; done < <(foreach_csv_ip "$RELAY_IPS")
    printf '%s\n' 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8 169.254.0.0/16 100.64.0.0/10
    # Yandex Cloud CDN edges (AS215013) — CDN-нода умрёт, если их заблокировать
    printf '%s\n' 188.72.96.0/19 89.223.9.0/24 94.131.190.0/23
    # Yandex core (legacy entries kept)
    printf '%s\n' 5.45.192.0/18 5.255.192.0/18 37.9.64.0/18 37.140.128.0/18 77.88.0.0/18 87.250.224.0/19 \
      93.158.128.0/18 95.108.128.0/17 141.8.128.0/18 178.154.128.0/17 213.180.192.0/19 185.32.184.0/22
    # this server's own addresses
    ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1
  } >/etc/scanner-block/never-block.txt

  cat >/usr/local/sbin/scanner-block-refresh.sh <<'REFRESH_EOF'
#!/bin/bash
# gorecshit scanner-block refresh (v2.7.0). Safe: on any failure keeps the previous lists;
# with no internet/DNS uses built-in lists. --local-only: just (re)load ipsets from disk (boot path).
set -uo pipefail
LOCAL_ONLY=0
[ "${1:-}" = "--local-only" ] && LOCAL_ONLY=1

DIR=/etc/scanner-block
LIST="$DIR/blocklist.txt"            # scanners v4  → DROP NEW on all ports
LIST6="$DIR/blocklist6.txt"          # scanners v6  → DROP NEW on all ports
REP="$DIR/reputation.txt"            # attackers v4 → DROP NEW on SSH only (never on client ports)
SNITCH="$DIR/snitch.txt"             # VK/MAX v4    → REJECT outbound NEW (netguard)

NEVER_DYN="$DIR/never-dynamic.txt"
MOB_DYN="$DIR/mobile-ru-dynamic.txt"
FROM_CONF="$DIR/blocklist-from.conf"
CT=8
MT=25
mkdir -p "$DIR"

log() { echo "[scanner-block] $*"; }

OF_V4_FALLBACK="a10networks academyforinternetresearch adscore agentcensus alphastrike apcosys binaryedge bitsight bufferoverrun censys criminalip crowdstrikefalconsurface cybcube cybergreen cyberok cyberresilience cypex dataplane deepfield detectify driftnet edgewatch eset flowiq fofa forestengine groupib hackertarget hadrian hunter infrawatch internetmeasurementresearch internetmetrics internetresearchproject internettl intrinsec intruder ipinfo ipip ki3 knoq leakix mandiantasm modat netlas netscout odin onlyscans onyphe other paloaltonetworks pocnroll probethenet quake rapid7 recordedfuture recyber researchscanner rootevidence securityresearch shadowforce shadowserver shodan silentpush strechoid synthient tenableasm tttx universities virustotal visionheight xmco zern zoomeye"
OF_V6_FALLBACK="alphastrike apcosys binaryedge bitsight censys dataplane deepfield driftnet forestengine hadrian infrawatch internetmeasurementresearch ipinfo leakix onyphe other paloaltonetworks rapid7 shadowserver shodan tenableasm universities"
SCANNER_ASNS="209334 398324 398705 398722 211298 213412 202425 51396"
NEVER_ASNS="13238 200350 215013"
MOBILE_ASNS="8359 31133 25159 31213 31163 16345 3216 15378 12958"
SNITCH_ASNS="47541 47764 28709 49797 60863"

js_mirrors() {
  local url="$1"
  if [[ "$url" =~ ^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.*)$ ]]; then
    echo "https://cdn.jsdelivr.net/gh/${BASH_REMATCH[1]}/${BASH_REMATCH[2]}@${BASH_REMATCH[3]}/${BASH_REMATCH[4]}"
    echo "https://fastly.jsdelivr.net/gh/${BASH_REMATCH[1]}/${BASH_REMATCH[2]}@${BASH_REMATCH[3]}/${BASH_REMATCH[4]}"
  fi
  echo "$url"
}
fetch_one() {
  # fetch_one <outfile> <url...>
  local out="$1" u; shift
  for u in "$@"; do
    if curl -fsSL --connect-timeout "$CT" --max-time "$MT" -o "$out.part" "$u" 2>/dev/null && [ -s "$out.part" ]; then
      mv -f "$out.part" "$out"; return 0
    fi
  done
  rm -f "$out.part"; return 1
}
fetch_gh() { local out="$1" raw="$2" urls; mapfile -t urls < <(js_mirrors "$raw"); fetch_one "$out" "${urls[@]}"; }
ripe_prefixes() {
  # ripe_prefixes <outfile> <asn...>  → announced v4+v6 prefixes (RIPEstat, no key)
  local out="$1" as; shift
  : >"$out.part"
  for as in "$@"; do
    curl -fsS --connect-timeout "$CT" --max-time "$MT" \
      "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${as}&sourceapp=gorecshit" 2>/dev/null \
      | grep -oE '"prefix": *"[^"]+"' | sed -E 's/.*"([^"]+)"$/\1/' >>"$out.part" || true
  done
  if [ -s "$out.part" ]; then mv -f "$out.part" "$out"; return 0; fi
  rm -f "$out.part"; return 1
}
import_from_source() {
  local src="$1" dest="$2"
  [ -n "$src" ] || return 1
  if [[ "$src" =~ ^https?:// ]]; then
    curl -fsSL --connect-timeout "$CT" --max-time "$MT" -o "$dest" "$src" || return 1
  elif [ -f "$src" ]; then
    cp -f "$src" "$dest" || return 1
  else
    scp -o ConnectTimeout=12 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
      "root@${src}:/etc/scanner-block/blocklist.txt" "$dest" 2>/dev/null || return 1
  fi
  [ -s "$dest" ]
}

download_all() {
  local T="$1" n jobs=0
  mkdir -p "$T/scan" "$T/scan6" "$T/rep" "$T/snitch" "$T/meta"
  # OpenFilters feed names: discover live (new scanners appear often), else built-in names
  local v4="$OF_V4_FALLBACK" v6="$OF_V6_FALLBACK" api
  api="$(curl -fsS --connect-timeout "$CT" --max-time "$MT" https://api.github.com/repos/OpenFilters/internet-scanners/contents/cidr 2>/dev/null \
        || curl -fsS --connect-timeout "$CT" --max-time "$MT" 'https://data.jsdelivr.com/v1/packages/gh/OpenFilters/internet-scanners@main?structure=flat' 2>/dev/null || true)"
  if [ -n "$api" ]; then
    local l4 l6
    l4="$(printf '%s' "$api" | grep -oE '[a-z0-9_-]+_v4\.txt' | sed 's/_v4\.txt$//' | sort -u | tr '\n' ' ')"
    l6="$(printf '%s' "$api" | grep -oE '[a-z0-9_-]+_v6\.txt' | sed 's/_v6\.txt$//' | sort -u | tr '\n' ' ')"
    [ -n "$l4" ] && v4="$l4"
    [ -n "$l6" ] && v6="$l6"
  fi
  local BASE="https://raw.githubusercontent.com/OpenFilters/internet-scanners/main/cidr"
  for n in $v4; do
    fetch_gh "$T/scan/of_$n.txt" "$BASE/${n}_v4.txt" &
    jobs=$((jobs+1)); [ $((jobs % 12)) -eq 0 ] && wait
  done
  for n in $v6; do
    fetch_gh "$T/scan6/of_$n.txt" "$BASE/${n}_v6.txt" &
    jobs=$((jobs+1)); [ $((jobs % 12)) -eq 0 ] && wait
  done
  wait
  # RU scanners (CyberOK Skipa, RU state networks), community anti-scanner list
  fetch_gh "$T/scan/skipa.txt" https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt &
  fetch_gh "$T/scan/antiscanner.txt" https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/main/public/antiscanner.list &
  fetch_gh "$T/scan/c24be_gov.txt" https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist-v4.txt &
  fetch_gh "$T/snitch/c24be_vk.txt" https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist-vk-v4.txt &
  for n in stretchoid binaryedge shadowserver censys internet-measurement.com; do
    fetch_one "$T/scan/wdes-$n.txt" "https://security.wdes.eu/scanners/$n.txt" &
  done
  wait
  # Hijacked / bulletproof netblocks — nobody legit connects from there (all ports)
  fetch_one "$T/scan/spamhaus_drop.txt" https://www.spamhaus.org/drop/drop.txt \
    https://cdn.jsdelivr.net/gh/firehol/blocklist-ipsets@master/spamhaus_drop.netset &
  fetch_one "$T/scan/spamhaus_edrop.txt" https://www.spamhaus.org/drop/edrop.txt \
    https://cdn.jsdelivr.net/gh/firehol/blocklist-ipsets@master/spamhaus_edrop.netset &
  # Reputation (brute-force/attackers). Contains CGNAT addresses of mobile operators → SSH only!
  fetch_one "$T/rep/firehol_level1.netset" https://iplists.firehol.org/files/firehol_level1.netset \
    https://cdn.jsdelivr.net/gh/firehol/blocklist-ipsets@master/firehol_level1.netset &
  fetch_one "$T/rep/firehol_level2.netset" https://iplists.firehol.org/files/firehol_level2.netset \
    https://cdn.jsdelivr.net/gh/firehol/blocklist-ipsets@master/firehol_level2.netset &
  fetch_one "$T/rep/blocklist_de_all.txt" https://lists.blocklist.de/lists/all.txt &
  fetch_one "$T/rep/cins_army.txt" https://cinsscore.com/list/ci-badguys.txt &
  fetch_gh "$T/rep/ipsum3.txt" https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt &
  # ASN-based (RIPEstat): scanners without public lists, never-block, RU mobile, VK
  ripe_prefixes "$T/scan/asn_scanners.txt" $SCANNER_ASNS &
  ripe_prefixes "$T/meta/never_asn.txt" $NEVER_ASNS &
  ripe_prefixes "$T/meta/mobile_asn.txt" $MOBILE_ASNS &
  ripe_prefixes "$T/snitch/asn_vk.txt" $SNITCH_ASNS &
  fetch_one "$T/meta/cf4.txt" https://www.cloudflare.com/ips-v4 &
  fetch_one "$T/meta/cf6.txt" https://www.cloudflare.com/ips-v6 &
  wait
  # cache dynamic never/mobile lists only when they look sane
  if [ "$(cat "$T"/meta/never_asn.txt "$T"/meta/cf4.txt 2>/dev/null | grep -c .)" -ge 20 ]; then
    cat "$T"/meta/never_asn.txt "$T"/meta/cf4.txt "$T"/meta/cf6.txt 2>/dev/null >"$NEVER_DYN.new" && mv -f "$NEVER_DYN.new" "$NEVER_DYN"
  fi
  if [ "$(grep -c . "$T/meta/mobile_asn.txt" 2>/dev/null || echo 0)" -ge 200 ]; then
    cp -f "$T/meta/mobile_asn.txt" "$MOB_DYN"
  fi
  # copy scanners v6 from the ASN file too
  grep ':' "$T/scan/asn_scanners.txt" 2>/dev/null >"$T/scan6/asn_scanners6.txt" || true
  local got
  got="$(find "$T/scan" "$T/rep" -type f -size +0 2>/dev/null | wc -l)"
  log "downloaded feeds: $got"
  [ "$got" -gt 0 ]
}

build_lists() {
  # build_lists <tmpdir>  → writes LIST/LIST6/REP/SNITCH (+.new then mv). Needs python3.
  local T="$1"
  command -v python3 >/dev/null 2>&1 || { log "python3 нет — оставляю встроенные/старые списки"; return 1; }
  python3 - "$T" "$DIR" <<'PY'
import sys, os, re, glob, ipaddress
T, D = sys.argv[1], sys.argv[2]
def nets(paths, v=4):
    out = []
    for p in paths:
        try:
            fh = open(p, errors="ignore")
        except OSError:
            continue
        for line in fh:
            tok = re.split(r"[\s;#,]", line.strip(), 1)[0] if line.strip() else ""
            if not tok or tok[0] in "#;":
                continue
            try:
                n = ipaddress.ip_network(tok, strict=False)
            except ValueError:
                continue
            if n.version == v:
                out.append(n)
    return out
def g(*pats):
    r = []
    for p in pats:
        r += glob.glob(p)
    return r
never4 = nets(g(D + "/never-block.txt", D + "/builtin-never.txt", D + "/never-dynamic.txt"))
never6 = nets(g(D + "/never-dynamic.txt", D + "/never-block.txt"), 6)
mobile = nets(g(D + "/builtin-mobile-ru.txt", D + "/mobile-ru-dynamic.txt"))
bog4 = [ipaddress.ip_network(x) for x in ("0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16",
        "172.16.0.0/12","192.0.0.0/24","192.0.2.0/24","192.168.0.0/16","198.18.0.0/15","198.51.100.0/24",
        "203.0.113.0/24","224.0.0.0/3")]
def collapse(lst):
    return list(ipaddress.collapse_addresses(lst))
def filt(lst, deny, minpref):
    import bisect
    deny = collapse(deny)  # disjoint + sorted
    starts = [int(n.network_address) for n in deny]
    ends = [int(n.broadcast_address) for n in deny]
    keep = []
    for n in lst:
        if n.prefixlen < minpref:
            continue
        lo, hi = int(n.network_address), int(n.broadcast_address)
        i = bisect.bisect_right(starts, hi) - 1
        if i >= 0 and ends[i] >= lo:
            continue
        keep.append(n)
    return collapse(keep)
def write(path, lst):
    with open(path + ".new", "w") as fh:
        fh.write("\n".join(str(n) for n in lst) + ("\n" if lst else ""))
    os.replace(path + ".new", path)
    return len(lst)
deny4 = never4 + bog4 + mobile
scan = nets(g(T + "/scan/*", D + "/builtin-scanners.txt"))
scan = filt(scan, deny4, 12)
rep = nets(g(T + "/rep/*"))
rep = filt(rep, deny4, 12)
scan6 = nets(g(T + "/scan6/*"), 6)
scan6 = filt(scan6, never6 + [ipaddress.ip_network(x) for x in ("::/8","fc00::/7","fe80::/10","ff00::/8")], 24)
snitch = nets(g(T + "/snitch/*", D + "/builtin-snitch.txt"))
snitch = filt(snitch, never4 + bog4, 8)
snitch6 = filt(nets(g(T + "/snitch/*"), 6), never6, 19)
c = {}
c["scan"] = write(D + "/blocklist.txt", scan) if scan else 0
c["rep"] = write(D + "/reputation.txt", rep) if rep else 0
c["scan6"] = write(D + "/blocklist6.txt", scan6) if scan6 else 0
c["snitch"] = write(D + "/snitch.txt", snitch) if snitch else 0
c["snitch6"] = write(D + "/snitch6.txt", snitch6) if snitch6 else 0
print("BUILT scanners=%(scan)d reputation=%(rep)d scanners6=%(scan6)d snitch=%(snitch)d snitch6=%(snitch6)d" % c)
PY
}

ensure_from_builtin() {
  # no previous list on disk → start from built-in (already filtered)
  [ -s "$LIST" ] || cp -f "$DIR/builtin-scanners.txt" "$LIST" 2>/dev/null || true
  [ -s "$SNITCH" ] || cp -f "$DIR/builtin-snitch.txt" "$SNITCH" 2>/dev/null || true
}

load_set() {
  # load_set <name> <family inet|inet6> <file>   (atomic swap via ipset restore)
  local SET="$1" fam="$2" file="$3" tmp
  ipset create "$SET" hash:net family "$fam" maxelem 1048576 -exist 2>/dev/null || true
  [ -s "$file" ] || { log "$SET: list empty (set kept)"; return 0; }
  tmp="$(mktemp)"
  {
    echo "create ${SET}-new hash:net family $fam maxelem 1048576 -exist"
    echo "flush ${SET}-new"
    grep -vE '^\s*(#|$)' "$file" | sed "s/^/add ${SET}-new /"
  } >"$tmp"
  if ipset restore -exist <"$tmp" 2>/dev/null; then
    ipset swap "${SET}-new" "$SET" && ipset destroy "${SET}-new" 2>/dev/null
  else
    log "$SET: ipset restore failed — keeping previous contents"
    ipset destroy "${SET}-new" 2>/dev/null || true
  fi
  rm -f "$tmp"
  log "$SET: $(ipset list "$SET" -t 2>/dev/null | awk -F': ' '/Number of entries/{print $2}') entries"
}

load_all() {
  ensure_from_builtin
  load_set scanner-block inet "$LIST"
  load_set gorecshit-rep inet "$REP"
  load_set gorecshit-snitch inet "$SNITCH"
  load_set scanner-block6 inet6 "$LIST6"
  load_set gorecshit-snitch6 inet6 "$DIR/snitch6.txt"
  # CDN edges (Yandex Cloud CDN / Cloudflare): exempt from per-source anti-probe limits (one edge = many users)
  grep -hvE '^\s*(#|$)' "$DIR/builtin-never.txt" "$NEVER_DYN" 2>/dev/null | grep -v ':' | sort -u >"$DIR/cdn-edges.txt" || true
  load_set gorecshit-cdn inet "$DIR/cdn-edges.txt"
  # Without the UFW hook (blocklist installed without ufw) — minimal INPUT rule (allow-list never in sets)
  if ! grep -q 'gorecshit-managed-begin' /etc/ufw/before.rules 2>/dev/null; then
    iptables -C INPUT -m conntrack --ctstate NEW -m set --match-set scanner-block src -j DROP 2>/dev/null \
      || iptables -I INPUT 1 -m conntrack --ctstate NEW -m set --match-set scanner-block src -j DROP 2>/dev/null || true
  fi
}

if [ "$LOCAL_ONLY" -eq 0 ]; then
  if ! getent ahostsv4 raw.githubusercontent.com >/dev/null 2>&1 && ! getent ahostsv4 stat.ripe.net >/dev/null 2>&1; then
    log "DNS не работает — скачивание пропущено, используются встроенные/сохранённые списки (пропишите nameserver 1.1.1.1)"
    if [ -s "$LIST" ] && [ "$(grep -c . "$LIST")" -gt "$(grep -c . "$DIR/builtin-scanners.txt" 2>/dev/null || echo 0)" ]; then
      log "оставляю сохранённые списки ($(grep -c . "$LIST") подсетей) — они полнее встроенных"
    else
      T="$(mktemp -d)"; build_lists "$T" || true; rm -rf "$T"
    fi
  else
    T="$(mktemp -d)"
    if download_all "$T"; then
      build_lists "$T" || log "build failed — keeping previous lists"
    else
      log "DOWNLOAD_FAILED all sources"
      src=""
      [ -f "$FROM_CONF" ] && src="$(head -1 "$FROM_CONF" | tr -d '\r')"
      [ -n "${GORECSHIT_BLOCKLIST_FROM:-}" ] && src="$GORECSHIT_BLOCKLIST_FROM"
      if [ -n "$src" ] && import_from_source "$src" "$T/scan/imported.txt"; then
        log "imported from $src"
      fi
      build_lists "$T" || true
    fi
    rm -rf "$T"
  fi
fi
load_all
exit 0
REFRESH_EOF
  chmod 755 /usr/local/sbin/scanner-block-refresh.sh

  cat >/etc/systemd/system/scanner-block.service <<'EOF2'
[Unit]
Description=Load gorecshit ipsets (scanners / reputation / snitch) before UFW
DefaultDependencies=no
# v2.7.0: ufw.service is Before=network-pre.target, so "After=network-pre" here made an ordering
# cycle and systemd dropped ufw (firewall OFF after reboot) or this unit. Load sets early instead.
Before=ufw.service network-pre.target
After=local-fs.target systemd-modules-load.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/scanner-block-refresh.sh --local-only

[Install]
WantedBy=multi-user.target
EOF2

  cat >/etc/systemd/system/scanner-block-refresh.service <<'EOF2'
[Unit]
Description=Refresh gorecshit scanner/reputation/snitch lists
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/scanner-block-refresh.sh
Nice=10
EOF2

  cat >/etc/systemd/system/scanner-block-refresh.timer <<'EOF2'
[Unit]
Description=Daily scanner blocklist refresh

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=7200

[Install]
WantedBy=timers.target
EOF2

  systemctl daemon-reload
  systemctl enable scanner-block.service >/dev/null 2>&1 || true
  systemctl enable --now scanner-block-refresh.timer >/dev/null 2>&1 || true

  if [[ "$NET_OFFLINE" -eq 1 ]]; then
    /usr/local/sbin/scanner-block-refresh.sh --local-only || true
  else
    /usr/local/sbin/scanner-block-refresh.sh || warn "Обновление списков не удалось — загружены встроенные/старые"
  fi
  local cnt rep sn
  cnt="$(ipset list scanner-block -t 2>/dev/null | awk -F': ' '/Number of entries/{print $2}')"
  rep="$(ipset list gorecshit-rep -t 2>/dev/null | awk -F': ' '/Number of entries/{print $2}')"
  sn="$(ipset list gorecshit-snitch -t 2>/dev/null | awk -F': ' '/Number of entries/{print $2}')"
  if [[ "${cnt:-0}" -eq 0 ]]; then
    warn "ipset scanner-block пуст — проверьте сеть/зеркала/--blocklist-from"
  else
    ok "Сканеры: ${cnt} подсетей (все порты) · репутация: ${rep:-0} (только SSH) · VK/MAX: ${sn:-0} (исходящие)"
  fi
}


# ---------- Hide server fingerprints (menu «Скрыть отпечатки» / --stealth) ----------
# Safe: no speed knobs, no IPv6 flip, no client-port/firewall rewrite, no panel edits.
# Risky stops/renames ask via /dev/tty (default No).

_fp_ask_yn() {
  # _fp_ask_yn "question" default_no=1 -> returns 0 if yes
  local q="$1" def_no="${2:-1}" ans=""
  if ! can_prompt_user; then
    # non-interactive: skip risky actions
    return 1
  fi
  if [[ "$def_no" -eq 1 ]]; then
    prompt_user "${q} [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]]
  else
    prompt_user "${q} [Y/n] " ans
    [[ -z "$ans" || "$ans" =~ ^[Yy]$ ]]
  fi
}

_fp_hostname_suspicious() {
  local h="$1"
  h="$(printf '%s' "$h" | tr '[:upper:]' '[:lower:]')"
  case "$h" in
    *vpn*|*node*|*xray*|*vless*|*reality*|*proxy*|*remna*|*v2ray*|*singbox*|*sing-box*|*hysteria*|*trojan*)
      return 0 ;;
  esac
  case "$h" in
    vm-*|vps-*|server-*|cloud-*|ubuntu-*|debian-*|centos-*|rocky-*|alma-*|host-*|dedicated-*|kvm-*|lxc-*|openvz-*)
      return 0 ;;
  esac
  # ip-style / bare numeric hostnames
  if [[ "$h" =~ ^ip-[0-9]+-[0-9]+-[0-9]+-[0-9]+ ]]; then return 0; fi
  if [[ "$h" =~ ^[0-9]+-[0-9]+-[0-9]+-[0-9]+ ]]; then return 0; fi
  if [[ "$h" =~ ^(host|srv|s|n)[0-9]{2,}$ ]]; then return 0; fi
  return 1
}

_fp_note_masked_service() {
  local s="$1"
  [[ -n "$s" ]] || return 0
  mkdir -p "$BACKUP_DIR" 2>/dev/null || true
  if [[ "$DRY_RUN" -eq 0 ]]; then
    grep -qxF "$s" "${BACKUP_DIR}/fingerprint-masked-services.txt" 2>/dev/null || \
      echo "$s" >>"${BACKUP_DIR}/fingerprint-masked-services.txt"
  fi
}

_fp_ensure_rollback_extras() {
  # Append fingerprint restore helpers into rollback.sh (idempotent marker).
  [[ "$DRY_RUN" -eq 0 ]] || return 0
  local rb="${BACKUP_DIR}/rollback.sh"
  [[ -f "$rb" ]] || return 0
  if grep -q 'gorecshit-fingerprint-restore' "$rb" 2>/dev/null; then
    return 0
  fi
  cat >>"$rb" <<'RBEOF'

# gorecshit-fingerprint-restore
if [[ -f "$BACKUP_DIR/fingerprint-masked-services.txt" ]]; then
  while IFS= read -r _svc; do
    [[ -n "$_svc" ]] || continue
    systemctl unmask "$_svc" 2>/dev/null || true
  done < "$BACKUP_DIR/fingerprint-masked-services.txt"
fi
if [[ -f /etc/hostname ]]; then
  hostnamectl set-hostname "$(tr -d ' \t\r\n' </etc/hostname)" 2>/dev/null || true
fi
# reload ssh after banner restore
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
RBEOF
}

configure_fingerprint_hiding() {
  step "Скрытие отпечатков сервера (без потери скорости)"
  echo "Не трогаем: IPv6, клиентские порты UFW, Docker compose, настройки панели, tcp_timestamps."
  local -a done_msgs=()

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b fingerprint: SSH banners/motd, optional hostname, TTL/ICMP fingerprint sysctl, closed-port DROP tip, mask noisy services (ask), docker listen report, server_tokens\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi

  mkdir -p "$BACKUP_DIR" "$MARKER_DIR" 2>/dev/null || true

  # ---- SSH banners / MOTD ----
  step "SSH / MOTD: убрать версию и рекламу"
  backup_file /etc/ssh/sshd_config
  backup_file /etc/ssh/sshd_config.d/99-hardening.conf
  backup_file /etc/ssh/sshd_config.d/99-gorecshit-fingerprint.conf
  backup_file /etc/issue.net
  backup_file /etc/issue
  backup_file /etc/motd

  local ssh_fp="/etc/ssh/sshd_config.d/99-gorecshit-fingerprint.conf"
  local ssh_body="# Managed by ${SCRIPT_NAME} ${VERSION} — fingerprint hide (Banner/DebianBanner)
Banner none
DebianBanner no
"
  # Validate DebianBanner support
  local testconf
  testconf="$(mktemp)"
  printf '%s\n' "$ssh_body" >"$testconf"
  if ! sshd -t -f "$testconf" 2>/dev/null; then
    ssh_body="# Managed by ${SCRIPT_NAME} ${VERSION}
Banner none
"
    warn "DebianBanner не поддерживается этим sshd — только Banner none"
  fi
  rm -f "$testconf"
  write_content "$ssh_fp" "$ssh_body"
  if sshd -t 2>/dev/null; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    ok "SSH: Banner none, DebianBanner no (если поддерживается)"
    done_msgs+=("SSH-баннер версии скрыт")
  else
    warn "sshd -t после fingerprint drop-in не прошёл — откатываю drop-in"
    rm -f "$ssh_fp"
    if [[ -f "${BACKUP_DIR}${ssh_fp}" ]]; then
      cp -a "${BACKUP_DIR}${ssh_fp}" "$ssh_fp" 2>/dev/null || true
    fi
  fi

  # Clear issue.net / issue ads (keep empty file so Banner none still fine)
  if [[ -f /etc/issue.net ]]; then
    if [[ -s /etc/issue.net ]]; then
      : >/etc/issue.net
      ok "Очищен /etc/issue.net"
      done_msgs+=("очищен /etc/issue.net")
    fi
  fi
  if [[ -f /etc/motd ]] && [[ -s /etc/motd ]]; then
    # only blank if looks like vendor ad
    if grep -qiE 'ubuntu|debian|welcome|authorized|legal|cloud|vpn|xray|remna|vless|reality|v2ray|proxy|marzban' /etc/motd 2>/dev/null; then
      : >/etc/motd
      ok "Очищен /etc/motd"
      done_msgs+=("очищен /etc/motd")
    fi
  fi

  # Disable update-motd news/ads (chmod -x, don't delete — reversible via backup)
  local motd_f
  for motd_f in \
    /etc/update-motd.d/10-help-text \
    /etc/update-motd.d/50-motd-news \
    /etc/update-motd.d/80-livepatch \
    /etc/update-motd.d/91-release-upgrade \
    /etc/update-motd.d/91-contract-ua-esm-status \
    /etc/update-motd.d/92-unattended-upgrade \
    /etc/update-motd.d/95-hwe-eol \
    /etc/update-motd.d/97-overlayroot \
    /etc/update-motd.d/98-fsck-at-reboot \
    /etc/update-motd.d/98-reboot-required; do
    if [[ -f "$motd_f" && -x "$motd_f" ]]; then
      backup_file "$motd_f"
      chmod a-x "$motd_f" 2>/dev/null || true
    fi
  done
  if [[ -f /etc/default/motd-news ]]; then
    backup_file /etc/default/motd-news
    if grep -qE '^ENABLED=' /etc/default/motd-news; then
      sed -i 's/^ENABLED=.*/ENABLED=0/' /etc/default/motd-news
    else
      echo 'ENABLED=0' >>/etc/default/motd-news
    fi
    ok "motd-news отключён"
    done_msgs+=("motd-news/update-motd ads отключены")
  else
    ok "Скрипты update-motd (help/news) отключены при наличии"
    done_msgs+=("update-motd help/news отключены")
  fi

  # ---- Hostname (ask, default No) ----
  step "Hostname"
  local cur_host
  cur_host="$(hostname -s 2>/dev/null || hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown)"
  if _fp_hostname_suspicious "$cur_host"; then
    warn "Hostname «${cur_host}» похож на шаблон провайдера/VPN"
    if _fp_ask_yn "Переименовать в нейтральный web-<random>? (по умолчанию нет)" 1; then
      local hex newhost
      hex="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 6)"
      newhost="web-${hex}"
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
      backup_file /etc/cloud/cloud.cfg.d/99-gorecshit-hostname.cfg
      echo 'preserve_hostname: true' >/etc/cloud/cloud.cfg.d/99-gorecshit-hostname.cfg
      ok "Hostname: ${cur_host} → ${newhost}"
      done_msgs+=("hostname ${cur_host} → ${newhost}")
    else
      log "Hostname оставлен: ${cur_host}"
    fi
  else
    ok "Hostname «${cur_host}» выглядит нейтрально — не меняем"
  fi

  # ---- TCP/IP fingerprint sysctl (no tcp_timestamps change) ----
  step "TCP/IP / ICMP fingerprint (без tcp_timestamps)"
  backup_file /etc/sysctl.d/99-gorecshit-fingerprint.conf
  local cur_ttl
  cur_ttl="$(sysctl -n net.ipv4.ip_default_ttl 2>/dev/null || echo 64)"
  local ttl_line="net.ipv4.ip_default_ttl = 64"
  if [[ "$cur_ttl" == "64" ]]; then
    log "ip_default_ttl уже 64"
  fi
  write_content /etc/sysctl.d/99-gorecshit-fingerprint.conf \
"# Managed by ${SCRIPT_NAME} ${VERSION} — OS fingerprint soften (speed-safe)
# Do NOT set tcp_timestamps=0 here (скорость/PAWS).
${ttl_line}
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
"
  sysctl -p /etc/sysctl.d/99-gorecshit-fingerprint.conf >/dev/null 2>&1 || true
  ok "sysctl: ttl=64, ignore broadcasts, no send/accept redirects"
  done_msgs+=("sysctl fingerprint (TTL/ICMP redirects/broadcasts)")

  # ICMP timestamp (13/14) and address-mask (17/18) DROP — dedicated chain, does not touch echo policy beyond existing
  if command -v iptables >/dev/null 2>&1; then
    iptables -N GORECSHIT-FP 2>/dev/null || iptables -F GORECSHIT-FP 2>/dev/null || true
    iptables -C GORECSHIT-FP -p icmp --icmp-type timestamp-request -j DROP 2>/dev/null || \
      iptables -A GORECSHIT-FP -p icmp --icmp-type timestamp-request -j DROP 2>/dev/null || true
    iptables -C GORECSHIT-FP -p icmp --icmp-type timestamp-reply -j DROP 2>/dev/null || \
      iptables -A GORECSHIT-FP -p icmp --icmp-type timestamp-reply -j DROP 2>/dev/null || true
    iptables -C GORECSHIT-FP -p icmp --icmp-type address-mask-request -j DROP 2>/dev/null || \
      iptables -A GORECSHIT-FP -p icmp --icmp-type address-mask-request -j DROP 2>/dev/null || true
    iptables -C GORECSHIT-FP -p icmp --icmp-type address-mask-reply -j DROP 2>/dev/null || \
      iptables -A GORECSHIT-FP -p icmp --icmp-type address-mask-reply -j DROP 2>/dev/null || true
    # Hook once at top of INPUT for icmp only
    iptables -C INPUT -p icmp -j GORECSHIT-FP 2>/dev/null || \
      iptables -I INPUT 1 -p icmp -j GORECSHIT-FP 2>/dev/null || true
    ok "iptables: DROP ICMP timestamp/address-mask (echo не трогаем здесь)"
    done_msgs+=("ICMP timestamp/address-mask DROP")

    # Persist via simple oneshot (no UFW client-port changes)
    local fp_script="/usr/local/sbin/gorecshit-fingerprint-net.sh"
    local fp_unit="/etc/systemd/system/gorecshit-fingerprint-net.service"
    backup_file "$fp_script"
    backup_file "$fp_unit"
    write_content "$fp_script" \
'#!/usr/bin/env bash
# Managed by gorecshit — restore ICMP fingerprint DROP chain (idempotent)
set -euo pipefail
command -v iptables >/dev/null 2>&1 || exit 0
iptables -N GORECSHIT-FP 2>/dev/null || true
iptables -F GORECSHIT-FP 2>/dev/null || true
iptables -A GORECSHIT-FP -p icmp --icmp-type timestamp-request -j DROP
iptables -A GORECSHIT-FP -p icmp --icmp-type timestamp-reply -j DROP
iptables -A GORECSHIT-FP -p icmp --icmp-type address-mask-request -j DROP
iptables -A GORECSHIT-FP -p icmp --icmp-type address-mask-reply -j DROP
iptables -C INPUT -p icmp -j GORECSHIT-FP 2>/dev/null || iptables -I INPUT 1 -p icmp -j GORECSHIT-FP
'
    chmod 755 "$fp_script"
    write_content "$fp_unit" \
"[Unit]
Description=gorecshit fingerprint ICMP hide (timestamp/address-mask DROP)
After=network-pre.target ufw.service
Before=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/gorecshit-fingerprint-net.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"
    systemctl daemon-reload
    systemctl enable --now gorecshit-fingerprint-net.service >/dev/null 2>&1 || true
  fi

  # Closed TCP ports: silent DROP if UFW present (no RST). Do not rewrite client allows.
  step "Закрытые TCP-порты (DROP без RST)"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qiE 'Status:\s*active'; then
    backup_file /etc/default/ufw
    if grep -q '^DEFAULT_INPUT_POLICY=' /etc/default/ufw 2>/dev/null; then
      sed -i 's/^DEFAULT_INPUT_POLICY=.*/DEFAULT_INPUT_POLICY="DROP"/' /etc/default/ufw || true
    fi
    if iptables -L ufw-reject-input -n >/dev/null 2>&1; then
      iptables -C ufw-reject-input -j DROP 2>/dev/null || iptables -I ufw-reject-input 1 -j DROP 2>/dev/null || true
    fi
    ok "UFW INPUT policy DROP; ufw-reject-input → DROP (ESTABLISHED/клиентские правила не трогали)"
    done_msgs+=("закрытые порты: DROP вместо RST (через UFW)")
  else
    warn "UFW неактивен — полную тишину закрытых портов без риска для SSH даёт пункт меню 1; пропускаем смену INPUT policy"
  fi

  # ---- Noisy services (ask) ----
  step "Сервисы, светящие ОС (только если установлены)"
  local svc unit_state
  for svc in rpcbind avahi-daemon cups cups-browsed snmpd exim4 postfix; do
    if systemctl list-unit-files "${svc}.service" 2>/dev/null | grep -q "${svc}.service"; then
      unit_state="$(systemctl is-enabled "${svc}.service" 2>/dev/null || true)"
      if systemctl is-active --quiet "${svc}.service" 2>/dev/null || [[ "$unit_state" == "enabled" ]]; then
        # skip postfix/exim if clearly only localhost — still ask
        warn "Обнаружен сервис ${svc} (enabled/active)"
        if _fp_ask_yn "Остановить и mask ${svc}? (может убрать лишний отпечаток; по умолчанию нет)" 1; then
          backup_file "/etc/systemd/system/${svc}.service"
          systemctl stop "${svc}.service" 2>/dev/null || true
          systemctl disable "${svc}.service" 2>/dev/null || true
          systemctl mask "${svc}.service" 2>/dev/null || true
          _fp_note_masked_service "${svc}.service"
          ok "Сервис ${svc}: stop+mask"
          done_msgs+=("mask ${svc}")
        else
          log "Сервис ${svc} оставлен"
        fi
      fi
    fi
  done

  # ---- Docker report only ----
  step "Docker: отчёт (без правок compose)"
  if command -v docker >/dev/null 2>&1; then
    local dhost pub
    dhost="$(docker info --format '{{.ListenerSecurity}}' 2>/dev/null || true)"
    # Check dockerd listening on 2375/2376
    if ss -lntp 2>/dev/null | grep -qE '[:.]2375\s|[:.]2376\s'; then
      warn "Docker API слушает 2375/2376 публично — закройте (не меняем daemon.json здесь)"
      done_msgs+=("WARN: docker 2375/2376 открыт (только отчёт)")
    else
      ok "Docker API 2375/2376 не слушает публично"
    fi
    # Published ports report
    pub="$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E '0\.0\.0\.0:|:::' || true)"
    if [[ -n "$pub" ]]; then
      log "Публикации контейнеров (только отчёт, compose не трогаем):"
      printf '%s\n' "$pub" | head -20 | while IFS= read -r line; do
        _audit_info 2>/dev/null || log "  $line"
        # _audit_info may not exist if called outside audit context — use log
      done
      # re-print with log for reliability
      printf '%s\n' "$pub" | head -20 | while IFS= read -r line; do log "  publish: $line"; done
    else
      ok "Лишних publish 0.0.0.0 у контейнеров не видно (или docker ps пуст)"
    fi
  else
    log "Docker не установлен — пропуск"
  fi

  # ---- nginx/apache server_tokens ----
  step "Web: server_tokens / ServerTokens"
  if [[ -d /etc/nginx ]]; then
    local ng
    while IFS= read -r ng; do
      [[ -f "$ng" ]] || continue
      backup_file "$ng"
      if grep -qE '^\s*server_tokens\s+' "$ng" 2>/dev/null; then
        sed -i -E 's/^\s*server_tokens\s+.*/    server_tokens off;/' "$ng" || true
      else
        # inject into http {} if this is nginx.conf
        if [[ "$ng" == */nginx.conf ]] && grep -qE '^\s*http\s*\{' "$ng"; then
          sed -i '/^\s*http\s*{/a\    server_tokens off;' "$ng" || true
        fi
      fi
    done < <(find /etc/nginx -type f \( -name 'nginx.conf' -o -name '*.conf' \) 2>/dev/null | head -40)
    if command -v nginx >/dev/null 2>&1 && nginx -t 2>/dev/null; then
      systemctl reload nginx 2>/dev/null || true
      ok "nginx: server_tokens off"
      done_msgs+=("nginx server_tokens off")
    else
      warn "nginx -t не прошёл или nginx нет в PATH — правки conf оставлены, reload пропущен"
    fi
  fi
  if [[ -d /etc/apache2 ]] || [[ -d /etc/httpd ]]; then
    local ac
    for ac in /etc/apache2/conf-available/security.conf /etc/apache2/conf-enabled/security.conf \
              /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/security.conf; do
      [[ -f "$ac" ]] || continue
      backup_file "$ac"
      if grep -qE '^\s*ServerTokens\s+' "$ac"; then
        sed -i -E 's/^\s*ServerTokens\s+.*/ServerTokens Prod/' "$ac" || true
      else
        echo 'ServerTokens Prod' >>"$ac"
      fi
      if grep -qE '^\s*ServerSignature\s+' "$ac"; then
        sed -i -E 's/^\s*ServerSignature\s+.*/ServerSignature Off/' "$ac" || true
      else
        echo 'ServerSignature Off' >>"$ac"
      fi
    done
    systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null || true
    ok "Apache: ServerTokens Prod / ServerSignature Off (если был)"
    done_msgs+=("apache ServerTokens Prod")
  fi

  # Marker
  echo "version=${VERSION}" >"${MARKER_DIR}/fingerprint.done"
  echo "ts=$(date -Iseconds)" >>"${MARKER_DIR}/fingerprint.done"
  backup_file "${MARKER_DIR}/fingerprint.done"
  _fp_ensure_rollback_extras

  echo
  menu_sep
  ok "Скрытие отпечатков завершено (read/write локально, панель не трогали)."
  local m
  printf '%bСделано:%b\n' "${C_BOLD}" "${C_RESET}"
  for m in "${done_msgs[@]}"; do
    printf '  • %s\n' "$m"
  done
  [[ ${#done_msgs[@]} -eq 0 ]] && echo "  • (существенных изменений не потребовалось / всё уже было)"
  echo "Откат: $(rollback_hint_cmd)  или  ${BACKUP_DIR}/rollback.sh"
}

run_fingerprint_only() {
  if [[ "$(id -u)" -ne 0 && "$DRY_RUN" -eq 0 ]]; then
    err "Нужен root для --stealth / «Скрыть отпечатки»"
    exit 1
  fi
  preflight
  write_rollback_script
  configure_fingerprint_hiding
  install_cli_command
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

  # Extended fingerprint hiding (banners/MOTD/TTL/ICMP FP/services/…)
  configure_fingerprint_hiding

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

validate_docker_daemon_json() {
  local f="$1"
  [[ -f "$f" ]] || return 1
  if command -v python3 >/dev/null 2>&1; then
    python3 -m json.tool "$f" >/dev/null 2>&1 || return 1
  elif command -v jq >/dev/null 2>&1; then
    jq -e . "$f" >/dev/null 2>&1 || return 1
  else
    # minimal brace check
    grep -q '{' "$f" || return 1
  fi
  if command -v dockerd >/dev/null 2>&1; then
    # dockerd --validate exists on newer docker; ignore if unsupported
    if dockerd --help 2>&1 | grep -q -- '--validate'; then
      dockerd --validate --config-file="$f" >/dev/null 2>&1 || return 1
    fi
  fi
  return 0
}

xray_listening() {
  ss -lntup 2>/dev/null | grep -qiE 'xray|rw-core|sing-box|hysteria' && return 0
  # fallback: any non-loopback listen by remnanode processes
  ss -lntup 2>/dev/null | grep -qiE 'remnanode' && return 0
  return 1
}

reapply_firewall_after_docker() {
  log "Переприменяю iptables/UFW/DOCKER-USER после рестарта Docker"
  if command -v ufw >/dev/null 2>&1; then
    ufw --force reload 2>/dev/null || true
  fi
  if [[ -x /usr/local/sbin/gorecshit-anti-probe.sh ]]; then
    /usr/local/sbin/gorecshit-anti-probe.sh 2>/dev/null || warn "anti-probe re-apply failed"
  elif systemctl list-unit-files gorecshit-anti-probe.service >/dev/null 2>&1; then
    systemctl start gorecshit-anti-probe.service 2>/dev/null || true
  fi
  if [[ -n "${NODE_PORT:-}" && -x "/usr/local/sbin/docker-user-${NODE_PORT}.sh" ]]; then
    "/usr/local/sbin/docker-user-${NODE_PORT}.sh" 2>/dev/null || warn "DOCKER-USER re-apply failed"
  fi
  if [[ -x /usr/local/sbin/gorecshit-hotpath.sh ]]; then
    /usr/local/sbin/gorecshit-hotpath.sh 2>/dev/null || true
  fi
  if [[ -x /usr/local/sbin/gorecshit-nic-tune.sh ]]; then
    /usr/local/sbin/gorecshit-nic-tune.sh 2>/dev/null || true
  fi
}

wait_remnanode_after_docker() {
  local i name
  # Prefer known container name; also accept remnanode_running
  for i in $(seq 1 60); do
    if docker info >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  if ! docker info >/dev/null 2>&1; then
    warn "Docker не ответил за 60с после restart"
    return 1
  fi
  # Try start remnanode if present but stopped
  if command -v docker >/dev/null 2>&1; then
    name="$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -iE '^remnanode$|remnanode' | head -1 || true)"
    if [[ -n "$name" ]]; then
      docker start "$name" >/dev/null 2>&1 || true
    fi
  fi
  for i in $(seq 1 60); do
    if remnanode_running && xray_listening; then
      ok "remnanode/xray снова живы (через ${i}с)"
      return 0
    fi
    if remnanode_running && [[ "$i" -ge 15 ]]; then
      # container up; xray may still be binding
      if xray_listening; then
        ok "remnanode/xray снова живы (через ${i}с)"
        return 0
      fi
    fi
    sleep 1
  done
  if remnanode_running; then
    warn "remnanode контейнер up, но xray listen не подтверждён за 60с"
    return 1
  fi
  warn "remnanode не поднялся за 60с после restart Docker"
  return 1
}

maybe_apply_docker_daemon_restart() {
  # Called after hardening writes daemon.json (CHANGED_DOCKER=1)
  if [[ "$CHANGED_DOCKER" -ne 1 ]]; then
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b maybe systemctl restart docker (daemon.json changed)\n' "${C_YEL}" "${C_RESET}"
    return 0
  fi
  if [[ "$NO_DOCKER_RESTART" -eq 1 ]]; then
    SKIPPED_DOCKER_RESTART=1
    warn "daemon.json изменён; Docker НЕ перезапущен (--no-docker-restart). Примените позже: systemctl restart docker"
    return 0
  fi

  local do_it=0
  if [[ "$FORCE_DOCKER_RESTART" -eq 1 ]]; then
    do_it=1
    log "Перезапуск Docker (--docker-restart)"
  elif _tty_usable; then
    # ALWAYS prompt when a real TTY exists — including menu install (FROM_MENU + ASSUME_YES=1).
    # Menu sets ASSUME_YES only to skip "Продолжить?"; docker restart must still ask.
    local ans=""
    prompt_user $'Перезапустить Docker сейчас? Нода отключится на ~10-30 сек [y/N]: ' ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      do_it=1
    else
      SKIPPED_DOCKER_RESTART=1
      warn "daemon.json изменён; перезапуск Docker пропущен (ответ пользователя). Позже: systemctl restart docker или gorecshit --docker-restart"
      return 0
    fi
  elif [[ "$CLI_ASSUME_YES" -eq 1 ]]; then
    # CLI --yes without /dev/tty: do not restart unless --docker-restart
    SKIPPED_DOCKER_RESTART=1
    warn "daemon.json изменён; Docker НЕ перезапущен (--yes без TTY). Добавьте --docker-restart."
    return 0
  else
    SKIPPED_DOCKER_RESTART=1
    warn "daemon.json изменён; Docker НЕ перезапущен (нет /dev/tty). Запустите интерактивно или с --docker-restart."
    return 0
  fi

  if [[ "$do_it" -ne 1 ]]; then
    return 0
  fi

  step "Перезапуск Docker для применения daemon.json"
  if ! systemctl restart docker; then
    warn "systemctl restart docker не удался"
    SKIPPED_DOCKER_RESTART=1
    return 1
  fi
  ok "Docker перезапущен"
  wait_remnanode_after_docker || true
  reapply_firewall_after_docker
  if remnanode_running && xray_listening; then
    ok "daemon.json применён; remnanode/xray OK; firewall rules re-applied"
  elif remnanode_running; then
    warn "daemon.json применён; remnanode up, проверьте listen порты xray вручную"
  else
    warn "daemon.json применён (docker restart OK), но remnanode/xray не подтверждены — проверьте docker ps / ss"
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
    # Validate JSON; restore backup on failure
    if ! validate_docker_daemon_json /etc/docker/daemon.json; then
      warn "daemon.json невалиден после записи — восстанавливаю бэкап"
      if [[ -f "${BACKUP_DIR}/etc/docker/daemon.json" ]]; then
        cp -a "${BACKUP_DIR}/etc/docker/daemon.json" /etc/docker/daemon.json
        ok "Восстановлен ${BACKUP_DIR}/etc/docker/daemon.json"
      elif [[ -n "$old" ]]; then
        printf '%s\n' "$old" >/etc/docker/daemon.json
        ok "Восстановлен предыдущий daemon.json из памяти"
      else
        rm -f /etc/docker/daemon.json
        warn "Бэкапа не было — daemon.json удалён"
      fi
      CHANGED_DOCKER=0
    elif [[ "$old" != "$(cat /etc/docker/daemon.json)" ]]; then
      CHANGED_DOCKER=1
      ok "daemon.json обновлён (ожидает применения через restart Docker)"
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
# IPv6 (v2.6.0): panel is IPv4 → no IPv6 source may reach a docker-published NODE_PORT
if command -v ip6tables >/dev/null 2>&1 && ip6tables -S DOCKER-USER >/dev/null 2>&1; then
  ip6tables -C DOCKER-USER -m conntrack --ctdir REPLY -j RETURN 2>/dev/null \\
    || ip6tables -I DOCKER-USER 1 -m conntrack --ctdir REPLY -j RETURN
  ip6tables -C DOCKER-USER -p tcp -m conntrack --ctorigdstport "\$NODE_PORT" -j DROP 2>/dev/null \\
    || ip6tables -A DOCKER-USER -p tcp -m conntrack --ctorigdstport "\$NODE_PORT" -j DROP
fi
exit 0
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
  echo "modules: ufw=$DO_UFW blocklist=$DO_BLOCKLIST hide=$DO_HIDE_PORTS probe=$DO_ANTI_PROBE ssh=$DO_SSH stealth=$DO_STEALTH f2b=$DO_FAIL2BAN sysctl=$DO_SYSCTL host=$DO_HOSTNAME docker=$DO_DOCKER_JOURNAL egress=$DO_EGRESS_GUARD decoy=$DO_DECOY_WEB"
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
  if [[ "$CHANGED_DOCKER" -eq 1 && "$SKIPPED_DOCKER_RESTART" -eq 1 ]]; then
    warn "daemon.json изменён без restart Docker — логи rotation не активны до: systemctl restart docker (или перезапуск с --docker-restart)"
  elif [[ "$CHANGED_DOCKER" -eq 1 ]]; then
    ok "daemon.json изменён и Docker был перезапущен для применения"
  fi
  ok "Hardening complete. Backups: ${BACKUP_DIR}"
  ok "Откат: $(rollback_hint_cmd)   OR   ${BACKUP_DIR}/rollback.sh"
}

# ---------- v2.6.0: helpers for rollback extras + tty y/N ----------
_tty_usable() {
  [[ -r /dev/tty && -w /dev/tty ]] || return 1
  { : </dev/tty; } 2>/dev/null
}

_tty_ask_yn() {
  # Ask y/N via /dev/tty even from menu (menu sets ASSUME_YES=1). Never under CLI --yes.
  local q="$1" ans=""
  [[ "${CLI_ASSUME_YES:-0}" -eq 0 ]] || return 1
  _tty_usable || return 1
  prompt_user "${q} [y/N] " ans
  [[ "$ans" =~ ^[YyДд]$ ]]
}

_rb_append_block() {
  # _rb_append_block TAG BODY — append once to this run's rollback.sh
  [[ "$DRY_RUN" -eq 0 ]] || return 0
  local tag="$1" body="$2" rb="${BACKUP_DIR}/rollback.sh"
  [[ -f "$rb" ]] || return 0
  grep -q "# ${tag}" "$rb" 2>/dev/null && return 0
  printf '\n# %s\n%s\n' "$tag" "$body" >>"$rb"
  return 0
}

configure_egress_guard() {
  # Outbound abuse/leak guard: SMTP 25 REJECT (host + docker FORWARD), ICMP unreachable/ttl leaks DROP.
  if [[ "$DO_EGRESS_GUARD" -eq 0 && "$DO_HIDE_PORTS" -eq 0 ]]; then
    log "egress_guard пропущен (--no-egress-guard)"
    return 0
  fi
  step "Egress guard: исходящий SMTP закрыт (egress=${DO_EGRESS_GUARD}), ICMP-утечки скрыты (hide=${DO_HIDE_PORTS})"
  local script="/usr/local/sbin/gorecshit-egress-guard.sh"
  local unit="/etc/systemd/system/gorecshit-egress-guard.service"
  local smtp_ports="" p
  if [[ "$DO_EGRESS_GUARD" -eq 1 ]]; then
    while IFS= read -r p; do
      is_port "$p" && smtp_ports+="${p} "
    done < <(foreach_csv "$EGRESS_BLOCK_PORTS")
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b install %s + %s (REJECT out tcp/%s; ICMP leak drop=%s; v4+v6; lo/docker bridges excluded for ICMP)\n' \
      "${C_YEL}" "${C_RESET}" "$script" "$unit" "${smtp_ports% }" "$DO_HIDE_PORTS"
    return 0
  fi
  local created=0
  [[ -e "$script" ]] || created=1
  backup_file "$script"
  backup_file "$unit"
  {
    echo '#!/bin/bash'
    echo "# Managed by ${SCRIPT_NAME} ${VERSION} — egress guard (idempotent; never touches client/panel inbound)"
    echo 'set -u'
    echo "SMTP_PORTS=\"${smtp_ports% }\""
    echo "ICMP_LEAK=${DO_HIDE_PORTS}"
    cat <<'GUARD'
for IPT in iptables ip6tables; do
  command -v "$IPT" >/dev/null 2>&1 || continue
  "$IPT" -S OUTPUT >/dev/null 2>&1 || continue
  "$IPT" -N GORECSHIT-EGRESS 2>/dev/null || "$IPT" -F GORECSHIT-EGRESS
  "$IPT" -A GORECSHIT-EGRESS -o lo -j RETURN
  for p in $SMTP_PORTS; do
    "$IPT" -A GORECSHIT-EGRESS -p tcp --dport "$p" -j REJECT --reject-with tcp-reset
  done
  if [ "$ICMP_LEAK" = "1" ]; then
    "$IPT" -A GORECSHIT-EGRESS -o docker+ -j RETURN
    "$IPT" -A GORECSHIT-EGRESS -o br-+ -j RETURN
    if [ "$IPT" = iptables ]; then
      # never touch fragmentation-needed (PMTU) — only port/proto unreachable + ttl exceeded
      "$IPT" -A GORECSHIT-EGRESS -p icmp --icmp-type port-unreachable -j DROP
      "$IPT" -A GORECSHIT-EGRESS -p icmp --icmp-type protocol-unreachable -j DROP
      "$IPT" -A GORECSHIT-EGRESS -p icmp --icmp-type time-exceeded -j DROP
    else
      # never touch packet-too-big / NDP
      "$IPT" -A GORECSHIT-EGRESS -p ipv6-icmp --icmpv6-type port-unreachable -j DROP
      "$IPT" -A GORECSHIT-EGRESS -p ipv6-icmp --icmpv6-type time-exceeded -j DROP
    fi
  fi
  "$IPT" -A GORECSHIT-EGRESS -j RETURN
  "$IPT" -C OUTPUT -j GORECSHIT-EGRESS 2>/dev/null || "$IPT" -I OUTPUT 1 -j GORECSHIT-EGRESS
  # docker bridge containers (remnanode itself is usually network_mode: host → OUTPUT)
  if [ -n "$SMTP_PORTS" ]; then
    "$IPT" -N GORECSHIT-EGRESS-FWD 2>/dev/null || "$IPT" -F GORECSHIT-EGRESS-FWD
    for p in $SMTP_PORTS; do
      "$IPT" -A GORECSHIT-EGRESS-FWD -p tcp --dport "$p" -j REJECT --reject-with tcp-reset
    done
    "$IPT" -A GORECSHIT-EGRESS-FWD -j RETURN
    if "$IPT" -S DOCKER-USER >/dev/null 2>&1; then
      "$IPT" -C DOCKER-USER -j GORECSHIT-EGRESS-FWD 2>/dev/null || "$IPT" -I DOCKER-USER 1 -j GORECSHIT-EGRESS-FWD
    else
      "$IPT" -C FORWARD -j GORECSHIT-EGRESS-FWD 2>/dev/null || "$IPT" -I FORWARD 1 -j GORECSHIT-EGRESS-FWD
    fi
  fi
done
exit 0
GUARD
  } >"$script"
  chmod 755 "$script"
  cat >"$unit" <<UNITEOF
[Unit]
Description=gorecshit egress guard (outbound SMTP block + ICMP leak hide)
After=network-pre.target ufw.service docker.service
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=${script}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNITEOF
  systemctl daemon-reload 2>/dev/null || true
  systemctl enable gorecshit-egress-guard.service >/dev/null 2>&1 || true
  "$script" || warn "egress guard apply returned non-zero"
  if [[ "$created" -eq 1 ]]; then
    : >"${BACKUP_DIR}/egress-guard.created"
  fi
  # shellcheck disable=SC2016  # body is literal rollback.sh code
  _rb_append_block "gorecshit-egress-restore" '
if [[ -f "$BACKUP_DIR/egress-guard.created" ]]; then
  systemctl disable gorecshit-egress-guard.service 2>/dev/null || true
  rm -f /etc/systemd/system/gorecshit-egress-guard.service /usr/local/sbin/gorecshit-egress-guard.sh
  systemctl daemon-reload 2>/dev/null || true
  for IPT in iptables ip6tables; do
    command -v "$IPT" >/dev/null 2>&1 || continue
    while "$IPT" -D OUTPUT -j GORECSHIT-EGRESS 2>/dev/null; do :; done
    while "$IPT" -D DOCKER-USER -j GORECSHIT-EGRESS-FWD 2>/dev/null; do :; done
    while "$IPT" -D FORWARD -j GORECSHIT-EGRESS-FWD 2>/dev/null; do :; done
    "$IPT" -F GORECSHIT-EGRESS 2>/dev/null || true
    "$IPT" -X GORECSHIT-EGRESS 2>/dev/null || true
    "$IPT" -F GORECSHIT-EGRESS-FWD 2>/dev/null || true
    "$IPT" -X GORECSHIT-EGRESS-FWD 2>/dev/null || true
  done
  echo "egress guard removed"
elif [[ -x /usr/local/sbin/gorecshit-egress-guard.sh ]]; then
  /usr/local/sbin/gorecshit-egress-guard.sh || true
fi'
  ok "Egress guard: out tcp/${smtp_ports% } → REJECT (хост + docker); ICMP unreachable/ttl-exceeded leak drop=${DO_HIDE_PORTS}; PMTU не тронут"
  log "Рекомендация (в панели, не трогаем): routing-правило protocol bittorrent → blackhole/block — меньше DMCA-жалоб хостеру"
}

# ---------- v2.7.0 netguard: what clients do through the node must not get the IP banned ----------
# Hosters ban/null-route for: torrents (DMCA), outbound scans/brute-force, SMB worms, spam, attacks on their LAN.
# Russian apps (MAX/VK, by Минцифры guideline 04.2026) report the exit IP of VPN users → RKN → IP block.
# Everything here is NEW-connection only (plus the first packets for P2P signatures): no shaping, no
# per-packet cost on established 80/443 traffic, BBR/fq untouched.
configure_netguard() {
  if [[ "$DO_NETGUARD" -eq 0 ]]; then
    log "netguard пропущен (--no-netguard)"
    return 0
  fi
  step "Netguard: торренты · сканы/брутфорс · SMB · LAN хостера · VK/MAX «стукачи» (только новые соединения)"
  local script="/usr/local/sbin/gorecshit-netguard.sh"
  local unit="/etc/systemd/system/gorecshit-netguard.service"
  local sysf="/etc/sysctl.d/99-gorecshit-netguard.conf"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b %s: p2p=%s abuse=%s private=%s snitch=%s metadata=%s (OUTPUT + docker egress, NEW only)\n' \
      "${C_YEL}" "${C_RESET}" "$script" "$DO_P2P_BLOCK" "$DO_ABUSE_LIMIT" "$DO_PRIVATE_EGRESS" "$DO_SNITCH_GUARD" "$EGRESS_BLOCK_METADATA"
    return 0
  fi
  local created=0
  [[ -e "$script" ]] || created=1
  backup_file "$script"; backup_file "$unit"; backup_file "$sysf"
  mkdir -p /etc/gorecshit
  if [[ ! -f /etc/gorecshit/egress-allow.txt ]]; then
    printf '# CIDR/IP, по одному в строке: исключения из netguard (LAN-сервисы, mesh-VPN и т.п.)\n' >/etc/gorecshit/egress-allow.txt
  fi
  local exempt="" a
  exempt+="${PANEL_IP} "
  [[ -n "$SSH_CLIENT_IP" ]] && exempt+="${SSH_CLIENT_IP} "
  while IFS= read -r a; do exempt+="${a} "; done < <(foreach_csv_ip "$ALLOW_SSH_FROM")
  while IFS= read -r a; do exempt+="${a} "; done < <(foreach_csv_ip "$RELAY_IPS")
  {
    echo '#!/bin/bash'
    echo "# Managed by ${SCRIPT_NAME} ${VERSION} — netguard (idempotent; re-run any time; flush: $0 --flush)"
    echo 'set -u'
    echo "P2P=${DO_P2P_BLOCK}"
    echo "ABUSE=${DO_ABUSE_LIMIT}"
    echo "PRIV=${DO_PRIVATE_EGRESS}"
    echo "SNITCH=${DO_SNITCH_GUARD}"
    echo "META=${EGRESS_BLOCK_METADATA}"
    echo "EXEMPT=\"${exempt% }\""
    cat <<'NETGUARD'
# ports typical for scans / brute-force from abused VPN accounts (max 15 for multiport)
ABUSE_PORTS="22,23,2323,3389,5900,1433,3306,5432,6379,9200,11211,27017,2375,5985,8291"
C=GS-NETGUARD
P2PMARK=0x10000000   # one connmark bit for caught P2P flows (Docker/k8s use other bits)
LOGLIM="-m limit --limit 6/min --limit-burst 12"

unhook() {
  local IPT="$1"
  while "$IPT" -D OUTPUT -j "$C" 2>/dev/null; do :; done
  while "$IPT" -D DOCKER-USER -i docker+ -j "$C" 2>/dev/null; do :; done
  while "$IPT" -D DOCKER-USER -i br-+ -j "$C" 2>/dev/null; do :; done
  while "$IPT" -D FORWARD -i docker+ -j "$C" 2>/dev/null; do :; done
  while "$IPT" -D FORWARD -i br-+ -j "$C" 2>/dev/null; do :; done
  local ch
  for ch in "$C" GS-NG-NEW GS-NG-P2P GS-HIT-P2P GS-HIT-ABUSE GS-HIT-SMB GS-HIT-PRIV GS-HIT-SNITCH; do
    "$IPT" -F "$ch" 2>/dev/null || true
  done
  for ch in "$C" GS-NG-NEW GS-NG-P2P GS-HIT-P2P GS-HIT-ABUSE GS-HIT-SMB GS-HIT-PRIV GS-HIT-SNITCH; do
    "$IPT" -X "$ch" 2>/dev/null || true
  done
}
if [ "${1:-}" = "--flush" ]; then
  unhook iptables; unhook ip6tables 2>/dev/null || true
  echo "netguard removed"; exit 0
fi

# conntrack accounting for connbytes (P2P handshake match only on the first packets)
[ "$P2P" = "1" ] && sysctl -qw net.netfilter.nf_conntrack_acct=1 2>/dev/null || true
CONNBYTES=0
if [ "$P2P" = "1" ] && iptables -N GS-NG-PROBE 2>/dev/null; then
  if iptables -A GS-NG-PROBE -m connbytes --connbytes 0:6 --connbytes-dir original --connbytes-mode packets -j RETURN 2>/dev/null; then
    CONNBYTES=1
  fi
  iptables -F GS-NG-PROBE 2>/dev/null; iptables -X GS-NG-PROBE 2>/dev/null
fi

private_exempt() {
  # destinations the HOST itself needs: on-link/LAN routes, docker nets, wg/mesh, resolvers, allow file
  ip -4 route show table main 2>/dev/null | awk '$1!="default" && $1 ~ /^[0-9]/ {print $1}'
  ip -4 route show table all 2>/dev/null | awk '$1!="default" && $1!="local" && $1!="broadcast" && $1 ~ /^[0-9]/ && $0 ~ / dev (wg|tun|tailscale|zt|nb|netbird|docker|br-)/ {print $1}'
  grep -hE '^\s*nameserver\s+[0-9.]+' /etc/resolv.conf /run/systemd/resolve/resolv.conf 2>/dev/null | awk '{print $2}'
  grep -vE '^\s*(#|$)' /etc/gorecshit/egress-allow.txt 2>/dev/null | awk '{print $1}'
}

apply_v4() {
  local IPT=iptables x
  unhook "$IPT"
  "$IPT" -N "$C"; "$IPT" -N GS-NG-NEW; "$IPT" -N GS-NG-P2P
  for x in P2P ABUSE SMB PRIV SNITCH; do "$IPT" -N "GS-HIT-$x"; done
  # hit chains: rate-limited log (prefix shows in journalctl -k / gorecshit --abuse-report) + verdict
  "$IPT" -A GS-HIT-P2P $LOGLIM -j LOG --log-prefix "[GS-P2P] " --log-level 6
  # remember the flow: retransmits / later packets of a caught P2P flow are dropped too
  "$IPT" -A GS-HIT-P2P -j CONNMARK --set-xmark "$P2PMARK/$P2PMARK"
  "$IPT" -A GS-HIT-P2P -p tcp -j REJECT --reject-with tcp-reset
  "$IPT" -A GS-HIT-P2P -j DROP
  "$IPT" -A GS-HIT-ABUSE $LOGLIM -j LOG --log-prefix "[GS-ABUSE] " --log-level 6
  "$IPT" -A GS-HIT-ABUSE -p tcp -j REJECT --reject-with tcp-reset
  "$IPT" -A GS-HIT-ABUSE -j DROP
  "$IPT" -A GS-HIT-SMB $LOGLIM -j LOG --log-prefix "[GS-SMB] " --log-level 6
  "$IPT" -A GS-HIT-SMB -p tcp -j REJECT --reject-with tcp-reset
  "$IPT" -A GS-HIT-SMB -j DROP
  "$IPT" -A GS-HIT-PRIV $LOGLIM -j LOG --log-prefix "[GS-PRIV] " --log-level 6
  "$IPT" -A GS-HIT-PRIV -p tcp -j REJECT --reject-with tcp-reset
  "$IPT" -A GS-HIT-PRIV -j REJECT --reject-with icmp-admin-prohibited
  "$IPT" -A GS-HIT-SNITCH $LOGLIM -j LOG --log-prefix "[GS-SNITCH] " --log-level 6
  "$IPT" -A GS-HIT-SNITCH -p tcp -j REJECT --reject-with tcp-reset
  "$IPT" -A GS-HIT-SNITCH -j REJECT --reject-with icmp-admin-prohibited

  # ---- main chain: cheap exits first ----
  "$IPT" -A "$C" -o lo -j RETURN
  "$IPT" -A "$C" -m conntrack --ctdir REPLY -j RETURN          # replies to inbound clients/panel/CDN
  [ "$P2P" = "1" ] && "$IPT" -A "$C" -m connmark --mark "$P2PMARK/$P2PMARK" -j DROP
  "$IPT" -A "$C" -m conntrack --ctstate NEW -j GS-NG-NEW
  if [ "$P2P" = "1" ]; then
    "$IPT" -A "$C" -p tcp --dport 443 -j RETURN
    [ "$CONNBYTES" = "1" ] || "$IPT" -A "$C" -p tcp --dport 80 -j RETURN
    "$IPT" -A "$C" -p udp -m multiport --dports 53,123,443 -j RETURN
    "$IPT" -A "$C" -j GS-NG-P2P
  fi
  "$IPT" -A "$C" -j RETURN

  # ---- NEW connections ----
  for x in $EXEMPT; do "$IPT" -A GS-NG-NEW -d "$x" -j RETURN; done
  if [ "$ABUSE" = "1" ]; then
    # SMB/NetBIOS/RPC to the internet: worm-like, instant abuse reports; no legit use over VPN
    "$IPT" -A GS-NG-NEW -p tcp -m multiport --dports 135,137,138,139,445 -j GS-HIT-SMB
    "$IPT" -A GS-NG-NEW -p udp -m multiport --dports 137,138 -j GS-HIT-SMB
    # scan: one port → many hosts (global per port); brute: many tries → one host:port
    "$IPT" -A GS-NG-NEW -p tcp -m multiport --dports "$ABUSE_PORTS" -m hashlimit --hashlimit-name gs_scan \
      --hashlimit-mode dstport --hashlimit-above 90/min --hashlimit-burst 180 --hashlimit-htable-expire 120000 -j GS-HIT-ABUSE
    "$IPT" -A GS-NG-NEW -p tcp -m multiport --dports "$ABUSE_PORTS" -m hashlimit --hashlimit-name gs_brute \
      --hashlimit-mode dstip,dstport --hashlimit-above 20/min --hashlimit-burst 40 --hashlimit-htable-expire 120000 -j GS-HIT-ABUSE
  fi
  if [ "$SNITCH" = "1" ] && ipset list -n gorecshit-snitch >/dev/null 2>&1; then
    "$IPT" -A GS-NG-NEW -m set --match-set gorecshit-snitch dst -j GS-HIT-SNITCH
  fi
  if [ "$PRIV" = "1" ]; then
    # host needs: DNS/NTP/DHCP anywhere + its own LAN/docker/mesh routes
    "$IPT" -A GS-NG-NEW -p udp -m multiport --dports 53,67,68,123 -j RETURN
    "$IPT" -A GS-NG-NEW -p tcp --dport 53 -j RETURN
    for x in $(private_exempt | sort -u); do "$IPT" -A GS-NG-NEW -d "$x" -j RETURN 2>/dev/null || true; done
    # (198.18.0.0/15 deliberately not here: xray/sing-box FakeDNS and some hosters' proxies use it)
    for x in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10; do
      "$IPT" -A GS-NG-NEW -d "$x" -j GS-HIT-PRIV
    done
    if [ "$META" = "1" ]; then
      "$IPT" -A GS-NG-NEW -d 169.254.0.0/16 -j GS-HIT-PRIV
    fi
  fi
  "$IPT" -A GS-NG-NEW -j RETURN

  # ---- P2P signatures (only small UDP / first TCP packets; 80/443/53 never inspected) ----
  if [ "$P2P" = "1" ]; then
    # DHT (bencoded KRPC) and µTP-wrapped handshakes
    "$IPT" -A GS-NG-P2P -p udp -m length --length 40:1200 -m string --algo bm --string "d1:ad2:id20:" --to 160 -j GS-HIT-P2P
    "$IPT" -A GS-NG-P2P -p udp -m length --length 40:1200 -m string --algo bm --string "d1:rd2:id20:" --to 160 -j GS-HIT-P2P
    "$IPT" -A GS-NG-P2P -p udp -m length --length 40:1200 -m string --algo bm --string "BitTorrent protocol" --to 160 -j GS-HIT-P2P
    # UDP tracker connect: protocol_id 0x41727101980
    "$IPT" -A GS-NG-P2P -p udp -m u32 --u32 "0>>22&0x3C@8=0x00000417 && 0>>22&0x3C@12=0x27101980" -j GS-HIT-P2P 2>/dev/null || true
    if [ "$CONNBYTES" = "1" ]; then
      "$IPT" -A GS-NG-P2P -p tcp -m connbytes --connbytes 0:6 --connbytes-dir original --connbytes-mode packets \
        -m string --algo bm --string "BitTorrent protocol" --to 160 -j GS-HIT-P2P
      "$IPT" -A GS-NG-P2P -p tcp -m connbytes --connbytes 0:6 --connbytes-dir original --connbytes-mode packets \
        -m string --algo bm --string "info_hash=" --to 600 -j GS-HIT-P2P
    else
      "$IPT" -A GS-NG-P2P -p tcp -m length --length 60:400 -m string --algo bm --string "BitTorrent protocol" --to 160 -j GS-HIT-P2P
    fi
    "$IPT" -A GS-NG-P2P -j RETURN
  fi

  # hooks: host (xray in network_mode host → OUTPUT) + bridge containers egress
  "$IPT" -I OUTPUT 1 -j "$C"
  if "$IPT" -S DOCKER-USER >/dev/null 2>&1; then
    "$IPT" -I DOCKER-USER 1 -i docker+ -j "$C"
    "$IPT" -I DOCKER-USER 1 -i br-+ -j "$C"
  else
    "$IPT" -I FORWARD 1 -i docker+ -j "$C"
    "$IPT" -I FORWARD 1 -i br-+ -j "$C"
  fi
}

apply_v6() {
  local IPT=ip6tables
  command -v "$IPT" >/dev/null 2>&1 || return 0
  "$IPT" -S OUTPUT >/dev/null 2>&1 || return 0
  unhook "$IPT"
  "$IPT" -N "$C"; "$IPT" -N GS-HIT-SMB; "$IPT" -N GS-HIT-ABUSE; "$IPT" -N GS-HIT-P2P
  "$IPT" -A GS-HIT-SMB $LOGLIM -j LOG --log-prefix "[GS-SMB] " --log-level 6
  "$IPT" -A GS-HIT-SMB -p tcp -j REJECT --reject-with tcp-reset
  "$IPT" -A GS-HIT-SMB -j DROP
  "$IPT" -A GS-HIT-ABUSE $LOGLIM -j LOG --log-prefix "[GS-ABUSE] " --log-level 6
  "$IPT" -A GS-HIT-ABUSE -p tcp -j REJECT --reject-with tcp-reset
  "$IPT" -A GS-HIT-ABUSE -j DROP
  "$IPT" -A GS-HIT-P2P $LOGLIM -j LOG --log-prefix "[GS-P2P] " --log-level 6
  "$IPT" -A GS-HIT-P2P -j CONNMARK --set-xmark "$P2PMARK/$P2PMARK"
  "$IPT" -A GS-HIT-P2P -j DROP
  "$IPT" -A "$C" -o lo -j RETURN
  "$IPT" -A "$C" -m conntrack --ctdir REPLY -j RETURN
  [ "$P2P" = "1" ] && "$IPT" -A "$C" -m connmark --mark "$P2PMARK/$P2PMARK" -j DROP
  if [ "$ABUSE" = "1" ]; then
    "$IPT" -A "$C" -m conntrack --ctstate NEW -p tcp -m multiport --dports 135,137,138,139,445 -j GS-HIT-SMB
    "$IPT" -A "$C" -m conntrack --ctstate NEW -p tcp -m multiport --dports "$ABUSE_PORTS" -m hashlimit --hashlimit-name gs_scan6 \
      --hashlimit-mode dstport --hashlimit-above 90/min --hashlimit-burst 180 -j GS-HIT-ABUSE
    "$IPT" -A "$C" -m conntrack --ctstate NEW -p tcp -m multiport --dports "$ABUSE_PORTS" -m hashlimit --hashlimit-name gs_brute6 \
      --hashlimit-mode dstip,dstport --hashlimit-above 20/min --hashlimit-burst 40 -j GS-HIT-ABUSE
  fi
  if [ "$SNITCH" = "1" ] && ipset list -n gorecshit-snitch6 >/dev/null 2>&1; then
    "$IPT" -N GS-HIT-SNITCH
    "$IPT" -A GS-HIT-SNITCH $LOGLIM -j LOG --log-prefix "[GS-SNITCH] " --log-level 6
    "$IPT" -A GS-HIT-SNITCH -p tcp -j REJECT --reject-with tcp-reset
    "$IPT" -A GS-HIT-SNITCH -j REJECT --reject-with icmp6-adm-prohibited
    "$IPT" -A "$C" -m conntrack --ctstate NEW -m set --match-set gorecshit-snitch6 dst -j GS-HIT-SNITCH
  fi
  if [ "$P2P" = "1" ]; then
    "$IPT" -A "$C" -p udp -m multiport --dports 53,123,443 -j RETURN
    "$IPT" -A "$C" -p udp -m length --length 40:1200 -m string --algo bm --string "d1:ad2:id20:" --to 180 -j GS-HIT-P2P
    "$IPT" -A "$C" -p udp -m length --length 40:1200 -m string --algo bm --string "d1:rd2:id20:" --to 180 -j GS-HIT-P2P
  fi
  "$IPT" -A "$C" -j RETURN
  "$IPT" -I OUTPUT 1 -j "$C"
}

apply_v4 || echo "netguard: IPv4 apply failed" >&2
apply_v6 || true
exit 0
NETGUARD
  } >"$script"
  chmod 755 "$script"
  write_content "$sysf" "# Managed by ${SCRIPT_NAME} ${VERSION} — conntrack byte/packet accounting for P2P first-packets match
net.netfilter.nf_conntrack_acct = 1
"
  cat >"$unit" <<UNITEOF
[Unit]
Description=gorecshit netguard (outbound abuse/P2P/LAN/snitch guard; NEW connections only)
After=network-pre.target ufw.service docker.service scanner-block.service

[Service]
Type=oneshot
ExecStart=${script}
ExecStop=${script} --flush
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNITEOF
  systemctl daemon-reload 2>/dev/null || true
  systemctl enable gorecshit-netguard.service >/dev/null 2>&1 || true
  sysctl -q -p "$sysf" >/dev/null 2>&1 || true
  "$script" || warn "netguard apply returned non-zero"
  if [[ "$created" -eq 1 ]]; then
    : >"${BACKUP_DIR}/netguard.created"
  fi
  # shellcheck disable=SC2016  # literal rollback code
  _rb_append_block "gorecshit-netguard-restore" '
if [[ -f "$BACKUP_DIR/netguard.created" ]]; then
  /usr/local/sbin/gorecshit-netguard.sh --flush 2>/dev/null || true
  systemctl disable gorecshit-netguard.service 2>/dev/null || true
  rm -f /etc/systemd/system/gorecshit-netguard.service /usr/local/sbin/gorecshit-netguard.sh /etc/sysctl.d/99-gorecshit-netguard.conf
  systemctl daemon-reload 2>/dev/null || true
  echo "netguard removed"
elif [[ -x /usr/local/sbin/gorecshit-netguard.sh ]]; then
  /usr/local/sbin/gorecshit-netguard.sh || true
fi
# re-apply restored anti-probe (ufw reload drops its hook), then drop sets nothing references any more
[[ -x /usr/local/sbin/gorecshit-anti-probe.sh ]] && /usr/local/sbin/gorecshit-anti-probe.sh >/dev/null 2>&1 || true
iptables -L ufw-reject-input -n >/dev/null 2>&1 && { iptables -C ufw-reject-input -j DROP 2>/dev/null || iptables -I ufw-reject-input 1 -j DROP 2>/dev/null; } || true
for _s in gorecshit-cdn gorecshit-snitch6 gorecshit-snitch gorecshit-rep; do ipset destroy "$_s" 2>/dev/null || true; done'
  local what=()
  [[ "$DO_P2P_BLOCK" -eq 1 ]] && what+=("торренты/DHT")
  [[ "$DO_ABUSE_LIMIT" -eq 1 ]] && what+=("сканы/брутфорс/SMB")
  [[ "$DO_PRIVATE_EGRESS" -eq 1 ]] && what+=("LAN хостера")
  [[ "$DO_SNITCH_GUARD" -eq 1 ]] && what+=("VK/MAX")
  ok "Netguard: ${what[*]:-ничего} — только новые соединения; 80/443 не инспектируются; скорость не трогаем"
  if [[ "$DO_SNITCH_GUARD" -eq 1 ]]; then
    log "VK/MAX/OK/mail.ru через ноду закрыты (MAX сдаёт IP VPN-серверов). Клиентам: РФ-сервисы — напрямую (split-routing в Happ)."
  fi
}

configure_decoy_web() {
  # Optional: port 80 → 301 https (как у любого HTTPS-сайта). Only via existing nginx; otherwise recommendation.
  step "Декой :80 (опционально)"
  local reason=""
  if [[ "$MODE" == "cdn" || "$CADDY_PRESENT" -eq 1 ]]; then
    reason="Caddy/CDN-режим — порт 80 уже ваш"
  elif ss -Hltn '( sport = :80 )' 2>/dev/null | grep -q .; then
    reason="порт 80 уже кем-то слушается"
  elif [[ ",${CLIENT_PORTS}," == *",80,"* ]]; then
    reason="80 — клиентский порт"
  elif [[ ",${CLIENT_PORTS}," != *",443,"* ]]; then
    reason="REALITY не на 443 — редирект на https://IP:443 вёл бы в никуда"
  elif ! command -v nginx >/dev/null 2>&1 || ! systemctl is-active --quiet nginx 2>/dev/null; then
    reason="nginx не установлен/не запущен — ставить веб-сервер ради декоя не будем (закрытый 80 — тоже нормально)"
  elif [[ ! -d /etc/nginx/conf.d ]] || ! grep -RqsE 'include[[:space:]]+/etc/nginx/conf\.d/\*\.conf' /etc/nginx/nginx.conf; then
    reason="nginx без include conf.d/*.conf — не трогаем конфиг"
  fi
  if [[ -n "$reason" ]]; then
    [[ "$DO_DECOY_WEB" -eq 1 ]] && warn "--decoy-web: пропуск — ${reason}"
    log "Декой :80 не ставим: ${reason}"
    return 0
  fi
  if [[ "$DO_DECOY_WEB" -eq 0 ]]; then
    if ! _tty_ask_yn "Включить декой на :80 (nginx: 301 → https, как у обычного сайта)? По умолчанию нет"; then
      log "Декой :80 не включён (по умолчанию нет; флаг --decoy-web)"
      return 0
    fi
  fi
  local conf="/etc/nginx/conf.d/gorecshit-decoy.conf"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b write %s (listen 80 → 301 https), nginx -t, reload, ufw allow 80/tcp\n' "${C_YEL}" "${C_RESET}" "$conf"
    return 0
  fi
  local created=0 v6listen=""
  [[ -e "$conf" ]] || created=1
  backup_file "$conf"
  if [[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" == "0" ]]; then
    v6listen="    listen [::]:80 default_server;"
  fi
  write_content "$conf" "# Managed by ${SCRIPT_NAME} ${VERSION} — decoy: behave like any HTTPS site on :80
server {
    listen 80 default_server;
${v6listen}
    server_name _;
    server_tokens off;
    access_log off;
    return 301 https://\$host\$request_uri;
}
"
  if ! nginx -t >/dev/null 2>&1; then
    warn "nginx -t не прошёл с декоем — убираю"
    rm -f "$conf"
    [[ -f "${BACKUP_DIR}${conf}" ]] && cp -a "${BACKUP_DIR}${conf}" "$conf"
    return 0
  fi
  systemctl reload nginx 2>/dev/null || true
  local ufw_added=0
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qiE 'Status:\s*active'; then
    if ! ufw status 2>/dev/null | grep -qE '^80(/tcp)?[[:space:]]+ALLOW[[:space:]]+Anywhere'; then
      ufw allow 80/tcp comment 'gorecshit-decoy-80' >/dev/null 2>&1 || true
      ufw_added=1
    fi
  fi
  [[ "$created" -eq 1 ]] && : >"${BACKUP_DIR}/decoy-web.created"
  [[ "$ufw_added" -eq 1 ]] && : >"${BACKUP_DIR}/decoy-web.ufw80"
  # shellcheck disable=SC2016  # body is literal rollback.sh code
  _rb_append_block "gorecshit-decoy-restore" '
if [[ -f "$BACKUP_DIR/decoy-web.created" ]]; then
  rm -f /etc/nginx/conf.d/gorecshit-decoy.conf
  nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true
fi
if [[ -f "$BACKUP_DIR/decoy-web.ufw80" ]] && command -v ufw >/dev/null; then
  ufw --force delete allow 80/tcp >/dev/null 2>&1 || true
fi'
  ok "Декой :80 включён (301 → https, server_tokens off)"
}

ufw_remove_public_node_port() {
  # Delete "NODE_PORT ALLOW Anywhere" (v4/v6) — only for a family where no non-panel
  # established peer exists on NODE_PORT (never cut the panel↔node link).
  command -v ufw >/dev/null 2>&1 || return 0
  local np="$NODE_PORT"
  is_port "$np" || return 0
  local peers v4_other=0 v6_other=0 pa
  peers="$(ss -Htn state established "( sport = :${np} )" 2>/dev/null | awk '{print $4}' || true)"
  while IFS= read -r pa; do
    [[ -n "$pa" ]] || continue
    pa="${pa%:*}"; pa="${pa#[}"; pa="${pa%]}"; pa="${pa#::ffff:}"
    if [[ "$pa" == *:* ]]; then v6_other=1
    elif [[ "$pa" != "$PANEL_IP" ]]; then v4_other=1
    fi
  done <<<"$peers"
  local -a del=()
  local line num is6
  while IFS= read -r line; do
    [[ "$line" =~ ^\[\ *([0-9]+)\]\ +${np}(/tcp)?(\ \(v6\))?\ +ALLOW(\ IN)?\ +Anywhere ]] || continue
    num="${BASH_REMATCH[1]}"
    is6=0; [[ -n "${BASH_REMATCH[3]}" ]] && is6=1
    if [[ "$is6" -eq 1 && "$v6_other" -eq 1 ]]; then
      warn "NODE_PORT ${np} открыт всем по IPv6, но есть живое IPv6-соединение к нему — правило оставлено (панель по IPv6?)"
      continue
    fi
    if [[ "$is6" -eq 0 && "$v4_other" -eq 1 ]]; then
      warn "NODE_PORT ${np} открыт всем по IPv4 и есть соединение не с IP панели — правило оставлено, проверьте вручную"
      continue
    fi
    del+=("$num")
  done < <(ufw status numbered 2>/dev/null || true)
  [[ ${#del[@]} -gt 0 ]] || return 0
  backup_file /etc/ufw/user.rules
  backup_file /etc/ufw/user6.rules
  local n
  for n in $(printf '%s\n' "${del[@]}" | sort -rn); do
    ufw --force delete "$n" >/dev/null 2>&1 || true
  done
  ok "Удалены публичные ALLOW для NODE_PORT ${np} (${#del[@]} шт.) — остался доступ только с панели ${PANEL_IP}"
}

run_hardening() {
  ensure_network_dns
  system_upgrade
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
  configure_egress_guard
  configure_netguard
  configure_stealth
  configure_decoy_web
  configure_hostname_tz
  configure_docker_journal
  maybe_apply_docker_daemon_restart
  configure_certbot_hooks
  final_verify
  install_cli_command  # ensure CLI after hardening
  restore_apt_timers
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
        && "$DO_AUDIT" -eq 0 \
        && "$DO_FINGERPRINT_ONLY" -eq 0 \
        && "$DO_UPDATE_ONLY" -eq 0 \
        && "$DO_IP_CHECK" -eq 0 && "$DO_ABUSE_REPORT" -eq 0 \
        && -t 0 && -t 1 ]]; then
    interactive_menu
  fi

  if [[ "$DO_STATUS_ONLY" -eq 1 ]]; then
    show_status_summary || true
    exit 0
  fi

  if [[ "$DO_DPI_CHECK" -eq 1 ]]; then
    run_dpi_check
    exit 0
  fi

  if [[ "$DO_AUDIT" -eq 1 ]]; then
    run_node_audit
    exit 0
  fi

  if [[ "$DO_FINGERPRINT_ONLY" -eq 1 ]]; then
    run_fingerprint_only
    exit 0
  fi

  if [[ "$DO_IP_CHECK" -eq 1 ]]; then
    run_ip_check
    exit 0
  fi

  if [[ "$DO_ABUSE_REPORT" -eq 1 ]]; then
    run_abuse_report
    exit 0
  fi

  if [[ "$DO_REFRESH_LISTS_ONLY" -eq 1 ]]; then
    if [[ "$(id -u)" -ne 0 ]]; then err "Must run as root"; exit 1; fi
    if [[ -x /usr/local/sbin/scanner-block-refresh.sh ]]; then
      /usr/local/sbin/scanner-block-refresh.sh
      exit 0
    fi
    warn "Защита ещё не установлена — списки сканеров обновляет пункт 1 (он их и ставит)"
    if [[ "$CLI_ASSUME_YES" -eq 1 ]] || ! _tty_usable; then
      err "scanner-block-refresh.sh не установлен — сначала: gorecshit → пункт 1 (или --panel-ip X --yes)"
      exit 1
    fi
    if _tty_ask_yn "Запустить полную установку защиты сейчас (пункт 1)?"; then
      DO_REFRESH_LISTS_ONLY=0
      apply_modules_csv "all"
      prompt_panel_ip
      FROM_MENU=1
      ASSUME_YES=1
    else
      log "Ок, установку не запускаем. Позже: gorecshit → пункт 1"
      exit 0
    fi
  fi

  if [[ "$DO_ROLLBACK" -eq 1 ]]; then
    if [[ "$DRY_RUN" -eq 0 && "$(id -u)" -ne 0 ]]; then err "Must run as root"; exit 1; fi
    do_rollback
  fi

  prompt_panel_ip
  preflight
  detect_remnanode
  write_rollback_script

  if [[ "$ASSUME_YES" -eq 0 && "$DRY_RUN" -eq 0 ]] && can_prompt_user; then
    echo
    log "Будет применён hardening: panel=${PANEL_IP} node_port=${NODE_PORT} clients=${CLIENT_PORTS} udp=${CLIENT_UDP_PORTS} mode=${MODE} relays=${RELAY_IPS}"
    local ans
    prompt_user 'Продолжить? [y/N] ' ans
    [[ "$ans" =~ ^[Yy]$ ]] || { warn "Отменено"; exit 0; }
  fi

  run_hardening
}

main "$@"
