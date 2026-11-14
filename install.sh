#!/usr/bin/env bash
# gorecshit v2.7.1 — one-command hardening for Remnawave VPN node servers (Debian 11+/Ubuntu 20.04+)
# Usage:
#   bash install.sh --panel-ip X.X.X.X [--node-port 2222] [--yes]
#   bash install.sh --check --panel-ip X.X.X.X
#   bash install.sh                      # interactive Russian menu (TTY)
# Idempotent. No secrets. Panel IP / NODE_PORT via flags or GORECSHIT_* env.
# Does NOT restart Docker while remnanode/xray is live. Does NOT deploy itself.
set -Eeuo pipefail

VERSION="2.7.1"
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
DO_DECOY_WEB=0           # --decoy-web: :80 → 301 https via existing nginx (else asks via /dev/tty, default no)
# v2.7.1 site camouflage (domain + Let's Encrypt + static site for REALITY self-steal)
DO_SITE=0                # module "site" (needs --site-domain)
DO_SITE_ONLY=0           # --site / menu 10: run only the site module
SITE_STANDALONE=0
SITE_DOMAIN=""           # --site-domain node.example.ru
SITE_EMAIL=""            # --site-email (Let's Encrypt account, optional)
SITE_THEME="auto"        # --site-theme it|photo|translate|coffee|auto
SITE_MODE="auto"         # --site-mode auto|selfsteal|public
SITE_MODE_ACTIVE=""
SITE_PORT=9443           # --site-port: local TLS port nginx serves for REALITY target
SITE_LISTEN="127.0.0.1"  # --site-listen: local address (docker bridge IP if remnanode is not host-network)
SITE_PP=0                # --site-proxy-protocol: nginx expects PROXY protocol (xver=1)
SITE_CLOSE80=0           # --site-close-80: close 80/tcp after issue; open briefly on renewal
SITE_SKIP_DNS=0          # --site-skip-dns-check
SITE_SEED=""             # --site-seed: change to regenerate a different site
SITE_ROOT=""
SITE_PORT_SET=""; SITE_LISTEN_SET=""; SITE_PP_SET=""
SITE_NET_HOST=2
SITE_DEFAULT80=1
SITE_GEN_THEME=""
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
  [[ -r /dev/tty ]] && return 0
  [[ -t 0 && -t 1 ]] && return 0
  return 1
}

read_user_input() {
  # read_user_input VAR — reads one line from /dev/tty if available, else stdin
  local __ru_var="$1"
  if [[ -r /dev/tty ]]; then
    IFS= read -r "$__ru_var" < /dev/tty || true
  else
    IFS= read -r "$__ru_var" || true
  fi
}

prompt_user() {
  # prompt_user "text" VAR — print prompt (to tty if possible) and read answer
  local __msg="$1" __var="$2"
  if [[ -w /dev/tty ]]; then
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
  install.sh --site-domain D [--site-email E]   # node subdomain + Let's Encrypt + decoy website

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
                             fail2ban,sysctl,hostname,docker,egress_guard,decoy_web,site
                             (default: all enabled except decoy_web and site)
  --ipv6-off                 Opt-in: disable IPv6 via sysctl (default: keep IPv6 on; safer under dual-stack xray)
  --no-ipv6-off              Keep IPv6 enabled (default; retained for compatibility)
  --no-blocklist             Skip scanner ipset blocklist
  --no-hostname              Do not change hostname
  --no-hide-ports            Skip ICMP/closed-port hiding
  --no-anti-probe            Skip client-port rate limits
  --no-stealth               Skip stealth / not-look-like-VPN tweaks
  --no-egress-guard          Skip outbound SMTP block (abuse guard) for host + docker
  --egress-block-ports LIST  Outbound TCP ports to block (default: 25; e.g. 25,465,587)
  --decoy-web                Port 80 → 301 https via existing nginx (only if safe; else skip)
  --site                     Only the site module (menu 10): subdomain + Let's Encrypt + website
  --site-domain DOMAIN       Node subdomain (A record → this IP, Cloudflare "DNS only").
                             Alone = --site; with --panel-ip = added to full install
  --site-email EMAIL         Let's Encrypt account e-mail (optional)
  --site-theme T             it|photo|translate|coffee|auto (default auto, picked from domain)
  --site-mode M              auto|selfsteal|public (auto: 443 busy by xray → selfsteal)
  --site-port N              Local TLS port for REALITY target (default 9443)
  --site-listen IP           Local listen address (default 127.0.0.1; docker0 IP if remnanode not host-net)
  --site-proxy-protocol      nginx expects PROXY protocol on the local port (set xver=1 in panel)
  --site-close-80            Close 80/tcp after issuing; certbot opens it briefly on renewal
  --site-seed S              Different seed = different generated site
  --site-skip-dns-check      Skip A/AAAA → this IP check
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
  DO_RESOLV_V4=0; DO_CERTBOT_HOOKS=0; DO_EGRESS_GUARD=0
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
      site|camouflage|website) DO_SITE=1 ;;
      docker|journald|journal)
        DO_DOCKER_JOURNAL=1; DO_DOCKER_USER=1; DO_RESOLV_V4=1; DO_CERTBOT_HOOKS=1; DO_NOFILE=1 ;;
      all)
        DO_UFW=1; DO_BLOCKLIST=1; DO_HIDE_PORTS=1; DO_ANTI_PROBE=1
        DO_SSH=1; DO_STEALTH=1; DO_FAIL2BAN=1; DO_SYSCTL=1
        DO_HOSTNAME=1; DO_DOCKER_JOURNAL=1; DO_DOCKER_USER=1; DO_NOFILE=1
        DO_RESOLV_V4=1; DO_CERTBOT_HOOKS=1; DO_EGRESS_GUARD=1 ;;
      minimum|min)
        DO_UFW=1; DO_SSH=1; DO_FAIL2BAN=1; DO_SYSCTL=1; DO_BLOCKLIST=1
        DO_HIDE_PORTS=1; DO_DOCKER_USER=1; DO_EGRESS_GUARD=1 ;;
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
      --site) DO_SITE_ONLY=1; shift ;;
      --site-domain) SITE_DOMAIN="${2:-}"; shift 2 ;;
      --site-email) SITE_EMAIL="${2:-}"; shift 2 ;;
      --site-theme) SITE_THEME="${2:-auto}"; shift 2 ;;
      --site-mode) SITE_MODE="${2:-auto}"; shift 2 ;;
      --site-port) SITE_PORT="${2:-}"; SITE_PORT_SET=1; shift 2 ;;
      --site-listen) SITE_LISTEN="${2:-}"; SITE_LISTEN_SET=1; shift 2 ;;
      --site-proxy-protocol) SITE_PP=1; SITE_PP_SET=1; shift ;;
      --site-close-80) SITE_CLOSE80=1; shift ;;
      --site-seed) SITE_SEED="${2:-}"; shift 2 ;;
      --site-skip-dns-check) SITE_SKIP_DNS=1; shift ;;
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
  if [[ -n "$SITE_LISTEN_SET" ]] && ! is_ipv4 "$SITE_LISTEN"; then
    err "Invalid --site-listen: $SITE_LISTEN (IPv4)"; exit 2
  fi
  # --site-domain: alone → site-only run; with --panel-ip → part of the full install
  if [[ -n "$SITE_DOMAIN" ]]; then
    if [[ -n "$PANEL_IP" ]]; then DO_SITE=1; else DO_SITE_ONLY=1; fi
  fi
}


prompt_panel_ip() {
  if [[ -n "$PANEL_IP" ]]; then return 0; fi
  if [[ "$DO_ROLLBACK" -eq 1 || "$DO_STATUS_ONLY" -eq 1 || "$DO_REFRESH_LISTS_ONLY" -eq 1 || "$DO_DPI_CHECK" -eq 1 || "$DO_AUDIT" -eq 1 || "$DO_FINGERPRINT_ONLY" -eq 1 || "$DO_UPDATE_ONLY" -eq 1 ]]; then return 0; fi
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
  if [[ -f "$SITE_STATE_FILE" ]]; then
    echo "---- сайт-маскировка ----"
    grep -E '^SITE_(DOMAIN|MODE_ACTIVE|LISTEN|PORT|PP|THEME)=' "$SITE_STATE_FILE" 2>/dev/null || true
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

_audit_is_own_site() {
  # true, если строка dest/SNI/CN указывает на наш сайт-маскировку (v2.7.1 self-steal)
  local s="${1,,}" d="" l="" p=""
  [[ -f /var/lib/gorecshit/site.env ]] || return 1
  d="$(sed -n 's/^SITE_DOMAIN=//p' /var/lib/gorecshit/site.env | head -1)"
  l="$(sed -n 's/^SITE_LISTEN=//p' /var/lib/gorecshit/site.env | head -1)"
  p="$(sed -n 's/^SITE_PORT=//p' /var/lib/gorecshit/site.env | head -1)"
  [[ -n "$d" && "$s" == *"$d"* ]] && return 0
  [[ -n "$l" && -n "$p" && "$s" == *"${l}:${p}"* ]] && return 0
  return 1
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
      _audit_is_own_site "$masked" && q="own"
      case "$q" in
        own)  _audit_ok "CN/SAN = ваш домен сайта-маскировки (${masked}) — self-steal" ;;
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
      _audit_is_own_site "${dest}|${sni}" && q="own"
      case "$q" in
        own)  _audit_ok "dest/serverNames → ваш сайт-маскировка (${dest:-$sni}) — self-steal, свой домен и сертификат" ;;
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
  _audit_site

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
    printf '  %b10)%b 🌐 Сайт-маскировка (поддомен + сертификат + сайт)\n' "${C_BOLD}" "${C_RESET}"
    menu_sep
    printf '  %b0)%b 🚪 Выход\n' "${C_BOLD}" "${C_RESET}"
    printf '%bCLI: gorecshit [--status|--update|--audit|--stealth|--site-domain D|--yes|--modules …]%b\n' "${C_GREY}" "${C_RESET}"
    if [[ -w /dev/tty ]]; then
      printf '%bВыберите пункт [0-10]:%b ' "${C_BOLD}" "${C_RESET}" > /dev/tty
    else
      printf '%bВыберите пункт [0-10]:%b ' "${C_BOLD}" "${C_RESET}"
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
        DO_SITE_ONLY=1
        return 0
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
  echo "  13 site (поддомен + сертификат + сайт для REALITY, нужен домен)"
  echo "  (или: minimum — UFW+SSH+fail2ban+blocklist+BBR)"
  local ans
  prompt_user 'Номера: ' ans
  if [[ -z "$ans" ]]; then
    selected="all"
  elif [[ "$ans" == "minimum" || "$ans" == "min" ]]; then
    selected="minimum"
  else
    local map=( "" ufw blocklist hide_ports anti_probe ssh stealth fail2ban sysctl hostname docker egress_guard decoy_web site )
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
  log "Выбраны модули: ufw=$DO_UFW blocklist=$DO_BLOCKLIST hide=$DO_HIDE_PORTS probe=$DO_ANTI_PROBE ssh=$DO_SSH stealth=$DO_STEALTH f2b=$DO_FAIL2BAN sysctl=$DO_SYSCTL host=$DO_HOSTNAME docker=$DO_DOCKER_JOURNAL egress=$DO_EGRESS_GUARD decoy=$DO_DECOY_WEB site=$DO_SITE"
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
    # IPv6 ping too (v2.6.0): only echo-request; NDP / packet-too-big untouched
    if [[ -f /etc/ufw/before6.rules ]]; then
      backup_file /etc/ufw/before6.rules
      sed -i -E 's/^(-A ufw6-before-input -p icmpv6 --icmpv6-type echo-request -j) ACCEPT/\1 DROP/' /etc/ufw/before6.rules || true
      sed -i -E 's/^(-A ufw6-before-forward -p icmpv6 --icmpv6-type echo-request -j) ACCEPT/\1 DROP/' /etc/ufw/before6.rules || true
    fi
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

  # IPv6 parity (v2.6.0): with IPv6 on, UFW must manage ip6tables too — else every port is open over v6
  if [[ "$IPV6_OFF" -eq 0 && -f /etc/default/ufw ]] && grep -qE '^IPV6=' /etc/default/ufw \
     && ! grep -qE '^IPV6=yes' /etc/default/ufw; then
    sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw || true
    ok "UFW IPV6=yes — правила зеркалируются на IPv6"
  fi

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
  elif [[ -r /dev/tty ]]; then
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
  echo "modules: ufw=$DO_UFW blocklist=$DO_BLOCKLIST hide=$DO_HIDE_PORTS probe=$DO_ANTI_PROBE ssh=$DO_SSH stealth=$DO_STEALTH f2b=$DO_FAIL2BAN sysctl=$DO_SYSCTL host=$DO_HOSTNAME docker=$DO_DOCKER_JOURNAL egress=$DO_EGRESS_GUARD decoy=$DO_DECOY_WEB site=$DO_SITE"
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

configure_decoy_web() {
  # Optional: port 80 → 301 https (как у любого HTTPS-сайта). Only via existing nginx; otherwise recommendation.
  step "Декой :80 (опционально)"
  local reason=""
  if [[ "$DO_SITE" -eq 1 || -f "$SITE_NGINX_CONF" ]]; then
    reason="порт 80 обслуживает сайт-маскировка (v2.7.1: ACME + 301 → https://домен)"
  elif [[ "$MODE" == "cdn" || "$CADDY_PRESENT" -eq 1 ]]; then
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

# ---------- v2.7.1: «Сайт-маскировка» — домен ноды + Let's Encrypt + многостраничный сайт ----------
# Схема self-steal: nginx отдаёт настоящий сайт с настоящим сертификатом на 127.0.0.1:SITE_PORT,
# REALITY на 443 использует target=127.0.0.1:SITE_PORT и serverNames=[домен].
# Скрипт НЕ трогает конфиг панели/инбаунды — печатает значения, которые вставляются вручную.

# Слова, которых не должно быть на сайте (проверка генератора и аудита). Кириллица — тремя
# регистрами явно: grep -i в C-локали не понимает кириллицу.
SITE_FORBIDDEN_RE='vpn|proxy|xray|v2ray|vless|reality|remnawave|gorec|tunnel|прокси|Прокси|ПРОКСИ|впн|Впн|ВПН|обход|Обход|ОБХОД'
# Слова в домене — только предупреждение (домен выбирает владелец нод, напр. gorecvpn.top)
SITE_DOMAIN_FORBIDDEN_RE='vpn|proxy|xray|v2ray|vless|reality|remnawave|tunnel'
SITE_STATE_FILE="/var/lib/gorecshit/site.env"
SITE_NGINX_CONF="/etc/nginx/conf.d/gorecshit-site.conf"
SITE_ACME_ROOT="/var/www/letsencrypt"
SITE_THEMES="it photo translate coffee"

site_forbidden_scan() {
  # site_forbidden_scan FILE... — печатает «файл:строка:совпадение»; rc 0 если что-то найдено
  LC_ALL=C grep -HnoiE "$SITE_FORBIDDEN_RE" "$@" 2>/dev/null
}

_site_seed_from() {
  local s
  s="$(printf '%s' "$1" | cksum | awk '{print $1}')"
  SITE_RNG=$(( s % 2147483647 ))
  [[ "$SITE_RNG" -gt 0 ]] || SITE_RNG=1
}

_site_next() {
  SITE_RNG=$(( (SITE_RNG * 1103515245 + 12345) % 2147483648 ))
}

_site_pick() {
  # _site_pick VAR item1 item2 ... — детерминированно от сида (без сабшелла: сид обновляется)
  local __v="$1"; shift
  _site_next
  local __i=$(( (SITE_RNG / 7) % $# + 1 ))
  printf -v "$__v" '%s' "${!__i}"
}

_site_rint() {
  # _site_rint VAR MIN MAX
  _site_next
  printf -v "$1" '%d' $(( $2 + (SITE_RNG / 7) % ($3 - $2 + 1) ))
}

_site_shuffle() {
  # _site_shuffle ARRNAME — Fisher–Yates на месте
  local -n __a="$1"
  local i j t
  for (( i=${#__a[@]}-1; i>0; i-- )); do
    _site_next
    j=$(( (SITE_RNG / 7) % (i + 1) ))
    t="${__a[i]}"; __a[i]="${__a[j]}"; __a[j]="$t"
  done
}

_site_html_esc() {
  local s="$1"
  s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"; s="${s//\"/&quot;}"
  printf '%s' "$s"
}

_site_ru_date() {
  # _site_ru_date EPOCH → «12 марта 2026»
  local d m y
  local -a months=(января февраля марта апреля мая июня июля августа сентября октября ноября декабря)
  d="$(date -d "@$1" +%-d)"; m="$(date -d "@$1" +%-m)"; y="$(date -d "@$1" +%Y)"
  printf '%s %s %s' "$d" "${months[m-1]}" "$y"
}

_site_write_ico() {
  # 16x16 32bpp ICO: цветной квадрат со светлой рамкой (чтобы /favicon.ico не был 404)
  local out="$1" r="$2" g="$3" b="$4" x y px
  local bg fg
  printf -v bg '\\x%02x\\x%02x\\x%02x\\xff' "$b" "$g" "$r"
  fg='\xf5\xf5\xf5\xff'
  {
    printf '\x00\x00\x01\x00\x01\x00'
    printf '\x10\x10\x00\x00\x01\x00\x20\x00\x68\x04\x00\x00\x16\x00\x00\x00'
    printf '\x28\x00\x00\x00\x10\x00\x00\x00\x20\x00\x00\x00\x01\x00\x20\x00'
    printf '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    for (( y=0; y<16; y++ )); do
      for (( x=0; x<16; x++ )); do
        px="$bg"
        if (( (x>=4 && x<=11) && (y>=4 && y<=11) && (x==4 || x==11 || y==4 || y==11) )); then px="$fg"; fi
        printf '%b' "$px"
      done
    done
    for (( y=0; y<64; y++ )); do printf '\x00'; done
  } >"$out"
}

# --- Тексты тем. Формат: "Заголовок|Описание" для услуг; "slug|Заголовок|Анонс|Абзац1|Абзац2|Абзац3" для статей.
_site_theme_data() {
  local theme="$1"
  SITE_T_NAMES=(); SITE_T_TAGS=(); SITE_T_SERV=(); SITE_T_POSTS=(); SITE_T_ABOUT=(); SITE_T_KIND=""; SITE_T_SERV_TITLE=""
  case "$theme" in
    it)
      SITE_T_KIND="Студия веб-разработки"
      SITE_T_SERV_TITLE="Услуги"
      SITE_T_NAMES=("Северный код" "Ясный пиксель" "Линия сборки" "Тихая гавань" "Два бита" "Кодовая мастерская" "Светлый стек" "Квадрат и точка")
      SITE_T_TAGS=("Делаем сайты и внутренние сервисы, которыми удобно пользоваться"
                   "Небольшая команда, аккуратный код и честные сроки"
                   "Проектируем, разрабатываем и сопровождаем веб-проекты")
      SITE_T_ABOUT=("Мы начинали как два разработчика, которые делали сайты для знакомых. Сегодня в команде дизайнер, фронтенд- и бэкенд-разработчики и менеджер проектов, но подход остался прежним: сначала разобраться в задаче, потом писать код."
                    "Работаем с малым и средним бизнесом, образовательными проектами и некоммерческими организациями. Не беремся за всё подряд: если задача не наша, честно скажем и посоветуем, к кому обратиться."
                    "Каждый проект сопровождаем после запуска: обновления, резервные копии, мониторинг доступности и понятные отчеты раз в месяц.")
      SITE_T_SERV=("Сайты-визитки|Лёгкие быстрые сайты на статике: открываются мгновенно и почти не требуют обслуживания."
                   "Интернет-каталоги|Каталог товаров или услуг с поиском, фильтрами и удобной админкой."
                   "Внутренние сервисы|Учёт заявок, графики смен, личные кабинеты для сотрудников и клиентов."
                   "Аудит и ускорение|Находим, почему сайт медленный, и исправляем: от картинок до запросов к базе."
                   "Сопровождение|Обновления, резервные копии, мониторинг и мелкие доработки по подписке."
                   "Дизайн интерфейсов|Прототипы и макеты, которые проверяем на реальных пользователях до разработки.")
      SITE_T_POSTS=("static-sites|Почему статический сайт — хороший выбор для малого бизнеса|Разбираем, когда сложная CMS не нужна и как статика экономит деньги.|Большинству небольших компаний сайт нужен, чтобы рассказать о себе, показать услуги и дать контакты. Для этого не требуется база данных, панель администратора и десяток плагинов.|Статический сайт собирается один раз и отдаётся веб-сервером как набор файлов. Он быстро открывается даже на слабом мобильном интернете, его сложно сломать, а хостинг стоит копейки.|Если контент меняется раз в месяц, правки удобно вносить через простой редактор или поручить нам. Когда появятся новые задачи, статический сайт легко дополнить нужными функциями."
                    "image-optimization|Как ускорить сайт за один вечер: картинки|Простые шаги, которые уменьшают вес страниц в несколько раз.|Чаще всего сайт тормозит не из-за кода, а из-за фотографий в исходном размере. Снимок с телефона весит 4–6 мегабайт, а на странице он показывается шириной 600 пикселей.|Достаточно подготовить несколько размеров изображения и отдавать современный формат вроде WebP или AVIF. Атрибуты width и height помогают браузеру не прыгать при загрузке.|Ленивая загрузка для картинок ниже первого экрана — ещё одна бесплатная оптимизация: браузер не тратит трафик на то, что пользователь может и не увидеть."
                    "backups|Резервные копии: правило 3-2-1 на практике|Как мы храним копии проектов клиентов и почему это не паранойя.|Правило простое: три копии данных, на двух разных носителях, одна из них — в другом месте. Звучит избыточно, пока не случится первая авария.|Мы делаем ежедневные снимки баз данных и еженедельные полные копии файлов. Раз в квартал проверяем, что из копии действительно можно восстановиться.|Самая частая ошибка — копия, которую никто никогда не пробовал развернуть. Восстановление нужно репетировать так же, как пожарную эвакуацию."
                    "accessibility|Доступность сайта: с чего начать|Пять проверок, которые можно сделать без специальных инструментов.|Попробуйте пройти по сайту только с клавиатуры: доходит ли фокус до всех ссылок и кнопок, видно ли, где он находится.|Проверьте контраст текста: светло-серый на белом выглядит стильно, но читается плохо. У всех картинок, которые несут смысл, должен быть альтернативный текст.|Заголовки должны идти по порядку, а формы — иметь подписи к полям. Эти простые правила помогают не только людям с особыми потребностями, но и всем остальным."
                    "estimates|Как мы оцениваем сроки проекта|Почему мы называем диапазон, а не одну дату, и как его сузить.|Точная дата в начале проекта — почти всегда обещание, которое придётся нарушить. Поэтому мы называем диапазон и объясняем, от чего он зависит.|Первая неделя уходит на уточнение требований и прототип. После неё неопределённость сильно уменьшается, и мы фиксируем план по этапам.|Каждые две недели показываем работающую версию. Так заказчик видит прогресс и может вовремя поменять приоритеты.")
      ;;
    photo)
      SITE_T_KIND="Фотостудия"
      SITE_T_SERV_TITLE="Съёмки"
      SITE_T_NAMES=("Светотень" "Мягкий свет" "Кадр за кадром" "Полдень" "Серебряная зернистость" "Северное окно" "Тёплый тон" "Длинная выдержка")
      SITE_T_TAGS=("Портреты, семейные истории и предметная съёмка при естественном свете"
                   "Спокойные живые фотографии без лишней постановки"
                   "Снимаем людей, вещи и места такими, какие они есть")
      SITE_T_ABOUT=("Студия выросла из любви к естественному свету. Мы снимаем у большого окна, на улице и дома у клиентов, стараясь, чтобы человек на фото узнавал себя."
                    "Перед съёмкой обязательно созваниваемся: обсуждаем идею, одежду, место и время. Это занимает пятнадцать минут, но экономит часы на площадке."
                    "Готовые фотографии передаём через закрытую галерею в течение двух недель. Ретушь деликатная: убираем случайное, но не меняем лицо.")
      SITE_T_SERV=("Портрет|Индивидуальная съёмка в студии или на улице, 1 час, 30 обработанных кадров."
                   "Семейная съёмка|Дома или на прогулке, с детьми и бабушками, без утомительных поз."
                   "Предметная съёмка|Фото товаров для каталога и маркетплейсов на белом фоне и в интерьере."
                   "Деловой портрет|Фото для сайта компании и профиля: быстро, аккуратно, в едином стиле."
                   "Репортаж|Конференции, семинары, открытия — снимаем незаметно и отдаём лучшие кадры."
                   "Печать и альбомы|Помогаем отобрать снимки и печатаем на хорошей бумаге.")
      SITE_T_POSTS=("window-light|Как снимать у окна: свет, который всегда с вами|Простые приёмы для портретов при дневном свете.|Большое окно — лучший софтбокс, и он бесплатный. Главное — не ставить человека прямо против света и не снимать в полдень под прямыми лучами.|Если свет слишком контрастный, повесьте на окно тонкую белую ткань. Отражатель можно заменить листом пенокартона или даже белой простынёй.|Попробуйте повернуть модель на три четверти к окну: появится объём, а глаза получат красивый блик."
                    "what-to-wear|Что надеть на фотосессию|Подсказки, которые мы даём всем клиентам перед съёмкой.|Однотонная одежда спокойных цветов почти всегда выглядит лучше ярких принтов и крупных логотипов. Она не отвлекает от лица.|Если снимаемся семьёй, договоритесь о палитре из двух-трёх оттенков, но не одевайтесь одинаково. Важно, чтобы всем было удобно двигаться.|Возьмите с собой запасной вариант одежды. Иногда на месте становится понятно, что другой цвет лучше подходит к фону."
                    "product-basics|Предметная съёмка для каталога: базовые правила|Как получить ровные одинаковые фото товаров.|Для каталога важнее всего единообразие: одинаковый фон, ракурс и свет на всех снимках. Покупатель сравнивает товары, и разный свет мешает.|Мы снимаем на штативе с фиксированными настройками и отмечаем положение предмета на столе. Так серия из сотни фото выглядит цельной.|Отдельно делаем несколько кадров в интерьере: они помогают понять размер и настроение вещи."
                    "film-look|Зачем мы иногда снимаем на плёнку|О медленной фотографии в цифровую эпоху.|Плёнка заставляет думать перед каждым кадром. В катушке всего тридцать шесть снимков, и это меняет темп съёмки.|Цвета и зерно плёнки сложно точно повторить фильтрами. Мы предлагаем добавить несколько плёночных кадров к любой съёмке.|Проявку и сканирование делаем в небольшой лаборатории, с которой работаем много лет."
                    "photo-archive|Как сохранить семейный фотоархив|Сканирование, подписи и хранение старых снимков.|Старые фотографии выцветают и теряются при переездах. Отсканируйте их с разрешением не меньше 600 dpi и сохраните в нескольких местах.|Самое ценное — подписи: кто изображён, где и когда. Через двадцать лет спросить будет не у кого, поэтому запишите это сейчас.|Оригиналы храните в бескислотных конвертах вдали от батарей и солнца.")
      ;;
    translate)
      SITE_T_KIND="Бюро переводов"
      SITE_T_SERV_TITLE="Услуги"
      SITE_T_NAMES=("Слово в слово" "Точный смысл" "Лингва Плюс" "Две строки" "Мост слов" "Ясный текст" "Полиглот" "Верный перевод")
      SITE_T_TAGS=("Письменные переводы документов, договоров и технических текстов"
                   "Переводим смысл, а не только слова"
                   "Технический, юридический и деловой перевод с редактурой")
      SITE_T_ABOUT=("Бюро объединяет переводчиков и редакторов, которые много лет работают в своих отраслях: машиностроение, медицина, право, IT."
                    "Каждый текст проходит два этапа: перевод и независимую редактуру. Для крупных проектов ведём глоссарий, чтобы термины не расходились между документами."
                    "Соблюдаем конфиденциальность: документы хранятся в зашифрованном архиве и удаляются по запросу после завершения работы.")
      SITE_T_SERV=("Личные документы|Паспорта, дипломы, справки и свидетельства с нотариальным заверением."
                   "Договоры|Юридический перевод контрактов и уставов с сохранением структуры."
                   "Технические тексты|Инструкции, спецификации, чертежи и руководства пользователя."
                   "Локализация|Сайты, приложения и интерфейсы с учётом местных особенностей."
                   "Медицинский перевод|Выписки, заключения и результаты анализов."
                   "Редактура|Проверка и вычитка готового перевода носителем языка.")
      SITE_T_POSTS=("glossary|Зачем нужен глоссарий в переводческом проекте|Как единые термины экономят время и нервы.|Когда документацию переводят несколько человек, один и тот же термин легко получает три разных варианта. Читатель путается, а заказчик тратит время на исправления.|Глоссарий — это таблица терминов и их утверждённых переводов. Мы составляем её на старте и согласуем со специалистами заказчика.|С каждым новым документом глоссарий пополняется, и следующие переводы получаются быстрее и единообразнее."
                    "notary|Нотариальный перевод: как это устроено|Что нужно знать, если документ требуется для госоргана.|Нотариус заверяет не сам перевод, а подпись переводчика, который его выполнил. Поэтому переводчик должен иметь подтверждённую квалификацию.|Перевод подшивается к копии или оригиналу документа. Перед подачей уточните требования конкретной организации: иногда нужен апостиль.|Обычно вся процедура занимает один-два рабочих дня, срочные заказы возможны за несколько часов."
                    "machine-translation|Машинный перевод: помощник, но не замена|Где автоматический перевод уместен, а где опасен.|Современные системы машинного перевода хорошо справляются с простыми текстами и помогают быстро понять общий смысл письма.|В договорах, медицинских и технических документах цена ошибки слишком высока. Одно неверно понятое отрицание меняет смысл пункта.|Мы используем инструменты автоматизации для черновиков и терминологии, но каждое предложение проверяет человек."
                    "localization|Локализация сайта: больше чем перевод|Почему текст на кнопке иногда сложнее договора.|Локализация учитывает формат дат, валюты, длину строк и даже цвета, которые в разных странах воспринимаются по-разному.|Немецкий текст в среднем на треть длиннее английского, и кнопки в интерфейсе могут просто не вместить перевод. Это нужно предусмотреть на этапе дизайна.|Мы просим доступ к тестовой версии, чтобы увидеть перевод в контексте, а не в таблице строк."
                    "deadlines|Как рассчитать срок перевода|Сколько страниц в день — реальная норма.|Профессиональный переводчик качественно переводит около восьми-десяти страниц в день. Ещё время нужно на редактуру и вёрстку.|Сложный технический текст идёт медленнее: приходится сверяться со стандартами и уточнять термины.|Если срок жёсткий, делим текст между несколькими переводчиками и обязательно проводим финальную сквозную редактуру.")
      ;;
    coffee|*)
      SITE_T_KIND="Кофейня и обжарка"
      SITE_T_SERV_TITLE="Меню"
      SITE_T_NAMES=("Медленное утро" "Зерно и чашка" "Тёплый угол" "Утренний рейс" "Кофейный двор" "Пенка" "Добрый помол" "Шесть утра")
      SITE_T_TAGS=("Свежая обжарка, домашняя выпечка и спокойная атмосфера"
                   "Обжариваем зерно сами и варим так, как любим"
                   "Небольшая кофейня для тех, кто никуда не спешит")
      SITE_T_ABOUT=("Мы открылись как маленький кофейный уголок на шесть мест. Сейчас у нас своя обжарка, но гостей по-прежнему встречают по имени."
                    "Зерно покупаем у проверенных импортёров и обжариваем небольшими партиями каждую неделю, поэтому кофе всегда свежий."
                    "Выпечку готовим сами каждое утро: круассаны, сырники, печенье по семейному рецепту.")
      SITE_T_SERV=("Эспрессо и молочные напитки|Капучино, флэт уайт, латте на зерне свежей обжарки."
                   "Фильтр-кофе|Воронка, аэропресс и кемекс — расскажем о каждом сорте."
                   "Чай и какао|Листовой чай, травяные сборы и густое какао."
                   "Завтраки|Сырники, каши и тосты до полудня."
                   "Зерно домой|Свежая обжарка в пачках по 250 г и 1 кг, помол под вашу кофеварку."
                   "Выпечка|Круассаны, печенье и пироги собственного приготовления.")
      SITE_T_POSTS=("grind-size|Как выбрать помол для домашнего кофе|Почему одна и та же пачка может дать совсем разный вкус.|Чем дольше вода контактирует с кофе, тем крупнее должен быть помол. Для френч-пресса — как крупная соль, для эспрессо — почти пудра.|Слишком мелкий помол даёт горечь, слишком крупный — кислинку и пустоту. Начните со среднего и меняйте понемногу.|Лучше всего молоть зерно прямо перед завариванием: аромат молотого кофе уходит за несколько минут."
                    "storage|Как хранить кофейное зерно|Простые правила, чтобы кофе оставался вкусным дольше.|Главные враги кофе — кислород, влага, свет и тепло. Храните зерно в непрозрачной банке с плотной крышкой при комнатной температуре.|Холодильник не лучший вариант: при доставании на зёрнах конденсируется влага, а сами зёрна впитывают чужие запахи.|Покупайте столько, сколько выпьете за две-три недели. Свежесть важнее любой хитрой упаковки."
                    "pour-over|Воронка за пять минут|Пошаговый рецепт фильтр-кофе для начинающих.|Возьмите 15 граммов кофе среднего помола и 250 граммов воды температурой около 93 градусов. Промойте бумажный фильтр горячей водой.|Сначала налейте немного воды, чтобы смочить весь кофе, и подождите тридцать секунд. Затем доливайте остальное медленными кругами.|Вся заварка должна занять около трёх минут. Если кофе горчит — помол крупнее, если кислит — мельче."
                    "roast-levels|Светлая, средняя, тёмная: что значит степень обжарки|Как обжарка влияет на вкус в чашке.|Светлая обжарка сохраняет фруктовые и цветочные ноты сорта, но требует аккуратного заваривания.|Средняя — баланс сладости и кислотности, её любят для молочных напитков. Тёмная даёт насыщенный горьковато-шоколадный вкус.|Мы обжариваем разные сорта по-разному и всегда подскажем, что лучше подойдёт под ваш способ приготовления."
                    "seasonal-menu|Сезонное меню: что мы готовим этой осенью|Новые напитки и выпечка на холодные дни.|С наступлением холодов добавили в меню пряный раф с корицей и кардамоном и облепиховый чай с мёдом.|На витрине появились тыквенный пирог и яблочный штрудель по рецепту нашего пекаря.|Заходите попробовать — первые гости каждое утро получают печенье в подарок.")
      ;;
  esac
}

_site_page() {
  # _site_page FILE TITLE DESCRIPTION ACTIVE BODY_HTML
  local file="$1" title="$2" desc="$3" active="$4" body="$5"
  local nav="" item href label cls
  for item in "/|Главная|home" "/about/|О нас|about" "/services/|${SITE_G_SERV_TITLE}|services" "/blog/|Блог|blog" "/contacts/|Контакты|contacts"; do
    IFS='|' read -r href label cls <<<"$item"
    if [[ "$cls" == "$active" ]]; then
      nav+="<a href=\"${href}\" class=\"active\" aria-current=\"page\">${label}</a>"
    else
      nav+="<a href=\"${href}\">${label}</a>"
    fi
  done
  local full_title
  if [[ "$active" == "home" ]]; then full_title="${SITE_G_BRAND} — ${title}"; else full_title="${title} — ${SITE_G_BRAND}"; fi
  mkdir -p "$(dirname "$file")"
  cat >"$file" <<HTML
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(_site_html_esc "$full_title")</title>
<meta name="description" content="$(_site_html_esc "$desc")">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon.ico" sizes="16x16">
<link rel="stylesheet" href="/assets/${SITE_G_CSS}">
<meta property="og:title" content="$(_site_html_esc "$full_title")">
<meta property="og:type" content="website">
<meta property="og:site_name" content="$(_site_html_esc "$SITE_G_BRAND")">
</head>
<body class="${SITE_G_LAYOUT}">
<header class="site-header">
<div class="wrap">
<a class="brand" href="/"><span class="logo">${SITE_G_LETTER}</span>$(_site_html_esc "$SITE_G_BRAND")</a>
<nav>${nav}</nav>
</div>
</header>
<main class="wrap">
${body}
</main>
<footer class="site-footer">
<div class="wrap">
<p>© ${SITE_G_SINCE}–${SITE_G_YEAR} $(_site_html_esc "$SITE_G_BRAND"). ${SITE_G_KIND}, ${SITE_G_CITY}.</p>
<p><a href="/contacts/">Контакты</a> · <a href="/blog/">Блог</a> · <a href="mailto:${SITE_G_EMAIL}">${SITE_G_EMAIL}</a></p>
</div>
</footer>
</body>
</html>
HTML
}

site_generate() {
  # site_generate OUTDIR DOMAIN THEME(auto|it|photo|translate|coffee) [SEED_EXTRA]
  local out="$1" domain="$2" theme="${3:-auto}" extra="${4:-}"
  _site_seed_from "${domain}|${extra}"
  if [[ "$theme" == "auto" || "$theme" == "random" || -z "$theme" ]]; then
    # shellcheck disable=SC2086
    _site_pick theme $SITE_THEMES
  fi
  SITE_GEN_THEME="$theme"
  _site_theme_data "$theme"

  local base="${domain#*.}"
  [[ "$base" == *.* ]] || base="$domain"
  SITE_G_KIND="$SITE_T_KIND"
  SITE_G_SERV_TITLE="$SITE_T_SERV_TITLE"
  _site_pick SITE_G_BRAND "${SITE_T_NAMES[@]}"
  SITE_G_LETTER="${SITE_G_BRAND:0:1}"
  _site_pick SITE_G_CITY "Казань" "Екатеринбург" "Новосибирск" "Нижний Новгород" "Самара" "Пермь" "Воронеж" "Краснодар" "Тюмень" "Томск" "Ярославль" "Калининград"
  local tagline; _site_pick tagline "${SITE_T_TAGS[@]}"
  local email_user; _site_pick email_user info hello mail studio contact
  SITE_G_EMAIL="${email_user}@${base}"
  SITE_G_YEAR="$(date +%Y)"
  local age; _site_rint age 2 9
  SITE_G_SINCE=$(( SITE_G_YEAR - age ))
  _site_pick SITE_G_LAYOUT "layout-left" "layout-center" "layout-split"
  local palette accent accent2 bg fg rgb
  _site_pick palette \
    "#2f6f5e|#1f4d41|#f7f5f0|#1d2321|47,111,94" \
    "#3456a3|#233b73|#f6f7fb|#1a1f2b|52,86,163" \
    "#a4532d|#733a1f|#fbf7f2|#2a1f1a|164,83,45" \
    "#6b4fa0|#4a3570|#f8f6fb|#211c2a|107,79,160" \
    "#8a6d1f|#5f4b15|#fbfaf4|#26231a|138,109,31" \
    "#b03a48|#7d2833|#fcf7f7|#2a1c1e|176,58,72" \
    "#1f7a8c|#155563|#f4f9fa|#17262a|31,122,140"
  IFS='|' read -r accent accent2 bg fg rgb <<<"$palette"
  local font radius width
  _site_pick font \
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif" \
    "Georgia, 'Times New Roman', serif" \
    "'PT Sans', 'Trebuchet MS', Verdana, sans-serif" \
    "'Noto Sans', 'Segoe UI', Tahoma, sans-serif" \
    "'IBM Plex Sans', 'Helvetica Neue', Arial, sans-serif"
  _site_pick radius 0 4px 8px 14px
  _site_pick width 960px 1040px 1120px
  local hash
  hash="$(printf '%s' "${domain}${extra}" | cksum | awk '{printf "%08x", $1}')"
  SITE_G_CSS="style.${hash:0:8}.css"

  rm -rf "$out"
  mkdir -p "$out/assets" "$out/blog"

  # --- CSS ---
  cat >"$out/assets/${SITE_G_CSS}" <<CSS
:root{--accent:${accent};--accent-dark:${accent2};--bg:${bg};--fg:${fg};--muted:rgba(${rgb},.08);--radius:${radius};--width:${width}}
*{box-sizing:border-box}
html{font-size:17px}
body{margin:0;background:var(--bg);color:var(--fg);font-family:${font};line-height:1.6}
a{color:var(--accent)}a:hover{color:var(--accent-dark)}
.wrap{max-width:var(--width);margin:0 auto;padding:0 20px}
.site-header{border-bottom:1px solid var(--muted);background:#fff}
.site-header .wrap{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;padding-top:14px;padding-bottom:14px}
.layout-center .site-header .wrap{flex-direction:column}
.brand{font-weight:700;font-size:1.15rem;text-decoration:none;color:var(--fg);display:flex;align-items:center;gap:10px}
.logo{display:inline-flex;width:34px;height:34px;align-items:center;justify-content:center;background:var(--accent);color:#fff;border-radius:var(--radius)}
nav a{margin-left:18px;text-decoration:none;color:var(--fg);opacity:.8}
nav a.active,nav a:hover{opacity:1;color:var(--accent)}
.layout-center nav a{margin:0 9px}
main{padding:32px 20px 56px}
.hero{padding:56px 0 40px}
.layout-split .hero{display:grid;grid-template-columns:3fr 2fr;gap:32px;align-items:center}
.hero h1{font-size:2.3rem;line-height:1.2;margin:0 0 16px}
.hero p{font-size:1.15rem;opacity:.85}
.hero .panel{background:var(--muted);border-radius:var(--radius);padding:24px}
.btn{display:inline-block;background:var(--accent);color:#fff;padding:10px 20px;border-radius:var(--radius);text-decoration:none}
.btn:hover{background:var(--accent-dark);color:#fff}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:20px}
.card{background:#fff;border:1px solid var(--muted);border-radius:var(--radius);padding:20px}
.card h3{margin-top:0}
.post-meta{font-size:.85rem;opacity:.65}
article{max-width:720px}
article h1{line-height:1.25}
.site-footer{border-top:1px solid var(--muted);font-size:.9rem;opacity:.85;padding:18px 0}
@media (max-width:700px){.layout-split .hero{grid-template-columns:1fr}.hero h1{font-size:1.8rem}nav a{margin-left:10px}}
CSS

  # --- favicon ---
  local r g b
  IFS=, read -r r g b <<<"$rgb"
  cat >"$out/favicon.svg" <<SVG
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="${accent}"/><text x="32" y="44" font-size="36" text-anchor="middle" fill="#fff" font-family="Arial, sans-serif">${SITE_G_LETTER}</text></svg>
SVG
  _site_write_ico "$out/favicon.ico" "$r" "$g" "$b"

  # --- services (выбираем 4 из 6, порядок случайный) ---
  local -a serv=("${SITE_T_SERV[@]}")
  _site_shuffle serv
  local serv_html="" s st sd n_serv
  _site_rint n_serv 4 6
  local i
  for (( i=0; i<n_serv; i++ )); do
    IFS='|' read -r st sd <<<"${serv[i]}"
    serv_html+="<div class=\"card\"><h3>${st}</h3><p>${sd}</p></div>"$'\n'
  done

  # --- blog posts (3–5 шт., даты в прошлом) ---
  local -a posts=("${SITE_T_POSTS[@]}")
  _site_shuffle posts
  local n_posts now_e
  _site_rint n_posts 3 5
  now_e="$(date +%s)"
  local -a p_slug=() p_title=() p_lead=() p_epoch=()
  local off=0 dd slug title lead a1 a2 a3
  for (( i=0; i<n_posts; i++ )); do
    _site_rint dd 9 55
    off=$(( off + dd ))
    IFS='|' read -r slug title lead a1 a2 a3 <<<"${posts[i]}"
    p_slug+=("$slug"); p_title+=("$title"); p_lead+=("$lead")
    p_epoch+=($(( now_e - off * 86400 - (SITE_RNG % 36000) )))
    _site_page "$out/blog/${slug}/index.html" "$title" "$lead" "blog" \
"<article>
<p class=\"post-meta\"><a href=\"/blog/\">Блог</a> · $(_site_ru_date "${p_epoch[i]}")</p>
<h1>${title}</h1>
<p><strong>${lead}</strong></p>
<p>${a1}</p>
<p>${a2}</p>
<p>${a3}</p>
<p><a href=\"/blog/\">← Все записи</a></p>
</article>"
  done

  local posts_html="" latest_html=""
  for (( i=0; i<n_posts; i++ )); do
    posts_html+="<div class=\"card\"><p class=\"post-meta\">$(_site_ru_date "${p_epoch[i]}")</p><h3><a href=\"/blog/${p_slug[i]}/\">${p_title[i]}</a></h3><p>${p_lead[i]}</p></div>"$'\n'
    if (( i < 2 )); then
      latest_html+="<div class=\"card\"><p class=\"post-meta\">$(_site_ru_date "${p_epoch[i]}")</p><h3><a href=\"/blog/${p_slug[i]}/\">${p_title[i]}</a></h3><p>${p_lead[i]}</p></div>"$'\n'
    fi
  done

  local hours; _site_pick hours "Пн–Пт 10:00–19:00" "Пн–Сб 9:00–18:00" "Вт–Вс 11:00–20:00" "Ежедневно 8:00–21:00"

  # --- index ---
  _site_page "$out/index.html" "$tagline" "${SITE_G_KIND} «${SITE_G_BRAND}», ${SITE_G_CITY}. ${tagline}." "home" \
"<section class=\"hero\">
<div>
<h1>$(_site_html_esc "$tagline")</h1>
<p>${SITE_T_ABOUT[0]}</p>
<p><a class=\"btn\" href=\"/services/\">${SITE_G_SERV_TITLE}</a></p>
</div>
<div class=\"panel\"><p><strong>${SITE_G_KIND}</strong><br>${SITE_G_CITY}<br>${hours}</p><p><a href=\"/contacts/\">Как с нами связаться →</a></p></div>
</section>
<h2>${SITE_G_SERV_TITLE}</h2>
<div class=\"grid\">
${serv_html}</div>
<h2>Из блога</h2>
<div class=\"grid\">
${latest_html}</div>"

  _site_page "$out/about/index.html" "О нас" "Кто мы и как работаем — ${SITE_G_BRAND}." "about" \
"<article>
<h1>О нас</h1>
<p>${SITE_T_ABOUT[0]}</p>
<p>${SITE_T_ABOUT[1]}</p>
<p>${SITE_T_ABOUT[2]}</p>
<p>Работаем с ${SITE_G_SINCE} года, город — ${SITE_G_CITY}.</p>
</article>"

  _site_page "$out/services/index.html" "$SITE_G_SERV_TITLE" "${SITE_G_SERV_TITLE} — ${SITE_G_BRAND}, ${SITE_G_CITY}." "services" \
"<h1>${SITE_G_SERV_TITLE}</h1>
<p>Стоимость и сроки зависят от задачи — напишите нам, и мы ответим в течение рабочего дня.</p>
<div class=\"grid\">
${serv_html}</div>"

  _site_page "$out/blog/index.html" "Блог" "Заметки и полезные статьи — ${SITE_G_BRAND}." "blog" \
"<h1>Блог</h1>
<div class=\"grid\">
${posts_html}</div>"

  _site_page "$out/contacts/index.html" "Контакты" "Как связаться — ${SITE_G_BRAND}, ${SITE_G_CITY}." "contacts" \
"<article>
<h1>Контакты</h1>
<p>Электронная почта: <a href=\"mailto:${SITE_G_EMAIL}\">${SITE_G_EMAIL}</a></p>
<p>Город: ${SITE_G_CITY}</p>
<p>Режим работы: ${hours}</p>
<p>Отвечаем на письма в течение рабочего дня. Встречи — по предварительной договорённости.</p>
</article>"

  _site_page "$out/404.html" "Страница не найдена" "Страница не найдена." "none" \
"<article>
<h1>Страница не найдена</h1>
<p>Возможно, ссылка устарела или в адресе опечатка.</p>
<p><a href=\"/\">На главную</a> · <a href=\"/blog/\">Блог</a></p>
</article>"

  printf 'User-agent: *\nAllow: /\n\nSitemap: https://%s/sitemap.xml\n' "$domain" >"$out/robots.txt"

  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    local u
    for u in "" "about/" "services/" "blog/" "contacts/"; do
      printf '  <url><loc>https://%s/%s</loc><lastmod>%s</lastmod></url>\n' "$domain" "$u" "$(date -d "@${p_epoch[0]}" +%Y-%m-%d)"
    done
    for (( i=0; i<n_posts; i++ )); do
      printf '  <url><loc>https://%s/blog/%s/</loc><lastmod>%s</lastmod></url>\n' "$domain" "${p_slug[i]}" "$(date -d "@${p_epoch[i]}" +%Y-%m-%d)"
    done
    echo '</urlset>'
  } >"$out/sitemap.xml"

  # Правдоподобные Last-Modified: статьи — дата статьи, остальное — недели/месяцы назад
  for (( i=0; i<n_posts; i++ )); do
    touch -d "@${p_epoch[i]}" "$out/blog/${p_slug[i]}/index.html" 2>/dev/null || true
  done
  local f fe
  while IFS= read -r -d '' f; do
    [[ "$f" == "$out/blog/"*/index.html && "$f" != "$out/blog/index.html" ]] && continue
    _site_rint fe 40 300
    touch -d "@$(( now_e - fe * 86400 - (SITE_RNG % 40000) ))" "$f" 2>/dev/null || true
  done < <(find "$out" -type f -print0)
  touch -d "@${p_epoch[0]}" "$out/blog/index.html" "$out/index.html" "$out/sitemap.xml" 2>/dev/null || true
  chmod -R a+rX "$out" 2>/dev/null || true
}

_site_ip2int() {
  local IFS=. a b c d
  read -r a b c d <<<"$1"
  printf '%d' $(( (a << 24) | (b << 16) | (c << 8) | d ))
}

_site_ip_is_cloudflare() {
  # Публичные IPv4-диапазоны Cloudflare (оранжевое облако = прокси, сертификат по HTTP-01 не выпустить на ноду)
  local ip="$1" n net bits base mask
  is_ipv4 "$ip" || return 1
  n="$(_site_ip2int "$ip")"
  for net in 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 \
             190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 \
             104.24.0.0/14 172.64.0.0/13 131.0.72.0/22; do
    base="$(_site_ip2int "${net%/*}")"; bits="${net#*/}"
    mask=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
    (( (n & mask) == (base & mask) )) && return 0
  done
  return 1
}

_site_resolve() {
  # _site_resolve A|AAAA DOMAIN — IP-адреса по одному на строку (DoH 1.1.1.1 → 8.8.8.8 → системный резолвер)
  local type="$1" d="$2" out="" url
  for url in "https://1.1.1.1/dns-query?name=${d}&type=${type}" "https://dns.google/resolve?name=${d}&type=${type}"; do
    out="$(curl -fsS --connect-timeout 4 --max-time 8 -H 'accept: application/dns-json' "$url" 2>/dev/null || true)"
    if [[ "$out" == *'"Status":0'* || "$out" == *'"Status": 0'* ]]; then
      if [[ "$type" == "A" ]]; then
        grep -oE '"data": ?"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"' <<<"$out" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true
      else
        grep -oE '"type": ?28,[^}]*"data": ?"[0-9a-fA-F:]+"' <<<"$out" | grep -oE '"data": ?"[0-9a-fA-F:]+"' | sed -E 's/.*"([0-9a-fA-F:]+)"$/\1/' || true
      fi
      return 0
    fi
    [[ "$out" == *'"Status":3'* || "$out" == *'"Status": 3'* ]] && return 0   # NXDOMAIN
  done
  if [[ "$type" == "A" ]]; then
    getent ahostsv4 "$d" 2>/dev/null | awk '{print $1}' | sort -u || true
  else
    getent ahostsv6 "$d" 2>/dev/null | awk '{print $1}' | grep ':' | sort -u || true
  fi
}

_site_valid_domain() {
  local d="$1"
  [[ ${#d} -le 253 ]] || return 1
  [[ "$d" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$ ]] || return 1
  [[ "$d" == *.* ]]
}

_site_load_state() {
  # подгружает SITE_* из state-файла, не перетирая заданные флагами значения
  [[ -f "$SITE_STATE_FILE" ]] || return 1
  local k v
  while IFS='=' read -r k v; do
    v="${v%\"}"; v="${v#\"}"
    case "$k" in
      SITE_DOMAIN) [[ -n "$SITE_DOMAIN" ]] || SITE_DOMAIN="$v" ;;
      SITE_EMAIL) [[ -n "$SITE_EMAIL" ]] || SITE_EMAIL="$v" ;;
      SITE_THEME) [[ "$SITE_THEME" != "auto" ]] || SITE_THEME="$v" ;;
      SITE_MODE_ACTIVE) SITE_MODE_ACTIVE="$v" ;;
      SITE_PORT) [[ -n "$SITE_PORT_SET" ]] || SITE_PORT="$v" ;;
      SITE_LISTEN) [[ -n "$SITE_LISTEN_SET" ]] || SITE_LISTEN="$v" ;;
      SITE_PP) [[ -n "$SITE_PP_SET" ]] || SITE_PP="$v" ;;
      SITE_ROOT) SITE_ROOT="$v" ;;
      SITE_SEED) [[ -n "$SITE_SEED" ]] || SITE_SEED="$v" ;;
      SITE_CLOSE80) [[ "$SITE_CLOSE80" -eq 1 ]] || SITE_CLOSE80="$v" ;;
    esac
  done <"$SITE_STATE_FILE"
  return 0
}

_site_port_owner() {
  # _site_port_owner PORT — имя процесса, слушающего TCP-порт (пусто — свободен)
  ss -Hltnp "( sport = :$1 )" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -1
}

_site_port_listening() {
  ss -Hltn "( sport = :$1 )" 2>/dev/null | grep -q .
}

_site_remnanode_net_host() {
  # 0 = host network (127.0.0.1 контейнера = хост), 1 = bridge, 2 = не нашли compose
  local f
  for f in /opt/remnanode/docker-compose.yml /opt/remnanode/docker-compose.yaml /opt/remnanode/compose.yml /opt/remnanode/compose.yaml; do
    [[ -f "$f" ]] || continue
    if grep -qE '^[[:space:]]*network_mode:[[:space:]]*["'"'"']?host' "$f"; then return 0; fi
    return 1
  done
  return 2
}

_site_nginx_ge_1251() {
  local v
  v="$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  [[ -n "$v" ]] || return 1
  [[ "$(printf '%s\n1.25.1\n' "$v" | sort -V | head -1)" == "1.25.1" ]]
}

_site_ufw_active() {
  command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qiE 'Status:\s*active'
}

_site_ufw_has_public() {
  # _site_ufw_has_public PORT — уже есть «PORT ALLOW Anywhere»
  ufw status 2>/dev/null | grep -qE "^$1(/tcp)?[[:space:]]+(ALLOW|LIMIT)[[:space:]]+(IN[[:space:]]+)?Anywhere"
}

_site_prompt_domain() {
  [[ -n "$SITE_DOMAIN" ]] && return 0
  _site_load_state || true
  [[ -n "$SITE_DOMAIN" ]] && return 0
  if [[ "${CLI_ASSUME_YES:-0}" -eq 0 ]] && _tty_usable; then
    echo "Нужен поддомен, который смотрит на IP этой ноды (A-запись, в Cloudflare — серое облако «DNS only»)."
    prompt_user 'Поддомен ноды (например, cdn.example.ru): ' SITE_DOMAIN
    SITE_DOMAIN="$(tr -d ' \r' <<<"$SITE_DOMAIN")"; SITE_DOMAIN="${SITE_DOMAIN,,}"
    if [[ -z "$SITE_EMAIL" ]]; then
      prompt_user 'E-mail для Let'"'"'s Encrypt (Enter — без почты): ' SITE_EMAIL
      SITE_EMAIL="$(tr -d ' \r' <<<"$SITE_EMAIL")"
    fi
  fi
  [[ -n "$SITE_DOMAIN" ]]
}

_site_check_dns() {
  # rc 0 — ок; иначе печатает понятную ошибку
  local d="$1" pub4="$2" pub6="$3" a aaaa ip ok4=0 bad=0
  a="$(_site_resolve A "$d")"
  aaaa="$(_site_resolve AAAA "$d")"
  if [[ -z "$a" && -z "$aaaa" ]]; then
    err "Домен ${d} не резолвится (нет A/AAAA). Создайте A-запись ${d} → ${pub4:-<IP ноды>} и подождите 1–5 минут."
    return 1
  fi
  while IFS= read -r ip; do
    [[ -n "$ip" ]] || continue
    if [[ "$ip" == "$pub4" ]]; then ok4=1; continue; fi
    if _site_ip_is_cloudflare "$ip"; then
      err "A-запись ${d} → ${ip} — это Cloudflare (оранжевое облако). Переключите запись на «DNS only» (серое облако): REALITY и выпуск сертификата требуют прямого IP ноды."
    else
      err "A-запись ${d} → ${ip}, а IP этой ноды ${pub4:-не определён}. Исправьте A-запись."
    fi
    bad=1
  done <<<"$a"
  if [[ -n "$aaaa" ]]; then
    while IFS= read -r ip; do
      [[ -n "$ip" ]] || continue
      if [[ -n "$pub6" && "${ip,,}" == "${pub6,,}" ]]; then continue; fi
      err "AAAA-запись ${d} → ${ip} не совпадает с IPv6 ноды (${pub6:-нет IPv6}). Let's Encrypt проверяет IPv6 первым — удалите AAAA или исправьте."
      bad=1
    done <<<"$aaaa"
  fi
  if [[ "$ok4" -eq 0 && "$bad" -eq 0 && -n "$pub4" ]]; then
    err "Домен ${d} не указывает на ${pub4}"
    bad=1
  fi
  [[ "$bad" -eq 0 ]] || return 1
  ok "DNS: ${d} → ${pub4}${aaaa:+ / ${aaaa//$'\n'/ }}"
}

_site_write_nginx_conf() {
  # _site_write_nginx_conf PHASE(acme|full)
  local phase="$1" d="$SITE_DOMAIN" v6=0 dflt=" default_server" h2listen="" h2line="" pp=""
  [[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" == "0" ]] && v6=1
  [[ "$SITE_DEFAULT80" -eq 1 ]] || dflt=""
  if _site_nginx_ge_1251; then h2line="    http2 on;"; else h2listen=" http2"; fi
  [[ "$SITE_PP" -eq 1 ]] && pp=" proxy_protocol"
  local live="/etc/letsencrypt/live/${d}"
  {
    echo "# Managed by ${SCRIPT_NAME} ${VERSION} — site ${d} (mode=${SITE_MODE_ACTIVE}, phase=${phase})"
    echo "server {"
    echo "    listen 80${dflt};"
    [[ "$v6" -eq 1 ]] && echo "    listen [::]:80${dflt};"
    if [[ -n "$dflt" ]]; then echo "    server_name ${d} _;"; else echo "    server_name ${d};"; fi
    echo "    server_tokens off;"
    echo "    access_log off;"
    echo "    location ^~ /.well-known/acme-challenge/ {"
    echo "        root ${SITE_ACME_ROOT};"
    echo "        default_type text/plain;"
    echo "    }"
    echo "    location / {"
    echo "        return 301 https://${d}\$request_uri;"
    echo "    }"
    echo "}"
    if [[ "$phase" == "full" ]]; then
      echo
      echo "server {"
      echo "    listen ${SITE_LISTEN}:${SITE_PORT} ssl${h2listen}${pp};"
      if [[ "$SITE_MODE_ACTIVE" == "public" ]]; then
        echo "    listen 443 ssl${h2listen};"
        [[ "$v6" -eq 1 ]] && echo "    listen [::]:443 ssl${h2listen};"
      fi
      [[ -n "$h2line" ]] && echo "$h2line"
      echo "    server_name ${d};"
      echo "    server_tokens off;"
      echo "    ssl_certificate ${live}/fullchain.pem;"
      echo "    ssl_certificate_key ${live}/privkey.pem;"
      echo "    ssl_protocols TLSv1.2 TLSv1.3;"
      echo "    ssl_ecdh_curve X25519:prime256v1:secp384r1;"
      echo "    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;"
      echo "    ssl_prefer_server_ciphers off;"
      echo "    ssl_session_cache shared:SITETLS:10m;"
      echo "    ssl_session_timeout 1d;"
      echo "    ssl_session_tickets off;"
      echo "    root ${SITE_ROOT};"
      echo "    index index.html;"
      echo "    charset utf-8;"
      echo "    access_log off;"
      echo "    gzip on;"
      echo "    gzip_types text/css image/svg+xml application/xml text/plain;"
      echo "    add_header Strict-Transport-Security \"max-age=31536000\" always;"
      echo "    add_header X-Content-Type-Options \"nosniff\" always;"
      echo "    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"
      echo "    add_header X-Frame-Options \"SAMEORIGIN\" always;"
      echo "    error_page 404 /404.html;"
      echo "    location = /404.html { internal; }"
      echo "    location / {"
      echo "        try_files \$uri \$uri/ =404;"
      echo "    }"
      echo "    location /assets/ {"
      echo "        expires 30d;"
      echo "    }"
      echo "}"
    fi
  } >"$SITE_NGINX_CONF"
}

_site_print_panel_values() {
  local d="$SITE_DOMAIN" target xver=0
  target="${SITE_LISTEN}:${SITE_PORT}"
  [[ "$SITE_PP" -eq 1 ]] && xver=1
  echo
  menu_sep
  printf '%b📋 Что вставить в панель Remnawave (сам скрипт панель НЕ меняет):%b\n' "${C_BOLD}" "${C_RESET}"
  echo "  Config Profiles → профиль ноды → inbound VLESS REALITY (порт 443) → streamSettings.realitySettings:"
  echo
  echo "    \"target\": \"${target}\",          ← в старых xray это поле называется \"dest\""
  echo "    \"serverNames\": [\"${d}\"],"
  echo "    \"xver\": ${xver}"
  echo
  echo "  privateKey / shortIds НЕ меняйте. Рекомендуется: \"flow\": \"xtls-rprx-vision\" у клиентов."
  echo "  Hosts → у хостов этой ноды поле SNI = ${d} (иначе клиенты пришлют старый SNI)."
  echo "  Плавный переход: на время добавьте ${d} в serverNames рядом со старыми именами, смените SNI"
  echo "  в Hosts, дождитесь обновления подписок (сутки), затем уберите старые имена."
  if [[ "$SITE_PP" -eq 1 ]]; then
    echo "  xver=1 обязателен: nginx на ${target} ждёт PROXY protocol — без него сайт через REALITY не откроется."
  fi
  if [[ "$SITE_MODE_ACTIVE" == "public" ]]; then
    echo "  Режим public: nginx сам слушает 443. Если REALITY на другом порту — target тот же (${target})."
  fi
  case "$SITE_NET_HOST" in
    0) echo "  remnanode: network_mode: host — 127.0.0.1 внутри контейнера = хост, target ${target} подходит." ;;
    1) echo "  remnanode НЕ в host-сети: target ${target} (адрес docker-моста хоста); правило UFW для 172.16.0.0/12 → ${SITE_PORT} добавлено." ;;
    *) echo "  /opt/remnanode/docker-compose.yml не найден — проверьте, что remnanode в network_mode: host (иначе target = IP docker0, флаг --site-listen)." ;;
  esac
  echo "  Проверка: gorecshit --audit (раздел «Сайт-маскировка»)."
  menu_sep
}

_site_restore_after_fail() {
  # вернуть nginx к состоянию до запуска (наш конфиг убрать/восстановить, декой/дефолт вернуть)
  rm -f "$SITE_NGINX_CONF"
  local f
  for f in "$SITE_NGINX_CONF" /etc/nginx/conf.d/gorecshit-decoy.conf /etc/nginx/sites-enabled/default; do
    [[ -e "${BACKUP_DIR}${f}" || -L "${BACKUP_DIR}${f}" ]] && cp -a "${BACKUP_DIR}${f}" "$f"
  done
  nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true
}

_site_local_get() {
  # _site_local_get PATH [-o FILE] — GET через локальный listener (как его видит REALITY)
  local path="$1"; shift
  local -a pp=()
  [[ "${SITE_PP:-0}" -eq 1 ]] && pp=(--haproxy-protocol)
  curl -sS --connect-timeout 4 --max-time 10 "${pp[@]}" \
    --resolve "${SITE_DOMAIN}:${SITE_PORT}:${SITE_LISTEN}" "$@" "https://${SITE_DOMAIN}:${SITE_PORT}${path}"
}

configure_site() {
  # Сайт-маскировка: поддомен ноды + Let's Encrypt + nginx-сайт для REALITY self-steal
  if [[ "$DO_SITE" -eq 0 ]]; then return 0; fi
  step "Сайт-маскировка: поддомен + сертификат + сайт (REALITY self-steal)"
  _site_load_state || true   # повторный запуск: прежние порт/режим/сид (флаги имеют приоритет)
  if ! _site_prompt_domain; then
    if [[ "$SITE_STANDALONE" -eq 1 ]]; then
      err "Не указан поддомен ноды: gorecshit --site-domain node.example.ru [--site-email you@example.ru]"
      return 1
    fi
    warn "Сайт-маскировка пропущена — не указан --site-domain"
    return 0
  fi
  SITE_DOMAIN="${SITE_DOMAIN%.}"; SITE_DOMAIN="${SITE_DOMAIN,,}"
  if ! _site_valid_domain "$SITE_DOMAIN"; then
    err "Некорректный домен: ${SITE_DOMAIN} (нужно вида node.example.ru; кириллицу — в punycode xn--…)"
    return 1
  fi
  if LC_ALL=C grep -qiE "$SITE_DOMAIN_FORBIDDEN_RE" <<<"$SITE_DOMAIN"; then
    warn "В домене ${SITE_DOMAIN} есть слово «$(LC_ALL=C grep -oiE "$SITE_DOMAIN_FORBIDDEN_RE" <<<"$SITE_DOMAIN" | head -1)» — SNI виден DPI открытым текстом, нейтральное имя заметно надёжнее. Продолжаю по вашему выбору."
  fi
  case "$SITE_THEME" in auto|random|it|photo|translate|coffee) ;; *) err "Неизвестная тема --site-theme ${SITE_THEME} (it|photo|translate|coffee|auto)"; return 1 ;; esac
  case "$SITE_MODE" in auto|selfsteal|public) ;; *) err "--site-mode: auto|selfsteal|public"; return 1 ;; esac
  if ! is_port "$SITE_PORT" || [[ "$SITE_PORT" == 80 || "$SITE_PORT" == 443 ]]; then
    err "Некорректный --site-port ${SITE_PORT} (локальный порт, не 80/443; по умолчанию 9443)"; return 1
  fi
  if [[ -n "$SITE_EMAIL" && ! "$SITE_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
    err "Некорректный --site-email: ${SITE_EMAIL}"; return 1
  fi

  # --- режим ---
  local owner443 prev_mode="${SITE_MODE_ACTIVE:-}"
  owner443="$(_site_port_owner 443)"
  if [[ -z "$owner443" ]] && _site_port_listening 443; then owner443="?"; fi
  SITE_MODE_ACTIVE="$SITE_MODE"
  if [[ "$SITE_MODE" == "auto" ]]; then
    if [[ -z "$owner443" ]]; then
      SITE_MODE_ACTIVE="public"
    elif [[ "$owner443" == nginx* && "$prev_mode" == "public" && -f "$SITE_NGINX_CONF" ]]; then
      SITE_MODE_ACTIVE="public"
    elif [[ "$owner443" == nginx* ]]; then
      err "443 уже слушает nginx (другой сайт). Освободите 443 или запустите с --site-mode selfsteal (сайт только на ${SITE_LISTEN}:${SITE_PORT})."
      return 1
    else
      SITE_MODE_ACTIVE="selfsteal"
    fi
  elif [[ "$SITE_MODE" == "public" && -n "$owner443" && "$owner443" != nginx* ]]; then
    err "--site-mode public: 443 занят процессом «${owner443}» (REALITY?). Используйте selfsteal."
    return 1
  fi
  if [[ "$SITE_MODE_ACTIVE" == "selfsteal" ]]; then
    log "Режим selfsteal: 443 держит «${owner443:-никто}», сайт будет на ${SITE_LISTEN}:${SITE_PORT}, REALITY отдаёт его чужим"
  else
    log "Режим public: 443 свободен — nginx откроет сайт на 443 + локально на ${SITE_LISTEN}:${SITE_PORT} (для REALITY на другом порту)"
  fi
  if [[ "${CLI_ASSUME_YES:-0}" -eq 0 ]] && _tty_usable && [[ "$DRY_RUN" -eq 0 ]]; then
    local ans=""
    prompt_user "Домен ${SITE_DOMAIN}, режим ${SITE_MODE_ACTIVE}. Продолжить? [Y/n] " ans
    if [[ "$ans" =~ ^[NnНн]$ ]]; then warn "Сайт-маскировка отменена"; return 0; fi
  fi

  # --- сеть remnanode ---
  SITE_NET_HOST=2
  _site_remnanode_net_host && SITE_NET_HOST=0 || SITE_NET_HOST=$?
  if [[ "$SITE_NET_HOST" -eq 1 && -z "$SITE_LISTEN_SET" ]]; then
    local d0
    d0="$(ip -4 -o addr show docker0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
    if [[ -n "$d0" ]]; then
      SITE_LISTEN="$d0"
      warn "remnanode не в host-сети — 127.0.0.1 контейнера ≠ хост. Сайт слушает ${SITE_LISTEN}:${SITE_PORT} (docker0)"
    else
      warn "remnanode не в host-сети, docker0 не найден — укажите адрес вручную: --site-listen <IP моста>"
    fi
  elif [[ "$SITE_NET_HOST" -eq 2 ]]; then
    warn "/opt/remnanode/docker-compose.yml не найден — считаем, что remnanode в network_mode: host"
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%b[DRY]%b DNS %s → IP ноды; apt nginx certbot; сайт (тема %s) → /var/www/%s; %s (80 ACME/301, %s:%s ssl h2%s%s); certbot --webroot; UFW 80%s; state %s\n' \
      "${C_YEL}" "${C_RESET}" "$SITE_DOMAIN" "$SITE_THEME" "$SITE_DOMAIN" "$SITE_NGINX_CONF" "$SITE_LISTEN" "$SITE_PORT" \
      "$([[ "$SITE_PP" -eq 1 ]] && echo ' proxy_protocol')" "$([[ "$SITE_MODE_ACTIVE" == public ]] && echo ' + public 443')" \
      "$([[ "$SITE_CLOSE80" -eq 1 ]] && echo ' (закрыть после выпуска)')" "$SITE_STATE_FILE"
    SITE_ROOT="/var/www/${SITE_DOMAIN}"
    _site_print_panel_values
    return 0
  fi
  if [[ "$(id -u)" -ne 0 ]]; then err "Нужен root"; return 1; fi

  # --- DNS ---
  local pub4="" pub6=""
  pub4="$(_audit_detect_public_ipv4 2>/dev/null || true)"
  pub6="$(_audit_detect_public_ipv6 2>/dev/null || true)"
  if [[ "$SITE_SKIP_DNS" -eq 1 ]]; then
    warn "Проверка DNS пропущена (--site-skip-dns-check)"
  elif ! _site_check_dns "$SITE_DOMAIN" "$pub4" "$pub6"; then
    err "Исправьте DNS и повторите: gorecshit --site-domain ${SITE_DOMAIN}"
    return 1
  fi

  # --- порты 80 / SITE_PORT ---
  local o
  o="$(_site_port_owner 80)"
  if [[ -n "$o" && "$o" != nginx* ]]; then
    err "Порт 80 занят «${o}» — он нужен nginx для выпуска сертификата (HTTP-01) и редиректа на https"
    return 1
  fi
  o="$(_site_port_owner "$SITE_PORT")"
  if [[ -n "$o" && "$o" != nginx* ]]; then
    err "Порт ${SITE_PORT} занят «${o}» — выберите другой: --site-port 9444"
    return 1
  fi

  # --- пакеты ---
  local nginx_installed=0
  if ! command -v nginx >/dev/null 2>&1 || ! command -v certbot >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    command -v nginx >/dev/null 2>&1 || nginx_installed=1
    apt_get_retry update -qq || warn "apt-get update failed (продолжаем)"
    if ! apt_get_retry install -y -qq nginx certbot; then
      err "Не удалось установить nginx/certbot"; return 1
    fi
  fi
  NGINX_PRESENT=1
  if [[ ! -d /etc/nginx/conf.d ]] || ! grep -RqsE 'include[[:space:]]+/etc/nginx/conf\.d/\*\.conf' /etc/nginx/nginx.conf; then
    err "nginx.conf не подключает /etc/nginx/conf.d/*.conf — нестандартный nginx, не трогаем"
    return 1
  fi

  # --- бэкапы и расчистка 80 ---
  local conf_created=0 state_created=0 root_created=0
  [[ -e "$SITE_NGINX_CONF" ]] || conf_created=1
  [[ -e "$SITE_STATE_FILE" ]] || state_created=1
  SITE_ROOT="/var/www/${SITE_DOMAIN}"
  [[ -e "$SITE_ROOT" ]] || root_created=1
  backup_file "$SITE_NGINX_CONF"
  backup_file "$SITE_STATE_FILE"
  if [[ -e /etc/nginx/conf.d/gorecshit-decoy.conf ]]; then
    backup_file /etc/nginx/conf.d/gorecshit-decoy.conf
    rm -f /etc/nginx/conf.d/gorecshit-decoy.conf
    log "Декой :80 из v2.6.0 заменён сайтом (80 теперь: ACME + 301 → https://${SITE_DOMAIN})"
  fi
  if [[ -e /etc/nginx/sites-enabled/default || -L /etc/nginx/sites-enabled/default ]] \
     && grep -qs 'default_server' /etc/nginx/sites-enabled/default; then
    if grep -qs 'Default server configuration' /etc/nginx/sites-enabled/default; then
      backup_file /etc/nginx/sites-enabled/default
      rm -f /etc/nginx/sites-enabled/default
      log "Убран стандартный «Welcome to nginx» (sites-enabled/default) — он выдавал бы голый nginx"
    fi
  fi
  SITE_DEFAULT80=1
  if grep -RlsE 'listen[^;]*\b80\b[^;]*default_server' /etc/nginx/conf.d /etc/nginx/sites-enabled 2>/dev/null \
       | grep -vqE "^${SITE_NGINX_CONF}$"; then
    SITE_DEFAULT80=0
    warn "В nginx уже есть другой default_server на :80 — наш сервер на 80 только для ${SITE_DOMAIN}"
  fi

  # --- сайт ---
  [[ -n "$SITE_SEED" ]] || SITE_SEED="$(od -An -N4 -tu4 /dev/urandom 2>/dev/null | tr -d ' ' || date +%s)"
  local newroot="${SITE_ROOT}.new.$$"
  site_generate "$newroot" "$SITE_DOMAIN" "$SITE_THEME" "$SITE_SEED"
  if site_forbidden_scan -r "$newroot" >/dev/null; then
    err "Генератор выдал запрещённое слово — сайт не публикуем:"
    site_forbidden_scan -r "$newroot" | head -5 >&2
    rm -rf "$newroot"; return 1
  fi
  rm -rf "$SITE_ROOT"; mv "$newroot" "$SITE_ROOT"
  ok "Сайт сгенерирован: тема ${SITE_GEN_THEME}, «${SITE_G_BRAND}», ${SITE_G_CITY} → ${SITE_ROOT}"
  mkdir -p "${SITE_ACME_ROOT}/.well-known/acme-challenge"

  # --- UFW 80 (нужен для HTTP-01; у обычного сайта 80 открыт) ---
  local ufw80=0 ufw443=0 ufwbr=0
  if _site_ufw_active && ! _site_ufw_has_public 80; then
    ufw allow 80/tcp comment 'gorecshit-site-80' >/dev/null 2>&1 || true
    ufw80=1
  fi

  # --- сертификат ---
  local live="/etc/letsencrypt/live/${SITE_DOMAIN}" cert_new=0
  if [[ ! -s "${live}/fullchain.pem" ]] || ! openssl x509 -checkend $(( 30 * 86400 )) -noout -in "${live}/fullchain.pem" >/dev/null 2>&1; then
    _site_write_nginx_conf acme
    if ! nginx -t >/dev/null 2>&1; then
      err "nginx -t не прошёл (фаза ACME):"; nginx -t 2>&1 | tail -5 >&2
      _site_restore_after_fail; return 1
    fi
    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl reload nginx 2>/dev/null || systemctl restart nginx
    [[ -s "${live}/fullchain.pem" ]] || cert_new=1
    local -a mail=(--register-unsafely-without-email)
    [[ -n "$SITE_EMAIL" ]] && mail=(--email "$SITE_EMAIL")
    log "Выпуск сертификата Let's Encrypt для ${SITE_DOMAIN} (HTTP-01 через :80)…"
    if ! certbot certonly --webroot -w "$SITE_ACME_ROOT" -d "$SITE_DOMAIN" --cert-name "$SITE_DOMAIN" \
         --non-interactive --agree-tos "${mail[@]}" --keep-until-expiring \
         --deploy-hook 'nginx -t && systemctl reload nginx' 2>&1 | tail -15; then
      :
    fi
    if [[ ! -s "${live}/fullchain.pem" ]]; then
      err "Сертификат не выпущен. Частые причины: A-запись не на этот IP / оранжевое облако Cloudflare; 80/tcp закрыт у хостера; лимит Let's Encrypt (5 в неделю на домен)."
      err "Лог: /var/log/letsencrypt/letsencrypt.log"
      _site_restore_after_fail
      [[ "$ufw80" -eq 1 ]] && ufw --force delete allow 80/tcp >/dev/null 2>&1 || true
      return 1
    fi
    ok "Сертификат: ${live}/fullchain.pem (до $(openssl x509 -enddate -noout -in "${live}/fullchain.pem" | cut -d= -f2))"
  else
    ok "Сертификат для ${SITE_DOMAIN} уже есть и действует > 30 дней — используем его"
  fi

  # --- полный конфиг ---
  _site_write_nginx_conf full
  if ! nginx -t >/dev/null 2>&1; then
    err "nginx -t не прошёл:"; nginx -t 2>&1 | tail -5 >&2
    _site_restore_after_fail; return 1
  fi
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl reload nginx 2>/dev/null || systemctl restart nginx

  if _site_ufw_active; then
    if [[ "$SITE_MODE_ACTIVE" == "public" ]] && ! _site_ufw_has_public 443; then
      ufw allow 443/tcp comment 'gorecshit-site-443' >/dev/null 2>&1 || true
      ufw443=1
    fi
    if [[ "$SITE_NET_HOST" -eq 1 && "$SITE_LISTEN" != 127.* ]]; then
      ufw allow from 172.16.0.0/12 to any port "$SITE_PORT" proto tcp comment 'gorecshit-site-bridge' >/dev/null 2>&1 || true
      ufwbr=1
    fi
  fi

  # --- автопродление ---
  local hookdir=/etc/letsencrypt/renewal-hooks
  mkdir -p "$hookdir/deploy" "$hookdir/pre" "$hookdir/post"
  backup_file "$hookdir/deploy/50-gorecshit-site.sh"
  printf '#!/bin/bash\n# Managed by %s %s — reload nginx after renewal\nnginx -t >/dev/null 2>&1 && systemctl reload nginx || true\n' "$SCRIPT_NAME" "$VERSION" \
    >"$hookdir/deploy/50-gorecshit-site.sh"
  chmod 755 "$hookdir/deploy/50-gorecshit-site.sh"
  if [[ "$SITE_CLOSE80" -eq 1 ]]; then
    cat >"$hookdir/pre/10-gorecshit-open80.sh" <<'HOOK'
#!/bin/bash
# Managed by gorecshit — open 80/tcp only for the renewal (HTTP-01)
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qiE 'Status:\s*active'; then
  if ! ufw status 2>/dev/null | grep -qE '^80(/tcp)?[[:space:]]+ALLOW[[:space:]]+(IN[[:space:]]+)?Anywhere'; then
    ufw allow 80/tcp comment 'gorecshit-acme-tmp' >/dev/null 2>&1 && : >/run/gorecshit-acme-80
  fi
fi
HOOK
    cat >"$hookdir/post/90-gorecshit-close80.sh" <<'HOOK'
#!/bin/bash
# Managed by gorecshit — close 80/tcp again after renewal
if [ -f /run/gorecshit-acme-80 ]; then
  ufw --force delete allow 80/tcp >/dev/null 2>&1 || true
  rm -f /run/gorecshit-acme-80
fi
HOOK
    chmod 755 "$hookdir/pre/10-gorecshit-open80.sh" "$hookdir/post/90-gorecshit-close80.sh"
    if [[ "$ufw80" -eq 1 ]]; then
      ufw --force delete allow 80/tcp >/dev/null 2>&1 || true
      ufw80=0
    fi
    ok "80/tcp закрыт; при продлении certbot откроет его на минуту и закроет обратно"
  else
    rm -f "$hookdir/pre/10-gorecshit-open80.sh" "$hookdir/post/90-gorecshit-close80.sh"
  fi
  if systemctl list-unit-files certbot.timer >/dev/null 2>&1 && systemctl list-unit-files certbot.timer 2>/dev/null | grep -q certbot.timer; then
    systemctl enable --now certbot.timer >/dev/null 2>&1 || true
    ok "Автопродление: systemd certbot.timer (2 раза в сутки) + reload nginx"
  elif [[ -f /etc/cron.d/certbot ]]; then
    ok "Автопродление: /etc/cron.d/certbot + reload nginx"
  else
    printf '# Managed by %s\n17 3,15 * * * root certbot renew -q\n' "$SCRIPT_NAME" >/etc/cron.d/gorecshit-certbot
    ok "Автопродление: /etc/cron.d/gorecshit-certbot + reload nginx"
  fi

  # --- состояние ---
  mkdir -p "$(dirname "$SITE_STATE_FILE")"
  {
    echo "SITE_DOMAIN=${SITE_DOMAIN}"
    echo "SITE_EMAIL=${SITE_EMAIL}"
    echo "SITE_THEME=${SITE_GEN_THEME}"
    echo "SITE_MODE_ACTIVE=${SITE_MODE_ACTIVE}"
    echo "SITE_PORT=${SITE_PORT}"
    echo "SITE_LISTEN=${SITE_LISTEN}"
    echo "SITE_PP=${SITE_PP}"
    echo "SITE_ROOT=${SITE_ROOT}"
    echo "SITE_SEED=${SITE_SEED}"
    echo "SITE_CLOSE80=${SITE_CLOSE80}"
    echo "SITE_VERSION=${VERSION}"
  } >"$SITE_STATE_FILE"

  # --- откат ---
  local rb_body
  rb_body="$(printf 'SITE_RB_DOMAIN=%q\nSITE_RB_ROOT=%q\nSITE_RB_PORT=%q\n' "$SITE_DOMAIN" "$SITE_ROOT" "$SITE_PORT")"
  [[ "$conf_created" -eq 1 ]] && rb_body+=$'\n'"rm -f $(printf '%q' "$SITE_NGINX_CONF")"
  [[ "$state_created" -eq 1 ]] && rb_body+=$'\n'"rm -f $(printf '%q' "$SITE_STATE_FILE")"
  [[ "$root_created" -eq 1 ]] && rb_body+=$'\n''rm -rf "$SITE_RB_ROOT"'
  [[ "$state_created" -eq 1 ]] && rb_body+=$'\n''rm -f /etc/letsencrypt/renewal-hooks/deploy/50-gorecshit-site.sh'
  [[ "$cert_new" -eq 1 ]] && rb_body+=$'\n''certbot delete --cert-name "$SITE_RB_DOMAIN" --non-interactive >/dev/null 2>&1 || true'
  rb_body+=$'\n''rm -f /etc/letsencrypt/renewal-hooks/pre/10-gorecshit-open80.sh /etc/letsencrypt/renewal-hooks/post/90-gorecshit-close80.sh /etc/cron.d/gorecshit-certbot'
  [[ "$ufw80" -eq 1 ]] && rb_body+=$'\n''command -v ufw >/dev/null && ufw --force delete allow 80/tcp >/dev/null 2>&1 || true'
  [[ "$ufw443" -eq 1 ]] && rb_body+=$'\n''command -v ufw >/dev/null && ufw --force delete allow 443/tcp >/dev/null 2>&1 || true'
  [[ "$ufwbr" -eq 1 ]] && rb_body+=$'\n''command -v ufw >/dev/null && ufw --force delete allow from 172.16.0.0/12 to any port "$SITE_RB_PORT" proto tcp >/dev/null 2>&1 || true'
  if [[ "$nginx_installed" -eq 1 ]]; then
    rb_body+=$'\n''if ls /etc/nginx/conf.d/*.conf >/dev/null 2>&1; then nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true; else systemctl disable --now nginx >/dev/null 2>&1 || true; fi'
  else
    rb_body+=$'\n''nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true'
  fi
  _rb_append_block "gorecshit-site-restore" "$rb_body"

  # --- самопроверка ---
  local code
  code="$(_site_local_get / -o /dev/null -w '%{http_code}' 2>/dev/null || true)"
  if [[ "$code" == "200" ]]; then
    ok "Самопроверка: https://${SITE_DOMAIN} через ${SITE_LISTEN}:${SITE_PORT} → 200, сертификат валиден"
  else
    warn "Самопроверка: ${SITE_LISTEN}:${SITE_PORT} ответил «${code:-нет ответа}» — проверьте: nginx -t; journalctl -u nginx"
  fi
  if [[ "$SITE_MODE_ACTIVE" == "public" ]]; then
    ok "Сайт открыт: https://${SITE_DOMAIN}/"
  fi
  _site_print_panel_values
}

run_site_only() {
  if [[ "$(id -u)" -ne 0 && "$DRY_RUN" -eq 0 ]]; then
    err "Нужен root для сайта-маскировки"
    exit 1
  fi
  DO_SITE=1
  SITE_STANDALONE=1
  preflight
  write_rollback_script
  if ! configure_site; then
    err "Сайт-маскировка не установлена — см. ошибку выше (при сбое nginx возвращается как был). Откат запуска: $(rollback_hint_cmd)"
    install_cli_command
    exit 1
  fi
  install_cli_command
  ok "Откат сайта: $(rollback_hint_cmd)   (или ${BACKUP_DIR}/rollback.sh)"
}

_audit_site() {
  step "Сайт-маскировка (домен ноды + сертификат)"
  SITE_DOMAIN=""; SITE_MODE_ACTIVE=""
  if ! _site_load_state || [[ -z "$SITE_DOMAIN" ]]; then
    _audit_info "Не установлена. С ней REALITY отдаёт зондам ваш собственный сайт с настоящим сертификатом (self-steal):"
    _audit_info "gorecshit --site-domain node.example.ru   |   меню → 10"
    return 0
  fi
  local d="$SITE_DOMAIN" live="/etc/letsencrypt/live/${SITE_DOMAIN}/fullchain.pem" end
  _audit_info "Домен: ${d}  режим: ${SITE_MODE_ACTIVE}  локально: ${SITE_LISTEN}:${SITE_PORT}$([[ "$SITE_PP" -eq 1 ]] && echo ' (proxy_protocol, xver=1)')"

  # 1) сертификат
  if [[ ! -s "$live" ]]; then
    _audit_err "Нет сертификата ${live} — повторите: gorecshit --site-domain ${d}"
  else
    end="$(openssl x509 -enddate -noout -in "$live" 2>/dev/null | cut -d= -f2)"
    if ! openssl x509 -checkend 0 -noout -in "$live" >/dev/null 2>&1; then
      _audit_err "Сертификат ИСТЁК (${end}) — certbot renew --force-renewal; проверьте 80/tcp и DNS"
    elif ! openssl x509 -checkend $(( 14 * 86400 )) -noout -in "$live" >/dev/null 2>&1; then
      _audit_warn "Сертификат истекает < 14 дней (${end}) — автопродление не сработало? certbot renew --dry-run"
    else
      _audit_ok "Сертификат Let's Encrypt действует до ${end}"
    fi
  fi
  if systemctl is-enabled --quiet certbot.timer 2>/dev/null || [[ -f /etc/cron.d/certbot || -f /etc/cron.d/gorecshit-certbot ]]; then
    _audit_ok "Автопродление настроено (certbot.timer / cron)"
  else
    _audit_warn "Автопродление не найдено — systemctl enable --now certbot.timer"
  fi

  # 2) DNS
  local a pub="${AUDIT_PUB_IP:-}"
  a="$(_site_resolve A "$d" | paste -sd' ' -)"
  if [[ -z "$a" ]]; then
    _audit_err "${d} не резолвится (нет A-записи)"
  elif [[ -n "$pub" && " $a " == *" $pub "* ]]; then
    _audit_ok "DNS: ${d} → ${a}"
  else
    local ip cf=0
    for ip in $a; do _site_ip_is_cloudflare "$ip" && cf=1; done
    if [[ "$cf" -eq 1 ]]; then
      _audit_err "DNS: ${d} → ${a} — оранжевое облако Cloudflare; нужно «DNS only» (серое)"
    else
      _audit_warn "DNS: ${d} → ${a}, а IP ноды ${pub:-не определён}"
    fi
  fi

  # 3) сайт через локальный порт (так его видит REALITY)
  if [[ "$SITE_PP" -eq 1 ]] && ! curl --help all 2>/dev/null | grep -q -- '--haproxy-protocol'; then
    _audit_warn "curl без --haproxy-protocol — локальную проверку сайта с proxy_protocol пропускаем"
  else
    local tmp code hdr srv
    tmp="$(mktemp -d)"
    code="$(_site_local_get / -o "$tmp/index" -D "$tmp/hdr" -w '%{http_code}' 2>/dev/null || true)"
    if [[ "$code" != "200" ]]; then
      _audit_err "Сайт на ${SITE_LISTEN}:${SITE_PORT} ответил «${code:-нет ответа}» — REALITY-зонды увидят ошибку (nginx -t; systemctl status nginx)"
    else
      _audit_ok "Сайт отдаётся через ${SITE_LISTEN}:${SITE_PORT} (HTTPS 200, сертификат проверен curl)"
      srv="$(grep -i '^server:' "$tmp/hdr" | tr -d '\r' | cut -d' ' -f2-)"
      if [[ -n "$srv" && "$srv" != "nginx" ]]; then
        _audit_warn "Заголовок Server: ${srv} — версия видна (server_tokens off)"
      fi
      grep -qi '^strict-transport-security:' "$tmp/hdr" || _audit_warn "Нет HSTS-заголовка"
      # все страницы из sitemap + служебные
      local -a paths=(/ /robots.txt /sitemap.xml)
      local p n=0 bad=0 hits
      _site_local_get /sitemap.xml -o "$tmp/sitemap" 2>/dev/null || true
      while IFS= read -r p; do
        [[ -n "$p" ]] && paths+=("$p")
      done < <(grep -oE "<loc>https://${d//./\\.}(/[^<]*)</loc>" "$tmp/sitemap" 2>/dev/null | sed -E 's#<loc>https://[^/]+(/[^<]*)</loc>#\1#' | sort -u)
      paths+=("/$(od -An -N4 -tx4 /dev/urandom 2>/dev/null | tr -d ' ')-missing")
      for p in "${paths[@]}"; do
        n=$((n + 1))
        _site_local_get "$p" -o "$tmp/page" 2>/dev/null || true
        # сам домен ноды (и его базовый домен в e-mail/ссылках) не считаем — его выбирает владелец
        local dbase="${d#*.}"; [[ "$dbase" == *.* ]] || dbase="$d"
        hits="$(sed -E "s/${dbase//./\\.}//Ig" "$tmp/page" 2>/dev/null | LC_ALL=C grep -oiE "$SITE_FORBIDDEN_RE" 2>/dev/null | sort -u | paste -sd, - || true)"
        if [[ -n "$hits" ]]; then
          _audit_warn "Страница ${p}: найдены слова «${hits}» (текст/title/meta/комментарии) — уберите их с сайта"
          bad=1
        fi
      done
      if [[ "$bad" -eq 0 ]]; then
        _audit_ok "Проверено ${n} адресов (страницы из sitemap, robots, sitemap, 404): слов vpn/proxy/xray/reality/gorec/обход… нет"
      fi
    fi
    rm -rf "$tmp"
  fi

  # 4) снаружи: 443 с SNI домена должен отдавать НАШ сертификат (= панель переключена на self-steal)
  if [[ -n "$pub" && -s "$live" ]] && command -v openssl >/dev/null 2>&1; then
    local ext loc
    ext="$(timeout 8 openssl s_client -connect "${pub}:443" -servername "$d" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 || true)"
    loc="$(openssl x509 -noout -fingerprint -sha256 -in "$live" 2>/dev/null | cut -d= -f2 || true)"
    if [[ -z "$ext" ]]; then
      _audit_warn "${pub}:443 с SNI ${d} не отдал сертификат — REALITY на 443 не настроен на этот домен?"
    elif [[ "$ext" == "$loc" ]]; then
      _audit_ok "Снаружи ${pub}:443 (SNI ${d}) отдаёт ваш сертификат — маскировка работает"
    else
      _audit_warn "Снаружи ${pub}:443 (SNI ${d}) отдаёт ЧУЖОЙ сертификат — в панели ещё старый target/dest"
    fi
  fi
  _audit_info "Сверьте в панели: target/dest = ${SITE_LISTEN}:${SITE_PORT}, serverNames содержит ${d}, xver = $([[ "$SITE_PP" -eq 1 ]] && echo 1 || echo 0), SNI в Hosts = ${d}"
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
  configure_stealth
  configure_decoy_web
  configure_site || warn "Сайт-маскировка не установлена (остальная защита применена) — повтор: gorecshit --site-domain <домен>"
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
        && "$DO_SITE_ONLY" -eq 0 \
        && "$DO_UPDATE_ONLY" -eq 0 \
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

  if [[ "$DO_SITE_ONLY" -eq 1 ]]; then
    run_site_only
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
