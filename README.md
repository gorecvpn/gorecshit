# gorecshit

Однокомандное hardening-окружение для **нод Remnawave** (Debian 11+ / Ubuntu 20.04+).

**Версия: 2.0.0**

Скрипт идемпотентен: его можно запускать повторно. IP панели **не зашит** в репозиторий — его нужно передать параметром `--panel-ip`.

## Что делает

1. **Preflight** — root, определение ОС, бэкап всех затрагиваемых файлов в `/root/hardening-backups/<timestamp>/` + `rollback.sh`.
2. **Автодетект remnanode** — `/opt/remnanode/.env` (`NODE_PORT` / `APP_PORT`), docker compose; клиентские порты через `ss` (исключая NODE_PORT, 22, localhost). В режиме `cdn` (есть Caddy) открывает 80/443 и не открывает внутренний порт xray снаружи.
3. **Пакеты** — `ufw`, `fail2ban`, `ipset`, `chrony`, `curl`; при отключении IPv6 — `Acquire::ForceIPv4`.
4. **UFW** — deny incoming / allow outgoing; `limit 22/tcp`; клиентские порты; `NODE_PORT` **только с IP панели**; deny публичного `4443/tcp`; whitelist HAProxy-релеев; анти-lockout (текущий `$SSH_CLIENT`, `--allow-ssh-from`, `--relay-ips`).
5. **DOCKER-USER** — ограничение `NODE_PORT` на bridge-publish (REPLY/ESTABLISHED не ломаются); Docker **не перезапускается**, пока на ноде живы remnanode/xray.
6. **sysctl** — BBR + `fq` (fallback `fq_codel`), буферы 32MB, `somaxconn`, `tcp_fastopen=3`, `mtu_probing`, `file-max`, conntrack (если модуль есть); опционально отключение IPv6; `nofile` 1048576.
7. **SSH** — drop-in `/etc/ssh/sshd_config.d/99-hardening.conf`: `DebianBanner no` (если поддерживается), `Banner none`, `MaxAuthTries 3`, `LoginGraceTime 20`, `MaxStartups 10:30:60`. **Парольный и root-логин не отключаются.** Проверка `sshd -t` перед reload.
8. **fail2ban (sshd)** — bantime 1h, findtime 10m, maxretry 5; `ignoreip`: localhost + панель + SSH-клиент + `--allow-ssh-from` + relay IPs.
9. **Блоклист сканеров** — `ipset` `hash:net` + systemd service/timer (еженедельно); при ошибке загрузки сохраняется старый список; панель/whitelist/relay никогда не попадают в DROP; хук в `ufw before.rules`.
10. **Hostname** — нейтральный `web-<6hex>`, `/etc/hosts`, cloud-init `preserve_hostname`; timezone — только если указан `--tz` (`auto` = геолокация по IP).
11. **Docker / journald / resolv / certbot** — ротация логов в `daemon.json` (merge без рестарта на live node), `SystemMaxUse=200M`; `chmod 600` на `.env`/compose; IPv4-only `resolv.conf` при отключённом IPv6; хуки certbot renew для caddy/nginx.
12. **Итог / `--check`** — сводка: ufw, DOCKER-USER, nofile, cc/qdisc, listeners, fail2ban, размер blocklist, контейнер ноды. `--check` / `--dry-run` — только план, без изменений.
13. **`--rollback` / `--uninstall`** — восстановление из последнего бэкапа.

## Changelog

### v2.0.0

- DOCKER-USER REPLY/ESTABLISHED fix для `NODE_PORT` на bridge-publish
- Docker не перезапускается на живой ноде (remnanode/xray)
- Whitelist HAProxy-релеев (`--relay-ips`, по умолчанию `188.225.24.250,188.225.27.46`)
- Явный deny публичного `4443/tcp`
- `nofile` 1048576
- IPv4 `resolv.conf` при отключённом IPv6
- Хукы certbot renew (caddy/nginx)
- Режим `--check` (alias `--dry-run`)

## Одной командой

```bash
bash <(curl -Ls https://raw.githubusercontent.com/gorecvpn/gorecshit/main/install.sh) --panel-ip X.X.X.X --yes
```

Интерактивно (спросит IP панели, если не передан):

```bash
bash <(curl -Ls https://raw.githubusercontent.com/gorecvpn/gorecshit/main/install.sh)
```

Или скачать и запустить локально:

```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/gorecvpn/gorecshit/main/install.sh
sudo bash install.sh --panel-ip X.X.X.X --yes
```

Проверка без изменений:

```bash
sudo bash install.sh --check --panel-ip X.X.X.X
```

## Флаги

| Флаг | Описание |
|------|----------|
| `--panel-ip IP` | **Обязателен** (или переменная `GORECSHIT_PANEL_IP`). Хост панели/управления, с которого разрешён `NODE_PORT`. |
| `--node-port PORT\|auto` | Порт remnanode API (по умолчанию `auto` из `.env`, иначе `3000`). |
| `--client-ports LIST\|auto` | Клиентские порты через запятую (по умолчанию автодетект; в `cdn` — `80,443`). |
| `--mode direct\|cdn` | `direct` — открыть порты xray; `cdn` — 80/443, внутренний xray снаружи закрыт. |
| `--allow-ssh-from IP,...` | Доп. IP в whitelist SSH / never-block. |
| `--relay-ips IP,...` | Extra never-block / ACCEPT (по умолчанию HAProxy-релеи). Env: `GORECSHIT_RELAY_IPS`. |
| `--no-ipv6-off` | Не отключать IPv6. |
| `--no-blocklist` | Не ставить ipset-блоклист сканеров. |
| `--no-hostname` | Не менять hostname. |
| `--no-docker-user` | Не ставить DOCKER-USER ограничение `NODE_PORT`. |
| `--no-nofile` | Не поднимать nofile до 1048576. |
| `--no-resolv-v4` | Оставить IPv6 nameserver в resolv.conf даже при отключённом IPv6. |
| `--no-certbot-hooks` | Не ставить certbot renew reload hooks для caddy/nginx. |
| `--tz ZONE\|auto` | Выставить timezone (по умолчанию **не меняет**). `auto` — по IP. |
| `--yes` | Без подтверждения. |
| `--dry-run` / `--check` | Только печать действий / проверка плана, без изменений. |
| `--rollback` / `--uninstall` | Откат из `/root/hardening-backups/`. |

## Откат

```bash
sudo bash install.sh --rollback
# или
sudo /root/hardening-backups/<timestamp>/rollback.sh
```

## Предупреждения

- Скрипт **не трогает** панель Remnawave, ключи REALITY, конфиг-профили, DNS и маскировку inbound.
- Работает на **ноде** (VPS с remnanode), не на сервере панели.
- Не коммитьте секреты и не подставляйте реальный IP панели в публичные примеры/форки без нужды.
- На живой ноде Docker **не перезапускается** (v2); reconnect из‑за `daemon.json` больше не делается, пока крутятся remnanode/xray.
- Убедитесь, что текущая SSH-сессия не будет отрезана: скрипт добавляет `$SSH_CLIENT`, `--panel-ip` и relay IPs в allow/ignore.

## Требования

- root
- Debian 11+ или Ubuntu 20.04+
- Сеть для `apt` и (опционально) загрузки блоклистов сканеров

## Лицензия

MIT — см. [LICENSE](LICENSE).
