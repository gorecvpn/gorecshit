# gorecshit

Однокомандное hardening-окружение для **нод Remnawave** (Debian 11+ / Ubuntu 20.04+).

Скрипт идемпотентен: его можно запускать повторно. IP панели **не зашит** в репозиторий — его нужно передать параметром `--panel-ip`.

## Что делает

1. **Preflight** — root, определение ОС, бэкап всех затрагиваемых файлов в `/root/hardening-backups/<timestamp>/` + `rollback.sh`.
2. **Автодетект remnanode** — `/opt/remnanode/.env` (`NODE_PORT` / `APP_PORT`), docker compose; клиентские порты через `ss` (исключая NODE_PORT, 22, localhost). В режиме `cdn` (есть Caddy) открывает 80/443 и не открывает внутренний порт xray снаружи.
3. **Пакеты** — `ufw`, `fail2ban`, `ipset`, `chrony`, `curl`; при отключении IPv6 — `Acquire::ForceIPv4`.
4. **UFW** — deny incoming / allow outgoing; `limit 22/tcp`; клиентские порты; `NODE_PORT` **только с IP панели**; анти-lockout (текущий `$SSH_CLIENT`, `--allow-ssh-from`).
5. **sysctl** — BBR + `fq` (fallback `fq_codel`), буферы 32MB, `somaxconn`, `tcp_fastopen=3`, `mtu_probing`, `file-max`, conntrack (если модуль есть); опционально отключение IPv6.
6. **SSH** — drop-in `/etc/ssh/sshd_config.d/99-hardening.conf`: `DebianBanner no` (если поддерживается), `Banner none`, `MaxAuthTries 3`, `LoginGraceTime 20`, `MaxStartups 10:30:60`. **Парольный и root-логин не отключаются.** Проверка `sshd -t` перед reload.
7. **fail2ban (sshd)** — bantime 1h, findtime 10m, maxretry 5; `ignoreip`: localhost + панель + SSH-клиент + `--allow-ssh-from`.
8. **Блоклист сканеров** — `ipset` `hash:net` + systemd service/timer (еженедельно); при ошибке загрузки сохраняется старый список; панель/whitelist никогда не попадают в DROP; хук в `ufw before.rules`.
9. **Hostname** — нейтральный `web-<6hex>`, `/etc/hosts`, cloud-init `preserve_hostname`; timezone — только если указан `--tz` (`auto` = геолокация по IP).
10. **Docker / journald** — ротация логов в `daemon.json` (merge), `SystemMaxUse=200M`; `chmod 600` на `.env`/compose; docker перезапускается **только** если конфиг изменился (клиенты могут кратко переподключиться).
11. **Итог** — сводка: ufw, cc/qdisc, listeners, fail2ban, размер blocklist, контейнер ноды.
12. **`--rollback` / `--uninstall`** — восстановление из последнего бэкапа.

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

## Флаги

| Флаг | Описание |
|------|----------|
| `--panel-ip IP` | **Обязателен** (или переменная `GORECSHIT_PANEL_IP`). Хост панели/управления, с которого разрешён `NODE_PORT`. |
| `--node-port PORT\|auto` | Порт remnanode API (по умолчанию `auto` из `.env`, иначе `3000`). |
| `--client-ports LIST\|auto` | Клиентские порты через запятую (по умолчанию автодетект; в `cdn` — `80,443`). |
| `--mode direct\|cdn` | `direct` — открыть порты xray; `cdn` — 80/443, внутренний xray снаружи закрыт. |
| `--allow-ssh-from IP,...` | Доп. IP в whitelist SSH / never-block. |
| `--no-ipv6-off` | Не отключать IPv6. |
| `--no-blocklist` | Не ставить ipset-блоклист сканеров. |
| `--no-hostname` | Не менять hostname. |
| `--tz ZONE\|auto` | Выставить timezone (по умолчанию **не меняет**). `auto` — по IP. |
| `--yes` | Без подтверждения. |
| `--dry-run` | Только печать действий, без изменений. |
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
- После смены `daemon.json` возможен краткий reconnect клиентов VPN.
- Убедитесь, что текущая SSH-сессия не будет отрезана: скрипт добавляет `$SSH_CLIENT` и `--panel-ip` в allow/ignore.

## Требования

- root
- Debian 11+ или Ubuntu 20.04+
- Сеть для `apt` и (опционально) загрузки блоклистов сканеров

## Лицензия

MIT — см. [LICENSE](LICENSE).
