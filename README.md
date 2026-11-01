# gorecshit

Однокомандное hardening-окружение для **нод Remnawave** (Debian 11+ / Ubuntu 20.04+).

**Версия: 2.1.0**

Скрипт идемпотентен: его можно запускать повторно. IP панели **не зашит** в репозиторий — его нужно передать параметром `--panel-ip` (или выбрать в интерактивном меню).

## Что делает

1. **Preflight** — root, определение ОС, бэкап всех затрагиваемых файлов в `/root/hardening-backups/<timestamp>/` + `rollback.sh`.
2. **Автодетект remnanode** — `/opt/remnanode/.env` (`NODE_PORT` / `APP_PORT`), docker compose; клиентские **TCP и UDP** порты через `ss` у процессов xray/rw-core/remnanode/sing-box/hysteria (**без хардкода 443/8443**). Явно: `--client-ports`, `--client-udp-ports`.
3. **Интерактивное меню (RU)** — при запуске в TTY без `--yes`: пресеты «Всё / Минимум / Выборочно», Проверка, Откат, Обновить списки, Статус (whiptail или обычный read).
4. **Пакеты** — `ufw`, `fail2ban`, `ipset`, `chrony`, `curl`; при отключении IPv6 — `Acquire::ForceIPv4`.
5. **UFW** — deny incoming (**DROP**), logging low; `limit 22/tcp`; клиентские TCP/UDP порты; `NODE_PORT` **только с IP панели**; deny публичного `4443/tcp`; whitelist HAProxy-релеев; анти-lockout (`$SSH_CLIENT`, `--allow-ssh-from`, `--relay-ips`).
6. **Скрытие портов и ping** — ICMP echo-request → DROP; закрытые порты без RST/REJECT (DROP); не светить unreachable.
7. **Anti-probing** — на **всех** автодетектнутых/указанных клиентских портах: hashlimit/connlimit (CGNAT-friendly: ~60 new/min burst 120, connlimit ~200/32) + recent soft-ban. Не ломает REALITY.
8. **DOCKER-USER** — ограничение `NODE_PORT` на bridge-publish; Docker **не перезапускается**, пока живы remnanode/xray.
9. **sysctl** — BBR + `fq`, буферы 32MB; опционально `--tcp-timestamps-off`; IPv6 off; `nofile` 1048576.
10. **SSH** — Banner none, MaxAuthTries 3, опция `--ssh-port N` (сначала UFW, `sshd -t`, **22 сохраняется**). Парольный и root-логин **не** отключаются. fail2ban sshd + **recidive**; сканеры из ipset режутся до SSH.
11. **Блоклист сканеров** — ipset + weekly timer; **зеркала** raw.githubusercontent.com → cdn.jsdelivr.net / fastly.jsdelivr.net; таймауты connect 8s / max 20s; параллельные загрузки; `--blocklist-from` (URL / ssh-host / файл); never-block для панели/релеев/`$SSH_CLIENT`/private/bogons.
12. **Стелс** — нейтральный hostname `web-<hex>`, без баннеров, предупреждение о лишних слушателях, отключение nginx default site; NODE_PORT только с панели.
13. **`--check` / `--rollback` / `--status` / `--refresh-lists`**.

## Changelog

### v2.1.0

- Зеркала блоклистов (jsDelivr CDN + fastly), короткие таймауты, параллельные загрузки; `--blocklist-from`
- Доп. источники (проверены curl 200): FireHOL level1/level2, Spamhaus DROP/EDROP, blocklist.de ssh/all, CINS army, stamparm ipsum/3, C24Be blacklist-v4 (RU AS), CyberOK Skipa (ГРЧЦ/НКЦКИ) + прежние OpenFilters/Xorlent/wdes/traffic-guard
- Скрытие ping и закрытых портов (DROP, logging low)
- Anti-probing на всех автодетектнутых клиентских TCP/UDP портах (не только 443/8443)
- `--ssh-port N`, fail2ban recidive
- Стелс-модуль (баннеры, default pages, лишние порты, опционально tcp_timestamps=0)
- Интерактивное русское меню (whiptail/read) + `--modules`
- `--client-udp-ports`, `--status`, `--refresh-lists`

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

Интерактивно (меню на русском, спросит IP панели):

```bash
bash <(curl -Ls https://raw.githubusercontent.com/gorecvpn/gorecshit/main/install.sh)
```

Проверка без изменений:

```bash
sudo bash install.sh --check --panel-ip X.X.X.X
```

Только выбранные модули:

```bash
sudo bash install.sh --panel-ip X.X.X.X --modules ufw,blocklist,hide_ports,anti_probe,ssh,fail2ban,sysctl --yes
```

## Флаги

| Флаг | Описание |
|------|----------|
| `--panel-ip IP` | **Обязателен** в non-interactive (или `GORECSHIT_PANEL_IP`). |
| `--node-port PORT\|auto` | Порт remnanode API (по умолчанию `auto`). |
| `--client-ports LIST\|auto` | Клиентские TCP-порты (автодетект xray/rw-core/…; **без хардкода**). |
| `--client-udp-ports LIST\|auto` | Клиентские UDP-порты (hysteria2 и т.п.). |
| `--mode direct\|cdn` | `direct` — открыть порты xray; `cdn` — 80/443. |
| `--allow-ssh-from IP,...` | Доп. IP в whitelist SSH / never-block. |
| `--relay-ips IP,...` | Extra never-block / ACCEPT (по умолчанию HAProxy-релеи). |
| `--ssh-port N` | Добавить SSH-порт N (22 сохраняется). |
| `--blocklist-from SRC` | URL / ssh-host / путь — запасной источник blocklist. |
| `--modules LIST` | `ufw,blocklist,hide_ports,anti_probe,ssh,stealth,fail2ban,sysctl,hostname,docker` или `all`/`minimum`. |
| `--no-hide-ports` / `--no-anti-probe` / `--no-stealth` | Отключить соответствующие модули. |
| `--tcp-timestamps-off` | `net.ipv4.tcp_timestamps=0`. |
| `--no-ipv6-off` / `--no-blocklist` / `--no-hostname` / … | Как в v2.0. |
| `--yes` | Без подтверждения / без меню. |
| `--dry-run` / `--check` | Только план. |
| `--refresh-lists` | Только обновить ipset-списки. |
| `--status` | Показать статус. |
| `--rollback` / `--uninstall` | Откат из бэкапа. |

## Откат

```bash
sudo bash install.sh --rollback
# или
sudo /root/hardening-backups/<timestamp>/rollback.sh
```

## Предупреждения

- Скрипт **не трогает** панель Remnawave, ключи REALITY, конфиг-профили, DNS и маскировку inbound.
- Работает на **ноде** (VPS с remnanode), не на сервере панели.
- На живой ноде Docker **не перезапускается**.
- Never-block всегда включает панель `188.225.77.137` (когда передана), релеи и текущий `$SSH_CLIENT` — SSH не отрежется.
- FireHOL/крупные списки фильтруются: private/bogons, prefixlen&lt;12, пересечение с never-block.

## Требования

- root
- Debian 11+ или Ubuntu 20.04+
- Сеть для `apt` и (опционально) загрузки блоклистов; при недоступности GitHub работают jsDelivr-зеркала и `--blocklist-from`

## Лицензия

MIT — см. [LICENSE](LICENSE).
