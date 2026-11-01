# gorecshit

Однокомандное hardening-окружение для **нод Remnawave** (Debian 11+ / Ubuntu 20.04+).

**Версия: 2.2.2**

Скрипт идемпотентен: его можно запускать повторно. IP панели **не зашит** в репозиторий — его нужно передать параметром `--panel-ip` (или выбрать в интерактивном меню).

Точка входа: `install.sh` (симлинк `gorecshit.sh` → тот же скрипт).

## Что делает

1. **Preflight** — root, определение ОС, бэкап всех затрагиваемых файлов в `/root/hardening-backups/<timestamp>/` + `rollback.sh`.
2. **Автодетект remnanode** — `/opt/remnanode/.env` (`NODE_PORT` / `APP_PORT`), docker compose; клиентские **TCP и UDP** порты через `ss` у процессов xray/rw-core/remnanode/sing-box/hysteria (**без хардкода 443/8443**). Явно: `--client-ports`, `--client-udp-ports`.
3. **Интерактивное меню (RU)** — при запуске в TTY без `--yes`: статус-строка + простые пункты с emoji (plain `read` + ANSI, whiptail не обязателен).
4. **Пакеты** — `ufw`, `fail2ban`, `ipset`, `chrony`, `curl`; при отключении IPv6 — `Acquire::ForceIPv4`.
5. **UFW** — deny incoming (**DROP**), logging low; `limit 22/tcp`; клиентские TCP/UDP порты; `NODE_PORT` **только с IP панели**; deny публичного `4443/tcp`; whitelist HAProxy-релеев; анти-lockout (`$SSH_CLIENT`, `--allow-ssh-from`, `--relay-ips`).
6. **Скрытие портов и ping** — ICMP echo-request → DROP; закрытые порты без RST/REJECT (DROP); не светить unreachable.
7. **Anti-probing** — на клиентских портах только для **NEW**; `ESTABLISHED,RELATED` всегда в обход (без hashlimit/connlimit на датаплейне). Потолки NAT-friendly; **без** xt_recent soft-ban. Не ломает REALITY.
8. **DOCKER-USER** — ограничение `NODE_PORT` на bridge-publish; Docker **не перезапускается**, пока живы remnanode/xray.
9. **sysctl / скорость** — BBR + `fq`, буферы **64MB**, `tcp_fastopen=3`, `tcp_slow_start_after_idle=0`, `tcp_mtu_probing=1`, `tcp_notsent_lowat=16384`, `somaxconn`/`netdev_max_backlog`, `conntrack_max`, `txqueuelen=10000`, `irqbalance`; `nf_conntrack_tcp_be_liberal=1`; IPv6 **включён по умолчанию** (`--ipv6-off` опционально); `nofile` 1048576; `--tcp-timestamps-off` опционально.
10. **SSH** — Banner none, MaxAuthTries 3, опция `--ssh-port N` (сначала UFW, `sshd -t`, **22 сохраняется**). Парольный и root-логин **не** отключаются. fail2ban sshd + **recidive**; сканеры из ipset режутся до SSH.
11. **Блоклист сканеров** — ipset + weekly timer; **зеркала** raw.githubusercontent.com → cdn.jsdelivr.net / fastly.jsdelivr.net; `--blocklist-from`; never-block для панели/релеев/`$SSH_CLIENT`/private/bogons.
12. **Стелс** — нейтральный hostname `web-<hex>`, без баннеров, предупреждение о лишних слушателях, отключение nginx default site; NODE_PORT только с панели.
13. **`--check` / `--rollback` / `--status` / `--refresh-lists` / `--dpi-check`**.

## Меню (TTY)

```
✅ Защита: активна · ufw on · fail2ban on · ipset N подсетей · порты: 8443
────────────────────────────────────────
📋 Меню:
  1) 🚀 Установить защиту (всё)
  2) 🧩 Выборочная установка
  3) 🔄 Обновить списки сканеров
  4) 📊 Показать статус
  5) 🔍 Проверка DPI/блокировок
  6) ↩️  Откат
  7) ⬆️  Обновить gorecshit (GitHub)
────────────────────────────────────────
  0) 🚪 Выход
CLI: gorecshit [--status|--update|--yes|--modules …]
Выберите пункт [0-7]:
```

## Проверка DPI/блокировок

Облегчённый bash-порт идей из [dpi-detector](https://github.com/Runnin4ik/dpi-detector) для **egress с VPN-ноды** (без Python/rich/httpx, без установок с GitHub):

1. **DNS** — сравнение system resolver vs Cloudflare DoH; эвристика stub/fake (RFC 5737, 198.18/15, private).
2. **TLS reachability** — `openssl s_client` / curl HEAD к известным доменам (в т.ч. часто блокируемым в РФ и «белым»).
3. **SNI-фильтр** — один IP Cloudflare, разные SNI (детект TLS DROP / RST на ClientHello).
4. **TCP 16–20KB-стиль** — keep-alive HEAD с `X-Pad` ~4KB × 8 (~32KB), как у dpi-detector fat-probe.
5. **Локальные слушатели** — список TCP listen + факт жизни remnanode (без рестарта Docker).

```bash
sudo bash install.sh --dpi-check
# или
sudo bash gorecshit.sh --dpi-check
```

На зарубежной VPS обычно всё OK — это нормально (российский DPI на пути ноды нет). Модуль полезен как диагностика egress/DNS ноды.

## Changelog

### v2.2.2

- Команда **`gorecshit`**: при любом запуске ставится `/usr/local/sbin/gorecshit` + symlink `/usr/local/bin/gorecshit`
- Без аргументов открывается меню; аргументы (`--status`, `--yes`, …) пробрасываются как раньше
- `--update` / пункт меню «Обновить gorecshit» — самообновление с GitHub (fallback jsDelivr/fastly)

### v2.2.1

- **IPv6 по умолчанию включён** (отключение только через `--ipv6-off`): под живым dual-stack xray `disable_ipv6=1` ломало сессии
- Всегда `net.netfilter.nf_conntrack_tcp_be_liberal=1` — меньше ложных INVALID при UFW `ctstate INVALID DROP` / NAT
- Anti-probe: **сначала** `ESTABLISHED,RELATED`; лимиты только на **NEW**; UDP тоже NEW-only; убран xt_recent 10‑минутный soft-ban; потолки подняты (TCP ~600/min burst 1200, connlimit 2000)
- На INPUT — ранний `ACCEPT` для ESTABLISHED/RELATED (горячий путь до fail2ban/antiprobe)
- ipset `scanner-block` в UFW before.rules только для **NEW**
- **Тюнинг скорости (safe defaults):** BBR + `fq` на default iface; буферы 64MB (`rmem`/`wmem`/`tcp_rmem`/`tcp_wmem`); `tcp_fastopen=3`; `tcp_slow_start_after_idle=0`; `tcp_mtu_probing=1`; `tcp_notsent_lowat=16384`; `somaxconn=4096`; `netdev_max_backlog=16384`; `nf_conntrack_max=1048576`; `nofile=1048576` (limits + systemd + docker remnanode); `txqueuelen=10000`; `irqbalance` (best-effort). `tcp_timestamps` по умолчанию не трогаем; без MSS clamp

### v2.2.0

- Простое интерактивное меню на русском (статус-строка + emoji), без обязательного whiptail
- Модуль `--dpi-check` / пункт меню «Проверка DPI/блокировок» (DNS / TLS / SNI / TCP16-стиль)
- Симлинк `gorecshit.sh` → `install.sh`
- Все прежние CLI-флаги сохранены (обратная совместимость)

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

После первого запуска (или просто `bash install.sh --status`) на сервере доступна команда:

```bash
gorecshit              # меню
gorecshit --status
gorecshit --update     # обновить скрипт с GitHub / jsDelivr
```

Интерактивно (меню на русском, спросит IP панели):

```bash
bash <(curl -Ls https://raw.githubusercontent.com/gorecvpn/gorecshit/main/install.sh)
# дальше: gorecshit
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
| `--ipv6-off` | Опционально отключить IPv6 (по умолчанию IPv6 **остаётся**). |
| `--no-ipv6-off` / `--no-blocklist` / `--no-hostname` / … | Как в v2.0 (`--no-ipv6-off` = поведение по умолчанию). |
| `--yes` | Без подтверждения / без меню. |
| `--dry-run` / `--check` | Только план. |
| `--refresh-lists` | Только обновить ipset-списки. |
| `--status` | Показать статус. |
| `--dpi-check` | DNS/TLS/SNI/TCP16 egress-проверка с ноды. |
| `--update` | Самообновление `install.sh` → `/usr/local/sbin/gorecshit` (GitHub, fallback jsDelivr). |
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
- Never-block всегда включает панель (когда передана), релеи и текущий `$SSH_CLIENT` — SSH не отрежется.
- FireHOL/крупные списки фильтруются: private/bogons, prefixlen&lt;12, пересечение с never-block.
- `--dpi-check` только диагностирует egress; ничего не меняет и не рестартит сервисы.

## Требования

- root
- Debian 11+ или Ubuntu 20.04+
- Сеть для `apt` и (опционально) загрузки блоклистов; при недоступности GitHub работают jsDelivr-зеркала и `--blocklist-from`
- Для `--dpi-check`: `curl`, `openssl`, `timeout` (обычно уже есть)

## Лицензия

MIT — см. [LICENSE](LICENSE).
