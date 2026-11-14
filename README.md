# gorecshit

Однокомандное hardening-окружение для **нод Remnawave** (Debian 11+ / Ubuntu 20.04+).

**Версия: 2.7.2**

📍 **[Карта: как вычисляют VPN-ноду и что закрывает gorecshit](docs/detection-vectors.md)** — активное зондирование, DPI, Shodan/Censys, порты, IPv6, PTR, abuse и т.д.

Скрипт идемпотентен: его можно запускать повторно. IP панели **не зашит** в репозиторий — его нужно передать параметром `--panel-ip` (или выбрать в интерактивном меню).

Точка входа: `install.sh` и `gorecshit.sh` — **идентичные полные файлы** (не symlink в репозитории).

## Что делает

1. **Preflight** — root, определение ОС, бэкап всех затрагиваемых файлов в `/root/hardening-backups/<timestamp>/` + `rollback.sh`.
2. **Автодетект remnanode** — `/opt/remnanode/.env` (`NODE_PORT` / `APP_PORT`), docker compose; клиентские **TCP и UDP** порты из xray **inbounds** (fallback: `ss` LISTEN вне ephemeral; UDP без эфемерного диапазона). Явно: `--client-ports`, `--client-udp-ports`.
3. **Интерактивное меню (RU)** — при запуске в TTY без `--yes`: статус-строка + простые пункты с emoji (plain `read` + ANSI, whiptail не обязателен).
4. **Обновление системы** — перед пакетами: пауза `apt-daily*` / `unattended-upgrades` (без kill dpkg), `dpkg --configure -a`, `apt-get update` + `full-upgrade` (сохранение локальных конфигов); сообщение если нужен reboot (**без** авто-reboot); в конце таймеры возвращаются. Пропуск: `--no-upgrade` / `GORECSHIT_NO_UPGRADE=1`.
5. **Пакеты** — `ufw`, `fail2ban`, `ipset`, `chrony`, `curl`; при отключении IPv6 — `Acquire::ForceIPv4`.
6. **UFW** — deny incoming (**DROP**), logging low; `limit 22/tcp`; клиентские TCP/UDP порты; `NODE_PORT` **только с IP панели**; deny публичного `4443/tcp`; whitelist HAProxy-релеев; анти-lockout (`$SSH_CLIENT`, `--allow-ssh-from`, `--relay-ips`).
7. **Скрытие портов и ping** — ICMP echo-request → DROP; закрытые порты без RST/REJECT (DROP); не светить unreachable.
8. **Anti-probing** — на клиентских портах только для **NEW**; `ESTABLISHED,RELATED` всегда в обход (без hashlimit/connlimit на датаплейне). Потолки NAT-friendly; **без** xt_recent soft-ban. Не ломает REALITY.
9. **DOCKER-USER** — ограничение `NODE_PORT` на bridge-publish; Docker **не перезапускается**, пока живы remnanode/xray.
10. **sysctl / скорость** — BBR + `fq`, буферы **64MB**, `tcp_fastopen=3`, `tcp_slow_start_after_idle=0`, `tcp_mtu_probing=1`, `tcp_notsent_lowat=16384`, `somaxconn`/`netdev_max_backlog`, `conntrack_max`, `txqueuelen=10000`, `irqbalance`; `nf_conntrack_tcp_be_liberal=1`; IPv6 **включён по умолчанию** (`--ipv6-off` опционально); `nofile` 1048576; `--tcp-timestamps-off` опционально.
11. **SSH** — Banner none, MaxAuthTries 3, опция `--ssh-port N` (сначала UFW, `sshd -t`, **22 сохраняется**). Парольный и root-логин **не** отключаются. fail2ban sshd + **recidive**; сканеры из ipset режутся до SSH.
12. **Блоклист сканеров** — ipset + weekly timer; **зеркала** raw.githubusercontent.com → cdn.jsdelivr.net / fastly.jsdelivr.net; `--blocklist-from`; never-block для панели/релеев/`$SSH_CLIENT`/private/bogons.
13. **Стелс** — нейтральный hostname `web-<hex>`, без баннеров, предупреждение о лишних слушателях, отключение nginx default site; NODE_PORT только с панели.
14. **Egress guard** (v2.6.0, по умолчанию вкл., `--no-egress-guard`) — исходящий **TCP 25** (SMTP) → REJECT с хоста и из Docker (IPv4+IPv6), чтобы через ноду нельзя было слать спам и хостер не получал abuse-жалобы. Порты: `--egress-block-ports 25,465,587`. Также режутся исходящие ICMP port/proto-unreachable и time-exceeded (PMTU frag-needed/packet-too-big **не** трогаются). Рекомендация (в панели): routing `bittorrent → blackhole`.
15. **IPv6 = IPv4** (v2.6.0) — UFW `IPV6=yes`, ping6 DROP, DOCKER-USER для NODE_PORT и по v6; публичные `ALLOW Anywhere` для NODE_PORT удаляются (кроме семейства, где есть живое соединение не с панели).
16. **Декой :80** (опционально, `--decoy-web` / вопрос y/N) — только если уже есть nginx, 80 свободен и REALITY на 443: `301 → https` как у обычного сайта; иначе только рекомендация.
17. **`--check` / `--rollback` / `--status` / `--version` / `--refresh-lists` / `--dpi-check` / `--audit` / `--stealth` / `--update` / `--no-upgrade`**.

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
  8) 🛡️  Проверка на блокировку и палевность ноды
  9) 🕵️  Скрыть отпечатки сервера
  10) 🌐 Сайт-маскировка (поддомен + сертификат + сайт)
────────────────────────────────────────
  0) 🚪 Выход
CLI: gorecshit [--status|--update|--audit|--stealth|--site-domain D|--yes|--modules …]
Выберите пункт [0-10]:
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

## Проверка на блокировку и палевность ноды

Read-only аудит (меню «8» / `--audit`): **ничего не меняет**, firewall/скорость не трогает.

1. **Доступность из России** — публичный IPv4 ноды + клиентские TCP-порты (тот же детект, что из xray inbounds). Через API [check-host.net](https://check-host.net) (`check-tcp` / `check-ping`, узлы `country=RU` + несколько зарубежных для сравнения). По каждому порту: «из России: доступен N/M», «из-за рубежа: …»; если зарубежье OK, а РФ нет → «IP, вероятно, заблокирован в РФ (ТСПУ)». Таймаут/ошибки API обрабатываются мягко (~60с общий лимит). Нужен `curl` (jq необязателен; есть fallback на python3 / grep).
2. **Палевность** — чтение конфига xray из контейнера `remnawave/node` / remnanode (файлы, `/proc` `-config`, xray API); если конфиг только в runtime/stdin — пассивный TLS/REALITY-зонд локальных портов (CN/SAN маскировки). Для VLESS/REALITY: порт ≠443, flow ≠ vision, «плохой» dest/SNI, dest без TLS1.3+h2, пустые shortIds, нет block bittorrent, plain TLS/WS без CDN. Сервер: отвечает ли ICMP echo, лишние публичные порты, SSH на 22, UFW выключен. Строки ✅/⚠️ с короткой рекомендацией на русском.

3. **Shodan InternetDB** (v2.6.0, без ключа) — какие порты/теги (`vpn`, `proxy`, `self-signed`…)/CPE/CVE/hostnames интернет уже видит по IPv4 и IPv6; NODE_PORT и «палевные» порты (2222, 62050, 2053, 54321, 10085…) подсвечиваются.
4. **Внешняя поверхность** (v2.6.0) — все слушатели TCP/UDP v4+v6 с учётом UFW и Docker publish; паритет UFW IPv6; NODE_PORT проверяется **снаружи** через check-host (должен быть 0/N).
5. **Активный зонд REALITY** (v2.6.0) — как ТСПУ/сканер: без ключа REALITY шлём TLS с настоящим SNI, HTTPS GET, plain HTTP на TLS-порт, случайный SNI и TLS 1.2-only, сравниваем сертификат/ALPN/HTTP-код/Server с настоящим `dest`. Совпадает = маскировка хорошая. Плюс версия xray (≥ 25.6.8 — защита от детекта по NewSessionTicket).
6. **Мелкие признаки** (v2.6.0) — SSH-баннер как видит интернет, PTR (обратный DNS), VPN-слова в motd/issue, `Server`-заголовки, MTU/MSS (JA4T), egress SMTP / ICMP-утечки.

```bash
sudo bash install.sh --audit
# или
gorecshit --audit
```

## Сайт-маскировка (поддомен + сертификат + сайт)

Модуль v2.7.0 (меню **10** / `--site-domain`). Ставит на поддомен ноды настоящий сертификат Let's Encrypt и правдоподобный многостраничный сайт. Затем REALITY отдаёт этот сайт всем, кто подключается без ключа (схема **self-steal**): зонд ТСПУ или сканер видит обычный сайт-визитку с валидным сертификатом на том же IP, а не чужой `dest`.

**Что нужно заранее:** A-запись `поддомен → IP ноды`. В Cloudflare — серое облако («DNS only»), оранжевое не подойдёт. AAAA либо не создавать, либо указать IPv6 ноды. В имени поддомена не должно быть слов vpn/proxy/xray и т.п.: SNI виден DPI. Скрипт такой домен не примет.

```bash
sudo gorecshit --update
sudo gorecshit --site-domain cdn.example.ru --site-email you@example.ru
# или меню: gorecshit → 10
```

Что делает:

1. Проверяет DNS через DoH: A/AAAA должны указывать на IP этой ноды. Отдельно ловит оранжевое облако Cloudflare.
2. Выбирает режим сам и спрашивает подтверждение:
   - **selfsteal** — 443 занят xray (REALITY). nginx отдаёт сайт только на `127.0.0.1:9443`.
   - **public** — 443 свободен. nginx слушает и публичный 443, и `127.0.0.1:9443` (для REALITY на другом порту).
3. Ставит `nginx` и `certbot` (apt). Выпускает сертификат по HTTP-01 через webroot на :80. В UFW открывает `80/tcp`: у обычного сайта 80 открыт и отвечает 301 на https. С `--site-close-80` порт закрывается после выпуска, а при продлении certbot открывает его примерно на минуту и закрывает обратно.
4. Генерирует статический сайт:
   - страницы: главная, «О нас», «Услуги»/«Меню»/«Съёмки», «Блог» с 3–5 статьями, «Контакты», 404, `robots.txt`, `sitemap.xml`, `favicon.svg`/`.ico`, CSS;
   - 4 темы: IT-студия, фотостудия, бюро переводов, кофейня. Тема выбирается от домена, или флагом `--site-theme`;
   - название, город, палитра, шрифт, раскладка, набор услуг и статей, даты и `Last-Modified` рандомизируются от домена и сида, поэтому ноды не похожи друг на друга;
   - нет форм, нет сбора данных, нет упоминаний VPN/прокси. Генератор сам проверяет страницы на «палевные» слова и не публикует сайт, если что-то нашёл.
5. Пишет `/etc/nginx/conf.d/gorecshit-site.conf`:
   - TLS 1.2/1.3, X25519, h2, HSTS, `server_tokens off`, без access-логов;
   - `:80` → ACME + 301 на `https://домен`.

   Декой :80 из v2.6.0 и стандартный «Welcome to nginx» заменяются (с бэкапом).
6. Автопродление: `certbot.timer` (или cron) плюс deploy-hook `reload nginx`.
7. Печатает **точные значения для панели**. Сам скрипт панель и инбаунды **не меняет**.

**Значения для панели Remnawave** (Config Profiles → inbound VLESS REALITY на 443 → `realitySettings`):

```json
"target": "127.0.0.1:9443",
"serverNames": ["cdn.example.ru"],
"xver": 0
```

- В старых xray поле называется `dest`.
- С `--site-proxy-protocol` нужно `"xver": 1`.
- `privateKey` и `shortIds` не меняются.
- В **Hosts** поле SNI = `cdn.example.ru`.
- Плавный переход: добавьте новый домен в `serverNames` рядом со старыми, смените SNI в Hosts, через сутки уберите старые.
- remnanode по умолчанию работает в `network_mode: host`, поэтому `127.0.0.1` в контейнере — это хост. Если compose не в host-сети, скрипт слушает на IP `docker0` и открывает UFW для `172.16.0.0/12` → порт.

Флаги:
- `--site-theme it|photo|translate|coffee|auto`
- `--site-mode auto|selfsteal|public`
- `--site-port 9443`
- `--site-listen IP`
- `--site-proxy-protocol`
- `--site-close-80`
- `--site-seed S` — сгенерировать другой сайт
- `--site-skip-dns-check`

С `--panel-ip` модуль входит в полную установку (`--modules …,site` / меню 2 → 13).

Аудит (меню 8) проверяет:
- сертификат (ошибка, если истёк; предупреждение, если до конца < 14 дней);
- автопродление;
- DNS → IP;
- сайт через локальный порт (HTTP 200 и заголовки);
- **все страницы из sitemap + robots + sitemap + 404**: ищет слова vpn/proxy/прокси/впн/xray/v2ray/vless/reality/remnawave/gorec/обход/tunnel в тексте, title, meta и HTML-комментариях;
- что снаружи `IP:443` с SNI домена отдаёт **ваш** сертификат, то есть панель уже переключена.

Откат: `gorecshit --rollback`. Удаляет конфиг, сайт и выпущенный этим запуском сертификат, правила UFW 80/443, хуки. Декой и дефолтный сайт nginx возвращаются.

## Скрытие отпечатков сервера

Опциональный модуль (меню «9» / `--stealth`), также вызывается из stealth при полной установке. **Не снижает скорость**, не трогает IPv6, клиентские порты firewall, Docker compose и настройки панели. Рискованные шаги (hostname, stop сервисов) спрашивают через `/dev/tty` (по умолчанию нет). Бэкап + откат через `--rollback`.

- SSH: `Banner none`, `DebianBanner no`, очистка issue.net/motd, отключение update-motd news/ads
- Hostname: если похож на vpn/node/xray/… или vm-/vps-/ubuntu-/ip-* — предложение `web-<random>` (спросит)
- TCP/IP: `ip_default_ttl=64`, ICMP timestamp/address-mask DROP, ignore broadcasts, `send_redirects=0` (**без** `tcp_timestamps=0`)
- Закрытые TCP: DROP без RST при активном UFW (не меняет allow клиентских портов)
- Сервисы rpcbind/avahi/cups/snmpd/exim/postfix — stop+mask только после подтверждения
- Docker 2375/2376 и publish — только отчёт
- nginx `server_tokens off` / Apache `ServerTokens Prod`
- `--audit` показывает эти маркеры

```bash
sudo gorecshit --stealth
```

## Changelog

### v2.7.2
- Сайт-маскировка: проверка сгенерированного сайта перед публикацией тоже не учитывает домен ноды (e-mail на «О нас»/«Контактах», robots.txt) — установка на домен со словами gorec/vpn больше не обрывается.

### v2.7.1
- Сайт-маскировка: слова в домене ноды (vpn, gorec и т.п.) больше не блокируют установку — только предупреждение. Домен выбирает владелец (например, отдельный домен для нод).
- Аудит: проверка слов на страницах сайта не учитывает сам домен ноды (e-mail, ссылки, sitemap), иначе срабатывала бы ложно.

### v2.7.0

- Новый модуль **«Сайт-маскировка»** (меню 10, `--site-domain D [--site-email E]`, `--modules …,site`, меню 2 → 13):
  - поддомен ноды + Let's Encrypt (certbot webroot, HTTP-01 через :80, автопродление + reload nginx, опционально `--site-close-80` с временным открытием 80 при продлении);
  - многостраничный сайт из 4 тем с рандомизацией от домена;
  - nginx для REALITY **self-steal** (`target 127.0.0.1:9443`, `serverNames=[домен]`, опционально PROXY protocol / `xver 1`) или public 443, если он свободен.
- Проверки перед установкой:
  - DNS A/AAAA → IP ноды через DoH, детект оранжевого облака Cloudflare;
  - запрет «палевных» слов в домене;
  - порты 80 и 9443 не заняты чужими процессами;
  - remnanode в host-сети (иначе слушаем на docker0).
- Скрипт печатает точные значения для инбаунда в панели; панель не трогает.
- Бэкап и откат через `--rollback`. Декой :80 v2.6.0 при установке сайта заменяется, а без сайта работает как раньше.
- `--audit` / меню 8, новый раздел «Сайт-маскировка»:
  - сертификат (< 14 дней) и автопродление;
  - DNS;
  - отдача через локальный порт;
  - фильтр слов (vpn, proxy, прокси, впн, xray, v2ray, vless, reality, remnawave, gorec, обход, tunnel) по всем страницам, sitemap, robots, 404, title, meta и комментариям;
  - внешний `IP:443` с SNI домена отдаёт наш сертификат;
  - напоминание сверить `serverNames`.
- `--status` показывает домен, режим и порт сайта.

### v2.6.0

- Цель: снаружи не должно быть видно, что на сервере нода. Добавлена карта способов детекта: [docs/detection-vectors.md](docs/detection-vectors.md)
- `--audit` / меню 8: **Shodan InternetDB** (v4+v6), **внешняя поверхность** (все слушатели TCP/UDP v4+v6 с учётом UFW/Docker, паритет IPv6, NODE_PORT снаружи через check-host), **активный зонд REALITY** без ключа против настоящего `dest` (5 проб), версия xray (≥ 25.6.8), мелкие признаки (SSH-баннер, PTR, motd/issue, Server-заголовки, MTU/TCPMSS, egress)
- Новый модуль **egress_guard** (по умолчанию вкл.; `--no-egress-guard`, `--egress-block-ports`): исходящий SMTP 25 → REJECT (хост + Docker, v4+v6); при hide_ports — DROP исходящих ICMP port/proto-unreachable и time-exceeded (PMTU не трогаем); systemd-unit + откат
- UFW: `IPV6=yes` принудительно при включённом IPv6; ping6 (echo-request) DROP в before6.rules; удаление публичных `ALLOW Anywhere` для NODE_PORT (не трогает семейство, где есть живое не-панельное соединение); DOCKER-USER закрывает NODE_PORT и по IPv6
- Опциональный модуль **decoy_web** (`--decoy-web` или вопрос y/N, по умолчанию нет): `:80 → 301 https` через уже установленный nginx, только если безопасно
- `--stealth`: /etc/motd очищается и при VPN-словах (xray/remna/vless/…)
- Меню 3 без установленной защиты: вместо ошибки предлагает запустить полную установку (y/N)
- `--modules`: `egress_guard`, `decoy_web`; меню 2: пункты 11/12

### v2.5.0

- Перед установкой пакетов: фаза **«Обновление системы»** — пауза `apt-daily.timer` / `apt-daily-upgrade.timer` (+ сервисы), `systemctl stop unattended-upgrades` (ждёт окончания текущей установки, без kill `dpkg`), затем `dpkg --configure -a`, `apt-get update`, `full-upgrade` с `--force-confdef/--force-confold`; опционально `autoremove`; если есть `/var/run/reboot-required` — предупреждение, **без** авто-reboot
- Таймеры apt и `unattended-upgrades` возвращаются в конце прогона и через `trap EXIT`
- Исправлен ложный busy-wait до 600с: `pgrep -x unattended-upgr` совпадал с постоянно висящим `unattended-upgrade-shutdown` (оба truncates до 15 символов); ожидание смотрит на держателей lock-файлов (`fuser`/`lsof`/`flock`) и реальный job `/usr/bin/unattended-upgrade`
- Флаг `--no-upgrade` и env `GORECSHIT_NO_UPGRADE=1` — пропустить full-upgrade (таймеры всё равно ставятся на паузу на время установки пакетов)

### v2.4.0


- Меню «9» / `--stealth`: скрытие отпечатков сервера (SSH/MOTD, TTL/ICMP FP, UFW DROP для закрытых портов, опциональный hostname и mask сервисов с подтверждением, отчёт Docker, server_tokens); бэкап+rollback; без потери скорости и без правок панели/IPv6/клиентских портов
- `--audit` дополнен проверками fingerprint-маркеров

### v2.3.1

- `--audit`: устойчивый поиск конфига xray (docker image `remnawave/node`, имя контейнера, `/proc/.../cmdline -config`, xray API, find json); если файла нет (stdin/runtime от панели) — пассивный REALITY/TLS-зонд по клиентским портам (CN/SAN, TLS1.3, h2)
- ICMP: приоритет у результата check-host ping (0/N → ✅ скрыт); локальные iptables/nft/ufw/sysctl — только fallback
- UFW inactive: явное «защита gorecshit не установлена/выключена»

### v2.3.0

- Меню «8» / `--audit`: проверка доступности IP:PORT из РФ через check-host.net (RU + зарубежные узлы, ping) и self-audit палевности xray/REALITY + серверных маркеров (ICMP, лишние порты, SSH/22, UFW)
- Только чтение: без правок firewall/sysctl/docker; общий лимит внешней проверки ~60с; `curl` обязателен, jq/python3 опциональны
- Версия **2.3.0**; `install.sh` и `gorecshit.sh` — идентичные полные файлы

### v2.2.9

- `--update` / меню «7»: SHA tip `main` через `api.github.com/.../commits/main` (без jq) → `raw/<sha>/install.sh`, затем jsDelivr `@<sha>`, затем `raw/main?t=…` cache-buster; сравнение версий `Уже последняя версия` / `X → Y`; после обновления re-exec меню
- Статус-строка меню: порты через тот же фильтр, что install (без `ip_local_port_range` / служебных) — не показывает эфемерные TCP вроде 33934…
- Флаг `--version` / `-V`

### v2.2.8


- Перед `apt-get`: ожидание dpkg/apt lock до 600с (сообщение каждые 15с), `DPkg::Lock::Timeout=600`, до 3 попыток — фикс падений на свежей Ubuntu 24.04 из‑за `unattended-upgrades`
- Подсказка отката: `gorecshit --rollback` (не `/dev/fd/63 --rollback` при `bash <(curl)`)

### v2.2.7

- Вопрос «Перезапустить Docker?» всегда через `/dev/tty` после установки из меню (п.1/2), даже если меню выставило `ASSUME_YES`; пропуск только при CLI `--yes` без TTY или `--no-docker-restart`

### v2.2.6

- Auto-detect клиентских портов: сначала xray **inbounds** (docker exec / config.json); ss-fallback **исключает** `ip_local_port_range` (эфемерные UDP UNCONN rw-core); не берёт 2222/3000/53
- Интерактив через `/dev/tty`: меню и вопросы (в т.ч. перезапуск Docker) работают при `bash <(curl …)` и `curl | bash`

### v2.2.5

- После изменения `daemon.json`: валидация JSON (`python3 -m json.tool` / `jq`, опционально `dockerd --validate`), откат из бэкапа при ошибке
- Применение: интерактивный вопрос «Перезапустить Docker сейчас? Нода отключится на ~10-30 сек [y/N]»; с `--yes` без TTY — **не** рестартит, пока нет `--docker-restart`; флаг `--no-docker-restart` всегда пропускает
- После restart: ожидание до ~60с remnanode + xray listen, переприменение UFW / anti-probe / DOCKER-USER

### v2.2.4

- Установка команды `gorecshit` работает при `bash <(curl …)` и `curl | bash`: если `BASH_SOURCE` не обычный файл на диске (`/dev/fd/*`/pipe) — скачиваем полный `install.sh` (GitHub → jsDelivr), `bash -n`, ставим `/usr/local/sbin/gorecshit` + symlink (seekable fd копируем, pipe не читаем повторно)

### v2.2.3

- `gorecshit.sh` больше **не symlink**, а полный скрипт (как `install.sh`) — `curl …/gorecshit.sh` больше не скачивает строку `install.sh`
- Установка команды `gorecshit` на каждый root-запуск: `/usr/local/sbin/gorecshit` (полное содержимое) + `/usr/local/bin/gorecshit`; сообщение `[ OK ] Команда gorecshit установлена`
- `--update` качает полный скрипт (`install.sh` / `gorecshit.sh`, GitHub + jsDelivr)

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
bash <(curl -fsSL https://raw.githubusercontent.com/gorecvpn/gorecshit/main/install.sh) --panel-ip X.X.X.X --yes
# или то же через gorecshit.sh (полный файл, не symlink):
# bash <(curl -fsSL https://raw.githubusercontent.com/gorecvpn/gorecshit/main/gorecshit.sh) --panel-ip X.X.X.X --yes
```

После первого запуска (или просто `bash install.sh --status`) на сервере доступна команда:

```bash
gorecshit              # меню
gorecshit --status
gorecshit --update     # обновить скрипт с GitHub / jsDelivr
```

Интерактивно (меню на русском, спросит IP панели):

```bash
curl -fsSL https://raw.githubusercontent.com/gorecvpn/gorecshit/main/gorecshit.sh -o /root/gorecshit.sh
bash /root/gorecshit.sh
# дальше на сервере: gorecshit
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
| `--modules LIST` | `ufw,blocklist,hide_ports,anti_probe,ssh,stealth,fail2ban,sysctl,hostname,docker,egress_guard,decoy_web,site` или `all`/`minimum` (`decoy_web` и `site` не входят в `all`). |
| `--no-hide-ports` / `--no-anti-probe` / `--no-stealth` | Отключить соответствующие модули. |
| `--no-egress-guard` | Не блокировать исходящий SMTP (по умолчанию блокируется TCP 25). |
| `--egress-block-ports LIST` | Какие исходящие TCP-порты блокировать (по умолчанию `25`; например `25,465,587`). |
| `--decoy-web` | Декой `:80 → 301 https` через существующий nginx (только если безопасно). |
| `--site-domain D` | Сайт-маскировка: поддомен + Let's Encrypt + сайт для REALITY self-steal. Без `--panel-ip` запускает только этот модуль. |
| `--site-email E` / `--site-theme T` / `--site-mode M` / `--site-port N` / `--site-listen IP` | Почта для LE; тема `it\|photo\|translate\|coffee\|auto`; режим `auto\|selfsteal\|public`; локальный порт (9443); адрес (127.0.0.1). |
| `--site-proxy-protocol` / `--site-close-80` / `--site-seed S` / `--site-skip-dns-check` | PROXY protocol (`xver 1`); закрыть 80 после выпуска; другой сайт; без проверки DNS. |
| `--tcp-timestamps-off` | `net.ipv4.tcp_timestamps=0`. |
| `--ipv6-off` | Опционально отключить IPv6 (по умолчанию IPv6 **остаётся**). |
| `--no-ipv6-off` / `--no-blocklist` / `--no-hostname` / … | Как в v2.0 (`--no-ipv6-off` = поведение по умолчанию). |
| `--yes` | Без подтверждения / без меню. |
| `--dry-run` / `--check` | Только план. |
| `--refresh-lists` | Только обновить ipset-списки. |
| `--status` | Показать статус. |
| `--dpi-check` | DNS/TLS/SNI/TCP16 egress-проверка с ноды. |
| `--audit` | Доступность из РФ (check-host) + Shodan InternetDB + порты v4/v6 + активный зонд REALITY + мелкие признаки (read-only). |
| `--stealth` | Скрыть отпечатки сервера (баннеры/MOTD/ICMP FP/…); спросит перед рискованным. |
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
- Для `--audit`: `curl` (+ желательно `python3`/`openssl`); check-host.net должен быть доступен с ноды

## Лицензия

MIT — см. [LICENSE](LICENSE).
