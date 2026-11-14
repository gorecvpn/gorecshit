# Как вычисляют, что на IP стоит VPN-нода — и что с этим делает gorecshit

Карта собрана в ноябре 2026 по открытым источникам: net4people/bbs, XTLS/Xray-core, GFW Report / USENIX, Хабр, ntc.party, bol-van/zapret, документация Remnawave. Для каждого способа указано:

- **как работает**;
- **источник**;
- **gorecshit** (v2.7.0):
  - 🛡 — закрывает на сервере (меню 1 / 9 / 10);
  - 🔍 — проверяет в аудите (меню 8 / `--audit`);
  - 👤 — сервер это не закрывает: нужна панель, конфиг xray, хостер или клиент. Рядом стоит конкретная рекомендация.

> Главное правило: ни одна мера gorecshit не трогает REALITY-ключи, inbounds, конфиг-профили панели и Docker на живой ноде. Всё серверное идёт с бэкапом и откатывается через `gorecshit --rollback`.

---

## A. Активное зондирование (к ноде подключаются «как клиент» и смотрят на ответ)

| # | Способ | Как работает | Источник | gorecshit |
|---|---|---|---|---|
| A1 | Ответ без ключа ≠ настоящий сайт | Цензор или сканер подключается к порту без REALITY-авторизации. Правильная нода прозрачно проксирует соединение на `dest`, и зонд видит настоящий сайт. Если в ответ приходит что-то своё (самоподписанный сертификат, обрыв, другой HTTP-код), это и есть признак ноды | [XTLS REALITY](https://xtls.github.io/en/config/transports/reality.html), [Censys «Hey, that's not my server»](https://censys.com/blog/hey-thats-not-my-server/) | 🔍 Активный зонд: TLS с настоящим SNI, HTTPS GET, обычный HTTP на TLS-порт, случайный SNI, только TLS 1.2. Ответы ноды и настоящего `dest` сравниваются побайтно по сертификату, ALPN, HTTP-коду и `Server` **v2.7.0:** 🛡 сайт-маскировка (меню 10): зонд без ключа получает **ваш** настоящий сайт с валидным Let's Encrypt на том же IP (self-steal, `target 127.0.0.1:9443`). 🔍 Аудит сверяет, что снаружи `IP:443` с SNI домена отдаёт именно этот сертификат |
| A2 | Сертификат, ALPN, JA3S/JA4S не совпадают с dest | ServerHello и сертификат сравнивают с тем, что отдаёт настоящий `dest` с того же SNI | [net4people #438](https://github.com/net4people/bbs/issues/438) | 🔍 Сравнивает SHA-256 сертификата, subject/issuer и ALPN. 👤 В панели: `dest` и `serverNames` должны принадлежать одному сайту с TLS1.3+h2 **v2.7.0:** при self-steal сертификат, ALPN (h2) и TLS 1.3/X25519 отдаёт тот же nginx, поэтому расхождения с `dest` нет по построению |
| A3 | Битые TLS 1.0–1.2 хендшейки | В Иране зонды слали ClientHello старых версий. При `minVersion 1.3` зонды прекращались | [net4people #441](https://github.com/net4people/bbs/issues/441) | 🔍 Зонд «только TLS 1.2» сравнивает поведение ноды и `dest` |
| A4 | Post-handshake / NewSessionTicket (Aparecium) | Старый REALITY отличался длинами записей после рукопожатия. Это исправлено в Xray **25.6.8** | [Xray-core #4778](https://github.com/XTLS/Xray-core/issues/4778), [v25.6.8](https://github.com/XTLS/Xray-core/releases/tag/v25.6.8) | 🔍 Проверяет версию xray в контейнере remnanode, предупреждает при < 25.6.8. 👤 Обновить образ `remnawave/node` в окно обслуживания |
| A5 | Replay + «пустые» TLS-записи | Настоящий ClientHello повторяют с валидной и невалидной авторизацией и смотрят, сколько no-op записей терпит каждая сторона. Go-стек и стек `dest` терпят по-разному | [net4people #576](https://github.com/net4people/bbs/issues/576) | 👤 На сервере это не закрыть. Держите xray свежим, `dest` выбирайте на похожем стеке (Go/nginx) |
| A6 | Sampling/MITM-попытки | В логах xray видны «sampling-style» атаки на REALITY | [net4people #526](https://github.com/net4people/bbs/issues/526) | 👤 Информационно. Значения не имеет, если A1–A4 в порядке |
| A7 | VLESS без UUID / битый HTTP | Шлют начало VLESS-запроса или кривой HTTP и смотрят на реакцию | [net4people #441](https://github.com/net4people/bbs/issues/441) | 🔍 Зонд обычного HTTP на TLS-порт: нода должна ответить как `dest` |
| A8 | Задержка ответа (timing) | Для зонда нода ходит к `dest` сама, поэтому ответ приходит с задержкой RTT нода→`dest`. Далёкий `dest` выдаёт ноду по таймингу | [XTLS discussion #1932](https://github.com/XTLS/Xray-core/discussions/1932), [RealiTLScanner](https://github.com/XTLS/RealiTLScanner) | 👤 Выберите `dest` в том же ДЦ или ASN, что и нода (поищите через RealiTLScanner по соседним IP) **v2.7.0:** 🛡 self-steal: `dest` на 127.0.0.1, лишнего RTT нода→`dest` нет |
| A9 | Массовое сканирование | Сканеры и цензор обходят IP-диапазоны хостеров | — | 🛡 ipset-блоклист сканеров (Shodan/Censys и др.), anti-probe hashlimit на NEW-соединения, DROP вместо RST |

## B. Пассивный DPI (смотрят на трафик, к ноде не подключаются)

| # | Способ | Как работает | Источник | gorecshit |
|---|---|---|---|---|
| B1 | TLS-in-TLS | Внутри TLS-туннеля видны размеры и тайминги вложенного TLS-рукопожатия | [USENIX Sec'24, Xue et al.](https://www.usenix.org/system/files/usenixsecurity24-xue-fingerprinting.pdf) | 🔍 Аудит ругается, если `flow` ≠ `xtls-rprx-vision`. 👤 В панели: VLESS+REALITY+Vision |
| B2 | «Полностью зашифрованный» трафик | Эвристики по энтропии и ASCII в первых байтах ловят SS/VMess | [USENIX Sec'23, GFW Report](https://gfw.report/publications/usenixsecurity23/en/) | 🔍 Аудит предупреждает об inbound'ах без REALITY/TLS. 👤 Переведите их на REALITY |
| B3 | Заморозка TCP после ~16–20 КБ к зарубежным хостерам | ТСПУ перестаёт пропускать пакеты (~25 пакетов, примерно 16 КБ) в одной TCP-сессии к «подозрительным» ASN. Работает без RST | [net4people #490](https://github.com/net4people/bbs/issues/490), [Хабр 985674](https://habr.com/ru/articles/985674/) | 🔍 `--dpi-check` (fat-probe) и доступность IP из РФ через check-host. 👤 Каскад: РФ-нода → зарубежная, или хостер вне «чёрных» ASN |
| B4 | SNI ↔ IP/ASN | В SNI стоит крупный сайт (ya.ru, microsoft.com), а IP принадлежит VPS в Европе, и соединение рвут. В Иране так же работает reverse-DNS-сопоставление | [Хабр 979128](https://habr.com/ru/articles/979128/), [net4people #441](https://github.com/net4people/bbs/issues/441) | 🔍 Аудит оценивает `dest`/SNI (крупный, зарубежный, не .ru). 👤 `dest` на том же ASN, что и нода, либо selfsteal со своим доменом **v2.7.0:** 🛡 сайт-маскировка: SNI = свой поддомен, A-запись которого указывает на этот же IP. SNI и IP согласованы, как у обычного сайта |
| B5 | Белые списки SNI/CIDR (РФ, 2025–2026) | В части регионов и мобильных сетей пропускается только разрешённое: подсети плюс SNI | [ntc.party](https://ntc.party/t/%D0%B1%D0%B5%D0%BB%D1%8B%D0%B5-%D1%81%D0%BF%D0%B8%D1%81%D0%BA%D0%B8/16717), [zapret #1967](https://github.com/bol-van/zapret/discussions/1967), [Атлас РКН](https://rkn.kitten.software/wiki/whitelists/) | 👤 С сервера не решается: нужен relay с IP из белого списка (РФ-облако) и SNI из списка |
| B6 | Порт 443 под особым надзором | По наблюдениям 2025 года VLESS на 443 режут агрессивнее, чем на высоких портах | [Хабр 969618](https://habr.com/ru/articles/969618/) | 👤 Компромисс. 443 лучше против сканеров (A1, C1), высокий порт иногда лучше против ТСПУ. Аудит показывает, на каком порту REALITY |
| B7 | Объём, длинные сессии, много пользователей на один IP | 2 ТБ за сутки на одном IP, десятки клиентов на «сайт» — так поведенчески выглядит прокси | [net4people #441](https://github.com/net4people/bbs/issues/441) (2 ТБ → блок за 24 ч) | 👤 Распределяйте пользователей по нодам, ставьте лимиты в панели |
| B8 | Отпечаток клиента (JA3/JA4) | ClientHello клиента должен выглядеть как браузер | [Хабр 1104872](https://habr.com/ru/articles/1104872/) | 👤 В подписке: `fp=chrome` (uTLS) |
| B9 | Ограничение UDP/QUIC | Hysteria2/TUIC и QUIC на нестандартных портах душат | [Хабр 1104872](https://habr.com/ru/articles/1104872/) | 👤 Держите TCP-REALITY основным, UDP — запасным |

## C. Сканеры и репутация IP

| # | Способ | Как работает | Источник | gorecshit |
|---|---|---|---|---|
| C1 | Shodan/Censys/FOFA/ZoomEye | Публичные базы хранят открытые порты, сертификаты и теги (`vpn`, `proxy`, `self-signed`) по каждому IP. По ним ищут ноды | [Shodan InternetDB](https://internetdb.shodan.io/), [Censys](https://censys.com/blog/hey-thats-not-my-server/) | 🔍 Запрос к InternetDB по IPv4 и IPv6: порты, теги, CPE, CVE, hostnames, подсветка NODE_PORT и «палевных» портов. 🛡 UFW закрывает всё лишнее |
| C2 | Репутация ASN хостера, блок диапазонами | В РФ дросселируют или блокируют целые подсети Hetzner, OVH, DO, AWS и др. | [net4people #490](https://github.com/net4people/bbs/issues/490), [Атлас РКН](https://rkn.kitten.software/wiki/whitelists/) | 🔍 check-host: из РФ порт недоступен, а из-за рубежа доступен, значит, вероятна блокировка. 👤 Смена хостера или IP |
| C3 | IP уже «засвечен» | IP раньше использовался под VPN и остался в базах и блок-листах | — | 🔍 Теги Shodan и проверка из РФ. 👤 Новый IP |
| C4 | Abuse-жалобы хостеру | Спам через SMTP 25, торренты (DMCA), сканы с IP ноды: хостер видит «VPN» и блокирует | [Remnawave install (Torrent Blocker)](https://forestsnet.cloud/en/wiki/vpn/remnawave-install) | 🛡 **egress_guard**: исходящий TCP 25 → REJECT с хоста и из Docker, IPv4 и IPv6 (`--egress-block-ports 25,465,587` при желании). 🔍 Аудит проверяет, есть ли в xray routing `block bittorrent`. 👤 В панели: правило `protocol: bittorrent → blackhole` или плагин Torrent Blocker |

## D. Порты и сервисы

| # | Способ | Как работает | Источник | gorecshit |
|---|---|---|---|---|
| D1 | Открытый NODE_PORT | API ноды (по умолчанию 2222) отвечает всем, и это прямой признак Remnawave | [Remnawave docs](https://github.com/remnawave/panel/blob/main/docs/install/remnawave-node.md) | 🛡 UFW открывает NODE_PORT только IP панели. **v2.6.0:** удаляет старые публичные `ALLOW Anywhere` для NODE_PORT (v4 и v6), но не трогает семейство адресов, по которому к порту идёт живое соединение не с панели. DOCKER-USER закрывает и IPv6. 🔍 Проверка извне через check-host + Shodan + локальные слушатели |
| D2 | Дефолтные порты | 2222 (Remnawave), 62050/62051 (Marzban), 2053/2083/2087/2096 (xray/CF), 54321 (3x-ui), 10085 (xray API), 51820 (WG) | — | 🔍 Каждый такой порт подписан в аудите. 🛡 UFW DROP |
| D3 | Docker publish мимо UFW | `0.0.0.0:port` в compose обходит UFW | [Remnawave install](https://forestsnet.cloud/en/wiki/vpn/remnawave-install) | 🔍 Аудит. 🛡 DOCKER-USER для NODE_PORT. 👤 Привязка к `127.0.0.1` в compose |
| D4 | IPv6 оставлен открытым | Правила есть только для v4, по IPv6 видно всё | — | 🛡 **v2.6.0:** UFW `IPV6=yes`, DROP ping6 (echo-request; NDP и packet-too-big не трогаются), DOCKER-USER v6. 🔍 Аудит сравнивает v4 и v6 |
| D5 | Поведение закрытых портов | RST или ICMP unreachable отличают «живой» хост от фильтра | — | 🛡 hide_ports: DROP вместо RST. **v2.6.0:** исходящие ICMP port/proto-unreachable и time-exceeded режутся (PMTU frag-needed / packet-too-big не трогаются) |
| D6 | SSH на 22 с баннером дистрибутива | `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13` выдаёт ОС и версию | — | 🛡 `DebianBanner no`, `Banner none`, опция `--ssh-port`. 🔍 Аудит читает баннер так, как его видит интернет |
| D7 | Порт 80 закрыт при «сайте» на 443 | У настоящих HTTPS-сайтов на 80 обычно стоит редирект | — | 🛡 опционально `--decoy-web`: только если уже есть nginx, порт 80 свободен и REALITY на 443. Тогда 301 → https. Иначе только рекомендация (закрытый 80 тоже нормален) **v2.7.0:** 🛡 сайт-маскировка держит 80 сама: ACME + 301 на `https://домен`. Стандартный «Welcome to nginx» убирается. Опция `--site-close-80` |
| D8 | Панель или подписка на том же IP | Домен подписки указывает на IP ноды | [F3 Cloud guide](https://docs.f3cloud.com/en/vpn-guide/remnawave-installation) | 👤 Панель и подписка на отдельном сервере, лучше за CDN |

## E. Отпечаток TCP/IP-стека

| # | Способ | Как работает | Источник | gorecshit |
|---|---|---|---|---|
| E1 | TTL / окно / опции (nmap, p0f) | Нестандартный TTL или стек выделяет сервер | — | 🛡 `ip_default_ttl=64` (как у обычного Linux) |
| E2 | MSS/MTU (JA4T) | Туннели и clamp дают MSS ≠ 1460, а это классический признак VPN | [FoxIO JA4T](https://foxio.io/blog/ja4t-tcp-fingerprinting) | 🔍 MTU интерфейса и правила TCPMSS в mangle. 👤 Не ставить MSS-clamp на ноде без нужды |
| E3 | tcp_timestamps | Аптайм по timestamps. При этом отключённые timestamps сами по себе редкость | — | Оставляем по умолчанию (опция `--tcp-timestamps-off`) |
| E4 | ICMP echo/timestamp/mask | Ping и ICMP-отпечатки | — | 🛡 DROP echo (v4 и v6), DROP timestamp/address-mask (`--stealth`) |

## F. DNS и имена

| # | Способ | Как работает | Источник | gorecshit |
|---|---|---|---|---|
| F1 | PTR со словами vpn/node | `vpn-de-1.example.com` в обратном DNS | [net4people #441](https://github.com/net4people/bbs/issues/441) (reverse DNS mapping) | 🔍 Аудит. 👤 Сменить PTR в панели хостера на нейтральный |
| F2 | Hostname | Утекает в SMTP HELO, cloud-init, баннеры | — | 🛡 `web-<hex>` (меню 1) или предложение в меню 9 |
| F3 | Certificate Transparency (crt.sh) | Selfsteal-домен и поддомены `vpn.`/`sub.` видны всем | [crt.sh](https://crt.sh/) | 🔍 Подсказка при локальном `dest`. 👤 Нейтральные имена, wildcard-сертификат **v2.7.0:** 🛡 в домене сайта запрещены слова vpn/proxy/xray/… (скрипт откажет). Сертификат выпускается только на один нейтральный поддомен |
| F4 | Passive DNS | История A-записей связывает домены подписки и панели с IP ноды | — | 👤 Не направлять домены панели и подписки на ноду |
| F5 | DNS-утечки с ноды | Резолвер ноды или ISP видит запросы | — | 🔍 `--dpi-check` (system vs DoH). 👤 DoH в DNS-секции xray |

## G. Клиентская сторона и утечки конфигов

| # | Способ | Как работает | gorecshit |
|---|---|---|---|
| G1 | Сбор ссылок из «бесплатных VPN» каналов | Цензор парсит опубликованные подписки и вытаскивает IP | 👤 Не публиковать конфиги, лимит HWID в панели |
| G2 | Ping/MTU с устройства пользователя | Клиенты пингуют IP сервера | 🛡 ICMP скрыт (с клиентов ping тоже не пройдёт) |
| G3 | Реклама и утечки в приложениях | Сторонние клиенты отправляют адрес сервера в аналитику | 👤 Рекомендовать проверенные клиенты |

## H. Особенности xray

| # | Способ | Источник | gorecshit |
|---|---|---|---|
| H1 | Особенности Vision / gRPC / XHTTP | [net4people #438](https://github.com/net4people/bbs/issues/438) | 🔍 Аудит flow и транспорта. 👤 Свежий xray |
| H2 | Открытый API/metrics xray | — | 🔍 Слушатели (10085 и т.п.) |
| H3 | Пустые shortIds | — | 🔍 Аудит |

## I. Сайт-маскировка (v2.7.0, меню 10 / `--site-domain`)

| # | Способ | Как работает | gorecshit |
|---|---|---|---|
| I1 | Чужой `dest` и SNI на IP VPS | Зонд видит сертификат microsoft.com или apple.com на IP немецкого VPS. Это несоответствие само по себе подозрительно (см. A1, A2, B4) | 🛡 Свой поддомен, Let's Encrypt, nginx на 127.0.0.1:9443. REALITY отдаёт его чужим. 👤 В панели: `target`, `serverNames`, SNI в Hosts (скрипт печатает значения) |
| I2 | Пустой или шаблонный сайт | Голый «Welcome to nginx», одна страница или одинаковый шаблон на десятке нод ищется по хешу HTML в Censys | 🛡 Многостраничный сайт (главная, о нас, услуги, блог, контакты, 404, sitemap, robots, favicon). 4 темы; название, город, палитра, тексты и `Last-Modified` рандомизированы от домена |
| I3 | «Палевные» слова в контенте | Title, meta, комментарии или тексты с vpn/proxy/xray индексируются сканерами | 🛡 Генератор проверяет каждую страницу и не публикует сайт при совпадении. 🔍 Аудит обходит все страницы из sitemap, robots, sitemap и 404 через локальный порт (как REALITY) и ищет vpn, proxy, прокси, впн, xray, v2ray, vless, reality, remnawave, gorec, обход, tunnel |
| I4 | Просроченный сертификат | Сайт с истёкшим сертификатом выглядит заброшенным или фальшивым | 🛡 certbot.timer + reload nginx. 🔍 Аудит: ошибка, если истёк; предупреждение, если до конца < 14 дней |
| I5 | Оранжевое облако Cloudflare | SNI указывает на Cloudflare, а соединение идёт на VPS, и сертификат не выпускается | 🛡 Перед установкой DNS проверяется через DoH. Диапазоны Cloudflare распознаются, ошибка понятная |

---

## Что может сделать только владелец

1. **PTR** у хостера → нейтральный (например `mail.<ваш-домен>` или имя сайта).
2. **Панель → inbound REALITY** (или self-steal: `gorecshit --site-domain <поддомен>` и значения, которые он напечатает): порт 443, `flow=xtls-rprx-vision`, `dest` и `serverNames` с одного крупного сайта с TLS1.3+h2. Лучше всего на том же ASN/ДЦ, что нода (RealiTLScanner), плюс несколько `shortIds`.
3. **Панель → routing**: `protocol: bittorrent → blackhole` (или плагин Torrent Blocker).
4. **Образ remnanode/xray** ≥ 25.6.8 (обновлять в окно обслуживания, gorecshit Docker не перезапускает).
5. **Хостер/IP**: если check-host показывает «зарубежье видит, РФ — нет», меняйте IP или ставьте РФ-relay (каскад). Белые списки сервер не обойдёт.
6. **Не светить** домены панели и подписки на IP ноды. Не публиковать подписки.

## Как проверить

```bash
sudo gorecshit --update   # затем меню 1 (защита) и меню 8 (аудит)
sudo gorecshit --audit
```
