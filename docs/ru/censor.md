# Цензор

[English](../en/censor.md) · [Документация](../README.md)

`wl-censor` — модель цензора. В лаборатории это маршрутизатор провода; отдельно он разбирает файлы захвата. Каждое правило ссылается на статью или отчёт, который воспроизводит; то, чего источники не решают, вынесено в именованную [гипотезу](#гипотезы), которую можно переключить, так что результат всегда говорит, на каком допущении стоит.

## Как работает

В контейнере провода ядро не маршрутизирует (`ip_forward=0`). `wl-censor` читает каждый кадр с обоих интерфейсов через пакетные сокеты (AF_PACKET), судит его по активному пресету и отправляет на другую сторону — или отбрасывает, переписывает в RST, отвечает за сервер. netem на исходящих интерфейсах действует под ним. Пресет — `censor-preset.json` в папке сессии, перечитывается при изменении; без файла трафик идёт нетронутым. Решения пишутся в `censor.jsonl`.

### Распознавание протоколов

Правилам нужно знать, что за поток. Это даёт классификатор:

| | |
|---|---|
| **nDPI** | [nDPI](https://github.com/ntop/nDPI) 5.0, вшитый в цензор лаборатории командой `wirelab censor build`. Распознаёт TLS, QUIC (расшифровывая Initial ради SNI), SSH, RDP, WireGuard, OpenVPN, DNS, DTLS, HTTP и считает JA4. |
| **встроенный** | Только по первым байтам: его даёт обычный `go build` и использует `-replay` на Windows. Без SNI из QUIC и без JA4. |

Первая строка журнала цензора называет классификатор и правила, которые он не может обслужить, так что правило никогда молча не «не срабатывает».

nDPI закреплён на 5.0: с 6.0 его диссекторы TLS, QUIC и DNS под двойной лицензией ntop, которая для коммерческого использования требует договора. 5.0 целиком под LGPL-3.0.

## Сборка

```bash
wirelab censor build
```

собирает `containers/censor-build/Dockerfile`: nDPI 5.0 из исходников, тесты цензора (включая nDPI на его собственных тестовых записях: Initial QUIC расшифрованы, туннели распознаны) и статический бинарник в `containers/wire/bin/wl-censor`. Лаборатория подхватывает его при старте.

## Проверка записи

```bash
cd wirelab-censor && go build -o ../target/wl-censor . && cd ..
./target/wl-censor -replay session.pcap -preset containers/censor/presets/ru-tspu.json \
    -client-net 192.168.1.0/24 -server-net 203.0.113.7/32
```

Читает pcap и pcapng; по каждому правилу перечисляет потоки, которые оно заблокировало бы, и на каком пакете. Правила, написанные под адреса лаборатории, переносятся на переданные сети. В такой сборке встроенный классификатор.

## Пресеты

В `containers/censor/presets/`. В комплекте:

- **Russia (TSPU)**, `ru-tspu.json`, на 2026-10;
- **Russia, mobile whitelist mode**, `ru-mobile-whitelist.json`.

Списки доменов и адресов в них — примеры: настоящие реестры не публичны.

### Russia (TSPU)

| Правило | Поведение | Источник |
|---|---|---|
| `ru-sni-rst` | SNI из списка: пакеты сервер→клиент превращаются в RST/ACK на 75 с | Xue et al., IMC 2022 (SNI-I) |
| `ru-sni-drop-after` | SNI из списка: ещё 5 пакетов, затем обе стороны режутся на 420 с | IMC 2022 (SNI-II) |
| `ru-sni-drop-all` | SNI из списка: всё режется на 40 с, включая ClientHello (выкл.) | IMC 2022 (SNI-IV) |
| `ru-quic-sni` | Initial QUIC v1 с SNI из списка, любой UDP-порт: поток режется на 420 с, каждый новый Initial продлевает; v2 не читается | Heitmann et al., FOCI 2026 (net4people #654) |
| `ru-quic-v1` | QUIC v1 на UDP 443 от 1001 байта (2022, заменено; выкл.) | IMC 2022 |
| `ru-ip` | Адреса серверов из блок-листа режутся | IMC 2022; массовые баны в #671 |
| `ru-wireguard` | WireGuard обрывается после рукопожатия и двух пакетов данных | net4people #274 |
| `ru-openvpn` | OpenVPN обрывается после рукопожатия и 15 пакетов данных | net4people #274 |
| `ru-freeze` | Серверы в зарубежных ДЦ: пакеты от сервера перестают приходить примерно после 25 пакетов (14–34 КБ); SSH не трогается; белый SNI спасает поток только на адресах этого домена; по UDP блокируется весь сервер на 10 минут | net4people #490 |
| `ru-encapsulated-tls` | Полностью зашифрованный протокол с TLS внутри: 3+ пакета клиента от 411 байт, при этом сервер шлёт чаще; порт 443 | net4people #363 |
| `ru-tls-rate` | Около 12 TLS-соединений с SNI к одному серверу за короткое время: новые ClientHello с тем же JA4 режутся на 120 с | Habr 1010336 через net4people #603; #546 |
| `ru-dns-udp` | UDP DNS для заблокированных имён получает NXDOMAIN; DNS по TCP не трогается | net4people #657 |
| `ru-ssh-police` | SSH урезается примерно до 2 КБ/с после 10–20 КБ (некоторые мобильные регионы; выкл.) | net4people #490 |

Не моделируется (с причиной в заметках пресета): блокировка DTLS по отпечатку (#603: значение не опубликовано), обнаружение TUN (#663: не подтверждено).

### Режим белых списков

`ru-wl`: серверы вне разрешённых сетей получают TCP-рукопожатие и ничего после него; UDP и ICMP к ним режутся; разрешённый SNI действует только на разрешённых адресах (#516, #650). Сервер лаборатории вне списка; добавьте `10.77.2.0/24`, чтобы смоделировать сервер в разрешённом российском облаке.

### Гипотезы

| Гипотеза | Правила | По умолчанию |
|---|---|---|
| `tcp-reassembly`: ТСПУ читает ClientHello, разбитый на TCP-сегменты | правила SNI | вкл. |
| `sni-tied-to-cidr`: белый SNI действует только на своих адресах | `ru-freeze` | вкл. |
| `freeze-counts-bytes`: заморозка считает байты от сервера, а не пакеты | `ru-freeze` | выкл. |
| `rdp-exempt`: RDP не трогается, как SSH | `ru-freeze` | выкл. |
| `tls-rate-by-fingerprint`: лимит TLS считается по JA4 | `ru-tls-rate` | вкл. |

Панель показывает каждую вместе с наблюдением, из которого она взялась.

## Формат пресета

```json
{
  "name": "Russia (TSPU)",
  "as_of": "2026-10",
  "notes": "Что моделируется, что нет и почему.",
  "hypotheses": [
    { "id": "…", "label": "…", "field": "<поле правила>", "rules": ["<id правила>"], "default": true, "note": "…" }
  ],
  "rules": [
    { "id": "…", "name": "…", "kind": "…", "action": "…", "source": "… https://…", "disabled": false }
  ]
}
```

Правило без `source` не загрузится, как и правило без того, что нужно его виду: правило, которое никогда не срабатывает, читалось бы как «цензор пропустил». Гипотеза записывает выбранное значение в `field` перечисленных правил.

| `kind` | `action` | Поля |
|---|---|---|
| `sni` | `rst_s2c`, `drop_both`, `drop_s2c` | `domains`, `drop_trigger`, `after_packets`, `block_seconds`, `reassemble_hello` |
| `quic_sni` | `drop_both` | `domains`, `quic_versions`, `block_seconds`, `restart_on_trigger` |
| `quic_v1` | `drop_both` | `port`, `min_payload`, `block_seconds` |
| `ip` | `drop_both` | `cidrs` |
| `freeze` | `drop_s2c`, `drop_both` | `cidrs`, `after_packets`, `count_bytes`, `max_s2c_bytes`, `exempt_protocols`, `exempt_rdp`, `allow_sni`, `sni_cidrs`, `sni_tied_to_cidr`, `udp_host_seconds` |
| `wireguard`, `openvpn` | `drop_both` | `max_data_packets` |
| `encapsulated_tls` | `drop_both`, `drop_s2c` | `min_client_packets`, `min_client_size`, `within_packets`, `only_unknown`, `ports`, `cidrs` |
| `tls_rate` | `drop_both` | `max_conns`, `window_seconds`, `block_seconds`, `by_fingerprint`, `ports`, `cidrs` |
| `dns_udp` | `nxdomain` | `domains` |
| `police` | `police` | `protocols`, `after_bytes`, `rate_kbit`, `cidrs` |
| `whitelist` | `drop_payload` | `cidrs` (разрешённые), `allow_sni`, `sni_cidrs`, `sni_tied_to_cidr` |

`domains` совпадают с именем и его поддоменами; пустые `ports` и `cidrs` совпадают со всем; `protocols` и `exempt_protocols` используют имена nDPI (`TLS`, `QUIC`, `SSH`, `RDP`, `WireGuard`, `OpenVPN`, `DNS`, `DTLS`, `HTTP`, `Unknown`).

## Как дополнять пресеты

Если источники не решают, как ведёт себя цензор, добавьте гипотезу, а не выбирайте ответ молча. Цитируйте наблюдение в `source` со ссылкой и датой; собственные решения (окно, порог, который источники оставляют размытым) так и называйте.
