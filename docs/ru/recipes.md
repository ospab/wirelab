# Рецепты

[English](../en/recipes.md) · [Документация](../README.md)

Рецепт настраивает протокол на обоих узлах без ручного ввода: скачивает релиз (или берёт локальную сборку), пишет конфиги из своих параметров, запускает обе стороны и оставляет прокси клиента готовым.

```bash
wirelab recipes                                   # список с параметрами
wirelab lab up --recipe xray-reality
wirelab lab up --recipe ostp --set transport=tls --set version=v0.4.7-beta.14
wirelab lab up --recipe ostp --set src=D:/builds/ostp   # локальная сборка под Linux вместо релиза
```

## Готовые

| Рецепт | Что | Со стороны клиента | Параметры |
|---|---|---|---|
| `ostp` | [OSTP](https://github.com/ospab/ostp) по UDP, UoT или TLS (самоподписанный сертификат) | SOCKS5/HTTP на `127.0.0.1:1088` | `version`, `transport` (`udp`, `uot`, `tls`), `src`, `key`, `log_level` |
| `xray-reality` | VLESS + XTLS-Vision поверх REALITY ([Xray-core](https://github.com/XTLS/Xray-core)); заимствуемый сайт — nginx с TLS 1.3 на сервере | SOCKS5 на `127.0.0.1:1080` | `version`, `src`, `sni`, `id`, `short_id`, `flow`, `fingerprint` |
| `shadowsocks` | [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust), TCP и UDP | SOCKS5 на `127.0.0.1:1080` | `version`, `src`, `method`, `key` |
| `wireguard` | WireGuard из ядра; `wg` из пакетов Alpine | нет: сеть цели маршрутизируется в `wg0` | `keepalive`, `mtu` |

Релизы кэшируются в `cache/dl/` в checkout, так что матрица лабораторий скачивает каждый один раз. `xray-reality` и `wireguard` при старте ставят пару пакетов из Alpine (openssl; wireguard-tools и iptables), поэтому их контейнерам один раз нужен интернет.

## Свой рецепт

Рецепт — папка `recipes/<имя>/`:

```
recipes/<имя>/
  recipe.toml   что это, параметры, что скачать
  client.sh     становится /lab/setup.sh клиента
  server.sh     становится /lab/setup.sh сервера
```

`recipe.toml`:

```toml
name = "example"                     # совпадает с именем папки
about = "Одна строка для `wirelab recipes`"
base = "alpine"                      # образ, нужный бинарникам (lab up --base важнее)
proxy = "socks5h://127.0.0.1:1080"   # что нагрузки передают curl в -x; не указывать, если туннель маршрутизирует
server_process = "example-server"    # для замера памяти в прогонах
client_process = "example-client"
version_param = "version"            # какой параметр отчёты считают версией

[params]
version = "v1.2.3"
src = "https://example.org/releases/${version}/example-linux-amd64.tar.gz"
key = "@random-hex-16"               # 16 случайных байт в hex, одинаковые на обоих узлах

[[fetch]]
url = "${src}"                       # http(s) или локальный путь; пусто — нечего скачивать
save_as = "example.tar.gz"           # имя в /lab/dl/
nodes = ["client", "server"]         # по умолчанию оба
```

Значения параметров могут ссылаться на другие как `${имя}`. Задать параметр, которого у рецепта нет, — ошибка: опечатка не запустит молча значение по умолчанию.

Скрипты:

- читают параметры из `/lab/recipe.env` (`. /lab/recipe.env`): каждый как `WL_P_<ИМЯ>` в верхнем регистре, плюс `WL_RECIPE`; лаборатория добавляет `WL_SERVER_ADDR` и `WL_SERVER_PORT`;
- находят скачанное в `/lab/dl/`;
- обмениваются сгенерированным (публичные ключи, сертификаты) через `/shared`: пишут файл целиком и переименовывают, а на другой стороне ждут файл;
- запускают протокол в фоне (`nohup ... &`), пишут лог в `/lab/<что-то>.log` и **завершаются**. Лаборатория ждёт, пока оба скрипта выйдут с кодом 0; прогон копирует все `/lab/*.log` в папку клетки.

`setup.sh`, написанный рецептом, начинается со строки-метки; `lab up --recipe` не заменит `setup.sh` без неё без `--force`. Копия рецепта с итоговыми параметрами попадает в папку сессии, а значит и в архив сессии.
