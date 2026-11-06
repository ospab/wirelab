# Симулятор

[English](../en/simulator.md) · [Документация](../README.md)

`wirelab run` помещает обе стороны протокола в один процесс поверх симулированного канала, детерминированно от сида. Подходит протоколам с sans-io ядром; для остального есть лаборатория. Пока есть один адаптер, OSTP: он гоняет настоящий `ostp-core`.

```bash
wirelab protocols                                   # адаптеры в этой сборке
wirelab run scenarios/ostp-lossy.toml [--seed 7] [--pace auto|virtual|realtime] [--out папка]
```

Результат, по умолчанию в `runs/<сценарий>-<сид>/`: `records.jsonl` (каждое событие), `wire.pcapng` (датаграммы, как их нёс канал), `report.json` и `report.txt` (по направлениям: размеры, энтропия, интервалы, сбои канала и дошла ли каждая передача целой). Код выхода 1, если передача не удалась.

## Сценарий

```toml
name = "ostp-lossy"
description = "Канал как у мобильной сети."
seed = 1
duration_ms = 10000
tick_ms = 5
sample_ms = 100
pace = "auto"          # realtime, если сторона читает часы ОС, иначе virtual

[protocol]
name = "ostp"          # остальные ключи — адаптера

[wire]                 # обе стороны, если [wire_c2s] / [wire_s2c] не заменяют
latency_ms = 40.0      # в одну сторону
jitter_ms = 10.0       # ± равномерно, без переупорядочивания
reorder = 0.0          # вероятность лишних 0..reorder_delay_ms
reorder_delay_ms = 0.0
loss = 0.02
duplicate = 0.005
corrupt = 0.0          # один перевёрнутый бит
bandwidth_kbps = 10000.0
queue_ms = 200.0       # очередь узкого места, как время на её опустошение
mtu = 0
impair_from_ms = 500.0 # потери, дубли и порча начинаются отсюда

[[transfer]]
from = "server"        # или "client"
stream = 1
bytes = 4000000
chunk = 1024
start_ms = 0
```

В `scenarios/` — примеры чистого канала, потерь, переупорядочивания и порчи; в `docs/reports/` — что они показали про `ostp-core`.
