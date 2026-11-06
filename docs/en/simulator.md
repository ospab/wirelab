# Simulator

[Русский](../ru/simulator.md) · [Docs](../README.md)

`wirelab run` puts both ends of a protocol in one process over a simulated link, deterministic from a seed. It suits protocols with a sans-io core; the lab suits everything else. OSTP is the one adapter so far: it drives the real `ostp-core`.

```bash
wirelab protocols                                   # adapters in this build
wirelab run scenarios/ostp-lossy.toml [--seed 7] [--pace auto|virtual|realtime] [--out dir]
```

Output, in `runs/<scenario>-<seed>/` by default: `records.jsonl` (every event), `wire.pcapng` (the datagrams as the link carried them), `report.json` and `report.txt` (per direction: sizes, entropy, gaps, link faults, and whether every transfer arrived intact). The exit code is 1 when a transfer failed.

## Scenario

```toml
name = "ostp-lossy"
description = "Mobile-like path."
seed = 1
duration_ms = 10000
tick_ms = 5
sample_ms = 100
pace = "auto"          # realtime if an endpoint reads the OS clock, virtual otherwise

[protocol]
name = "ostp"          # every other key is the adapter's

[wire]                 # both directions, unless [wire_c2s] / [wire_s2c] replace it
latency_ms = 40.0      # one way
jitter_ms = 10.0       # ± uniform, never reordering
reorder = 0.0          # probability of an extra 0..reorder_delay_ms
reorder_delay_ms = 0.0
loss = 0.02
duplicate = 0.005
corrupt = 0.0          # one flipped bit
bandwidth_kbps = 10000.0
queue_ms = 200.0       # bottleneck queue, as time to drain
mtu = 0
impair_from_ms = 500.0 # loss, duplication, corruption start here

[[transfer]]
from = "server"        # or "client"
stream = 1
bytes = 4000000
chunk = 1024
start_ms = 0
```

`scenarios/` has clean, lossy, reordering and corrupting examples; `docs/reports/` has what they showed about `ostp-core`.
