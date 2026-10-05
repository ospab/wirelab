# wirelab

A sandbox for censorship-resistant transport protocols. Every run has three
zones: the client, the server, and the wire between them, which sees only
what an observer on the path would see: bytes, sizes, timing.

[Русская версия](README.ru.md)

Two modes:

- **in-process** (works now): both endpoints in one process, the link
  simulated between them. For protocols with a sans-io core (OSTP).
- **containers** (next): `client`, `wire` and `server` as three Alpine
  containers, the wire one a real router with `tc netem` and packet capture.
  For any protocol that ships a binary.

Results are `PASS`, `FAIL` or `NO DATA`. A check that could not measure
says so; it is never reported as a pass.

## Run

Needs Rust and a checkout of `ostp` next to this one (`../ostp`).

```
cargo build --release
./target/release/wirelab run scenarios/ostp-clean.toml
```

Each run writes `runs/<scenario>-<seed>/`:

| File | Contents |
|---|---|
| `records.jsonl` | one timeline across all three zones |
| `wire.pcapng` | the wire, openable in Wireshark (synthetic IPv4/UDP headers) |
| `report.json`, `report.txt` | checks, metrics, wire summary |

Scenario format: see `scenarios/`. Plans: [docs/ROADMAP.md](docs/ROADMAP.md).
