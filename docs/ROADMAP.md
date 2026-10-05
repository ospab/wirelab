# Roadmap

[Русский](ROADMAP.ru.md)

## Done: in-process mode

- `wirelab-core`: zones, simulated time, the adapter contract (`Endpoint`),
  the run recording, `PASS` / `FAIL` / `NO DATA` outcomes.
- `wirelab-wire`: link model (delay, order-preserving jitter, explicit
  reordering, loss, duplicates, bit flips, bandwidth with a queue, MTU), an
  observer that only gets bytes and time, pcapng export.
- `wirelab-sim`: discrete-event simulator, TOML scenarios, report.
- `wirelab-ostp`: adapter over the real `ostp-core::ProtocolMachine`, with
  the client's and server's production parameters.

OSTP limitation: the core reads `Instant::now()` itself, so its runs go in
real time and a seed reproduces the link's faults but not the timing.

## Next: containers

Three Alpine containers on two isolated networks, with no direct
`client ↔ server` route:

```
client ── net_c ── wire ── net_s ── server
```

- `wire`: `ip_forward`, `tc netem` on both interfaces (profile taken from the
  scenario's `[wire]`), `tcpdump` to pcapng. Censor models on NFQUEUE later.
- `client`, `server`: the protocol from a recipe (Dockerfile + config
  templates) and load: `curl` over SOCKS to an HTTP target, `iperf3`.
- `wirelab` generates the compose file, runs it, collects the pcap from
  `wire` and the logs from the zones, builds the same report.
- Recipes: ostp, VLESS-Reality (xray), WireGuard, Shadowsocks.
- Runtime: Docker Engine in WSL Debian.

## Later

- Censor models over pcap, shared by both modes: entropy, size and gap
  distributions, TLS fingerprints, active probing. Detectors move over from
  `ostp-prober`.
- CRTS CT-### tests as wirelab scenarios.
- Web panel with three columns on one timeline (`DESIGN.md` first).
- overnet adapter.
