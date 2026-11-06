# wirelab

[Русский](README.ru.md) · [Documentation](docs/README.md) · [Roadmap](docs/ROADMAP.md) · [Contributing](CONTRIBUTING.md)

![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20(WSL2)-green.svg)
![Docker](https://img.shields.io/badge/runs%20on-Docker-2496ED.svg)

**A test bench for censorship-resistant transport protocols.** A client, a server, and the wire between them. The wire carries their traffic through link impairments and a model of a real censor, and shows what an observer on the path sees. Run it by hand from a browser panel, or let it run a whole matrix of protocols, versions, censors and network conditions on its own and hand you a table of PASS, FAIL and NO DATA.

Everything runs on your machine, in Docker: no CI minutes, no VPS, as many runs as you like.

## What is inside

- **Lab.** Client, wire, server and a target site behind the server, as containers on isolated networks. A local panel gives you a console in the client and in the server, the live capture with dissected handshakes, throughput and RTT charts, path impairments (netem) and the censor controls. A session packs into one archive.
- **Recipes.** OSTP (UDP, UoT, TLS), VLESS-REALITY (Xray), Shadowsocks and WireGuard, set up on both ends with one command, from a release or from your own build.
- **Lab tests.** `wirelab lab test scenario.toml` runs recipes × versions × censors × paths, a fresh lab per cell, with workloads (bulk transfers checked by sha256, web page, steady stream, messenger, idle, probes), outages, a slow site, a server memory limit, and A/B comparison of versions.
- **Censor.** `wl-censor` routes the lab and applies a preset. *Russia (TSPU)*, as of 2026-10, has SNI blocking, QUIC SNI blocking, the foreign-datacentre freeze, encapsulated-TLS and TLS-rate heuristics, UDP DNS spoofing and more, and every rule cites its source. Behaviour the sources leave open is a hypothesis you switch. Protocols are recognised by [nDPI](https://github.com/ntop/nDPI). The same censor judges any pcap or pcapng.
- **CRTS outcomes.** Lab runs can write [CRTS](https://github.com/ospab/crts) conformance tables: amplification, length mode and periodicity measured from the captures.
- **Simulator.** `wirelab run` puts both ends of a sans-io protocol in one process over a seeded link model.

## Quick start

You need Docker (on Windows inside WSL2), Rust and git; see [Getting started](docs/en/getting-started.md).

```bash
git clone https://github.com/ospab/wirelab && cd wirelab
cargo build --release
./target/release/wirelab doctor                 # checks the machine, says how to fix what is missing
./target/release/wirelab censor build           # the censor, with nDPI, built in Docker
./target/release/wirelab lab up --recipe ostp --set transport=tls
./target/release/wirelab lab panel              # open the printed link
```

Or let it test on its own:

```bash
./target/release/wirelab lab test scenarios/lab/recipes.toml
```

## Documentation

| | |
|---|---|
| [Getting started](docs/en/getting-started.md) | install, build, first lab, first test run |
| [Lab](docs/en/lab.md) | addresses, folders, the panel, session archives |
| [Recipes](docs/en/recipes.md) | protocols set up on both ends, writing your own |
| [Lab tests](docs/en/lab-tests.md) | scenario reference, workloads, reports, A/B |
| [Censor](docs/en/censor.md) | rules, presets, hypotheses, sources |
| [CRTS](docs/en/crts.md) | conformance outcomes from lab runs |
| [Simulator](docs/en/simulator.md) | both ends in one process |

## What it is not

A lab is not a censored network. A PASS under a preset means "passes this model of the censor", and the model is only as good as the published observations it is built from: lists of blocked names and addresses are examples, and some thresholds are the preset's own choice (it says which). Field results come from field tests; the presets are meant to be checked against them and corrected.

## Layout

| Path | What |
|---|---|
| `wirelab-cli/` | the `wirelab` command |
| `wirelab-lab/` | lab, panel, recipes, lab tests, CRTS export, doctor |
| `wirelab-censor/` | the censor (Go): router, rules, nDPI binding, `-replay` |
| `wirelab-wire/` | capture parsing, analysis, pcapng |
| `wirelab-sim/`, `wirelab-core/`, `wirelab-ostp/` | the simulator and its OSTP adapter |
| `containers/` | node, wire and censor-build files; censor presets |
| `recipes/`, `scenarios/` | protocol recipes; lab test and simulator scenarios |
| `docs/` | documentation, roadmap, reports |

## License

GNU Affero General Public License v3.0 only, see [LICENSE](LICENSE). Third-party components and their licences: [NOTICE.md](NOTICE.md).
