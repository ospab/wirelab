# wirelab

A test bench for censorship-resistant transport protocols. A lab is three
zones: the client, the server, and the wire between them. You run your own
client and server binaries; the wire carries their traffic through link
impairments and a censor model, and shows what an observer on the path
would see.

[Русская версия](README.ru.md)

## What is in it

- **Lab** (`wirelab lab`): client, wire and server as containers, plus a
  target that stands for the internet behind the server. A local panel gives
  you a console in the client and in the server, the live packet capture,
  link impairments (netem) and the censor controls.
- **Censor** (`wl-censor`): routes the lab and applies a preset of censor
  behaviours. Each rule cites the paper or report it reproduces; behaviour
  the sources leave open is a named hypothesis you switch on or off. The
  same engine judges any pcap or pcapng file.
- **Simulator** (`wirelab run`): both ends in one process over a simulated
  link, for protocols with a sans-io core. OSTP is the one adapter so far.

Results are reported as `PASS`, `FAIL` or `NO DATA`. A check that could not
measure says so; it is never counted as a pass.

## Requirements

- Rust (stable) and Go 1.26 or newer.
- Docker Engine on Linux, or inside WSL2 on Windows. On Windows the lab
  talks to the `Debian` distro by default; set `WIRELAB_WSL_DISTRO` for
  another one.
- For the OSTP simulator adapter, a checkout of `ostp` next to this one
  (`../ostp`).

## Run a lab

```
cargo build --release
cd wirelab-censor && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ../containers/wire/bin/wl-censor . && cd ..
./target/release/wirelab lab up
./target/release/wirelab lab panel
```

`lab up` prints the addresses: the server is `10.77.2.3` and listens on 443
unless you pass `--port`; the client reaches it at that address. Each node's
`lab/<id>/<node>/` folder is `/lab` inside the container, and a
`/lab/setup.sh` there runs every time the node starts, so a lab can be torn
down and rebuilt without redoing the setup by hand.

`lab panel` prints a link with a token made for this run. Open it, pick
**Russia (TSPU)** under Censor, apply, and start your server and client in
the two consoles. Every censor decision appears in the panel with the rule
that made it and its source, and is logged to the session folder together
with the capture and both consoles.

## Judge a capture

```
cd wirelab-censor && go build -o ../target/wl-censor . && cd ..
./target/wl-censor -replay session.pcap -preset containers/censor/presets/ru-tspu.json \
    -client-net 192.168.1.0/24 -server-net 203.0.113.7/32
```

The report lists, per rule, the flows it would have blocked and at which
packet. Rules written for the lab's addresses are mapped onto the networks
you pass.

## Adding to a preset

Presets live in `containers/censor/presets/`. A rule without a `source` is
rejected when the preset loads. If the sources do not settle how the censor
behaves, add a hypothesis instead of picking one answer silently.

## Layout

| Path | What |
|---|---|
| `wirelab-cli/` | the `wirelab` command |
| `wirelab-lab/` | lab orchestration and the panel |
| `wirelab-censor/` | the censor (Go): router mode and `-replay` |
| `wirelab-wire/`, `wirelab-sim/`, `wirelab-core/`, `wirelab-ostp/` | the simulator |
| `containers/` | node, wire and censor files mounted into the lab |
| `docs/` | roadmap and reports |

## License

GNU Affero General Public License v3.0 only. See [LICENSE](LICENSE).
