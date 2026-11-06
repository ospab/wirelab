# Lab

[Русский](../ru/lab.md) · [Docs](../README.md)

A lab is four containers on isolated networks. Traffic between the client and the server can only go through the wire, which applies the path impairments and the censor and records what passes.

```
client 10.77.1.3 ── wire 10.77.1.2 | 10.77.2.2 ── server 10.77.2.3 ── target 10.77.3.10
     net_c                                 net_s                 net_t (no way out)
```

| Node | Role |
|---|---|
| client | Runs the protocol's client. Reaches the server only through the wire. |
| wire | Routes between the two networks: netem on both egress interfaces, the censor in between, the capture on the client side. |
| server | Runs the protocol's server. The only node that reaches the target. |
| target | The internet behind the server: an nginx at `target.lab`. |

The client resolves `target.lab` too, for tunnels that route rather than proxy (WireGuard); without the tunnel the address is unreachable from it.

## Starting and stopping

```bash
wirelab lab up [--id default] [--base alpine|debian] [--port 443] [--recipe NAME --set k=v ...] [--blob-mb 20] [--force]
wirelab lab panel [--id default] [--port 7077]
wirelab lab down [--id default]
```

| Option | Meaning |
|---|---|
| `--id` | Name of the lab; its files live in `lab/<id>/`. |
| `--base` | Image for client, server and target: Alpine (musl) or Debian (glibc). |
| `--port` | Port the server listens on; in the containers as `WL_SERVER_PORT`, the server address as `WL_SERVER_ADDR`. |
| `--recipe`, `--set` | Set both nodes up from a [recipe](recipes.md). |
| `--blob-mb` | Size of `http://target.lab/blob`. |
| `--force` | Replace a `setup.sh` in the node folders that no recipe wrote. |

All labs use the same subnets, so one can be up at a time; `lab up` names the lab in the way and the command to stop it.

## Folders

| On the host | In the container | |
|---|---|---|
| `lab/<id>/client/` | `/lab` on the client | `setup.sh` here runs at every start; output to `setup.log`. |
| `lab/<id>/server/` | `/lab` on the server | the same |
| `lab/<id>/shared/` | `/shared` on client and server | Emptied at `lab up`. Recipes exchange keys through it. |
| `lab/<id>/sessions/<unix time>/` | `/out` on the wire | Everything recorded in this run of the lab. |

Because `setup.sh` runs at every start, a lab can be recreated without setting it up again by hand.

## The target

| URL | |
|---|---|
| `http://target.lab/blob`, `/blob.sha256` | Random bytes (`--blob-mb`) and their sha256. |
| `http://target.lab/obj/1` … `/obj/40` | Object *i* is 2000 + 700·*i* bytes: a page's assets. |
| `http://target.lab/up/<name>` | PUT stores an upload, GET returns it, DELETE removes it. |

## The panel

`wirelab lab panel` serves on 127.0.0.1 only and requires the token it prints, because the consoles are root shells in the lab.

- **Consoles** in the client and the server (xterm.js), both recorded to the session folder.
- **Wire**: packet and byte counts each way, a chart of the last five minutes (throughput each way, round-trip time, censor decisions as marks), and a packet feed with what the dissectors read: TLS ClientHello with SNI and ALPN, ServerHello, ICMP unreachable.
- **RTT** is read passively from TCP (a client segment, then the server's ACK for it). For UDP protocols, tick *ping the server every second*; the pings show up on the wire.
- **Impairments**: delay and jitter as a round trip (split between the directions), loss, duplication, corruption, rate. `tc` holds what is shown, verbatim.
- **Censor**: pick a preset, switch rules and [hypotheses](censor.md#hypotheses), apply. Decisions appear with the rule and its source.
- **Secrets in the clear**: labels and values (UUIDs and hex also as raw bytes) looked for in every payload.
- **Download session archive**: see below.

## Session records

| File | |
|---|---|
| `wire.pcap` | Capture on the client side of the wire: client-to-server as sent, server-to-client after the impairments. |
| `censor.jsonl` | The censor's decisions, one JSON object per line: time, rule, action, flow, direction, payload length, detail, source. |
| `censor-preset.json` | The active preset, with the chosen hypotheses. |
| `wire-changes.log` | Every change of impairments and censor, with the `tc` commands. |
| `client-console.log`, `server-console.log` | Raw console output. |

## Session archive

```bash
wirelab lab export [--id default] [--session latest|<unix time>] [--out file.tar.gz]
```

or **Download session archive** in the panel. The archive holds the session folder, the lab description, the setup logs, the recipe with its resolved parameters, and `wire.pcapng`: the capture with each censor decision as a comment on the packet it was made on. In Wireshark, the display filter `frame.comment` lists them; decisions not tied to a packet are in *Statistics → Capture File Properties*.
