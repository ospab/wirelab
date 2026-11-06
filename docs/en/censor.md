# Censor

[Русский](../ru/censor.md) · [Docs](../README.md)

`wl-censor` is a censor model. In a lab it is the wire's router; on its own it judges capture files. Every rule cites the paper or report it reproduces; what the sources leave open is a named [hypothesis](#hypotheses) you switch, so a result always says which assumption it rests on.

## How it runs

In the wire container the kernel does not forward (`ip_forward=0`). `wl-censor` reads every frame from both interfaces with packet sockets (AF_PACKET), judges it against the active preset and writes it out the other side, or drops it, rewrites it into an RST, or answers it. netem on the egress interfaces still applies below it. The preset is `censor-preset.json` in the session folder, reread when it changes; with no file, traffic passes untouched. Decisions go to `censor.jsonl`.

### Protocol recognition

Rules need to know what a flow is. That comes from a classifier:

| | |
|---|---|
| **nDPI** | [nDPI](https://github.com/ntop/nDPI) 5.0, linked into the lab's censor by `wirelab censor build`. Recognises TLS, QUIC (decrypting the Initial to read its SNI), SSH, RDP, WireGuard, OpenVPN, DNS, DTLS, HTTP, and computes JA4. |
| **built-in** | First bytes only: what a plain `go build` gives, and what `-replay` uses on Windows. No QUIC SNI and no JA4. |

The censor's first log line names the classifier and the rules it cannot serve, so a rule never silently fails to fire.

nDPI is pinned to 5.0: from 6.0 its TLS, QUIC and DNS dissectors are under ntop's dual licence, which needs a commercial agreement for for-profit use. 5.0 is entirely LGPL-3.0.

## Building

```bash
wirelab censor build
```

builds `containers/censor-build/Dockerfile`: nDPI 5.0 from source, the censor's tests (including nDPI against nDPI's own test captures: QUIC Initials decrypted, tunnels recognised), and a static binary in `containers/wire/bin/wl-censor`. A lab picks it up at start.

## Judging a capture

```bash
cd wirelab-censor && go build -o ../target/wl-censor . && cd ..
./target/wl-censor -replay session.pcap -preset containers/censor/presets/ru-tspu.json \
    -client-net 192.168.1.0/24 -server-net 203.0.113.7/32
```

Reads pcap and pcapng; reports, per rule, the flows it would have blocked and at which packet. Rules written for the lab's addresses are mapped onto the networks you pass. The build above has the built-in classifier.

## Presets

In `containers/censor/presets/`. Shipped:

- **Russia (TSPU)**, `ru-tspu.json`, as of 2026-10;
- **Russia, mobile whitelist mode**, `ru-mobile-whitelist.json`.

Domain and address lists in them are examples: the real registries are not public.

### Russia (TSPU)

| Rule | Behaviour | Source |
|---|---|---|
| `ru-sni-rst` | SNI on the list: server-to-client packets become RST/ACK for 75 s | Xue et al., IMC 2022 (SNI-I) |
| `ru-sni-drop-after` | SNI on the list: 5 more packets, then both directions dropped for 420 s | IMC 2022 (SNI-II) |
| `ru-sni-drop-all` | SNI on the list: everything dropped for 40 s, the ClientHello too (off) | IMC 2022 (SNI-IV) |
| `ru-quic-sni` | QUIC v1 Initial with a blocked SNI, any UDP port: flow dropped for 420 s, renewed by each new Initial; v2 not read | Heitmann et al., FOCI 2026 (net4people #654) |
| `ru-quic-v1` | QUIC v1 to UDP 443 of 1001+ bytes dropped (2022, replaced; off) | IMC 2022 |
| `ru-ip` | Server addresses on the block list dropped | IMC 2022; mass bans in #671 |
| `ru-wireguard` | WireGuard cut after the handshake and two data packets | net4people #274 |
| `ru-openvpn` | OpenVPN cut after the handshake and 15 data packets | net4people #274 |
| `ru-freeze` | Foreign data-centre servers: server-to-client packets stop after about 25 packets (14–34 KB); SSH spared; a whitelisted SNI spares a flow only on that domain's addresses; UDP blocks the whole server for 10 minutes | net4people #490 |
| `ru-encapsulated-tls` | Fully encrypted protocol carrying TLS: 3+ client packets of 411+ bytes while the server sends more often; port 443 | net4people #363 |
| `ru-tls-rate` | About 12 TLS connections with SNI to one server in a short time: new ClientHellos with the same JA4 dropped for 120 s | Habr 1010336 via net4people #603; #546 |
| `ru-dns-udp` | UDP DNS for blocked names answered NXDOMAIN; DNS over TCP untouched | net4people #657 |
| `ru-ssh-police` | SSH held to about 2 KB/s after 10–20 KB (some mobile regions; off) | net4people #490 |

Not modelled, with the reason, in the preset's notes: DTLS blocking by fingerprint (#603: the value is not published), TUN detection (#663: unconfirmed).

### Mobile whitelist mode

`ru-wl`: servers off the allowed networks get the TCP handshake and nothing after it; UDP and ICMP to them dropped; an allowed SNI counts only on the allowed addresses (#516, #650). The lab server is off the list; add `10.77.2.0/24` to model a server on an allowed Russian cloud network.

### Hypotheses

| Hypothesis | Rules | Default |
|---|---|---|
| `tcp-reassembly`: TSPU reads a ClientHello split across TCP segments | SNI rules | on |
| `sni-tied-to-cidr`: a whitelisted SNI counts only on its own addresses | `ru-freeze` | on |
| `freeze-counts-bytes`: the freeze counts bytes from the server, not packets | `ru-freeze` | off |
| `rdp-exempt`: RDP is spared like SSH | `ru-freeze` | off |
| `tls-rate-by-fingerprint`: the TLS limit is per JA4 | `ru-tls-rate` | on |

The panel shows each with the observation it comes from.

## Preset format

```json
{
  "name": "Russia (TSPU)",
  "as_of": "2026-10",
  "notes": "What is modelled and what is not, and why.",
  "hypotheses": [
    { "id": "…", "label": "…", "field": "<rule field>", "rules": ["<rule id>"], "default": true, "note": "…" }
  ],
  "rules": [
    { "id": "…", "name": "…", "kind": "…", "action": "…", "source": "… https://…", "disabled": false }
  ]
}
```

A rule without a `source` is refused, and so is a rule missing what its kind needs: a rule that never fires would read as "the censor let it through". A hypothesis writes its chosen value into `field` of the listed rules.

| `kind` | `action` | Fields |
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
| `whitelist` | `drop_payload` | `cidrs` (allowed), `allow_sni`, `sni_cidrs`, `sni_tied_to_cidr` |

`domains` match a name and its subdomains; `ports` and `cidrs` left empty match everything; `protocols` and `exempt_protocols` use nDPI's names (`TLS`, `QUIC`, `SSH`, `RDP`, `WireGuard`, `OpenVPN`, `DNS`, `DTLS`, `HTTP`, `Unknown`).

## Adding to a preset

If the sources do not settle how the censor behaves, add a hypothesis instead of picking one answer silently. Quote the observation in `source` with its link and date; give your own choices (a window, a threshold the sources leave vague) as such.
