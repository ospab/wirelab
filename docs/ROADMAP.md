# Roadmap

[Русский](ROADMAP.ru.md)

## Done

- **Simulator.** Two endpoints in one process over a seeded link model
  (delay, order-preserving jitter, explicit reordering, loss, duplicates, bit
  flips, bandwidth with a queue, MTU); recording, pcapng export, report. OSTP
  adapter over the real `ostp-core`.
- **Lab.** Client, wire, server and target containers on isolated networks;
  `/lab/setup.sh` per node; Alpine or Debian bases; server port chosen at
  `lab up`.
- **Panel.** Consoles in client and server, live capture with dissected
  ClientHello and ICMP, netem for the whole path (round-trip delay split
  between directions), secrets-in-the-clear search, resizable columns,
  everything recorded to the session folder.
- **Censor.** Userspace router in the wire with a decision log. Preset
  Russia (TSPU): SNI-I, SNI-II, SNI-IV, QUIC v1, IP, WireGuard, OpenVPN,
  foreign data-centre freeze; every rule cites its source. Hypothesis
  switch for ClientHello reassembly. IP fragments follow their flow.
- **Replay.** `wl-censor -replay` judges pcap and pcapng files.
- **Doctor.** `wirelab doctor` checks Docker, the WSL distro, netem, packet
  sockets and WireGuard in the kernel, free space where captures and
  Docker's data live (and where the WSL disk is), and the censor build; each
  problem comes with the command that fixes it. NFQUEUE turned out not to be
  needed: the censor reads frames with AF_PACKET.
- **Recipes.** `recipes/<name>/` with a manifest, `client.sh` and
  `server.sh`; releases are downloaded and cached, a local build can stand
  in. OSTP (UDP, UoT, TLS), VLESS-REALITY, Shadowsocks, WireGuard.
  `wirelab lab up --recipe ... --set k=v`.
- **Workloads.** Download and upload with sha256 on the far side, web page,
  steady stream, messenger, idle, unauthenticated probes; outages, a slow
  site, a server memory limit.
- **Test matrix with A/B.** `wirelab lab test scenario.toml`: recipe ×
  version × censor × path, a fresh lab per cell, a table with PASS / FAIL /
  NO DATA, versions side by side, which censor rule fired and when.
- **Charts in the panel.** Throughput each way and RTT (passive from TCP,
  ping on request) over five minutes, censor decisions on the time line.
- **Session export.** `wirelab lab export` and a panel button: one .tar.gz
  with the capture, decisions, consoles, wire changes and the recipe.
- **Decisions in Wireshark.** Censor decisions as packet comments in the
  exported and test-run pcapng.
- **CRTS export.** A `[crts]` section in a scenario writes `crts.md` and
  `crts.json`: CT-005, CT-006 and CT-007 measured from the captures, every
  other test `NO DATA` with the reason.

## Next

In the order that makes the bench useful to someone other than its author.

1. **Preset fixtures.** For each rule, a small capture that must trigger it
   and one that must not; run in CI with `-replay`. Catches a preset that
   silently stopped matching.
2. **More presets.** China (GFW fully-encrypted-traffic heuristic, Wu et
   al., USENIX Security 2023), Iran. Same rule: a source for every rule,
   hypotheses for the rest.
3. **Link profiles from measurements.** netem settings derived from real
   path measurements (for example `ostp-prober` runs), stored with where
   and when they were taken.
4. **More of CRTS.** CT-001 (byte uniformity) and CT-003 (handshake spread)
   need many deployments with distinct keys: a matrix that repeats a cell
   with fresh keys and pools the captures.
5. **CI and releases.** Rust and Go tests on every push; release builds of
   `wirelab` and `wl-censor`.

## Later

- QUIC Initial decryption, for the SNI-dependent QUIC rule TSPU moved to
  in 2022 and 2023.
- Console resize without reconnecting.
- Remote Docker host over SSH, so a lab can run on a Linux server.
- IPv6 and more than one client.
