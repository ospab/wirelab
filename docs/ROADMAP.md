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

## Next

In the order that makes the bench useful to someone other than its author.

1. **`wirelab doctor`.** Check Docker, the WSL distro, netem and NFQUEUE
   modules, free disk on the drive that holds Docker's data, and that
   `wl-censor` is built. Each failure says what to run. A full system drive
   already broke builds once.
2. **Protocol recipes.** `recipes/<name>/{client,server}/setup.sh` plus a
   short manifest: what to install, which port, where the local proxy
   listens. `wirelab lab up --recipe xray-reality` sets up both ends. Start
   with ostp, VLESS-Reality, WireGuard, Shadowsocks.
3. **Workload profiles.** Bulk download, web page (many small fetches),
   steady stream, messenger (small periodic). Run from the client through
   its proxy against the target; each reports what it measured or NO DATA.
4. **Test matrix with A/B.** Recipe × preset × link profile, two versions
   of a recipe side by side, fresh lab per cell. Report as a table:
   connected, data intact, throughput, which rule fired and when.
5. **Charts in the panel.** Throughput and round-trip time per direction
   over time, with censor decisions marked on the timeline.
6. **Session export.** One archive with the capture, decision log,
   consoles, wire changes and the recipe used.
7. **Preset fixtures.** For each rule, a small capture that must trigger it
   and one that must not; run in CI with `-replay`. Catches a preset that
   silently stopped matching.
8. **Decisions in Wireshark.** Write each censor decision as a comment on
   the packet it concerns in the exported pcapng.
9. **More presets.** China (GFW fully-encrypted-traffic heuristic, Wu et
   al., USENIX Security 2023), Iran. Same rule: a source for every rule,
   hypotheses for the rest.
10. **Link profiles from measurements.** netem settings derived from real
    path measurements (for example `ostp-prober` runs), stored with where
    and when they were taken.
11. **CRTS export.** Map scenarios to CRTS CT-### tests and write results
    in its format.
12. **CI and releases.** Rust and Go tests on every push; release builds of
    `wirelab` and `wl-censor`.

## Later

- QUIC Initial decryption, for the SNI-dependent QUIC rule TSPU moved to
  in 2022 and 2023.
- Console resize without reconnecting.
- Remote Docker host over SSH, so a lab can run on a Linux server.
- IPv6 and more than one client.
