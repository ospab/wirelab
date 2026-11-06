# Third-party components

wirelab is licensed under the GNU Affero General Public License v3.0 only ([LICENSE](LICENSE)). It builds on, or fetches at run time, the components below, each under its own licence.

## Linked into wirelab's binaries

| Component | Where | Licence |
|---|---|---|
| [nDPI](https://github.com/ntop/nDPI) 5.0 | Statically linked into `wl-censor` by `wirelab censor build` | LGPL-3.0 |
| [ostp-core](https://github.com/ospab/ostp) | The simulator's OSTP adapter (Cargo git dependency) | AGPL-3.0 |
| Rust crates | `wirelab` (see `Cargo.lock`) | mostly MIT or Apache-2.0 |
| Go standard library | `wl-censor` | BSD-3-Clause |

nDPI is pinned to 5.0 on purpose: from 6.0 its TLS, QUIC and DNS dissectors are under ntop's dual licence, which requires a commercial agreement for for-profit use; 5.0 is entirely LGPL-3.0. LGPL-3.0 section 4 asks that a statically linked binary can be relinked against a modified library: the censor's source and [`containers/censor-build/Dockerfile`](containers/censor-build/Dockerfile), which builds both from source, are what that takes. No censor binary is distributed in this repository.

## Loaded by the panel page

| Component | Licence |
|---|---|
| [xterm.js](https://github.com/xtermjs/xterm.js) and its fit addon, from jsDelivr | MIT |
| [IBM Plex](https://github.com/IBM/plex) Sans and Mono, from Google Fonts | SIL Open Font License 1.1 |

## Fetched at run time, not redistributed

| Component | Used by | Licence |
|---|---|---|
| [OSTP](https://github.com/ospab/ostp) releases | `ostp` recipe | AGPL-3.0 |
| [Xray-core](https://github.com/XTLS/Xray-core) releases | `xray-reality` recipe | MPL-2.0 |
| [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) releases | `shadowsocks` recipe | MIT |
| wireguard-tools, iptables, openssl (Alpine packages) | `wireguard`, `xray-reality` recipes | GPL-2.0, GPL-2.0, Apache-2.0 |
| Alpine Linux, Debian, nginx, curl, tcpdump, iproute2 | container images | their own licences |
| nDPI's test captures | the censor's build-time tests | LGPL-3.0 (part of nDPI) |

## Sources of the censor presets

Each rule in `containers/censor/presets/` cites the paper or report it reproduces, among them Xue et al., *TSPU: Russia's Decentralized Censorship System* (IMC 2022), Heitmann et al., *On Russia's Early Introduction of QUIC SNI Censorship* (FOCI 2026), and reports on [net4people/bbs](https://github.com/net4people/bbs). The presets restate their findings as rules; quotations are short and attributed.
