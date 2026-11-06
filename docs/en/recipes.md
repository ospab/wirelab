# Recipes

[Русский](../ru/recipes.md) · [Docs](../README.md)

A recipe sets a protocol up on both nodes with no typing: it downloads the release (or takes a local build), writes the configs from its parameters, starts both ends and leaves the client's proxy ready.

```bash
wirelab recipes                                   # list them with their parameters
wirelab lab up --recipe xray-reality
wirelab lab up --recipe ostp --set transport=tls --set version=v0.4.7-beta.14
wirelab lab up --recipe ostp --set src=D:/builds/ostp   # a local Linux build instead
```

## Shipped

| Recipe | What | Client side | Parameters |
|---|---|---|---|
| `ostp` | [OSTP](https://github.com/ospab/ostp) over UDP, UoT or TLS (self-signed certificate) | SOCKS5/HTTP on `127.0.0.1:1088` | `version`, `transport` (`udp`, `uot`, `tls`), `src`, `key`, `log_level` |
| `xray-reality` | VLESS + XTLS-Vision over REALITY ([Xray-core](https://github.com/XTLS/Xray-core)); the borrowed site is a TLS 1.3 nginx on the server | SOCKS5 on `127.0.0.1:1080` | `version`, `src`, `sni`, `id`, `short_id`, `flow`, `fingerprint` |
| `shadowsocks` | [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust), TCP and UDP | SOCKS5 on `127.0.0.1:1080` | `version`, `src`, `method`, `key` |
| `wireguard` | Kernel WireGuard; `wg` from Alpine packages | none: the target network is routed into `wg0` | `keepalive`, `mtu` |

Releases are cached in `cache/dl/` in the checkout, so a matrix of labs downloads each one once. `xray-reality` and `wireguard` install a package or two from Alpine at start (openssl; wireguard-tools and iptables), so their containers need the internet once.

## Writing one

A recipe is a folder `recipes/<name>/`:

```
recipes/<name>/
  recipe.toml   what it is, parameters, files to fetch
  client.sh     becomes /lab/setup.sh on the client
  server.sh     becomes /lab/setup.sh on the server
```

`recipe.toml`:

```toml
name = "example"                     # must match the folder
about = "One line for `wirelab recipes`"
base = "alpine"                      # image the binaries need (lab up --base overrides)
proxy = "socks5h://127.0.0.1:1080"   # what workloads give curl as -x; omit when the tunnel routes
server_process = "example-server"    # for memory readings in lab tests
client_process = "example-client"
version_param = "version"            # which parameter reports call the version

[params]
version = "v1.2.3"
src = "https://example.org/releases/${version}/example-linux-amd64.tar.gz"
key = "@random-hex-16"               # 16 random bytes in hex, the same on both nodes

[[fetch]]
url = "${src}"                       # http(s) or a local path; empty means nothing to fetch
save_as = "example.tar.gz"           # name under /lab/dl/
nodes = ["client", "server"]         # default: both
```

Parameter values may refer to others as `${name}`. Setting a parameter the recipe does not have is an error, so a typo cannot quietly run the default.

The scripts:

- read the parameters from `/lab/recipe.env` (`. /lab/recipe.env`): each as `WL_P_<NAME>` in upper case, plus `WL_RECIPE`; the lab adds `WL_SERVER_ADDR` and `WL_SERVER_PORT`;
- find fetched files in `/lab/dl/`;
- exchange generated material (public keys, certificates) through `/shared`: write it whole and rename, and on the other side wait for the file;
- start the protocol in the background (`nohup ... &`), log to `/lab/<something>.log`, and **exit**. The lab waits for both scripts to exit 0 before it calls the node ready; a lab test copies every `/lab/*.log` into the cell folder.

The `setup.sh` a recipe writes starts with a marker line; `lab up --recipe` refuses to replace a `setup.sh` without it unless given `--force`. A copy of the recipe with its resolved parameters goes into the session folder, and so into the session archive.
