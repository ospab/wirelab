# Lab tests

[Русский](../ru/lab-tests.md) · [Docs](../README.md)

`wirelab lab test` runs the lab without a person. A scenario file names recipes, versions to compare, path profiles, censor presets and workloads. Every combination of recipe × version × censor × path is a **cell**, and every cell gets a fresh lab. In each cell the workloads run in the client, the wire is captured, and each result is checked against the scenario's thresholds.

```bash
wirelab lab test scenarios/lab/ostp-e2e.toml
wirelab lab test scenarios/lab/ostp-ab.toml --dry-run          # list the cells and stop
wirelab lab test scenarios/lab/recipes.toml --only xray        # cells whose name contains "xray"
wirelab lab test scenarios/lab/smoke.toml --keep               # leave the last lab up for the panel
wirelab lab test scenarios/lab/smoke.toml --out runs/mine
```

It runs on your machine, so it costs no CI minutes and can repeat as often as needed.

## Outcomes

Every check is **PASS**, **FAIL** or **NO DATA**. NO DATA means the measurement could not be made (the client never connected, a workload printed nothing, there was no process to read memory from); nothing is substituted for it. A workload with nothing to check against shows `-` and its measurement.

Exit code: 0 when nothing failed, 1 when a check failed, 3 when a cell could not run at all.

## Output

`runs/lab-<name>-<time>/` (or `--out`):

| File | |
|---|---|
| `report.md` | The table (one row per cell, one column per workload, which censor rule fired and when), versions side by side, and per cell every check with what it measured. |
| `report.json` | The same, for tools. |
| `crts.md`, `crts.json` | With a `[crts]` section: see [CRTS](crts.md). |
| `scenario.toml` | The scenario as run. |
| `cells/<n>-<name>/` | `result.json`, `wire.pcapng` with the censor's decisions as packet comments, `censor.jsonl`, setup logs and the recipe's logs from both nodes. |

## Scenario reference

```toml
name = "ostp-e2e"               # used for the lab id and the run folder
about = "One line for the report."
base = "alpine"                 # override the recipes' image base
port = 443                      # server port
blob_mb = 100                   # size of http://target.lab/blob
setup_timeout_s = 60            # both setup.sh must exit 0 within this
connect_timeout_s = 30          # the first request through the tunnel within this
capture = true                  # record the wire (needed for CRTS and censor comments)
snaplen = 256                   # bytes kept per packet: headers and a ClientHello's SNI
censor = ["off", "ru-tspu.json"]   # presets from containers/censor/presets; default ["off"]

[[recipe]]                      # one or more
use = "ostp"                    # recipe name
label = "udp"                   # name in the report; default: the recipe name
set = { transport = "udp" }     # recipe parameters

[[variant]]                     # optional: versions (or any parameter sets) to compare
label = "beta.13"
set = { version = "v0.4.7-beta.13" }

[[path]]                        # optional; default: one clean path
label = "300M-35ms"
rtt_ms = 35                     # round trip, split between the directions
rtt_jitter_ms = 0
loss_pct = 0.01                 # each direction
duplicate_pct = 0
corrupt_pct = 0
rate_kbit = 300000              # each direction

[[workload]]                    # one or more, run in order in every cell they apply to
kind = "down"
label = "speed"
paths = ["300M-35ms"]           # only in cells with these paths (also: recipes, censors)
min_mbps = 100

[crts]                          # optional: see crts.md
ct005 = true
ct006 = { max_mode_share = 0.5 }
ct007 = { max_peak = 0.5 }
```

Unknown keys are refused, so a misspelt threshold is an error rather than a check that silently never runs.

### Workloads

| `kind` | What it does | Checks | Fields (default) |
|---|---|---|---|
| `down` | Downloads the blob through the tunnel | size and sha256 against the target's; rate | `max_s` (300), `min_mbps` |
| `up` | Uploads random bytes with PUT; the server then reads them back from the target, outside the tunnel | sha256 on the far side; rate | `bytes_mb` (20), `max_s`, `min_mbps` |
| `web` | The 40 page objects, in parallel, several rounds | every object intact; total time | `rounds` (3), `parallel` (6), `max_s` (120) |
| `stream` | A download held to a rate for a fixed time | share of the rate held | `rate_kbit` (4000), `seconds` (30), `min_share` (0.9) |
| `chat` | Small requests at random intervals around `interval_s` | all answered; p95 latency | `count` (30), `interval_s` (2), `max_p95_ms` |
| `idle` | Nothing: only the tunnel's own traffic | measurement only (CRTS CT-007) | `seconds` (60) |
| `unauth` | Unauthenticated probes at the server port: random UDP of 64 and 1200 bytes, random TCP, an HTTP GET | measurement only (CRTS CT-005) | |

Fields any workload takes:

| Field | |
|---|---|
| `label` | Column name; default: the kind. Labels must be unique. |
| `paths`, `recipes`, `censors` | Run only in matching cells. |
| `max_s` | Longest it may run. |
| `outage = [{ at_s = 3, for_s = 30 }]` | Cut the path (100 % loss both ways) during the workload, then restore it. |
| `target_rate_kbit` | Slow the target's link both ways: a slow site behind the server. |
| `max_server_rss_mb` | Highest acceptable memory of the recipe's server process, read every second. |

## Versions side by side

With two or more `[[variant]]`s the report adds a table: every recipe, path, censor and workload, the main measurement under each version, and the difference against the first one (+ is better, whichever way the measurement goes). A variant can point `src` at a local build to compare it with a release.

## Examples in `scenarios/lab/`

| File | |
|---|---|
| `smoke.toml` | One recipe, a few small workloads: does it come up and move data. |
| `recipes.toml` | Every recipe, with and without the TSPU preset. |
| `ostp-e2e.toml` | OSTP release check: 100 MB both ways on UDP and TLS, speed on a fast path, 5 s and 30 s outages mid-download, server memory under a slow site. |
| `ostp-ab.toml` | Two OSTP versions on a clean and a lossy path, with and without the censor. |
| `ostp-crts.toml` | The CRTS measurements for OSTP. |
