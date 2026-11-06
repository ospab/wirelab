# CRTS outcomes

[Русский](../ru/crts.md) · [Docs](../README.md)

[CRTS](https://github.com/ospab/crts), the Censorship-Resistant Transport Standard, defines conformance tests CT-001 … CT-014 with three outcomes: `PASS`, `FAIL`, `NO DATA`. A lab test with a `[crts]` section writes `crts.md` and `crts.json`: one outcome table per implementation under test (recipe label and version), in the catalogue's format.

## What a lab measures

| Test | Measured from | Outcome |
|---|---|---|
| CT-005 Amplification | `unauth` workload: answers to unauthenticated probes, from the capture | ratio answered/sent over IP bytes for UDP, payload bytes for TCP; PASS when every class is ≤ 1 |
| CT-006 Length mode | transport payload lengths under the other workloads, per direction (bare ACKs left out) | the most frequent length's share, and whether 90 %+ of lengths are multiples of one step; PASS when under `max_mode_share` and no step |
| CT-007 Periodicity | `idle` and `chat` workloads: packet arrival times binned, normalised autocorrelation | highest peak at a non-zero lag; PASS when under `max_peak` |

Every other test is `NO DATA` with the reason: not implemented, or a field test (CT-012) that a lab cannot be. Cells with a censor are left out: they measure the censor as much as the protocol.

## Thresholds

CRTS leaves thresholds to the profile under test. Without one the measurement is reported and the outcome is `NO DATA`: the catalogue forbids substituting a plausible value, and that includes a threshold.

```toml
[crts]
ct005 = true
ct006 = { max_mode_share = 0.5 }
ct007 = { max_peak = 0.5, bin_ms = 50, max_lag_s = 30 }
```

`scenarios/lab/ostp-crts.toml` runs the workloads these need.
