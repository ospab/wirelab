//! A test run as CRTS conformance outcomes (Censorship-Resistant Transport
//! Standard, conformance catalogue 0.1): one outcome table per
//! implementation under test, `PASS`, `FAIL` or `NO DATA` for every CT-###,
//! with the grounds for each.
//!
//! What a lab run can measure from its captures:
//!
//! - CT-005 amplification: unauthenticated probes at the server port, and
//!   how much came back (the `unauth` workload);
//! - CT-006 length mode: payload length histograms under the workloads;
//! - CT-007 periodicity: arrival times when idle and under low load (`idle`
//!   and `chat` workloads).
//!
//! Every other test is `NO DATA` with the reason. Where CRTS leaves the
//! threshold to the profile and the scenario gives none, the measurement is
//! reported and the outcome is `NO DATA`: CRTS forbids substituting a
//! plausible value, and that includes a threshold.

use crate::bench::{CellResult, CrtsConfig, Kind, RunResult, Verdict};
use serde::Serialize;

pub const CATALOGUE: &str = "0.1";

#[derive(Debug, Serialize)]
pub struct Claim {
    pub standard: &'static str,
    pub catalogue_version: &'static str,
    pub generated: String,
    pub tool: String,
    pub scenario: String,
    pub environment: &'static str,
    pub implementations: Vec<Implementation>,
}

#[derive(Debug, Serialize)]
pub struct Implementation {
    pub name: String,
    pub recipe: String,
    pub version: Option<String>,
    pub cells: Vec<usize>,
    pub outcomes: Vec<Outcome>,
}

#[derive(Debug, Serialize)]
pub struct Outcome {
    pub test: &'static str,
    pub title: &'static str,
    pub outcome: Verdict,
    pub grounds: String,
}

const TESTS: &[(&str, &str)] = &[
    ("CT-001", "Byte uniformity"),
    ("CT-002", "Cross-deployment invariants"),
    ("CT-003", "Handshake spread"),
    ("CT-004", "Active probing"),
    ("CT-005", "Amplification"),
    ("CT-006", "Length mode"),
    ("CT-007", "Periodicity"),
    ("CT-008", "Version gate"),
    ("CT-009", "Replay"),
    ("CT-010", "Forward secrecy"),
    ("CT-011", "Nonce exhaustion"),
    ("CT-012", "Field reachability"),
    ("CT-013", "Fail-closed and leaks"),
    ("CT-014", "Unauthenticated path"),
];

pub fn build(run: &RunResult, cfg: &CrtsConfig) -> Claim {
    // One implementation per recipe label and version; censor cells are left
    // out: they measure the censor as much as the protocol.
    let mut groups: Vec<(String, Vec<&CellResult>)> = Vec::new();
    for c in run.cells.iter().filter(|c| c.censor == "off" && c.error.is_none()) {
        let key = format!("{}{}", c.recipe_label, c.variant.as_ref().map(|v| format!(" @{v}")).unwrap_or_default());
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(c),
            None => groups.push((key, vec![c])),
        }
    }
    let implementations = groups
        .into_iter()
        .map(|(name, cells)| {
            let outcomes = TESTS
                .iter()
                .map(|&(test, title)| {
                    let (outcome, grounds) = match test {
                        "CT-005" if cfg.ct005 => ct005(&cells),
                        "CT-006" if cfg.ct006.is_some() => ct006(&cells, cfg.ct006.as_ref().and_then(|c| c.max_mode_share)),
                        "CT-007" if cfg.ct007.is_some() => ct007(&cells, cfg.ct007.as_ref().and_then(|c| c.max_peak)),
                        "CT-005" | "CT-006" | "CT-007" => (Verdict::NoData, "Not requested in the scenario's [crts] section".into()),
                        "CT-012" => (Verdict::NoData, "Field test: a lab run is not a censored network".into()),
                        _ => (Verdict::NoData, "Test not implemented in wirelab".into()),
                    };
                    Outcome { test, title, outcome, grounds }
                })
                .collect();
            Implementation {
                name,
                recipe: cells[0].recipe.name.clone(),
                version: cells[0].version.clone(),
                cells: cells.iter().map(|c| c.index).collect(),
                outcomes,
            }
        })
        .collect();
    Claim {
        standard: "CRTS",
        catalogue_version: CATALOGUE,
        generated: crate::bench::utc_now(),
        tool: format!("wirelab {} lab test", run.wirelab),
        scenario: run.scenario.clone(),
        environment: "lab (L): wirelab containers, emulated path, no real censored network",
        implementations,
    }
}

fn ct005(cells: &[&CellResult]) -> (Verdict, String) {
    let mut worst: Option<(f64, String)> = None;
    let mut n = 0;
    for c in cells {
        for w in c.workloads.iter().filter(|w| w.kind == Kind::Unauth) {
            for a in w.capture.iter().flat_map(|s| &s.amplification) {
                n += 1;
                let text = format!("{} in cell {}: {} B answered to {} B (×{:.2})", a.class, c.index, a.answered, a.sent, a.ratio);
                if worst.as_ref().map_or(true, |(r, _)| a.ratio > *r) {
                    worst = Some((a.ratio, text));
                }
            }
        }
    }
    match worst {
        None => (Verdict::NoData, "No unauthenticated probes in the capture (add an `unauth` workload)".into()),
        Some((r, t)) => (
            if r <= 1.0 { Verdict::Pass } else { Verdict::Fail },
            format!("{n} probe class run(s); highest ratio: {t}. Ratio over IP bytes for UDP, payload bytes for TCP"),
        ),
    }
}

fn ct006(cells: &[&CellResult], max: Option<f64>) -> (Verdict, String) {
    let mut worst: Option<(f64, String)> = None;
    let mut step: Option<String> = None;
    let mut n = 0;
    for c in cells {
        for w in c.workloads.iter().filter(|w| !matches!(w.kind, Kind::Unauth | Kind::Idle)) {
            for (dir, l) in w.capture.iter().flat_map(|s| &s.lengths) {
                if l.packets < 50 {
                    continue;
                }
                n += 1;
                let text = format!("{} {dir} in cell {}: {} B is {:.1}% of {} packets", w.label, c.index, l.mode_len, l.mode_share * 100.0, l.packets);
                if worst.as_ref().map_or(true, |(s, _)| l.mode_share > *s) {
                    worst = Some((l.mode_share, text));
                }
                if let (Some(s), None) = (l.step, &step) {
                    step = Some(format!("{} {dir} in cell {}: {:.0}% of lengths are multiples of {s}", w.label, c.index, l.step_share * 100.0));
                }
            }
        }
    }
    let Some((share, text)) = worst else {
        return (Verdict::NoData, "No workload with at least 50 payload-carrying packets in the capture".into());
    };
    let mut grounds = format!("{n} workload/direction histogram(s) of transport payload lengths; highest mode: {text}");
    if let Some(s) = &step {
        grounds.push_str(&format!("; degenerate step: {s}"));
    }
    match max {
        None => (Verdict::NoData, format!("{grounds}. No threshold declared (ct006.max_mode_share)")),
        Some(m) => {
            let ok = share <= m && step.is_none();
            (if ok { Verdict::Pass } else { Verdict::Fail }, format!("{grounds}; threshold {:.1}%", m * 100.0))
        }
    }
}

fn ct007(cells: &[&CellResult], max: Option<f64>) -> (Verdict, String) {
    let mut worst: Option<(f64, String)> = None;
    let mut n = 0;
    for c in cells {
        for w in c.workloads.iter().filter(|w| matches!(w.kind, Kind::Idle | Kind::Chat)) {
            for (dir, p) in w.capture.iter().flat_map(|s| &s.periodicity) {
                n += 1;
                let text = format!(
                    "{} {dir} in cell {}: autocorrelation {:.2} at lag {:.0} ms ({} packets over {:.0} s, {} ms bins)",
                    w.label, c.index, p.peak, p.peak_lag_ms, p.packets, p.span_s, p.bin_ms
                );
                if worst.as_ref().map_or(true, |(s, _)| p.peak > *s) {
                    worst = Some((p.peak, text));
                }
            }
        }
    }
    let Some((peak, text)) = worst else {
        return (Verdict::NoData, "No idle or low-load window with enough packets (add `idle` and `chat` workloads)".into());
    };
    let grounds = format!("{n} series; highest peak: {text}");
    match max {
        None => (Verdict::NoData, format!("{grounds}. No threshold declared (ct007.max_peak)")),
        Some(m) => (if peak <= m { Verdict::Pass } else { Verdict::Fail }, format!("{grounds}; threshold {m:.2}")),
    }
}

pub fn render(c: &Claim) -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "# CRTS outcome table · {}\n\n**Standard:** CRTS, conformance catalogue {} · **Generated:** {} · **Tool:** {}\n\n**Environment:** {}\n\n\
         Outcomes follow the catalogue's rules: `PASS`, `FAIL` or `NO DATA`, and a test that could not be run is `NO DATA`. \
         Only cells without a censor count; censored cells are in the test report.\n",
        c.scenario, c.catalogue_version, c.generated, c.tool, c.environment
    ));
    for i in &c.implementations {
        o.push_str(&format!(
            "\n## {}\n\n**Recipe:** {} · **Version:** {} · **Cells:** {}\n\n| Test | Outcome | Grounds |\n|---|---|---|\n",
            i.name,
            i.recipe,
            i.version.as_deref().unwrap_or("not stated"),
            i.cells.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ")
        ));
        for t in &i.outcomes {
            o.push_str(&format!("| {} {} | `{}` | {} |\n", t.test, t.title, t.outcome.as_str(), t.grounds.replace('|', "\\|")));
        }
    }
    o
}
