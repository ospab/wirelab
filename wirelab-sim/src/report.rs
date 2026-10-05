//! Turns a run into checks, metrics and a wire summary.

use crate::engine::{ResolvedPace, RunOutput};
use crate::scenario::Scenario;
use serde::Serialize;
use std::fmt::Write as _;
use wirelab_core::{Check, Dir, Metric, Outcome, Side};
use wirelab_wire::{summarize, DirSummary, LinkStats};

#[derive(Debug, Serialize)]
pub struct Report {
    pub scenario: String,
    pub protocol: String,
    pub seed: u64,
    pub pace: ResolvedPace,
    pub timing_valid: bool,
    pub ended_at_ms: f64,
    pub end_reason: String,
    pub checks: Vec<Check>,
    pub metrics: Vec<Metric>,
    pub wire: [DirSummary; 2],
    pub link: [LinkStats; 2],
}

const TIMING_NOTE: &str = "an endpoint reads the OS clock and simulated time ran ahead of it; rerun with pace = \"realtime\"";

pub fn build(sc: &Scenario, run: &RunOutput) -> Report {
    let mut checks = Vec::new();
    let mut metrics = Vec::new();
    let [client_up, server_up] = run.established_at;

    checks.push(match (client_up, server_up) {
        (Some(c), Some(s)) => Check {
            id: "session.established".into(),
            outcome: Outcome::Pass,
            evidence: format!("client at {c}, server at {s}"),
        },
        _ => Check {
            id: "session.established".into(),
            outcome: Outcome::Fail,
            evidence: format!(
                "client {}, server {} by {:.0} ms ({})",
                if client_up.is_some() { "established" } else { "not established" },
                if server_up.is_some() { "established" } else { "not established" },
                run.ended_at.as_ms_f64(),
                run.end_reason
            ),
        },
    });

    // A scenario that configures faults the run never hit has tested the clean
    // path, whatever its other checks say.
    let mut configured = Vec::new();
    let mut silent = Vec::new();
    for (dir, (profile, stats)) in Dir::BOTH.iter().zip([sc.c2s(), sc.s2c()].into_iter().zip(&run.link_stats)) {
        for (name, p, fired) in [
            ("loss", profile.loss, stats.lost),
            ("duplicate", profile.duplicate, stats.duplicated),
            ("corrupt", profile.corrupt, stats.corrupted),
            ("reorder", profile.reorder, stats.reordered),
        ] {
            if p > 0.0 {
                configured.push(format!("{dir:?} {name} ×{fired}"));
                if fired == 0 {
                    silent.push(format!("{dir:?} {name}"));
                }
            }
        }
    }
    if !configured.is_empty() {
        checks.push(Check {
            id: "scenario.faults_fired".into(),
            outcome: if silent.is_empty() { Outcome::Pass } else { Outcome::NoData },
            evidence: if silent.is_empty() {
                configured.join(", ")
            } else {
                format!(
                    "configured but never fired: {} (run ended at {:.0} ms); the other checks did not exercise them",
                    silent.join(", "),
                    run.ended_at.as_ms_f64()
                )
            },
        });
    }

    metrics.push(timed("session.handshake_ms", "ms", run.timing_valid, client_up.map(|t| t.as_ms_f64()), "client never established"));

    for (i, t) in run.transfers.iter().enumerate() {
        let id = format!("transfer.{i}");
        let label = format!("{:?}→{:?} stream {}", t.spec.from, t.spec.from.peer(), t.spec.stream);
        let check = if t.sent == 0 {
            Check {
                id: format!("{id}.integrity"),
                outcome: Outcome::NoData,
                evidence: format!("{label}: nothing was sent (session not established or start_ms past the end)"),
            }
        } else if let Some(off) = t.first_mismatch {
            Check {
                id: format!("{id}.integrity"),
                outcome: Outcome::Fail,
                evidence: format!("{label}: delivered bytes differ from sent ones at offset {off}"),
            }
        } else if t.delivered < t.spec.bytes {
            Check {
                id: format!("{id}.integrity"),
                outcome: Outcome::Fail,
                evidence: format!(
                    "{label}: {} of {} bytes delivered ({} handed to the sender) by {:.0} ms",
                    t.delivered,
                    t.spec.bytes,
                    t.sent,
                    run.ended_at.as_ms_f64()
                ),
            }
        } else {
            Check {
                id: format!("{id}.integrity"),
                outcome: Outcome::Pass,
                evidence: format!("{label}: all {} bytes delivered intact, in order", t.spec.bytes),
            }
        };
        checks.push(check);

        let elapsed = match (t.started_at, t.completed_at) {
            (Some(a), Some(b)) => Some(b.saturating_sub(a).as_ms_f64()),
            _ => None,
        };
        metrics.push(timed(&format!("{id}.duration_ms"), "ms", run.timing_valid, elapsed, "transfer did not complete"));
        let goodput = elapsed.filter(|&ms| ms > 0.0).map(|ms| t.spec.bytes as f64 * 8.0 / (ms * 1000.0));
        metrics.push(timed(&format!("{id}.goodput_mbps"), "Mbit/s", run.timing_valid, goodput, "transfer did not complete"));
    }

    Report {
        scenario: sc.name.clone(),
        protocol: run.protocol.to_string(),
        seed: sc.seed,
        pace: run.pace,
        timing_valid: run.timing_valid,
        ended_at_ms: run.ended_at.as_ms_f64(),
        end_reason: run.end_reason.clone(),
        checks,
        metrics,
        wire: Dir::BOTH.map(|d| summarize(&run.observations, d, run.timing_valid)),
        link: run.link_stats,
    }
}

fn timed(id: &str, unit: &'static str, timing_valid: bool, value: Option<f64>, missing: &str) -> Metric {
    let (value, note) = match (timing_valid, value) {
        (false, _) => (None, TIMING_NOTE.to_string()),
        (true, None) => (None, missing.to_string()),
        (true, Some(v)) => (Some(v), String::new()),
    };
    Metric { id: id.to_string(), value, unit, note }
}

impl Report {
    pub fn has_failures(&self) -> bool {
        self.checks.iter().any(|c| c.outcome == Outcome::Fail)
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "{}  ·  {}  ·  seed {}  ·  {:?} pace", self.scenario, self.protocol, self.seed, self.pace);
        let _ = writeln!(s, "ended at {:.1} ms: {}", self.ended_at_ms, self.end_reason);
        if !self.timing_valid {
            let _ = writeln!(s, "timing: NO DATA ({TIMING_NOTE})");
        }

        let _ = writeln!(s, "\nchecks");
        for c in &self.checks {
            let _ = writeln!(s, "  {:<8} {:<26} {}", c.outcome.to_string(), c.id, c.evidence);
        }

        let _ = writeln!(s, "\nmetrics");
        for m in &self.metrics {
            match m.value {
                Some(v) => {
                    let _ = writeln!(s, "  {:<26} {:>10.2} {}", m.id, v, m.unit);
                }
                None => {
                    let _ = writeln!(s, "  {:<26} {:>10} ({})", m.id, "NO DATA", m.note);
                }
            }
        }

        let _ = writeln!(s, "\nwire (tap at sender egress)");
        for (w, l) in self.wire.iter().zip(&self.link) {
            let side = if w.dir == Dir::C2s { Side::Client } else { Side::Server };
            let _ = writeln!(
                s,
                "  {:?} from {:?}: {} packets, {} bytes, size {}..{} (median {}), {} distinct sizes",
                w.dir,
                side,
                w.packets,
                w.bytes,
                opt(w.size_min),
                opt(w.size_max),
                opt(w.size_median),
                w.distinct_sizes
            );
            let top: Vec<String> = w.top_sizes.iter().take(5).map(|(sz, n)| format!("{sz}×{n}")).collect();
            let _ = writeln!(s, "    top sizes {}", top.join(" "));
            let _ = writeln!(s, "    first sizes {:?}", w.first_sizes);
            let _ = writeln!(
                s,
                "    entropy {} bit/byte, gap median {} ms, p90 {} ms",
                w.mean_entropy.map_or("NO DATA".into(), |e| format!("{e:.2}")),
                w.gap_median_ms.map_or("NO DATA".into(), |g| format!("{g:.2}")),
                w.gap_p90_ms.map_or("NO DATA".into(), |g| format!("{g:.2}"))
            );
            let _ = writeln!(
                s,
                "    link: lost {}, corrupted {}, duplicated {}, reordered {}, mtu drop {}, queue drop {}",
                l.lost, l.corrupted, l.duplicated, l.reordered, l.mtu_dropped, l.queue_dropped
            );
        }
        s
    }
}

fn opt(v: Option<usize>) -> String {
    v.map_or("-".into(), |v| v.to_string())
}
