//! Controls on the wire container shared by the panel and the test runner:
//! netem on both egress interfaces, and the censor's active preset.

use crate::docker::Docker;
use crate::lab::LabInfo;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// One direction of netem.
pub struct NetemReq {
    pub delay_ms: f64,
    pub jitter_ms: f64,
    pub loss_pct: f64,
    pub duplicate_pct: f64,
    pub corrupt_pct: f64,
    pub rate_kbit: f64,
}

pub fn netem_args(r: &NetemReq) -> Result<Vec<String>> {
    for (name, v, max) in [
        ("delay_ms", r.delay_ms, 60_000.0),
        ("jitter_ms", r.jitter_ms, 60_000.0),
        ("loss_pct", r.loss_pct, 100.0),
        ("duplicate_pct", r.duplicate_pct, 100.0),
        ("corrupt_pct", r.corrupt_pct, 100.0),
        ("rate_kbit", r.rate_kbit, 100_000_000.0),
    ] {
        if !(v.is_finite() && (0.0..=max).contains(&v)) {
            bail!("{name} = {v}: must be between 0 and {max}");
        }
    }
    if r.jitter_ms > 0.0 && r.delay_ms == 0.0 {
        bail!("jitter needs a delay to vary around");
    }
    let mut a = Vec::new();
    if r.delay_ms > 0.0 {
        a.extend(["delay".into(), format!("{}ms", r.delay_ms)]);
        if r.jitter_ms > 0.0 {
            a.push(format!("{}ms", r.jitter_ms));
        }
    }
    for (k, v) in [("loss", r.loss_pct), ("duplicate", r.duplicate_pct), ("corrupt", r.corrupt_pct)] {
        if v > 0.0 {
            a.extend([k.to_string(), format!("{v}%")]);
        }
    }
    if r.rate_kbit > 0.0 {
        a.extend(["rate".into(), format!("{}kbit", r.rate_kbit)]);
    }
    if !a.is_empty() {
        // netem holds every delayed packet in its queue, 1000 by default: at
        // a few hundred Mbit/s that is less than the delay, and the excess
        // is dropped as if the path lost it. The queue gets room for the
        // delay plus 200 ms at the set rate, or 10,000 packets without one.
        let limit = if r.rate_kbit > 0.0 {
            ((r.rate_kbit * 1000.0 / 8.0 / 1500.0) * (0.2 + r.delay_ms / 1000.0)).ceil().max(1000.0)
        } else {
            10_000.0
        };
        a.extend(["limit".into(), format!("{limit}")]);
    }
    Ok(a)
}

/// Impairments for the whole path, as a person thinks of them: the delay a
/// ping would show (round trip) rather than per-direction one-way values.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PathReq {
    #[serde(default)]
    pub rtt_ms: f64,
    #[serde(default)]
    pub rtt_jitter_ms: f64,
    #[serde(default)]
    pub loss_pct: f64,
    #[serde(default)]
    pub duplicate_pct: f64,
    #[serde(default)]
    pub corrupt_pct: f64,
    #[serde(default)]
    pub rate_kbit: f64,
}

impl PathReq {
    /// One direction's netem: delay and jitter split evenly between the two
    /// directions; loss, duplication, corruption and rate apply in each.
    pub fn one_way(&self) -> NetemReq {
        NetemReq {
            delay_ms: self.rtt_ms / 2.0,
            jitter_ms: self.rtt_jitter_ms / 2.0,
            loss_pct: self.loss_pct,
            duplicate_pct: self.duplicate_pct,
            corrupt_pct: self.corrupt_pct,
            rate_kbit: self.rate_kbit,
        }
    }

    /// The same path with nothing getting through: a cut cable.
    pub fn cut(&self) -> PathReq {
        PathReq { loss_pct: 100.0, ..self.clone() }
    }
}

/// The wire container and its two egress interfaces.
#[derive(Clone)]
pub struct Wire {
    pub docker: Docker,
    pub container: String,
    /// Towards the server: carries c2s.
    pub if_to_server: String,
    /// Towards the client: carries s2c.
    pub if_to_client: String,
}

impl Wire {
    pub fn open(docker: &Docker, info: &LabInfo) -> Result<Wire> {
        let ifaces = docker
            .run(&["exec", &info.wire, "cat", "/tmp/ifaces"])
            .with_context(|| format!("reading the wire's interfaces; is lab {:?} running?", info.id))?;
        let mut it = ifaces.split_whitespace();
        let (Some(if_c), Some(if_s)) = (it.next(), it.next()) else { bail!("unexpected /tmp/ifaces in the wire: {ifaces:?}") };
        Ok(Wire { docker: docker.clone(), container: info.wire.clone(), if_to_server: if_s.into(), if_to_client: if_c.into() })
    }

    pub fn qdisc(&self) -> HashMap<&'static str, String> {
        let show = |dev: &str| {
            self.docker
                .run(&["exec", &self.container, "tc", "qdisc", "show", "dev", dev])
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|e| format!("error: {e}"))
        };
        HashMap::from([("c2s", show(&self.if_to_server)), ("s2c", show(&self.if_to_client))])
    }

    /// Apply a path to both directions. `log` gets one line per direction,
    /// with the outcome; the first failure stops it, so what `tc` then holds
    /// is what `qdisc` shows.
    pub fn apply(&self, r: &PathReq, mut log: impl FnMut(&str)) -> Result<()> {
        let args = netem_args(&r.one_way())?;
        for (dir, dev) in [("c2s", &self.if_to_server), ("s2c", &self.if_to_client)] {
            let mut cmd: Vec<String> = vec!["exec".into(), self.container.clone(), "tc".into(), "qdisc".into()];
            let clearing = args.is_empty();
            if clearing {
                cmd.extend(["del".into(), "dev".into(), dev.clone(), "root".into()]);
            } else {
                cmd.extend(["replace".into(), "dev".into(), dev.clone(), "root".into(), "netem".into()]);
                cmd.extend(args.iter().cloned());
            }
            let refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
            let shown = cmd[2..].join(" ");
            let res = match self.docker.run(&refs) {
                // Deleting a qdisc that is not there is the state we wanted anyway.
                Err(e) if clearing && (e.to_string().contains("No such file") || e.to_string().contains("handle of zero")) => Ok(String::new()),
                other => other,
            };
            log(&format!("{dir}: {shown} -> {}", match &res {
                Ok(_) => "ok".to_string(),
                Err(e) => format!("error: {e}"),
            }));
            res?;
        }
        Ok(())
    }
}

/// A preset from `containers/censor/presets` with some rules switched off
/// and hypotheses chosen (absent ones take the preset's default): the file
/// the censor reads. Also returns a one-line summary of the choices.
pub fn build_preset(presets: &Path, file: &str, disabled: &[String], hypotheses: &HashMap<String, bool>) -> Result<(serde_json::Value, String)> {
    if file.contains(['/', '\\']) || !file.ends_with(".json") {
        bail!("preset must be a file name from containers/censor/presets, got {file:?}");
    }
    let bytes = std::fs::read(presets.join(file)).with_context(|| format!("reading preset {file}"))?;
    let mut preset: serde_json::Value = serde_json::from_slice(&bytes).with_context(|| format!("parsing preset {file}"))?;
    let ids: Vec<String> = preset["rules"].as_array().map(|a| a.iter().filter_map(|r| r["id"].as_str().map(String::from)).collect()).unwrap_or_default();
    for d in disabled {
        if !ids.contains(d) {
            bail!("preset {file} has no rule {d:?}; it has: {}", ids.join(", "));
        }
    }
    if let Some(rules) = preset["rules"].as_array_mut() {
        for rule in rules {
            let id = rule["id"].as_str().unwrap_or_default().to_string();
            rule["disabled"] = serde_json::Value::Bool(disabled.contains(&id));
        }
    }
    let mut chosen_note = Vec::new();
    let hyps = preset["hypotheses"].as_array().cloned().unwrap_or_default();
    for (i, h) in hyps.iter().enumerate() {
        let id = h["id"].as_str().unwrap_or_default().to_string();
        let value = hypotheses.get(&id).copied().unwrap_or(h["default"].as_bool().unwrap_or(false));
        let field = h["field"].as_str().unwrap_or_default().to_string();
        let targets: Vec<String> = h["rules"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        if let Some(rules) = preset["rules"].as_array_mut() {
            for rule in rules.iter_mut().filter(|rule| targets.iter().any(|t| rule["id"] == t.as_str())) {
                rule[field.as_str()] = serde_json::Value::Bool(value);
            }
        }
        preset["hypotheses"][i]["chosen"] = serde_json::Value::Bool(value);
        chosen_note.push(format!("{id}={value}"));
    }
    let note = format!(
        "censor: {file}, rules off: {}, hypotheses: {}",
        if disabled.is_empty() { "none".into() } else { disabled.join(",") },
        if chosen_note.is_empty() { "none".into() } else { chosen_note.join(",") }
    );
    Ok((preset, note))
}

pub const ACTIVE_PRESET: &str = "censor-preset.json";

/// Make `preset` the censor's active one in a session folder (or turn the
/// censor off with `None`). Written whole and renamed, so the censor never
/// reads half a file.
pub fn activate_preset(session: &Path, preset: Option<&serde_json::Value>) -> Result<()> {
    let target = session.join(ACTIVE_PRESET);
    match preset {
        None => {
            let _ = std::fs::remove_file(&target);
        }
        Some(p) => {
            let tmp = session.join("censor-preset.json.tmp");
            std::fs::write(&tmp, serde_json::to_vec_pretty(p)?)?;
            std::fs::rename(&tmp, &target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netem_line_names_only_what_is_set() {
        let r = NetemReq { delay_ms: 40.0, jitter_ms: 0.0, loss_pct: 1.5, duplicate_pct: 0.0, corrupt_pct: 0.0, rate_kbit: 10000.0 };
        assert_eq!(netem_args(&r).unwrap().join(" "), "delay 40ms loss 1.5% rate 10000kbit limit 1000");
        let empty = NetemReq { delay_ms: 0.0, loss_pct: 0.0, rate_kbit: 0.0, ..r };
        assert!(netem_args(&empty).unwrap().is_empty());
    }

    #[test]
    fn fast_links_get_a_deeper_queue() {
        let r = NetemReq { delay_ms: 17.5, jitter_ms: 0.0, loss_pct: 0.0, duplicate_pct: 0.0, corrupt_pct: 0.0, rate_kbit: 300_000.0 };
        let a = netem_args(&r).unwrap();
        let limit: f64 = a.last().unwrap().parse().unwrap();
        // 300 Mbit/s is 25,000 full packets a second; a fifth of a second of them and more.
        assert!(limit > 5000.0, "{a:?}");
    }

    #[test]
    fn round_trip_delay_is_split_between_directions() {
        let path = PathReq { rtt_ms: 80.0, rtt_jitter_ms: 10.0, loss_pct: 1.0, ..Default::default() };
        assert_eq!(netem_args(&path.one_way()).unwrap().join(" "), "delay 40ms 5ms loss 1% limit 10000");
    }

    #[test]
    fn netem_rejects_nonsense() {
        let r = NetemReq { delay_ms: 0.0, jitter_ms: 5.0, loss_pct: 0.0, duplicate_pct: 0.0, corrupt_pct: 0.0, rate_kbit: 0.0 };
        assert!(netem_args(&r).is_err());
        let r = NetemReq { jitter_ms: 0.0, loss_pct: 150.0, ..r };
        assert!(netem_args(&r).is_err());
    }
}
