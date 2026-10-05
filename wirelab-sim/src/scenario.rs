use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;
use wirelab_core::Side;
use wirelab_wire::LinkProfile;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Pace {
    /// Realtime if either endpoint reads the OS clock, virtual otherwise.
    #[default]
    Auto,
    Virtual,
    Realtime,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transfer {
    pub from: Side,
    #[serde(default = "default_stream")]
    pub stream: u32,
    pub bytes: usize,
    #[serde(default = "default_chunk")]
    pub chunk: usize,
    /// Delay after both ends are established.
    #[serde(default)]
    pub start_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_seed")]
    pub seed: u64,
    #[serde(default = "default_duration")]
    pub duration_ms: u64,
    #[serde(default = "default_tick")]
    pub tick_ms: u64,
    #[serde(default = "default_sample")]
    pub sample_ms: u64,
    #[serde(default)]
    pub pace: Pace,
    /// `name` selects the adapter; every other key is the adapter's own.
    pub protocol: toml::value::Table,
    /// Applied to both directions unless `wire_c2s` / `wire_s2c` replace it.
    #[serde(default)]
    pub wire: LinkProfile,
    pub wire_c2s: Option<LinkProfile>,
    pub wire_s2c: Option<LinkProfile>,
    #[serde(default, rename = "transfer")]
    pub transfers: Vec<Transfer>,
}

fn default_stream() -> u32 {
    1
}
fn default_chunk() -> usize {
    1024
}
fn default_seed() -> u64 {
    1
}
fn default_duration() -> u64 {
    10_000
}
fn default_tick() -> u64 {
    5
}
fn default_sample() -> u64 {
    100
}

impl Scenario {
    pub fn load(path: &Path) -> Result<Scenario> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let s: Scenario = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        s.validate().with_context(|| format!("in {}", path.display()))?;
        Ok(s)
    }

    pub fn protocol_name(&self) -> Result<&str> {
        match self.protocol.get("name") {
            Some(toml::Value::String(n)) => Ok(n),
            _ => bail!("[protocol] needs name = \"...\""),
        }
    }

    pub fn c2s(&self) -> &LinkProfile {
        self.wire_c2s.as_ref().unwrap_or(&self.wire)
    }

    pub fn s2c(&self) -> &LinkProfile {
        self.wire_s2c.as_ref().unwrap_or(&self.wire)
    }

    pub fn validate(&self) -> Result<()> {
        self.protocol_name()?;
        self.c2s().validate("wire_c2s")?;
        self.s2c().validate("wire_s2c")?;
        if self.tick_ms == 0 || self.sample_ms == 0 {
            bail!("tick_ms and sample_ms must be at least 1");
        }
        let mut seen = HashSet::new();
        for (i, t) in self.transfers.iter().enumerate() {
            if t.bytes == 0 || t.chunk == 0 {
                bail!("transfer {i}: bytes and chunk must be positive");
            }
            // The receiver reassembles per (direction, stream); two transfers
            // sharing one would interleave and fail integrity for no real reason.
            if !seen.insert((t.from, t.stream)) {
                bail!("transfer {i}: another transfer already sends on stream {} from {:?}", t.stream, t.from);
            }
        }
        Ok(())
    }
}
