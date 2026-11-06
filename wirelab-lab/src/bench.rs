//! `wirelab lab test`: the lab without a person. A scenario file names
//! recipes, versions to compare, path profiles, censor presets and
//! workloads; every combination of recipe × version × censor × path is a
//! cell, and every cell gets a fresh lab. In each cell the workloads run in
//! the client, the wire is captured, and the result is checked against the
//! scenario's thresholds: PASS, FAIL, or NO DATA when the measurement could
//! not be made. Nothing is substituted for a missing measurement.

use crate::docker::Docker;
use crate::export;
use crate::lab::{self, Base, LabInfo, UpOptions};
use crate::recipe::{self, RecipeUse};
use crate::wirectl::{self, PathReq, Wire};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wirelab_wire::analyze::{length_stats, periodicity, LengthStats, Periodicity, Throughput, Way};
use wirelab_wire::capture::{parse_record, read_pcap_records, Packet, Transport};

// ---------------------------------------------------------------- scenario

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub name: String,
    #[serde(default)]
    pub about: String,
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub blob_mb: Option<u32>,
    /// How long both nodes' setup.sh may take.
    #[serde(default = "d60")]
    pub setup_timeout_s: u64,
    /// How long the first request through the tunnel may take.
    #[serde(default = "d30")]
    pub connect_timeout_s: u64,
    /// Capture the wire. Without it there are no censor comments, no CRTS
    /// measurements and no per-second throughput.
    #[serde(default = "yes")]
    pub capture: bool,
    /// Bytes kept per packet: headers and the start of the payload (enough
    /// for a TLS ClientHello's SNI) keep the files small.
    #[serde(default = "d256")]
    pub snaplen: u32,
    pub recipe: Vec<RecipeEntry>,
    /// Versions (or any parameter sets) to compare side by side: each one
    /// is applied on top of every recipe's parameters.
    #[serde(default)]
    pub variant: Vec<Variant>,
    #[serde(default)]
    pub path: Vec<PathEntry>,
    /// Preset files from containers/censor/presets, or "off".
    #[serde(default = "censor_off")]
    pub censor: Vec<String>,
    pub workload: Vec<Workload>,
    #[serde(default)]
    pub crts: Option<CrtsConfig>,
}

fn d60() -> u64 {
    60
}
fn d30() -> u64 {
    30
}
fn d256() -> u32 {
    256
}
fn yes() -> bool {
    true
}
fn censor_off() -> Vec<String> {
    vec!["off".into()]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeEntry {
    #[serde(rename = "use")]
    pub use_: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub set: BTreeMap<String, String>,
}

impl RecipeEntry {
    pub fn label(&self) -> String {
        self.label.clone().unwrap_or_else(|| self.use_.clone())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Variant {
    pub label: String,
    #[serde(default)]
    pub set: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathEntry {
    pub label: String,
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

impl PathEntry {
    pub fn req(&self) -> PathReq {
        PathReq {
            rtt_ms: self.rtt_ms,
            rtt_jitter_ms: self.rtt_jitter_ms,
            loss_pct: self.loss_pct,
            duplicate_pct: self.duplicate_pct,
            corrupt_pct: self.corrupt_pct,
            rate_kbit: self.rate_kbit,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Download the target's blob and check its sha256.
    Down,
    /// Upload random bytes, check their sha256 on the target's side.
    Up,
    /// A web page: the 40 small objects, in parallel, several rounds.
    Web,
    /// A steady download at a fixed rate for a fixed time.
    Stream,
    /// A messenger: small requests at intervals, latency of each.
    Chat,
    /// Nothing at all: the tunnel's own traffic (keepalives).
    Idle,
    /// Unauthenticated packets at the server port (CRTS CT-005).
    Unauth,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Outage {
    /// Seconds after the workload starts.
    pub at_s: f64,
    pub for_s: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    pub kind: Kind,
    #[serde(default)]
    pub label: Option<String>,
    /// Only in cells with these path labels / recipe labels / censors.
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    #[serde(default)]
    pub recipes: Option<Vec<String>>,
    #[serde(default)]
    pub censors: Option<Vec<String>>,
    /// Longest the workload may run (default 300 s; web 120 s).
    #[serde(default)]
    pub max_s: Option<u64>,
    /// down, up: lowest acceptable rate.
    #[serde(default)]
    pub min_mbps: Option<f64>,
    /// Cut the path (100% loss both ways) during the workload.
    #[serde(default)]
    pub outage: Vec<Outage>,
    /// Highest acceptable memory (RSS) of the recipe's server process while
    /// the workload runs; it is read every second.
    #[serde(default)]
    pub max_server_rss_mb: Option<f64>,
    /// Slow the target's link (both directions) to model a slow site.
    #[serde(default)]
    pub target_rate_kbit: Option<f64>,
    /// up: how much to send.
    #[serde(default)]
    pub bytes_mb: Option<u32>,
    /// web
    #[serde(default)]
    pub rounds: Option<u32>,
    #[serde(default)]
    pub parallel: Option<u32>,
    /// stream: the rate to hold and for how long; share of it to reach.
    #[serde(default)]
    pub rate_kbit: Option<f64>,
    #[serde(default)]
    pub seconds: Option<u64>,
    #[serde(default)]
    pub min_share: Option<f64>,
    /// chat
    #[serde(default)]
    pub count: Option<u32>,
    #[serde(default)]
    pub interval_s: Option<f64>,
    #[serde(default)]
    pub max_p95_ms: Option<f64>,
}

impl Workload {
    pub fn label(&self) -> String {
        self.label.clone().unwrap_or_else(|| format!("{:?}", self.kind).to_lowercase())
    }

    fn applies(&self, recipe: &str, path: &str, censor: &str) -> bool {
        let ok = |f: &Option<Vec<String>>, v: &str| f.as_ref().map_or(true, |l| l.iter().any(|x| x == v));
        ok(&self.recipes, recipe) && ok(&self.paths, path) && ok(&self.censors, censor)
    }
}

/// Which CRTS conformance tests to compute from the captures, with the
/// thresholds the profile under test declares. A test without a threshold
/// is measured and reported, but its outcome is NO DATA: CRTS leaves the
/// threshold to the profile, and this tool does not invent one.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrtsConfig {
    #[serde(default)]
    pub ct005: bool,
    #[serde(default)]
    pub ct006: Option<Ct006>,
    #[serde(default)]
    pub ct007: Option<Ct007>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ct006 {
    #[serde(default)]
    pub max_mode_share: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ct007 {
    #[serde(default)]
    pub max_peak: Option<f64>,
    #[serde(default = "d50")]
    pub bin_ms: u64,
    #[serde(default = "d30")]
    pub max_lag_s: u64,
}

fn d50() -> u64 {
    50
}

impl Scenario {
    pub fn load(path: &Path) -> Result<Scenario> {
        let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let sc: Scenario = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        sc.check()?;
        Ok(sc)
    }

    fn check(&self) -> Result<()> {
        if self.recipe.is_empty() {
            bail!("scenario {}: no [[recipe]]", self.name);
        }
        if self.workload.is_empty() {
            bail!("scenario {}: no [[workload]]", self.name);
        }
        let mut seen = Vec::new();
        for r in &self.recipe {
            if seen.contains(&r.label()) {
                bail!("two recipes labelled {:?}; give them distinct labels", r.label());
            }
            seen.push(r.label());
        }
        let mut seen = Vec::new();
        for w in &self.workload {
            if seen.contains(&w.label()) {
                bail!("two workloads labelled {:?}; give them distinct labels", w.label());
            }
            seen.push(w.label());
            for o in &w.outage {
                if !(o.at_s >= 0.0 && o.for_s > 0.0) {
                    bail!("workload {}: outage at {} s for {} s", w.label(), o.at_s, o.for_s);
                }
            }
        }
        for p in &self.path {
            wirectl::netem_args(&p.req().one_way()).with_context(|| format!("path {}", p.label))?;
        }
        Ok(())
    }

    fn paths(&self) -> Vec<PathEntry> {
        if self.path.is_empty() {
            vec![PathEntry { label: "clean".into(), rtt_ms: 0.0, rtt_jitter_ms: 0.0, loss_pct: 0.0, duplicate_pct: 0.0, corrupt_pct: 0.0, rate_kbit: 0.0 }]
        } else {
            self.path.clone()
        }
    }

    fn variants(&self) -> Vec<Option<Variant>> {
        if self.variant.is_empty() {
            vec![None]
        } else {
            self.variant.iter().cloned().map(Some).collect()
        }
    }
}

// ----------------------------------------------------------------- results

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Verdict {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "FAIL")]
    Fail,
    #[serde(rename = "NO DATA")]
    NoData,
    /// Measured, with nothing to compare against.
    #[serde(rename = "-")]
    Info,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::NoData => "NO DATA",
            Verdict::Info => "-",
        }
    }
}

/// What the capture showed of the tunnel during one workload, one entry
/// per direction.
#[derive(Debug, Clone, Default, Serialize)]
pub struct WindowStats {
    pub lengths: BTreeMap<String, LengthStats>,
    pub periodicity: BTreeMap<String, Periodicity>,
    /// unauth: per probe class, bytes sent and answered as the wire saw them.
    pub amplification: Vec<Amplification>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Amplification {
    pub class: String,
    pub proto: String,
    /// IP bytes for UDP; transport payload for TCP, whose handshake is no
    /// reflector (a spoofed SYN never completes).
    pub sent: u64,
    pub answered: u64,
    pub ratio: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkResult {
    pub label: String,
    pub kind: Kind,
    pub verdict: Verdict,
    /// Each check made, as text: what was required and what was measured.
    pub checks: Vec<String>,
    /// The number the workload is about, for tables and A/B comparison.
    pub metric: Option<Metric>,
    pub measured: BTreeMap<String, f64>,
    pub raw: serde_json::Value,
    /// Window on the lab clock (the capture's), unix ms.
    pub t0_ms: i64,
    pub t1_ms: i64,
    pub outages_ms: Vec<(i64, i64)>,
    pub capture: Option<WindowStats>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Metric {
    pub name: String,
    pub value: f64,
    pub unit: String,
    /// Whether a larger value is better (for A/B deltas).
    pub higher_is_better: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CensorHit {
    /// Seconds after the cell's first connection attempt.
    pub t_s: f64,
    pub rule: String,
    pub action: String,
    pub flow: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CellResult {
    pub index: usize,
    pub recipe_label: String,
    pub variant: Option<String>,
    pub path: String,
    pub censor: String,
    pub recipe: RecipeUse,
    pub version: Option<String>,
    pub dir: PathBuf,
    pub session: PathBuf,
    /// Why the cell could not be run, when it could not.
    pub error: Option<String>,
    pub connect: Option<WorkResult>,
    pub workloads: Vec<WorkResult>,
    pub censor_hits: Vec<CensorHit>,
    pub capture: Option<export::PcapngSummary>,
    /// IP bytes per second each way, from the first connection attempt.
    pub throughput: Option<Throughput>,
}

impl CellResult {
    pub fn name(&self) -> String {
        let mut n = self.recipe_label.clone();
        if let Some(v) = &self.variant {
            n.push_str(&format!(" @{v}"));
        }
        format!("{n} / {} / censor {}", self.path, self.censor)
    }

    pub fn failed(&self) -> bool {
        self.connect.as_ref().is_some_and(|c| c.verdict == Verdict::Fail) || self.workloads.iter().any(|w| w.verdict == Verdict::Fail)
    }
}

#[derive(Debug, Serialize)]
pub struct RunResult {
    pub scenario: String,
    pub about: String,
    pub started: String,
    pub wirelab: String,
    pub dir: PathBuf,
    pub cells: Vec<CellResult>,
    pub crts: Option<CrtsConfig>,
}

// ------------------------------------------------------------------ runner

pub struct RunOptions {
    pub out: Option<PathBuf>,
    /// Run only cells whose name contains this.
    pub only: Option<String>,
    /// List the cells and stop.
    pub dry_run: bool,
    /// Leave the last cell's lab running, for a look in the panel.
    pub keep: bool,
}

struct Cell {
    index: usize,
    recipe: RecipeEntry,
    variant: Option<Variant>,
    path: PathEntry,
    censor: String,
}

impl Cell {
    fn name(&self) -> String {
        let mut n = self.recipe.label();
        if let Some(v) = &self.variant {
            n.push_str(&format!(" @{}", v.label));
        }
        format!("{n} / {} / censor {}", self.path.label, self.censor)
    }

    fn slug(&self) -> String {
        let s = format!(
            "{:02}-{}{}-{}-{}",
            self.index,
            self.recipe.label(),
            self.variant.as_ref().map(|v| format!("-{}", v.label)).unwrap_or_default(),
            self.path.label,
            self.censor.trim_end_matches(".json")
        );
        s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' }).collect()
    }
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

pub fn run(docker: &Docker, root: &Path, scenario_path: &Path, opts: &RunOptions) -> Result<RunResult> {
    let sc = Scenario::load(scenario_path)?;
    let mut cells = Vec::new();
    for r in &sc.recipe {
        recipe::load(root, &r.use_)?;
        for v in sc.variants() {
            for c in &sc.censor {
                for p in sc.paths() {
                    let cell = Cell { index: cells.len() + 1, recipe: r.clone(), variant: v.clone(), path: p, censor: c.clone() };
                    if opts.only.as_ref().map_or(true, |o| cell.name().contains(o.as_str())) {
                        cells.push(cell);
                    }
                }
            }
        }
    }
    if cells.is_empty() {
        bail!("no cells to run{}", if opts.only.is_some() { " (--only matched none)" } else { "" });
    }
    let presets = root.join("containers/censor/presets");
    for c in &sc.censor {
        if c != "off" {
            wirectl::build_preset(&presets, c, &[], &HashMap::new())?;
        }
    }
    println!("scenario {}: {} cell(s)", sc.name, cells.len());
    for c in &cells {
        let wl: Vec<String> = sc.workload.iter().filter(|w| w.applies(&c.recipe.label(), &c.path.label, &c.censor)).map(|w| w.label()).collect();
        println!("  {:>2}. {}  [{}]", c.index, c.name(), wl.join(", "));
    }
    if opts.dry_run {
        return Ok(RunResult {
            scenario: sc.name.clone(),
            about: sc.about.clone(),
            started: String::new(),
            wirelab: env!("CARGO_PKG_VERSION").into(),
            dir: PathBuf::new(),
            cells: Vec::new(),
            crts: sc.crts.clone(),
        });
    }

    let stamp = utc_stamp();
    let dir = opts.out.clone().unwrap_or_else(|| root.join("runs").join(format!("lab-{}-{}", sc.name, stamp.replace([':', '-'], "").replace('T', "-").trim_end_matches('Z'))));
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    fs::copy(scenario_path, dir.join("scenario.toml"))?;
    let lab_id: String = format!("t-{}", sc.name).chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' }).take(40).collect();

    let mut results = Vec::new();
    let n = cells.len();
    for (i, cell) in cells.iter().enumerate() {
        println!("\n[{}/{}] {}", i + 1, n, cell.name());
        let cdir = dir.join("cells").join(cell.slug());
        fs::create_dir_all(&cdir)?;
        let last = i + 1 == n;
        let res = run_cell(docker, root, &sc, cell, &lab_id, &cdir, opts.keep && last);
        let res = match res {
            Ok(r) => r,
            Err(e) => {
                println!("  cell could not run: {e:#}");
                let _ = lab::down(docker, root, &lab_id);
                CellResult {
                    index: cell.index,
                    recipe_label: cell.recipe.label(),
                    variant: cell.variant.as_ref().map(|v| v.label.clone()),
                    path: cell.path.label.clone(),
                    censor: cell.censor.clone(),
                    recipe: RecipeUse::new(&cell.recipe.use_, BTreeMap::new()),
                    version: None,
                    dir: cdir.clone(),
                    session: PathBuf::new(),
                    error: Some(format!("{e:#}")),
                    connect: None,
                    workloads: Vec::new(),
                    censor_hits: Vec::new(),
                    capture: None,
                    throughput: None,
                }
            }
        };
        fs::write(cdir.join("result.json"), serde_json::to_vec_pretty(&res)?)?;
        results.push(res);
    }

    let run = RunResult {
        scenario: sc.name.clone(),
        about: sc.about.clone(),
        started: stamp,
        wirelab: env!("CARGO_PKG_VERSION").into(),
        dir: dir.clone(),
        cells: results,
        crts: sc.crts.clone(),
    };
    fs::write(dir.join("report.json"), serde_json::to_vec_pretty(&run)?)?;
    fs::write(dir.join("report.md"), render_report(&run, &sc))?;
    if let Some(cfg) = &sc.crts {
        let claim = crate::crts::build(&run, cfg);
        fs::write(dir.join("crts.json"), serde_json::to_vec_pretty(&claim)?)?;
        fs::write(dir.join("crts.md"), crate::crts::render(&claim))?;
    }
    Ok(run)
}

/// Lab clock minus host clock, ms. The capture and the censor stamp packets
/// with the lab's kernel clock, which in WSL can drift from Windows'.
fn clock_offset(docker: &Docker, container: &str) -> Result<i64> {
    let before = now_ms();
    let out = docker.run_for(&["exec", container, "date", "+%s%N"], Duration::from_secs(20))?;
    let after = now_ms();
    let ns = out.trim().parse::<i64>().context("reading the lab clock")?;
    if ns < 1_000_000_000_000_000_000 {
        bail!("the lab clock reads {ns}: not nanoseconds (a date without %N?)");
    }
    let lab_ms = ns / 1_000_000;
    Ok(lab_ms - (before + after) / 2)
}

fn run_cell(docker: &Docker, root: &Path, sc: &Scenario, cell: &Cell, lab_id: &str, cdir: &Path, keep: bool) -> Result<CellResult> {
    let mut set = cell.recipe.set.clone();
    if let Some(v) = &cell.variant {
        set.extend(v.set.clone());
    }
    let rdef = recipe::load(root, &cell.recipe.use_)?;
    let base = match sc.base.as_deref().or(rdef.base.as_deref()) {
        Some(b) => Base::parse(b)?,
        None => Base::Alpine,
    };
    let opts = UpOptions {
        base,
        port: sc.port.unwrap_or(lab::DEFAULT_PORT),
        blob_mb: sc.blob_mb.unwrap_or(lab::DEFAULT_BLOB_MB),
        recipe: Some(RecipeUse::new(&cell.recipe.use_, set)),
        force: true,
    };
    // A lab left over from an interrupted run would hold the names.
    let _ = lab::down(docker, root, lab_id);
    let info = lab::up(docker, root, lab_id, &opts)?;
    let result = drive_cell(docker, root, sc, cell, &info, &rdef, cdir);
    if !keep {
        if let Err(e) = lab::down(docker, root, lab_id) {
            println!("  note: lab down failed: {e:#}");
        }
    } else {
        println!("  lab {lab_id} left running: wirelab lab panel --id {lab_id}");
    }
    result
}

fn drive_cell(docker: &Docker, root: &Path, sc: &Scenario, cell: &Cell, info: &LabInfo, rdef: &recipe::Recipe, cdir: &Path) -> Result<CellResult> {
    let resolved = info.recipe.clone().unwrap_or_default();
    let version = rdef.version_param.as_ref().and_then(|p| resolved.resolved.get(p).cloned());
    let mut res = CellResult {
        index: cell.index,
        recipe_label: cell.recipe.label(),
        variant: cell.variant.as_ref().map(|v| v.label.clone()),
        path: cell.path.label.clone(),
        censor: cell.censor.clone(),
        recipe: resolved,
        version,
        dir: cdir.to_path_buf(),
        session: info.session.clone(),
        error: None,
        connect: None,
        workloads: Vec::new(),
        censor_hits: Vec::new(),
        capture: None,
        throughput: None,
    };
    // The client has coreutils' date (busybox's in the wire ignores %N);
    // all containers share the kernel clock.
    let offset = clock_offset(docker, &info.client)?;
    let wire = Wire::open(docker, info)?;
    let log = |line: &str| append(&info.session.join("wire-changes.log"), line);

    if sc.capture {
        docker.run_for(
            &["exec", "-d", &info.wire, "sh", "-c", &format!(
                "tcpdump -i {} -U -s {} -B 16384 -w /tmp/wire.pcap 'net 10.77.0.0/16' 2> /tmp/wire-tcpdump.log",
                wire.if_to_client, sc.snaplen
            )],
            Duration::from_secs(30),
        )?;
    }

    // The censor and the path are in place before either side starts
    // talking: the censor judges the handshake.
    if cell.censor != "off" {
        if !info.censor {
            bail!("censor {} asked for, but wl-censor is not built ({}); `wirelab doctor` says how", cell.censor, lab::CENSOR_BIN);
        }
        let (preset, note) = wirectl::build_preset(&root.join("containers/censor/presets"), &cell.censor, &[], &HashMap::new())?;
        wirectl::activate_preset(&info.session, Some(&preset))?;
        log(&note);
    }
    let path = cell.path.req();
    wire.apply(&path, log)?;

    let setup = wait_setup(info, Duration::from_secs(sc.setup_timeout_s));
    for node in ["client", "server"] {
        let _ = fs::copy(info.dir.join(node).join("setup.log"), cdir.join(format!("{node}-setup.log")));
    }
    let t_connect = now_ms() + offset;
    let proxy = rdef.proxy.clone().unwrap_or_else(|| "-".into());
    match setup {
        Err(e) => {
            res.error = Some(format!("{e:#}"));
            println!("  setup failed: {e:#}");
        }
        Ok(()) => {
            let conn = run_probe(docker, info, &proxy, sc.connect_timeout_s);
            println!("  connect: {} {}", conn.verdict.as_str(), conn.checks.join("; "));
            let connected = conn.verdict == Verdict::Pass;
            res.connect = Some(conn);
            for w in sc.workload.iter().filter(|w| w.applies(&cell.recipe.label(), &cell.path.label, &cell.censor)) {
                let r = if connected {
                    run_workload(docker, info, &wire, &path, rdef, &proxy, w, offset)
                } else {
                    no_data(w, "the client never connected")
                };
                println!("  {}: {} {}", r.label, r.verdict.as_str(), r.checks.join("; "));
                res.workloads.push(r);
            }
        }
    }

    // Recipe logs (ostp.log, xray.log...) from both nodes.
    for node in ["client", "server"] {
        if let Ok(rd) = fs::read_dir(info.dir.join(node)) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.ends_with(".log") && name != "setup.log" {
                    let _ = fs::copy(e.path(), cdir.join(format!("{node}-{name}")));
                }
            }
        }
    }

    if sc.capture {
        let _ = docker.run_for(&["exec", &info.wire, "pkill", "-INT", "tcpdump"], Duration::from_secs(20));
        std::thread::sleep(Duration::from_millis(700));
        let dest = docker.daemon_path(cdir)?;
        docker
            .run_for(&["cp", &format!("{}:/tmp/wire.pcap", info.wire), &format!("{dest}/wire.pcap")], Duration::from_secs(300))
            .context("copying the capture out of the wire")?;
        let pcap = cdir.join("wire.pcap");
        let (bin_ms, lag_s) = sc.crts.as_ref().and_then(|c| c.ct007.as_ref()).map_or((50, 30), |c| (c.bin_ms, c.max_lag_s));
        analyze_capture(&pcap, &mut res, t_connect, info.server_port, bin_ms * 1000, lag_s * 1_000_000)?;
        let censor_log = info.session.join("censor.jsonl");
        let note = format!("wirelab lab test, cell {}", res.name());
        let summary = export::pcapng_with_decisions(&pcap, censor_log.is_file().then_some(censor_log.as_path()), &cdir.join("wire.pcapng"), &note)?;
        res.capture = Some(summary);
        // The pcapng holds the same frames and the decisions on top.
        let _ = fs::remove_file(&pcap);
    }
    for f in ["censor.jsonl", "wire-changes.log", "censor-preset.json"] {
        let _ = fs::copy(info.session.join(f), cdir.join(f));
    }
    res.censor_hits = censor_hits(&info.session.join("censor.jsonl"), t_connect);
    if let Some(h) = res.censor_hits.first() {
        println!("  censor: {} {} at {:.1} s ({} hit(s))", h.rule, h.action, h.t_s, res.censor_hits.len());
    }
    Ok(res)
}

fn append(path: &Path, line: &str) {
    use std::io::Write;
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{} {line}", now_ms());
    }
}

/// Both nodes' setup.sh have exited 0.
fn wait_setup(info: &LabInfo, limit: Duration) -> Result<()> {
    let start = Instant::now();
    let mut done: HashMap<&str, i32> = HashMap::new();
    loop {
        for node in ["client", "server"] {
            if done.contains_key(node) {
                continue;
            }
            let log = fs::read_to_string(info.dir.join(node).join("setup.log")).unwrap_or_default();
            if let Some(l) = log.lines().rev().find(|l| l.starts_with("--- setup.sh exited ")) {
                done.insert(node, l.trim_start_matches("--- setup.sh exited ").trim().parse().unwrap_or(-1));
            }
        }
        if done.len() == 2 {
            break;
        }
        if start.elapsed() > limit {
            let missing: Vec<&str> = ["client", "server"].into_iter().filter(|n| !done.contains_key(n)).collect();
            bail!("setup.sh on {} did not finish within {} s; see {}-setup.log", missing.join(" and "), limit.as_secs(), missing[0]);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let failed: Vec<String> = done.iter().filter(|(_, &c)| c != 0).map(|(n, c)| format!("{n} (exit {c})")).collect();
    if !failed.is_empty() {
        bail!("setup.sh failed on {}; see the setup logs in the cell folder", failed.join(", "));
    }
    Ok(())
}

/// Run workload.sh in the client between two readings of the lab clock.
fn exec_workload(docker: &Docker, info: &LabInfo, args: &[String], limit: Duration) -> (i64, i64, Result<serde_json::Value>) {
    let script = "t0=$(date +%s%N); sh /wl-node/workload.sh \"$@\"; echo \"WLT $t0 $(date +%s%N)\"";
    let mut a: Vec<&str> = vec!["exec", &info.client, "sh", "-c", script, "workload"];
    a.extend(args.iter().map(String::as_str));
    let out = docker.run_for(&a, limit);
    let (mut t0, mut t1) = (0, 0);
    let res = out.and_then(|text| {
        let mut json = None;
        for l in text.lines() {
            if let Some(rest) = l.strip_prefix("WLT ") {
                let mut it = rest.split_whitespace().map(|v| v.parse::<i64>().unwrap_or(0) / 1_000_000);
                t0 = it.next().unwrap_or(0);
                t1 = it.next().unwrap_or(0);
            } else if l.starts_with('{') {
                json = Some(serde_json::from_str::<serde_json::Value>(l).with_context(|| format!("workload printed {l:?}"))?);
            }
        }
        json.with_context(|| format!("the workload printed no result: {}", text.trim()))
    });
    (t0, t1, res)
}

fn blank(label: &str, kind: Kind) -> WorkResult {
    WorkResult {
        label: label.into(),
        kind,
        verdict: Verdict::Info,
        checks: Vec::new(),
        metric: None,
        measured: BTreeMap::new(),
        raw: serde_json::Value::Null,
        t0_ms: 0,
        t1_ms: 0,
        outages_ms: Vec::new(),
        capture: None,
    }
}

fn no_data(w: &Workload, why: &str) -> WorkResult {
    let mut r = blank(&w.label(), w.kind);
    r.verdict = Verdict::NoData;
    r.checks.push(why.into());
    r
}

/// Combine checks: any failure fails; otherwise a missing measurement is
/// NO DATA; otherwise PASS when something was checked.
struct Checks {
    list: Vec<String>,
    fail: bool,
    nodata: bool,
    any: bool,
}

impl Checks {
    fn new() -> Checks {
        Checks { list: Vec::new(), fail: false, nodata: false, any: false }
    }
    fn check(&mut self, ok: bool, text: String) {
        self.any = true;
        if !ok {
            self.fail = true;
        }
        self.list.push(format!("{} {text}", if ok { "ok" } else { "FAILED" }));
    }
    fn missing(&mut self, text: String) {
        self.nodata = true;
        self.list.push(format!("no data: {text}"));
    }
    fn note(&mut self, text: String) {
        self.list.push(text);
    }
    fn verdict(&self) -> Verdict {
        if self.fail {
            Verdict::Fail
        } else if self.nodata {
            Verdict::NoData
        } else if self.any {
            Verdict::Pass
        } else {
            Verdict::Info
        }
    }
}

fn run_probe(docker: &Docker, info: &LabInfo, proxy: &str, timeout_s: u64) -> WorkResult {
    let args = vec!["probe".into(), proxy.into(), "http://target.lab/obj/1".into(), timeout_s.to_string()];
    let (t0, t1, out) = exec_workload(docker, info, &args, Duration::from_secs(timeout_s + 30));
    let mut r = blank("connect", Kind::Chat);
    r.t0_ms = t0;
    r.t1_ms = t1;
    let mut c = Checks::new();
    match out {
        Ok(v) => {
            let ok = v["ok"].as_bool().unwrap_or(false);
            let ms = v["ms"].as_f64().unwrap_or(0.0);
            c.check(ok, format!("first request through the tunnel after {:.1} s{}", ms / 1000.0, v["error"].as_str().map(|e| format!(" ({e})")).unwrap_or_default()));
            if ok {
                r.metric = Some(Metric { name: "connect".into(), value: ms, unit: "ms".into(), higher_is_better: false });
            }
            r.measured.insert("ms".into(), ms);
            r.raw = v;
        }
        Err(e) => c.missing(format!("{e:#}")),
    }
    r.verdict = c.verdict();
    r.checks = c.list;
    r
}

fn run_workload(docker: &Docker, info: &LabInfo, wire: &Wire, path: &PathReq, rdef: &recipe::Recipe, proxy: &str, w: &Workload, offset: i64) -> WorkResult {
    let label = w.label();
    // Under a censor a transfer can hang until curl gives up: keep it bounded.
    let max_s = w.max_s.unwrap_or(match w.kind {
        Kind::Web => 120,
        _ => 300,
    });
    let name = format!("wl-{}-{}", label.replace(|c: char| !c.is_ascii_alphanumeric(), "-"), now_ms());
    let blob = info.blob_mb as u64 * 1_000_000;
    let args: Vec<String> = match w.kind {
        Kind::Down => vec!["down".into(), proxy.into(), "http://target.lab/blob".into(), max_s.to_string()],
        Kind::Up => vec!["up".into(), proxy.into(), "http://target.lab".into(), (w.bytes_mb.unwrap_or(20) as u64 * 1_000_000).to_string(), name.clone(), max_s.to_string()],
        Kind::Web => vec!["web".into(), proxy.into(), "http://target.lab".into(), w.rounds.unwrap_or(3).to_string(), w.parallel.unwrap_or(6).to_string(), max_s.to_string()],
        Kind::Stream => {
            let bytes_per_s = (w.rate_kbit.unwrap_or(4000.0) * 1000.0 / 8.0) as u64;
            vec!["stream".into(), proxy.into(), "http://target.lab/blob".into(), bytes_per_s.to_string(), w.seconds.unwrap_or(30).to_string()]
        }
        Kind::Chat => vec!["chat".into(), proxy.into(), "http://target.lab/obj/1".into(), w.count.unwrap_or(30).to_string(), w.interval_s.unwrap_or(2.0).to_string()],
        Kind::Idle => Vec::new(),
        Kind::Unauth => vec!["unauth".into(), lab::SERVER_IP.into(), info.server_port.to_string()],
    };

    // A slow site: the target's link, both ways.
    if let Some(k) = w.target_rate_kbit {
        if let Err(e) = target_rate(docker, info, Some(k)) {
            let mut r = no_data(w, &format!("could not slow the target: {e:#}"));
            r.label = label;
            return r;
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    // Memory of the server process, read every second.
    let rss: Arc<Mutex<Option<f64>>> = Arc::new(Mutex::new(None));
    let rss_thread = match (&w.max_server_rss_mb, rdef.server_process.as_deref().filter(|p| !p.is_empty())) {
        (Some(_), Some(proc_)) => {
            let (d, c, s, m, p) = (docker.clone(), info.server.clone(), stop.clone(), rss.clone(), proc_.to_string());
            Some(std::thread::spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    if let Ok(out) = d.run_for(&["exec", &c, "ps", "-C", &p, "-o", "rss="], Duration::from_secs(10)) {
                        let kb: f64 = out.split_whitespace().filter_map(|v| v.parse::<f64>().ok()).sum();
                        if kb > 0.0 {
                            let mb = kb / 1024.0;
                            let mut g = m.lock().unwrap();
                            *g = Some(g.map_or(mb, |x: f64| x.max(mb)));
                        }
                    }
                    std::thread::sleep(Duration::from_millis(1000));
                }
            }))
        }
        _ => None,
    };
    // Outages: cut the path, then put it back as it was.
    let outages: Arc<Mutex<Vec<(i64, i64)>>> = Arc::new(Mutex::new(Vec::new()));
    let outage_thread = (!w.outage.is_empty()).then(|| {
        let (wire, path, list, plan, s) = (wire.clone(), path.clone(), outages.clone(), w.outage.clone(), stop.clone());
        let log_path = info.session.join("wire-changes.log");
        std::thread::spawn(move || {
            let start = Instant::now();
            for o in plan {
                let at = Duration::from_secs_f64(o.at_s);
                while start.elapsed() < at {
                    if s.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let t_cut = now_ms() + offset;
                let _ = wire.apply(&path.cut(), |l| append(&log_path, &format!("outage: {l}")));
                std::thread::sleep(Duration::from_secs_f64(o.for_s));
                let _ = wire.apply(&path, |l| append(&log_path, &format!("outage over: {l}")));
                list.lock().unwrap().push((t_cut, now_ms() + offset));
            }
        })
    });

    let (t0, t1, out) = if w.kind == Kind::Idle {
        let t0 = now_ms() + offset;
        std::thread::sleep(Duration::from_secs(w.seconds.unwrap_or(60)));
        (t0, now_ms() + offset, Ok(serde_json::json!({})))
    } else {
        let limit = match w.kind {
            Kind::Chat => (w.count.unwrap_or(30) as f64 * (w.interval_s.unwrap_or(2.0) + 11.0)) as u64 + 30,
            Kind::Stream => w.seconds.unwrap_or(30) + 60,
            _ => max_s + 60,
        };
        exec_workload(docker, info, &args, Duration::from_secs(limit))
    };
    stop.store(true, Ordering::Relaxed);
    if let Some(t) = outage_thread {
        let _ = t.join();
    }
    if let Some(t) = rss_thread {
        let _ = t.join();
    }
    if w.target_rate_kbit.is_some() {
        let _ = target_rate(docker, info, None);
    }

    let mut r = blank(&label, w.kind);
    r.t0_ms = t0;
    r.t1_ms = t1;
    r.outages_ms = outages.lock().unwrap().clone();
    let mut c = Checks::new();
    let v = match out {
        Ok(v) => v,
        Err(e) => {
            c.missing(format!("{e:#}"));
            r.verdict = c.verdict();
            r.checks = c.list;
            return r;
        }
    };
    let f = |k: &str| v[k].as_f64().unwrap_or(0.0);
    let mbps = |bytes: f64, secs: f64| if secs > 0.0 { bytes * 8.0 / secs / 1e6 } else { 0.0 };
    match w.kind {
        Kind::Down => {
            let (bytes, secs) = (f("bytes"), f("seconds"));
            let sha = v["sha256"].as_str().unwrap_or("");
            let want = v["expected_sha256"].as_str().unwrap_or("");
            let intact = f("http") == 200.0 && bytes as u64 == blob && !want.is_empty() && sha == want;
            c.check(intact, format!("{:.1} of {:.1} MB, sha256 {}{}", bytes / 1e6, blob as f64 / 1e6, if sha == want && !want.is_empty() { "matches" } else { "differs" },
                v["error"].as_str().filter(|e| !e.is_empty()).map(|e| format!(" ({e})")).unwrap_or_default()));
            let rate = mbps(bytes, secs);
            if intact {
                r.metric = Some(Metric { name: "download".into(), value: rate, unit: "Mbit/s".into(), higher_is_better: true });
            }
            if let Some(min) = w.min_mbps {
                c.check(rate >= min, format!("{rate:.1} Mbit/s, at least {min} required"));
            } else {
                c.note(format!("{rate:.1} Mbit/s over {secs:.1} s"));
            }
            r.measured.insert("mbps".into(), rate);
            r.measured.insert("seconds".into(), secs);
        }
        Kind::Up => {
            let (bytes, secs) = (f("bytes"), f("seconds"));
            let sent_sha = v["sha256"].as_str().unwrap_or("").to_string();
            let http = f("http");
            let remote = docker
                .run_for(
                    &["exec", &info.server, "sh", "-c", &format!(
                        "curl -s --max-time 120 http://target.lab/up/{name} | sha256sum | cut -c1-64; curl -s -o /dev/null -X DELETE http://target.lab/up/{name}"
                    )],
                    Duration::from_secs(180),
                )
                .map(|s| s.trim().to_string());
            match remote {
                Ok(got) => {
                    let intact = (http == 201.0 || http == 204.0) && got == sent_sha;
                    c.check(intact, format!("{:.1} MB sent (HTTP {http}), sha256 on the target {}", bytes / 1e6, if got == sent_sha { "matches" } else { "differs" }));
                    if intact {
                        r.metric = Some(Metric { name: "upload".into(), value: mbps(bytes, secs), unit: "Mbit/s".into(), higher_is_better: true });
                    }
                }
                Err(e) => c.missing(format!("reading the upload back on the target: {e:#}")),
            }
            let rate = mbps(bytes, secs);
            if let Some(min) = w.min_mbps {
                c.check(rate >= min, format!("{rate:.1} Mbit/s, at least {min} required"));
            } else {
                c.note(format!("{rate:.1} Mbit/s over {secs:.1} s"));
            }
            r.measured.insert("mbps".into(), rate);
            r.measured.insert("seconds".into(), secs);
        }
        Kind::Web => {
            let (objects, ok, ms) = (f("objects"), f("ok"), f("ms"));
            c.check(objects > 0.0 && ok == objects, format!("{ok} of {objects} objects intact"));
            if let Some(max) = w.max_s {
                c.check(ms / 1000.0 <= max as f64, format!("{:.1} s, at most {max} s allowed", ms / 1000.0));
            }
            r.metric = Some(Metric { name: "page set".into(), value: ms / 1000.0, unit: "s".into(), higher_is_better: false });
            r.measured.insert("seconds".into(), ms / 1000.0);
        }
        Kind::Stream => {
            let want = w.rate_kbit.unwrap_or(4000.0);
            let secs = f("seconds");
            // Time to first byte is setup, not streaming.
            let got = if secs - f("ttfb") > 0.0 { f("bytes") * 8.0 / 1000.0 / (secs - f("ttfb")) } else { 0.0 };
            let share = w.min_share.unwrap_or(0.9);
            c.check(got >= want * share, format!("{got:.0} kbit/s held, {:.0}% of {want:.0} required", share * 100.0));
            r.metric = Some(Metric { name: "stream".into(), value: got, unit: "kbit/s".into(), higher_is_better: true });
            r.measured.insert("kbps".into(), got);
        }
        Kind::Chat => {
            let (sent, ok) = (f("sent"), f("ok"));
            let mut ms: Vec<f64> = v["ms"].as_array().map(|a| a.iter().filter_map(|x| x.as_f64()).collect()).unwrap_or_default();
            ms.sort_by(|a, b| a.total_cmp(b));
            c.check(sent > 0.0 && ok == sent, format!("{ok} of {sent} messages answered"));
            if !ms.is_empty() {
                let pct = |p: f64| ms[((ms.len() - 1) as f64 * p).round() as usize];
                let (p50, p95) = (pct(0.5), pct(0.95));
                if let Some(max) = w.max_p95_ms {
                    c.check(p95 <= max, format!("p95 {p95:.0} ms, at most {max} ms allowed (p50 {p50:.0} ms)"));
                } else {
                    c.note(format!("p50 {p50:.0} ms, p95 {p95:.0} ms"));
                }
                r.metric = Some(Metric { name: "p95".into(), value: p95, unit: "ms".into(), higher_is_better: false });
                r.measured.insert("p50_ms".into(), p50);
                r.measured.insert("p95_ms".into(), p95);
            }
        }
        Kind::Idle => c.note(format!("{} s with no traffic of its own", w.seconds.unwrap_or(60))),
        Kind::Unauth => c.note("probes sent; the CRTS export reads the answers from the capture".into()),
    }
    if let Some(max) = w.max_server_rss_mb {
        match *rss.lock().unwrap() {
            Some(mb) => {
                c.check(mb <= max, format!("server memory peaked at {mb:.0} MB, at most {max} MB allowed"));
                r.measured.insert("server_rss_mb".into(), mb);
            }
            None => c.missing(match rdef.server_process.as_deref().filter(|p| !p.is_empty()) {
                Some(p) => format!("no {p} process found to read memory from"),
                None => format!("recipe {} names no server process", rdef.name),
            }),
        }
    }
    if !r.outages_ms.is_empty() {
        c.note(format!("{} outage(s) during the transfer", r.outages_ms.len()));
    }
    r.raw = v;
    r.verdict = c.verdict();
    r.checks = c.list;
    r
}

/// netem rate on the target's link: the target's own egress (towards the
/// server) and the server's egress towards the target. `None` removes both.
fn target_rate(docker: &Docker, info: &LabInfo, kbit: Option<f64>) -> Result<()> {
    let target = format!("{}-target", info.project);
    let dev_of = "$(ip -o route get 10.77.3.10 | sed -E 's/.* dev ([^ ]+).*/\\1/')";
    let dev_target = "$(ip -o route get 10.77.3.2 | sed -E 's/.* dev ([^ ]+).*/\\1/')";
    let cmd = |dev: &str| match kbit {
        Some(k) => {
            let args = wirectl::netem_args(&wirectl::NetemReq { delay_ms: 0.0, jitter_ms: 0.0, loss_pct: 0.0, duplicate_pct: 0.0, corrupt_pct: 0.0, rate_kbit: k }).unwrap_or_default();
            format!("tc qdisc replace dev {dev} root netem {}", args.join(" "))
        }
        None => format!("tc qdisc del dev {dev} root 2> /dev/null; true"),
    };
    docker.run_for(&["exec", &info.server, "sh", "-c", &cmd(dev_of)], Duration::from_secs(20))?;
    docker.run_for(&["exec", &target, "sh", "-c", &cmd(dev_target)], Duration::from_secs(20))?;
    Ok(())
}

/// Rule hits from the censor's log, timed from the first connection attempt.
fn censor_hits(log: &Path, t0_ms: i64) -> Vec<CensorHit> {
    let Ok(text) = fs::read_to_string(log) else { return Vec::new() };
    text.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["rule"].as_str().is_some_and(|r| r != "-") && v["action"] != "expired")
        .map(|v| CensorHit {
            t_s: (v["t"].as_i64().unwrap_or(0) - t0_ms) as f64 / 1000.0,
            rule: v["rule"].as_str().unwrap_or_default().into(),
            action: v["action"].as_str().unwrap_or_default().into(),
            flow: v["flow"].as_str().unwrap_or_default().into(),
            detail: v["detail"].as_str().unwrap_or_default().into(),
        })
        .collect()
}

/// Client source ports of the unauthenticated probes (workload.sh).
const PROBE_PORTS: std::ops::RangeInclusive<u16> = 40101..=40104;

fn analyze_capture(pcap: &Path, res: &mut CellResult, t0_ms: i64, port: u16, bin_us: u64, max_lag_us: u64) -> Result<()> {
    let bytes = fs::read(pcap).with_context(|| format!("reading {}", pcap.display()))?;
    let (linktype, records) = read_pcap_records(&bytes)?;
    let server: std::net::Ipv4Addr = lab::SERVER_IP.parse().unwrap();
    let mut tp = Throughput::default();
    let mut tunnel: Vec<(Way, Packet)> = Vec::new();
    for rec in &records {
        let Ok(Some(p)) = parse_record(linktype, rec) else { continue };
        let way = if p.dst == server { Way::C2s } else if p.src == server { Way::S2c } else { continue };
        tp.add(t0_ms.max(0) as u64 * 1000, way, &p);
        let (cport, sport) = match way {
            Way::C2s => (p.sport, p.dport),
            Way::S2c => (p.dport, p.sport),
        };
        if sport == port && !matches!(p.transport, Transport::Icmp(..)) {
            tunnel.push((way, p.clone()));
            let _ = cport;
        }
    }
    res.throughput = Some(tp);
    for w in &mut res.workloads {
        if w.t0_ms == 0 || w.t1_ms <= w.t0_ms {
            continue;
        }
        let (a, b) = (w.t0_ms as u64 * 1000, w.t1_ms as u64 * 1000);
        let in_window = |(_, p): &&(Way, Packet)| p.t_us >= a && p.t_us <= b;
        let mut st = WindowStats::default();
        if w.kind == Kind::Unauth {
            for (i, cp) in PROBE_PORTS.enumerate() {
                let class = ["udp-random-64", "udp-random-1200", "tcp-random-512", "tcp-http-get"][i];
                let tcp = class.starts_with("tcp");
                let size = |p: &Packet| if tcp { p.payload_len as u64 } else { p.ip_len as u64 };
                let mut sent = 0;
                let mut answered = 0;
                for (way, p) in tunnel.iter().filter(in_window) {
                    match way {
                        Way::C2s if p.sport == cp => sent += size(p),
                        Way::S2c if p.dport == cp => answered += size(p),
                        _ => {}
                    }
                }
                if sent > 0 {
                    st.amplification.push(Amplification {
                        class: class.into(),
                        proto: if tcp { "tcp" } else { "udp" }.into(),
                        sent,
                        answered,
                        ratio: answered as f64 / sent as f64,
                    });
                }
            }
        } else {
            for (name, way) in [("c2s", Way::C2s), ("s2c", Way::S2c)] {
                let pk: Vec<&Packet> = tunnel
                    .iter()
                    .filter(in_window)
                    .filter(|(w2, p)| *w2 == way && !(PROBE_PORTS.contains(&p.sport) || PROBE_PORTS.contains(&p.dport)))
                    .map(|(_, p)| p)
                    .collect();
                // Lengths of what the protocol sends: transport payloads,
                // not the carrier's bare ACKs.
                let lens: Vec<usize> = pk.iter().map(|p| p.payload_len).filter(|&l| l > 0).collect();
                if let Some(s) = length_stats(&lens) {
                    st.lengths.insert(name.into(), s);
                }
                if matches!(w.kind, Kind::Idle | Kind::Chat) {
                    let times: Vec<u64> = pk.iter().filter(|p| p.payload_len > 0).map(|p| p.t_us).collect();
                    if let Some(pr) = periodicity(&times, bin_us, 2 * bin_us, max_lag_us) {
                        st.periodicity.insert(name.into(), pr);
                    }
                }
            }
        }
        w.capture = Some(st);
    }
    Ok(())
}

// ------------------------------------------------------------------ report

fn utc_stamp() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (d, s) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = d as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60)
}

pub fn utc_now() -> String {
    utc_stamp()
}

fn cell_text(w: &WorkResult) -> String {
    match &w.metric {
        Some(m) => format!("{} {}", w.verdict.as_str(), fmt_metric(m)),
        None => w.verdict.as_str().to_string(),
    }
}

fn fmt_metric(m: &Metric) -> String {
    let v = if m.value >= 100.0 { format!("{:.0}", m.value) } else { format!("{:.1}", m.value) };
    format!("{v} {}", m.unit)
}

pub fn render_report(run: &RunResult, sc: &Scenario) -> String {
    let mut o = String::new();
    o.push_str(&format!("# wirelab lab test: {}\n\n", run.scenario));
    if !run.about.is_empty() {
        o.push_str(&format!("{}\n\n", run.about));
    }
    let (pass, fail, nodata) = run.cells.iter().flat_map(|c| c.connect.iter().chain(&c.workloads)).fold((0, 0, 0), |(p, f, n), w| match w.verdict {
        Verdict::Pass => (p + 1, f, n),
        Verdict::Fail => (p, f + 1, n),
        Verdict::NoData => (p, f, n + 1),
        Verdict::Info => (p, f, n),
    });
    let errors = run.cells.iter().filter(|c| c.error.is_some()).count();
    o.push_str(&format!(
        "Started {} · wirelab {} · {} cell(s): {pass} PASS, {fail} FAIL, {nodata} NO DATA{}\n\n",
        run.started,
        run.wirelab,
        run.cells.len(),
        if errors > 0 { format!(", {errors} cell(s) could not run") } else { String::new() }
    ));

    let labels: Vec<String> = sc.workload.iter().map(|w| w.label()).collect();
    o.push_str("| # | recipe | version | path | censor | connect |");
    for l in &labels {
        o.push_str(&format!(" {l} |"));
    }
    o.push_str(" censor fired |\n|---|---|---|---|---|---|");
    for _ in &labels {
        o.push_str("---|");
    }
    o.push_str("---|\n");
    for c in &run.cells {
        let ver = match (&c.variant, &c.version) {
            (Some(v), Some(x)) if v != x => format!("{v} ({x})"),
            (Some(v), _) => v.clone(),
            (None, Some(x)) => x.clone(),
            (None, None) => "-".into(),
        };
        o.push_str(&format!("| {} | {} | {} | {} | {} | ", c.index, c.recipe_label, ver, c.path, c.censor));
        o.push_str(&match (&c.error, &c.connect) {
            (Some(_), _) => "ERROR".into(),
            (None, Some(w)) => cell_text(w),
            (None, None) => "-".into(),
        });
        o.push_str(" |");
        for l in &labels {
            let t = c.workloads.iter().find(|w| &w.label == l).map(cell_text).unwrap_or_else(|| "".into());
            o.push_str(&format!(" {t} |"));
        }
        let fired = match c.censor_hits.first() {
            Some(h) => format!("{} {} at {:.1} s", h.rule, h.action, h.t_s),
            None if c.censor == "off" => "".into(),
            None => "nothing".into(),
        };
        o.push_str(&format!(" {fired} |\n"));
    }

    // A/B: the same cell under each variant, against the first one.
    if sc.variant.len() > 1 {
        o.push_str("\n## Versions side by side\n\nDifference against the first version; + is better.\n\n");
        let first = &sc.variant[0].label;
        o.push_str("| recipe | path | censor | workload |");
        for v in &sc.variant {
            o.push_str(&format!(" {} |", v.label));
        }
        o.push_str("\n|---|---|---|---|");
        for _ in &sc.variant {
            o.push_str("---|");
        }
        o.push('\n');
        let mut keys: Vec<(String, String, String)> = run.cells.iter().map(|c| (c.recipe_label.clone(), c.path.clone(), c.censor.clone())).collect();
        keys.dedup();
        for (rl, p, cz) in keys {
            for l in labels.iter().map(String::as_str).chain(["connect"]) {
                let get = |v: &str| {
                    run.cells
                        .iter()
                        .find(|c| c.recipe_label == rl && c.path == p && c.censor == cz && c.variant.as_deref() == Some(v))
                        .and_then(|c| if l == "connect" { c.connect.as_ref() } else { c.workloads.iter().find(|w| w.label == l) })
                };
                if sc.variant.iter().all(|v| get(&v.label).is_none()) {
                    continue;
                }
                let base = get(first).and_then(|w| w.metric.clone());
                o.push_str(&format!("| {rl} | {p} | {cz} | {l} |"));
                for v in &sc.variant {
                    let cell = match get(&v.label) {
                        None => String::new(),
                        Some(w) => {
                            let mut t = cell_text(w);
                            if let (Some(b), Some(m)) = (&base, &w.metric) {
                                if v.label != *first && b.value != 0.0 {
                                    let mut d = (m.value - b.value) / b.value * 100.0;
                                    if !m.higher_is_better {
                                        d = -d;
                                    }
                                    t.push_str(&format!(" ({d:+.0}%)"));
                                }
                            }
                            t
                        }
                    };
                    o.push_str(&format!(" {cell} |"));
                }
                o.push('\n');
            }
        }
    }

    o.push_str("\n## Cells\n");
    for c in &run.cells {
        o.push_str(&format!("\n### {}. {}\n\n", c.index, c.name()));
        if !c.recipe.resolved.is_empty() {
            let kv: Vec<String> = c
                .recipe
                .resolved
                .iter()
                .filter(|(k, _)| !k.contains("key") && *k != "id" && *k != "short_id")
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            o.push_str(&format!("Recipe {}: {}\n\n", c.recipe.name, kv.join(", ")));
        }
        if let Some(e) = &c.error {
            o.push_str(&format!("Could not run: {e}\n\n"));
        }
        for w in c.connect.iter().chain(&c.workloads) {
            o.push_str(&format!("- **{}** {}: {}\n", w.label, w.verdict.as_str(), w.checks.join("; ")));
            if let Some(st) = &w.capture {
                for (d, l) in &st.lengths {
                    o.push_str(&format!(
                        "  - {d} payload lengths: {} packets, mode {} B at {:.0}%{}\n",
                        l.packets,
                        l.mode_len,
                        l.mode_share * 100.0,
                        l.step.map(|s| format!(", {:.0}% on multiples of {s}", l.step_share * 100.0)).unwrap_or_default()
                    ));
                }
                for (d, p) in &st.periodicity {
                    o.push_str(&format!("  - {d} periodicity: peak {:.2} at {:.0} ms over {} packets\n", p.peak, p.peak_lag_ms, p.packets));
                }
                for a in &st.amplification {
                    o.push_str(&format!("  - probe {}: {} B sent, {} B answered (×{:.2})\n", a.class, a.sent, a.answered, a.ratio));
                }
            }
        }
        if !c.censor_hits.is_empty() {
            o.push_str("\nCensor decisions:\n\n");
            for h in c.censor_hits.iter().take(20) {
                o.push_str(&format!("- {:.1} s {} {} {} — {}\n", h.t_s, h.rule, h.action, h.flow, h.detail));
            }
            if c.censor_hits.len() > 20 {
                o.push_str(&format!("- … {} more in censor.jsonl\n", c.censor_hits.len() - 20));
            }
        }
        if let Some(s) = &c.capture {
            o.push_str(&format!(
                "\nCapture: {} packets in wire.pcapng; {} censor decision(s) on their packets, {} on their flow, {} unplaced.\n",
                s.packets, s.on_packet, s.on_flow, s.unplaced
            ));
        }
        o.push_str(&format!("\nFiles: {}\n", c.dir.display()));
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_parses_and_expands() {
        let sc: Scenario = toml::from_str(
            r#"
            name = "t"
            censor = ["off", "ru-tspu.json"]
            [[recipe]]
            use = "ostp"
            label = "udp"
            set = { transport = "udp" }
            [[variant]]
            label = "a"
            [[variant]]
            label = "b"
            [[path]]
            label = "clean"
            [[path]]
            label = "fast"
            rtt_ms = 35
            loss_pct = 0.01
            rate_kbit = 300000
            [[workload]]
            kind = "down"
            min_mbps = 50
            paths = ["fast"]
            outage = [{ at_s = 5, for_s = 5 }]
            [crts]
            ct006 = { max_mode_share = 0.5 }
            "#,
        )
        .unwrap();
        sc.check().unwrap();
        assert_eq!(sc.variants().len() * sc.censor.len() * sc.paths().len(), 8);
        let w = &sc.workload[0];
        assert!(w.applies("udp", "fast", "off"));
        assert!(!w.applies("udp", "clean", "off"));
    }

    #[test]
    fn unknown_fields_are_refused() {
        let r: Result<Scenario, _> = toml::from_str(
            r#"
            name = "t"
            [[recipe]]
            use = "ostp"
            [[workload]]
            kind = "down"
            min_mpbs = 50
            "#,
        );
        assert!(r.is_err());
    }

    #[test]
    fn checks_combine() {
        let mut c = Checks::new();
        c.check(true, "a".into());
        assert_eq!(c.verdict(), Verdict::Pass);
        c.missing("b".into());
        assert_eq!(c.verdict(), Verdict::NoData);
        c.check(false, "c".into());
        assert_eq!(c.verdict(), Verdict::Fail);
    }

    #[test]
    fn stamp_is_iso() {
        let s = utc_stamp();
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z'));
    }
}
