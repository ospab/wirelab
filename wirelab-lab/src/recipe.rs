//! Protocol recipes: everything a lab needs to run one protocol on both
//! sides without anyone typing into the consoles.
//!
//! A recipe is a folder `recipes/<name>/` with
//!
//! - `recipe.toml`: what it is, its parameters with defaults, the files to
//!   fetch (release archives, local builds), and how the client reaches the
//!   target (a local proxy, or routed through the tunnel);
//! - `client.sh` and `server.sh`: installed as `/lab/setup.sh` on each node,
//!   so the node runs it at start. They read the parameters from
//!   `/lab/recipe.env`, find fetched files in `/lab/dl/`, may exchange
//!   generated material (keys, certificates) through `/shared`, start the
//!   protocol in the background and exit.
//!
//! Fetched files are cached under `cache/dl/` in the checkout, so a matrix of
//! twenty labs downloads a release once.

use anyhow::{bail, Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// First line of every setup.sh a recipe writes, so a later `lab up` can tell
/// it from one a person wrote and must not overwrite.
pub const MARKER: &str = "# written by a wirelab recipe; `lab up --recipe` replaces it";

#[derive(Debug, Clone, Deserialize)]
pub struct Recipe {
    pub name: String,
    pub about: String,
    /// Image base the protocol's binaries need; `lab up --base` overrides.
    #[serde(default)]
    pub base: Option<String>,
    /// URL the workloads give curl as `-x`; absent when the tunnel routes
    /// (the client then reaches the target by address, through the tunnel).
    #[serde(default)]
    pub proxy: Option<String>,
    /// Process names, for memory readings during workloads.
    #[serde(default)]
    pub server_process: Option<String>,
    #[serde(default)]
    pub client_process: Option<String>,
    /// The parameter that names the implementation's version, for reports.
    #[serde(default)]
    pub version_param: Option<String>,
    /// Parameter defaults. `@random-hex-N` is replaced by N random bytes in
    /// hex, the same on both nodes; `${other}` by another parameter.
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    #[serde(default)]
    pub fetch: Vec<Fetch>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Fetch {
    /// http(s) URL or a local path; `${param}` is substituted. Empty after
    /// substitution means nothing to fetch.
    pub url: String,
    /// Name under `/lab/dl/`.
    pub save_as: String,
    #[serde(default = "both")]
    pub nodes: Vec<String>,
}

fn both() -> Vec<String> {
    vec!["client".into(), "server".into()]
}

/// A recipe as a lab or a test cell uses it: its name and the parameters
/// given on top of its defaults.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RecipeUse {
    pub name: String,
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    /// Every parameter after defaults, overrides and generation; filled in
    /// when the recipe is installed.
    #[serde(default)]
    pub resolved: BTreeMap<String, String>,
}

impl RecipeUse {
    pub fn new(name: &str, set: BTreeMap<String, String>) -> RecipeUse {
        RecipeUse { name: name.to_string(), set, resolved: BTreeMap::new() }
    }

    /// `name` or `name (k=v, ...)` with the parameters that were set.
    pub fn describe(&self) -> String {
        if self.set.is_empty() {
            self.name.clone()
        } else {
            let kv: Vec<String> = self.set.iter().map(|(k, v)| format!("{k}={v}")).collect();
            format!("{} ({})", self.name, kv.join(", "))
        }
    }

    /// Parse `k=v` pairs from the command line.
    pub fn parse_sets(pairs: &[String]) -> Result<BTreeMap<String, String>> {
        let mut out = BTreeMap::new();
        for p in pairs {
            let Some((k, v)) = p.split_once('=') else { bail!("--set {p:?}: expected name=value") };
            out.insert(k.trim().to_string(), v.to_string());
        }
        Ok(out)
    }
}

pub fn recipes_dir(root: &Path) -> PathBuf {
    root.join("recipes")
}

pub fn load(root: &Path, name: &str) -> Result<Recipe> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        bail!("recipe name {name:?}: letters, digits, '-' and '_'");
    }
    let path = recipes_dir(root).join(name).join("recipe.toml");
    let text = fs::read_to_string(&path).with_context(|| format!("no recipe {name:?} ({} missing); `wirelab recipes` lists them", path.display()))?;
    let r: Recipe = toml::from_str(&text).with_context(|| format!("reading {}", path.display()))?;
    if r.name != name {
        bail!("{}: name = {:?}, but the folder is {name:?}", path.display(), r.name);
    }
    for node in ["client", "server"] {
        let script = recipes_dir(root).join(name).join(format!("{node}.sh"));
        if !script.is_file() {
            bail!("recipe {name}: {} is missing", script.display());
        }
    }
    Ok(r)
}

/// Every recipe in the checkout, sorted by name, with load errors in place.
pub fn list(root: &Path) -> Vec<(String, Result<Recipe>)> {
    let mut names: Vec<String> = fs::read_dir(recipes_dir(root))
        .map(|rd| rd.flatten().filter(|e| e.path().join("recipe.toml").is_file()).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    names.sort();
    names.into_iter().map(|n| (n.clone(), load(root, &n))).collect()
}

/// Defaults, then what was set, then generated values and `${...}`
/// references. Setting a parameter the recipe does not have is an error:
/// a typo would otherwise run the default and look like a result.
pub fn resolve(recipe: &Recipe, set: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>> {
    let mut p = recipe.params.clone();
    for (k, v) in set {
        if !p.contains_key(k) {
            let known: Vec<&str> = recipe.params.keys().map(String::as_str).collect();
            bail!("recipe {} has no parameter {k:?}; it has: {}", recipe.name, known.join(", "));
        }
        p.insert(k.clone(), v.clone());
    }
    for v in p.values_mut() {
        if let Some(n) = v.strip_prefix("@random-hex-") {
            let n: usize = n.parse().with_context(|| format!("{v}: expected @random-hex-<bytes>"))?;
            let mut raw = vec![0u8; n];
            rand::thread_rng().fill_bytes(&mut raw);
            *v = raw.iter().map(|b| format!("{b:02x}")).collect();
        }
    }
    let snapshot = p.clone();
    for v in p.values_mut() {
        *v = substitute(v, &snapshot)?;
    }
    Ok(p)
}

/// Replace `${name}` with the parameter's value.
pub fn substitute(s: &str, params: &BTreeMap<String, String>) -> Result<String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("${") {
        out.push_str(&rest[..i]);
        let Some(j) = rest[i..].find('}') else { bail!("unclosed ${{ in {s:?}") };
        let key = &rest[i + 2..i + j];
        let v = params.get(key).with_context(|| format!("{s:?} refers to ${{{key}}}, which is not a parameter"))?;
        out.push_str(v);
        rest = &rest[i + j + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Write the recipe into the lab's node folders and keep a copy, with the
/// resolved parameters, in the session folder.
pub fn install(root: &Path, lab_dir: &Path, session: &Path, use_: &RecipeUse, force: bool) -> Result<RecipeUse> {
    let recipe = load(root, &use_.name)?;
    let params = resolve(&recipe, &use_.set)?;
    let src = recipes_dir(root).join(&recipe.name);

    for node in ["client", "server"] {
        let setup = lab_dir.join(node).join("setup.sh");
        if let Ok(old) = fs::read_to_string(&setup) {
            if !old.starts_with(MARKER) && !force {
                bail!(
                    "{} was not written by a recipe; move it away or pass --force to replace it",
                    setup.display()
                );
            }
        }
    }

    let mut fetched: BTreeMap<String, Vec<(String, PathBuf)>> = BTreeMap::new();
    for f in &recipe.fetch {
        let url = substitute(&f.url, &params)?;
        if url.trim().is_empty() {
            continue;
        }
        let file = obtain(root, &url).with_context(|| format!("recipe {}: fetching {url}", recipe.name))?;
        for n in &f.nodes {
            if n != "client" && n != "server" {
                bail!("recipe {}: fetch node {n:?} must be client or server", recipe.name);
            }
            fetched.entry(n.clone()).or_default().push((f.save_as.clone(), file.clone()));
        }
    }

    let mut env = String::from("# Parameters of the recipe this lab was set up from.\n");
    env.push_str(&format!("export WL_RECIPE={}\n", sh_quote(&recipe.name)));
    for (k, v) in &params {
        env.push_str(&format!("export WL_P_{}={}\n", k.to_ascii_uppercase().replace('-', "_"), sh_quote(v)));
    }
    for node in ["client", "server"] {
        let dir = lab_dir.join(node);
        fs::create_dir_all(&dir)?;
        let dl = dir.join("dl");
        if dl.exists() {
            fs::remove_dir_all(&dl).with_context(|| format!("clearing {}", dl.display()))?;
        }
        fs::create_dir_all(&dl)?;
        for (name, file) in fetched.get(node).into_iter().flatten() {
            fs::copy(file, dl.join(name)).with_context(|| format!("copying {} into {}", file.display(), dl.display()))?;
        }
        let script = fs::read_to_string(src.join(format!("{node}.sh")))?.replace("\r\n", "\n");
        fs::write(dir.join("setup.sh"), format!("{MARKER}\n{script}"))?;
        fs::write(dir.join("recipe.env"), &env)?;
        // A fresh log per lab: the old one would make a stale run look current.
        let _ = fs::remove_file(dir.join("setup.log"));
    }

    let keep = session.join("recipe");
    fs::create_dir_all(&keep)?;
    for e in fs::read_dir(&src)?.flatten() {
        if e.path().is_file() {
            fs::copy(e.path(), keep.join(e.file_name()))?;
        }
    }
    let resolved = RecipeUse { name: recipe.name.clone(), set: use_.set.clone(), resolved: params };
    fs::write(keep.join("resolved.json"), serde_json::to_vec_pretty(&resolved)?)?;
    Ok(resolved)
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// A local file as is; a URL from the cache, downloading it first if needed.
fn obtain(root: &Path, url: &str) -> Result<PathBuf> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        let p = PathBuf::from(url);
        let p = if p.is_absolute() { p } else { std::env::current_dir()?.join(p) };
        if !p.is_file() {
            bail!("{} is not a file", p.display());
        }
        return Ok(p);
    }
    let cache = root.join("cache").join("dl");
    fs::create_dir_all(&cache)?;
    let base = url.rsplit('/').next().unwrap_or("file");
    let base: String = base.chars().map(|c| if c.is_ascii_alphanumeric() || ".-_".contains(c) { c } else { '_' }).collect();
    let file = cache.join(format!("{:016x}-{base}", fnv1a(url.as_bytes())));
    if file.is_file() {
        return Ok(file);
    }
    let part = file.with_extension("part");
    println!("downloading {url}");
    let status = Command::new("curl")
        .args(["-fL", "--retry", "2", "--connect-timeout", "20", "-sS", "-o"])
        .arg(&part)
        .arg(url)
        .status()
        .context("running curl (it ships with Windows 10 and later and with most Linux systems)")?;
    if !status.success() {
        let _ = fs::remove_file(&part);
        bail!("curl failed ({status}) for {url}");
    }
    fs::rename(&part, &file)?;
    Ok(file)
}

/// Stable across builds, unlike std's hasher: cache names must not change.
fn fnv1a(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &x| (h ^ x as u64).wrapping_mul(0x0100_0000_01b3))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipe(params: &[(&str, &str)]) -> Recipe {
        Recipe {
            name: "t".into(),
            about: String::new(),
            base: None,
            proxy: None,
            server_process: None,
            client_process: None,
            version_param: None,
            params: params.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            fetch: Vec::new(),
        }
    }

    #[test]
    fn parameters_resolve_in_order() {
        let r = recipe(&[("version", "v1"), ("src", "https://x/${version}/a.tgz"), ("key", "@random-hex-16")]);
        let set = BTreeMap::from([("version".to_string(), "v2".to_string())]);
        let p = resolve(&r, &set).unwrap();
        assert_eq!(p["src"], "https://x/v2/a.tgz");
        assert_eq!(p["key"].len(), 32);
        assert!(p["key"].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn unknown_parameter_is_an_error() {
        let r = recipe(&[("version", "v1")]);
        let set = BTreeMap::from([("verison".to_string(), "v2".to_string())]);
        assert!(resolve(&r, &set).is_err());
    }

    #[test]
    fn quoting_survives_single_quotes() {
        assert_eq!(sh_quote("a'b"), r"'a'\''b'");
    }
}
