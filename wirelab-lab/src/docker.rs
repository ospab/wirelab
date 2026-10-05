//! Reaching the Docker engine. On Windows it lives inside a WSL distro, so
//! every call goes through `wsl -d <distro> -- docker ...` and host paths are
//! translated to the distro's `/mnt/<drive>/...` view.

use anyhow::{anyhow, bail, Context, Result};
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug, Clone)]
pub struct Docker {
    /// WSL distro running dockerd; `None` when docker is native.
    distro: Option<String>,
}

impl Docker {
    pub fn detect() -> Docker {
        let distro = cfg!(windows).then(|| std::env::var("WIRELAB_WSL_DISTRO").unwrap_or_else(|_| "Debian".into()));
        Docker { distro }
    }

    /// Program and leading arguments that run `tool` where docker lives.
    fn prefix(&self, tool: &str) -> (String, Vec<String>) {
        match &self.distro {
            Some(d) => ("wsl".into(), vec!["-d".into(), d.clone(), "--".into(), tool.into()]),
            None => (tool.into(), Vec::new()),
        }
    }

    pub fn command(&self, args: &[&str]) -> Command {
        let (prog, pre) = self.prefix("docker");
        let mut c = Command::new(prog);
        c.args(pre).args(args);
        c
    }

    pub fn tokio_command(&self, args: &[&str]) -> tokio::process::Command {
        let (prog, pre) = self.prefix("docker");
        let mut c = tokio::process::Command::new(prog);
        c.args(pre).args(args);
        c
    }

    /// `docker exec -it` needs a terminal on our side. `script` provides one
    /// inside Linux, and its size is set before docker reads it.
    pub fn tty_exec(&self, container: &str, workdir: &str, shell: &str, cols: u16, rows: u16) -> tokio::process::Command {
        let inner = format!(
            "stty rows {rows} cols {cols}; exec docker exec -it -e TERM=xterm-256color -w {workdir} {container} {shell} -l"
        );
        let (prog, pre) = self.prefix("script");
        let mut c = tokio::process::Command::new(prog);
        c.args(pre).args(["-qfec", &inner, "/dev/null"]);
        c
    }

    /// Run and return stdout; a non-zero exit becomes an error carrying stderr.
    pub fn run(&self, args: &[&str]) -> Result<String> {
        let out = self
            .command(args)
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("starting docker {}", args.join(" ")))?;
        if !out.status.success() {
            bail!("docker {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Run with output passed through to our terminal (image builds).
    pub fn run_visible(&self, args: &[&str]) -> Result<()> {
        let status = self.command(args).status().with_context(|| format!("starting docker {}", args.join(" ")))?;
        if !status.success() {
            bail!("docker {} failed ({status})", args.join(" "));
        }
        Ok(())
    }

    /// A host path as the docker daemon sees it.
    pub fn daemon_path(&self, p: &Path) -> Result<String> {
        let abs = p.canonicalize().with_context(|| format!("resolving {}", p.display()))?;
        let s = abs.to_string_lossy().replace('\\', "/");
        if self.distro.is_none() {
            return Ok(s);
        }
        let s = s.trim_start_matches("//?/");
        let mut chars = s.chars();
        match (chars.next(), chars.next()) {
            (Some(drive), Some(':')) if drive.is_ascii_alphabetic() => {
                Ok(format!("/mnt/{}{}", drive.to_ascii_lowercase(), &s[2..]))
            }
            _ => Err(anyhow!("{} is not on a drive WSL mounts under /mnt", abs.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn windows_paths_map_to_wsl_mounts() {
        let d = Docker { distro: Some("Debian".into()) };
        let here = std::env::current_dir().unwrap();
        let p = d.daemon_path(&here).unwrap();
        assert!(p.starts_with("/mnt/"), "{p}");
        assert!(!p.contains('\\'));
    }
}
