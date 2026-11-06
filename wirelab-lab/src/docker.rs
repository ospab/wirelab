//! Reaching the Docker engine. On Windows it lives inside a WSL distro, so
//! every call goes through `wsl -d <distro> -e docker ...` and host paths are
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
    /// `wsl -e` passes the arguments as they are; `wsl --` would hand them
    /// to a shell, which splits on spaces and quotes.
    fn prefix(&self, tool: &str) -> (String, Vec<String>) {
        match &self.distro {
            Some(d) => ("wsl".into(), vec!["-d".into(), d.clone(), "-e".into(), tool.into()]),
            None => (tool.into(), Vec::new()),
        }
    }

    /// A command run where docker lives (the WSL distro, or here), with a
    /// deadline. Returns stdout, or an error with stderr.
    pub fn host_run(&self, tool: &str, args: &[&str], limit: std::time::Duration) -> Result<String> {
        let (prog, pre) = self.prefix(tool);
        let mut c = Command::new(prog);
        c.args(pre).args(args);
        run_with_deadline(c, &format!("{tool} {}", args.join(" ")), limit)
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

    /// Run with a deadline: past it the call is killed and reported as such.
    /// Returns stdout; a non-zero exit becomes an error carrying stderr.
    pub fn run_for(&self, args: &[&str], limit: std::time::Duration) -> Result<String> {
        run_with_deadline(self.command(args), &format!("docker {}", args.join(" ")), limit)
    }

    /// Whether docker answers at all, with its server version.
    pub fn version(&self) -> Result<String> {
        Ok(self.run_for(&["version", "--format", "{{.Server.Version}}"], std::time::Duration::from_secs(30))?.trim().to_string())
    }

    pub fn distro(&self) -> Option<&str> {
        self.distro.as_deref()
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

/// Run with a deadline: past it the process is killed and that is the
/// error. Returns stdout; a non-zero exit becomes an error carrying stderr.
pub fn run_with_deadline(mut cmd: Command, shown: &str, limit: std::time::Duration) -> Result<String> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {shown}"))?;
    // Drain both pipes on threads so a chatty command cannot block on a full pipe.
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = std::io::Read::read_to_end(&mut so, &mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = std::io::Read::read_to_end(&mut se, &mut b);
        b
    });
    let deadline = std::time::Instant::now() + limit;
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let out = t_out.join().unwrap_or_default();
    let err = t_err.join().unwrap_or_default();
    match status {
        None => bail!("{shown} did not finish within {} s", limit.as_secs()),
        Some(st) if !st.success() => {
            let e = String::from_utf8_lossy(&err);
            bail!("{shown} failed ({st}): {}", e.trim())
        }
        Some(_) => Ok(String::from_utf8_lossy(&out).into_owned()),
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
