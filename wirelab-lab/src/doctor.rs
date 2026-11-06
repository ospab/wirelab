//! `wirelab doctor`: what the lab needs, checked one by one. Every problem
//! comes with the command that fixes it.

use crate::docker::{run_with_deadline, Docker};
use crate::lab::CENSOR_BIN;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Note,
    Warn,
    Fail,
}

pub struct Finding {
    pub level: Level,
    pub what: String,
    /// Commands or steps that fix it, one per line.
    pub fix: Vec<String>,
}

fn f(level: Level, what: impl Into<String>, fix: &[&str]) -> Finding {
    Finding { level, what: what.into(), fix: fix.iter().map(|s| s.to_string()).collect() }
}

const GB: f64 = 1e9;
/// Below this a lab, a release download and a capture may not fit.
const WARN_FREE: f64 = 5.0 * GB;
const FAIL_FREE: f64 = 1.0 * GB;
const T: Duration = Duration::from_secs(60);

pub fn run(docker: &Docker, root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();

    // Docker, and on Windows the WSL distro it lives in.
    let docker_ok = match docker.version() {
        Ok(v) => {
            out.push(f(Level::Ok, match docker.distro() {
                Some(d) => format!("Docker {v} in the WSL distro {d}"),
                None => format!("Docker {v}"),
            }, &[]));
            true
        }
        Err(e) => {
            let mut fix = Vec::new();
            if let Some(d) = docker.distro() {
                let distros = wsl_distros();
                if !distros.iter().any(|x| x == d) {
                    fix.push(format!("WSL has no distro {d:?} (it has: {}). Point wirelab at the one with Docker:", if distros.is_empty() { "none".into() } else { distros.join(", ") }));
                    fix.push("  $env:WIRELAB_WSL_DISTRO = \"<name>\"     (PowerShell; export WIRELAB_WSL_DISTRO=<name> in bash)".into());
                } else {
                    fix.push(format!("start the Docker engine in {d}:"));
                    fix.push(format!("  wsl -d {d} -u root -e service docker start"));
                }
            } else {
                fix.push("sudo systemctl start docker     (and add yourself to the docker group, or run as root)".into());
            }
            out.push(Finding { level: Level::Fail, what: format!("Docker does not answer: {}", first_line(&e.to_string())), fix });
            false
        }
    };
    if docker_ok {
        match docker.run_for(&["compose", "version", "--short"], T) {
            Ok(v) => out.push(f(Level::Ok, format!("Docker Compose {}", v.trim()), &[])),
            Err(_) => out.push(Finding {
                level: Level::Fail,
                what: "Docker Compose (the `docker compose` plugin) is missing".into(),
                fix: vec![match docker.distro() {
                    Some(d) => format!("wsl -d {d} -u root -e apt-get install -y docker-compose-plugin"),
                    None => "sudo apt-get install docker-compose-plugin     (or your distribution's equivalent)".into(),
                }],
            }),
        }
    }

    // Kernel features, tried in a throwaway container: netem for the path,
    // packet sockets for the censor, WireGuard for its recipe.
    if docker_ok {
        let images = docker.run_for(&["image", "ls", "--format", "{{.Repository}}"], T).unwrap_or_default();
        let have = |name: &str| images.lines().any(|l| l.trim() == name);
        if have("wl-wire") {
            match docker.run_for(&["run", "--rm", "--cap-add", "NET_ADMIN", "--entrypoint", "tc", "wl-wire", "qdisc", "add", "dev", "lo", "root", "netem", "delay", "1ms"], T) {
                Ok(_) => out.push(f(Level::Ok, "netem works (a qdisc was added in a test container)", &[])),
                Err(e) => out.push(Finding {
                    level: Level::Fail,
                    what: format!("netem does not work: {}", first_line(&e.to_string())),
                    fix: vec![match docker.distro() {
                        Some(d) => format!("wsl -d {d} -u root -e modprobe sch_netem     (the WSL kernel ships it as a module)"),
                        None => "sudo modprobe sch_netem     (on some distributions: install kernel-modules-extra first)".into(),
                    }],
                }),
            }
        } else {
            out.push(f(Level::Note, "images are not built yet; the first `wirelab lab up` builds them (about 60 MB)", &[]));
        }
        let config = docker
            .host_run("sh", &["-c", "zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r) 2>/dev/null"], T)
            .unwrap_or_default();
        let opt = |name: &str| config.lines().find_map(|l| l.strip_prefix(&format!("{name}="))).map(str::to_string);
        if !config.is_empty() {
            match opt("CONFIG_PACKET").as_deref() {
                Some("y") | Some("m") => out.push(f(Level::Ok, "packet sockets (AF_PACKET) for the censor: the kernel has them", &[])),
                _ => out.push(f(Level::Fail, "the kernel has no packet sockets (CONFIG_PACKET); the censor cannot route", &["use a kernel with CONFIG_PACKET (every stock distribution kernel has it)"])),
            }
            out.push(f(Level::Note, "NFQUEUE is not needed: the censor reads frames itself with AF_PACKET", &[]));
            match opt("CONFIG_WIREGUARD").as_deref() {
                Some("y") | Some("m") => out.push(f(Level::Ok, "WireGuard in the kernel (for the wireguard recipe)", &[])),
                _ => out.push(f(Level::Warn, "no WireGuard in the kernel: the wireguard recipe will not start", &["use a kernel with CONFIG_WIREGUARD, or skip that recipe"])),
            }
        }
    }

    // Disk space: the checkout (captures, downloads, runs), and wherever
    // Docker keeps images and containers.
    if let Some(free) = free_bytes(docker, root) {
        out.push(space("the checkout", &root.display().to_string(), free, &[
            "remove old runs: runs/ and lab/<id>/sessions/ in the checkout",
            "clear downloaded releases: cache/dl/ in the checkout",
        ]));
    }
    if docker_ok {
        let inner = docker.host_run("sh", &["-c", "df -B1 --output=avail \"$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo /)\" | tail -1"], T);
        if let Ok(v) = inner {
            if let Ok(free) = v.trim().parse::<f64>() {
                out.push(space("Docker's data", "Docker root directory", free, &["docker system prune     (removes stopped containers and unused images)"]));
            }
        }
    }
    if let Some(d) = docker.distro() {
        if let Some(base) = wsl_base_path(d) {
            let drive = base.get(..2).unwrap_or("").to_string();
            let free = drive_free(docker, &drive);
            let what = format!("the WSL disk of {d} lives in {base}");
            match free {
                Some(fr) if fr < WARN_FREE => out.push(Finding {
                    level: if fr < FAIL_FREE { Level::Fail } else { Level::Warn },
                    what: format!("{what}, and {drive} has {:.1} GB free: the disk grows as images and containers are written", fr / GB),
                    fix: vec![
                        "move the distro to a drive with room (WSL 2.3 or later):".into(),
                        "  wsl --shutdown".into(),
                        format!("  wsl --manage {d} --move D:\\wsl\\{d}"),
                        "or, on older WSL, export and import it (the tar is the backup; keep it until the import works):".into(),
                        "  wsl --shutdown".into(),
                        format!("  wsl --export {d} D:\\wsl\\{d}.tar"),
                        format!("  wsl --unregister {d}"),
                        format!("  wsl --import {d} D:\\wsl\\{d} D:\\wsl\\{d}.tar"),
                    ],
                }),
                Some(fr) => out.push(f(Level::Ok, format!("{what}; {drive} has {:.1} GB free", fr / GB), &[])),
                None => out.push(f(Level::Note, what, &[])),
            }
        }
    }

    // The censor: built, for Linux, and not older than its sources.
    let bin = root.join(CENSOR_BIN);
    let build = [
        "wirelab censor build     (builds it with nDPI inside Docker; nothing else to install)".to_string(),
        "then `wirelab lab down` and `wirelab lab up`: a lab picks the censor up at start".to_string(),
    ];
    match std::fs::read(&bin) {
        Err(_) => out.push(Finding { level: Level::Warn, what: format!("the censor is not built ({CENSOR_BIN}): labs run without it", ), fix: build.to_vec() }),
        Ok(b) if !b.starts_with(b"\x7fELF") => {
            out.push(Finding { level: Level::Fail, what: format!("{CENSOR_BIN} is not a Linux program (built without GOOS=linux?)"), fix: build.to_vec() })
        }
        Ok(_) => {
            let built = mtime(&bin);
            let newest_src = std::fs::read_dir(root.join("wirelab-censor"))
                .map(|rd| rd.flatten().filter(|e| e.path().extension().is_some_and(|x| x == "go" || x == "mod") && !e.file_name().to_string_lossy().ends_with("_test.go")).filter_map(|e| mtime(&e.path())).max())
                .ok()
                .flatten();
            match (built, newest_src) {
                (Some(b), Some(s)) if s > b => out.push(Finding { level: Level::Warn, what: "the censor is older than its sources: rebuild it".into(), fix: build.to_vec() }),
                _ if !root.join(crate::censor_build::NDPI_STAMP).is_file() => out.push(Finding {
                    level: Level::Warn,
                    what: "the censor was built without nDPI: rules that need QUIC SNI or JA4 cannot fire".into(),
                    fix: build.to_vec(),
                }),
                _ => out.push(f(Level::Ok, "the censor is built with nDPI and current", &[])),
            }
        }
    }

    // Tools the recipes and the session export run on this machine.
    match run_with_deadline(cmd("curl", &["--version"]), "curl --version", T) {
        Ok(_) => out.push(f(Level::Ok, "curl, for recipe downloads", &[])),
        Err(_) => out.push(f(Level::Warn, "curl is missing: recipes cannot download releases (local builds still work)", &["install curl (Windows 10 and later ship it in System32)"])),
    }
    if docker_ok {
        if let Ok(names) = docker.run_for(&["ps", "--filter", "name=wl-lab-", "--format", "{{.Names}}"], T) {
            let labs: std::collections::BTreeSet<String> = names
                .lines()
                .filter_map(|n| n.strip_prefix("wl-lab-").and_then(|r| r.rsplit_once('-')).map(|(id, _)| id.to_string()))
                .collect();
            if !labs.is_empty() {
                let list: Vec<String> = labs.into_iter().collect();
                out.push(Finding {
                    level: Level::Note,
                    what: format!("running lab(s): {}", list.join(", ")),
                    fix: list.iter().map(|id| format!("wirelab lab down --id {id}")).collect(),
                });
            }
        }
    }
    out
}

fn cmd(prog: &str, args: &[&str]) -> Command {
    let mut c = Command::new(prog);
    c.args(args);
    c
}

fn first_line(s: &str) -> String {
    s.lines().find(|l| !l.trim().is_empty()).unwrap_or(s).trim().to_string()
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

fn space(name: &str, place: &str, free: f64, fix: &[&str]) -> Finding {
    let level = if free < FAIL_FREE {
        Level::Fail
    } else if free < WARN_FREE {
        Level::Warn
    } else {
        Level::Ok
    };
    let fix = if level == Level::Ok { &[][..] } else { fix };
    f(level, format!("{name}: {:.1} GB free ({place})", free / GB), fix)
}

/// Free bytes on the filesystem holding `p`, read with df where docker lives
/// (WSL sees Windows drives under /mnt).
fn free_bytes(docker: &Docker, p: &Path) -> Option<f64> {
    let path = docker.daemon_path(p).ok()?;
    let out = docker.host_run("df", &["-B1", "--output=avail", &path], T).ok()?;
    out.lines().last()?.trim().parse().ok()
}

fn drive_free(docker: &Docker, drive: &str) -> Option<f64> {
    let letter = drive.chars().next()?.to_ascii_lowercase();
    let out = docker.host_run("df", &["-B1", "--output=avail", &format!("/mnt/{letter}")], T).ok()?;
    out.lines().last()?.trim().parse().ok()
}

/// `wsl -l -q` prints UTF-16.
fn wsl_distros() -> Vec<String> {
    let Ok(out) = Command::new("wsl").args(["-l", "-q"]).output() else { return Vec::new() };
    let units: Vec<u16> = out.stdout.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units).lines().map(|l| l.trim_matches(|c: char| c.is_whitespace() || c == '\0').to_string()).filter(|l| !l.is_empty()).collect()
}

/// Where a WSL distro's disk lives, from the registry.
fn wsl_base_path(distro: &str) -> Option<String> {
    let out = Command::new("reg").args(["query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss", "/s"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut base = None;
    for l in text.lines() {
        let l = l.trim();
        if l.starts_with("HKEY_") {
            base = None;
        }
        let mut parts = l.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("BasePath"), Some("REG_SZ")) => base = Some(parts.collect::<Vec<_>>().join(" ")),
            (Some("DistributionName"), Some("REG_SZ")) if parts.next() == Some(distro) => {
                // BasePath may come before or after the name in a key.
                if base.is_some() {
                    return base.map(|b| b.trim_start_matches(r"\\?\").to_string());
                }
                return text
                    .split("HKEY_")
                    .find(|k| k.contains(&format!("DistributionName    REG_SZ    {distro}")))
                    .and_then(|k| k.lines().find_map(|x| x.trim().strip_prefix("BasePath    REG_SZ    ").map(|b| b.trim_start_matches(r"\\?\").to_string())));
            }
            _ => {}
        }
    }
    None
}

pub fn render(findings: &[Finding]) -> String {
    let mut o = String::new();
    for x in findings {
        let tag = match x.level {
            Level::Ok => "ok  ",
            Level::Note => "note",
            Level::Warn => "WARN",
            Level::Fail => "FAIL",
        };
        o.push_str(&format!("{tag}  {}\n", x.what));
        for l in &x.fix {
            o.push_str(&format!("      {l}\n"));
        }
    }
    let fails = findings.iter().filter(|x| x.level == Level::Fail).count();
    let warns = findings.iter().filter(|x| x.level == Level::Warn).count();
    o.push_str(&match (fails, warns) {
        (0, 0) => "\nEverything the lab needs is in place.\n".to_string(),
        (0, w) => format!("\n{w} warning(s); the lab can run.\n"),
        (f, _) => format!("\n{f} problem(s) to fix before the lab can run.\n"),
    });
    o
}
