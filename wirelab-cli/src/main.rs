use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use wirelab_core::Endpoint;
use wirelab_sim::{Pace, Report, Scenario};
use wirelab_wire::PcapngWriter;

#[derive(Parser)]
#[command(name = "wirelab", version, about = "Protocol sandbox: client, wire and server zones")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a scenario in-process and write the recording, pcapng and report.
    Run {
        scenario: PathBuf,
        /// Override the scenario's seed.
        #[arg(long)]
        seed: Option<u64>,
        #[arg(long, value_enum)]
        pace: Option<PaceArg>,
        /// Output directory. Default: runs/<scenario>-<seed>.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// List the protocol adapters this build has.
    Protocols,
    /// Check Docker, WSL, kernel features, disk space and the censor build;
    /// every problem comes with the command that fixes it.
    Doctor,
    /// List the protocol recipes for `lab up --recipe` and `lab test`.
    Recipes,
    /// The censor that runs in the wire container.
    Censor {
        #[command(subcommand)]
        cmd: CensorCmd,
    },
    /// Containers left running for you to work in: client, wire, server.
    Lab {
        #[command(subcommand)]
        cmd: LabCmd,
    },
}

#[derive(Subcommand)]
enum LabCmd {
    /// Build the images and start the lab.
    Up {
        #[arg(long, default_value = "default")]
        id: String,
        /// Image base for client and server: alpine (musl) or debian (glibc).
        #[arg(long, default_value = "alpine")]
        base: String,
        /// Port the server listens on and the client connects to.
        #[arg(long, default_value_t = wirelab_lab::lab::DEFAULT_PORT)]
        port: u16,
        /// Set both nodes up from a recipe (`wirelab recipes` lists them).
        #[arg(long)]
        recipe: Option<String>,
        /// Recipe parameter, name=value; repeatable.
        #[arg(long = "set", value_name = "NAME=VALUE")]
        set: Vec<String>,
        /// Size of http://target.lab/blob, MB.
        #[arg(long, default_value_t = wirelab_lab::lab::DEFAULT_BLOB_MB)]
        blob_mb: u32,
        /// Replace a setup.sh in the node folders that no recipe wrote.
        #[arg(long)]
        force: bool,
    },
    /// Run a test scenario: a fresh lab per cell (recipe x version x censor
    /// x path), workloads in each, a report with PASS / FAIL / NO DATA.
    Test {
        scenario: PathBuf,
        /// Output folder. Default: runs/lab-<name>-<time>.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Only cells whose name contains this text.
        #[arg(long)]
        only: Option<String>,
        /// List the cells and stop.
        #[arg(long)]
        dry_run: bool,
        /// Leave the last cell's lab running, to look at it in the panel.
        #[arg(long)]
        keep: bool,
    },
    /// Pack a session into one .tar.gz: the capture as pcapng with censor
    /// decisions as packet comments, the decision log, consoles, recipe.
    Export {
        #[arg(long, default_value = "default")]
        id: String,
        /// Session folder name (unix time), or latest.
        #[arg(long, default_value = "latest")]
        session: String,
        /// Archive path. Default: lab/<id>/exports/<session>.tar.gz.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Serve the panel for a running lab on 127.0.0.1.
    Panel {
        #[arg(long, default_value = "default")]
        id: String,
        #[arg(long, default_value_t = 7077)]
        port: u16,
    },
    /// Stop and remove the lab's containers. Folders and sessions stay.
    Down {
        #[arg(long, default_value = "default")]
        id: String,
    },
}

#[derive(Subcommand)]
enum CensorCmd {
    /// Build wl-censor with nDPI inside Docker into containers/wire/bin.
    Build,
}

#[derive(Clone, Copy, ValueEnum)]
enum PaceArg {
    Auto,
    Virtual,
    Realtime,
}

/// Every adapter that exists. Only implemented ones are listed: an entry
/// here must be runnable.
const PROTOCOLS: &[(&str, &str)] = &[("ostp", "in-process, real ostp-core ProtocolMachine (reads the OS clock)")];

type Pair = (Box<dyn Endpoint>, Box<dyn Endpoint>);

fn build_pair(sc: &Scenario) -> Result<Pair> {
    match sc.protocol_name()? {
        "ostp" => wirelab_ostp::build_pair(&sc.protocol),
        other => bail!("unknown protocol {other:?}; `wirelab protocols` lists the available ones"),
    }
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn real_main() -> Result<ExitCode> {
    match Cli::parse().cmd {
        Cmd::Protocols => {
            for (name, what) in PROTOCOLS {
                println!("{name:<10} {what}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Doctor => {
            let root = wirelab_lab::lab::find_root()?;
            let findings = wirelab_lab::doctor::run(&wirelab_lab::Docker::detect(), &root);
            print!("{}", wirelab_lab::doctor::render(&findings));
            let failed = findings.iter().any(|f| f.level == wirelab_lab::doctor::Level::Fail);
            Ok(if failed { ExitCode::from(1) } else { ExitCode::SUCCESS })
        }
        Cmd::Censor { cmd: CensorCmd::Build } => {
            let root = wirelab_lab::lab::find_root()?;
            let commit = wirelab_lab::censor_build::build(&wirelab_lab::Docker::detect(), &root)?;
            println!("built {} with nDPI {}", wirelab_lab::lab::CENSOR_BIN, if commit.is_empty() { "(commit unknown)" } else { &commit });
            println!("a lab picks it up at start: wirelab lab down, then wirelab lab up");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Recipes => {
            let root = wirelab_lab::lab::find_root()?;
            for (name, r) in wirelab_lab::recipe::list(&root) {
                match r {
                    Ok(r) => {
                        println!("{name:<14} {}", r.about);
                        let params: Vec<String> = r.params.iter().map(|(k, v)| format!("{k}={v}")).collect();
                        if !params.is_empty() {
                            println!("{:<14} parameters: {}", "", params.join(", "));
                        }
                    }
                    Err(e) => println!("{name:<14} broken: {e:#}"),
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Lab { cmd } => {
            let root = wirelab_lab::lab::find_root()?;
            let docker = wirelab_lab::Docker::detect();
            match cmd {
                LabCmd::Up { id, base, port, recipe, set, blob_mb, force } => {
                    let sets = wirelab_lab::recipe::RecipeUse::parse_sets(&set)?;
                    if recipe.is_none() && !sets.is_empty() {
                        bail!("--set needs --recipe");
                    }
                    let opts = wirelab_lab::lab::UpOptions {
                        base: wirelab_lab::Base::parse(&base)?,
                        port,
                        blob_mb,
                        recipe: recipe.map(|r| wirelab_lab::recipe::RecipeUse::new(&r, sets)),
                        force,
                    };
                    let info = wirelab_lab::lab::up(&docker, &root, &id, &opts)?;
                    println!("{}", info.summary());
                }
                LabCmd::Test { scenario, out, only, dry_run, keep } => {
                    let opts = wirelab_lab::bench::RunOptions { out, only, dry_run, keep };
                    let run = wirelab_lab::bench::run(&docker, &root, &scenario, &opts)?;
                    if dry_run {
                        return Ok(ExitCode::SUCCESS);
                    }
                    println!("
report: {}", run.dir.join("report.md").display());
                    if run.crts.is_some() {
                        println!("CRTS:   {}", run.dir.join("crts.md").display());
                    }
                    let failed = run.cells.iter().any(|c| c.failed());
                    let errored = run.cells.iter().any(|c| c.error.is_some());
                    return Ok(if failed {
                        ExitCode::from(1)
                    } else if errored {
                        ExitCode::from(3)
                    } else {
                        ExitCode::SUCCESS
                    });
                }
                LabCmd::Export { id, session, out } => {
                    let dir = root.join("lab").join(&id);
                    let session = wirelab_lab::export::find_session(&dir, &session)?;
                    let name = session.file_name().unwrap().to_string_lossy().into_owned();
                    let out = out.unwrap_or_else(|| dir.join("exports").join(format!("{id}-{name}.tar.gz")));
                    let sum = wirelab_lab::export::archive_session(&dir, &session, &out)?;
                    println!("{}", out.display());
                    if sum.packets > 0 {
                        println!(
                            "wire.pcapng: {} packets, {} censor decision(s) on their packets, {} on their flow, {} unplaced",
                            sum.packets, sum.on_packet, sum.on_flow, sum.unplaced
                        );
                    }
                }
                LabCmd::Panel { id, port } => {
                    tokio::runtime::Runtime::new()?.block_on(wirelab_lab::panel::serve(root, id, port))?;
                }
                LabCmd::Down { id } => {
                    wirelab_lab::lab::down(&docker, &root, &id)?;
                    println!("lab {id} stopped; its folders and sessions are kept");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Run { scenario, seed, pace, out } => {
            let mut sc = Scenario::load(&scenario)?;
            if let Some(seed) = seed {
                sc.seed = seed;
            }
            let pace = match pace {
                Some(PaceArg::Auto) => Pace::Auto,
                Some(PaceArg::Virtual) => Pace::Virtual,
                Some(PaceArg::Realtime) => Pace::Realtime,
                None => sc.pace,
            };
            let (client, server) = build_pair(&sc)?;
            let out = out.unwrap_or_else(|| PathBuf::from("runs").join(format!("{}-{}", sc.name, sc.seed)));

            let started = std::time::SystemTime::now();
            let run = wirelab_sim::run(&sc, client, server, pace);
            let report = wirelab_sim::report::build(&sc, &run);

            let base_us = started.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0);
            write_outputs(&out, &run, &report, base_us)?;
            print!("{}", report.render());
            println!("\nwritten to {}", out.display());
            Ok(if report.has_failures() { ExitCode::from(1) } else { ExitCode::SUCCESS })
        }
    }
}

fn write_outputs(dir: &Path, run: &wirelab_sim::RunOutput, report: &Report, base_us: u64) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    let mut rec = BufWriter::new(fs::File::create(dir.join("records.jsonl"))?);
    for r in &run.records {
        serde_json::to_writer(&mut rec, r)?;
        rec.write_all(b"\n")?;
    }
    rec.flush()?;

    let mut pcap = PcapngWriter::new(BufWriter::new(fs::File::create(dir.join("wire.pcapng"))?), base_us, 443)?;
    for o in &run.observations {
        pcap.write_datagram(o.at, o.dir, &o.data)?;
    }
    pcap.finish()?;

    fs::write(dir.join("report.json"), serde_json::to_vec_pretty(report)?)?;
    fs::write(dir.join("report.txt"), report.render())?;
    Ok(())
}
