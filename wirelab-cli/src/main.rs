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
        Cmd::Lab { cmd } => {
            let root = wirelab_lab::lab::find_root()?;
            let docker = wirelab_lab::Docker::detect();
            match cmd {
                LabCmd::Up { id, base, port } => {
                    let info = wirelab_lab::lab::up(&docker, &root, &id, wirelab_lab::Base::parse(&base)?, port)?;
                    println!("{}", info.summary());
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
