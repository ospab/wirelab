//! A session as one file: the capture as pcapng with the censor's decisions
//! on the packets they were made on (Wireshark shows them as packet
//! comments; filter `frame.comment`), the decision log, consoles, wire
//! changes, the recipe and the lab's description.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::fs;
use std::io::BufWriter;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use wirelab_wire::capture::{parse_record, read_pcap_records, Packet, Transport};
use wirelab_wire::PcapngFrames;

#[derive(Debug, Clone, Default, Serialize)]
pub struct PcapngSummary {
    pub packets: usize,
    /// Decisions about a flow (rule hits and block expiries).
    pub decisions: usize,
    /// Of those, put on the exact packet they were made on.
    pub on_packet: usize,
    /// Put on the flow's nearest packet instead: the packet itself never
    /// reached the capture (dropped on its way to the client).
    pub on_flow: usize,
    /// No packet of the flow in the capture at all; listed in the section
    /// comment.
    pub unplaced: usize,
}

/// One line of censor.jsonl, as far as placing it is concerned.
struct Decision {
    t_ms: i64,
    proto: u8,
    client: (Ipv4Addr, u16),
    server: (Ipv4Addr, u16),
    dir: Option<String>,
    len: Option<usize>,
    text: String,
}

/// "tcp 10.77.1.3:40000 > 10.77.2.3:443"
fn parse_flow(s: &str) -> Option<(u8, (Ipv4Addr, u16), (Ipv4Addr, u16))> {
    let mut it = s.split_whitespace();
    let proto = match it.next()? {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        _ => return None,
    };
    let addr = |a: &str| -> Option<(Ipv4Addr, u16)> {
        let (ip, port) = a.rsplit_once(':')?;
        Some((ip.parse().ok()?, port.parse().ok()?))
    };
    let c = addr(it.next()?)?;
    if it.next()? != ">" {
        return None;
    }
    Some((proto, c, addr(it.next()?)?))
}

fn read_decisions(path: &Path) -> (Vec<Decision>, Vec<String>) {
    let mut placed = Vec::new();
    let mut other = Vec::new();
    let Ok(text) = fs::read_to_string(path) else { return (placed, other) };
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let rule = v["rule"].as_str().unwrap_or("-");
        let action = v["action"].as_str().unwrap_or("?");
        let detail = v["detail"].as_str().unwrap_or("");
        let mut text = if rule == "-" { format!("wl-censor {action}") } else { format!("wl-censor {rule}: {action}") };
        if !detail.is_empty() {
            text.push_str(" — ");
            text.push_str(detail);
        }
        if let Some(src) = v["source"].as_str().filter(|s| !s.is_empty()) {
            text.push_str(" [source: ");
            text.push_str(src);
            text.push(']');
        }
        match v["flow"].as_str().and_then(parse_flow) {
            Some((proto, client, server)) => placed.push(Decision {
                t_ms: v["t"].as_i64().unwrap_or(0),
                proto,
                client,
                server,
                dir: v["dir"].as_str().map(String::from),
                len: v["len"].as_u64().map(|n| n as usize),
                text,
            }),
            None => other.push(format!("{} {text}", v["t"].as_i64().unwrap_or(0))),
        }
    }
    (placed, other)
}

fn proto_of(p: &Packet) -> u8 {
    match p.transport {
        Transport::Tcp => 6,
        Transport::Udp => 17,
        Transport::Icmp(..) => 1,
    }
}

/// Rewrite a classic pcap as pcapng with the decisions of `censor_log` as
/// packet comments. A decision goes on the packet of its flow, direction
/// and payload length nearest its time (within 2 s); failing that, on the
/// flow's nearest packet, saying the packet itself is not in the capture.
pub fn pcapng_with_decisions(pcap: &Path, censor_log: Option<&Path>, out: &Path, comment: &str) -> Result<PcapngSummary> {
    let bytes = fs::read(pcap).with_context(|| format!("reading {}", pcap.display()))?;
    let (linktype, records) = read_pcap_records(&bytes)?;
    let packets: Vec<Option<Packet>> = records.iter().map(|r| parse_record(linktype, r).ok().flatten()).collect();
    let (decisions, other) = censor_log.map(read_decisions).unwrap_or_default();

    let mut comments: Vec<Vec<String>> = vec![Vec::new(); records.len()];
    let mut sum = PcapngSummary { packets: records.len(), decisions: decisions.len(), ..Default::default() };
    let mut unplaced = Vec::new();
    for d in &decisions {
        let t_us = d.t_ms.max(0) as u64 * 1000;
        let in_flow = |p: &Packet| {
            proto_of(p) == d.proto
                && ((p.src == d.client.0 && p.sport == d.client.1 && p.dst == d.server.0 && p.dport == d.server.1)
                    || (p.src == d.server.0 && p.sport == d.server.1 && p.dst == d.client.0 && p.dport == d.client.1))
        };
        let exact = |p: &Packet| {
            let dir_ok = match d.dir.as_deref() {
                Some("c2s") => p.src == d.client.0,
                Some("s2c") => p.src == d.server.0,
                _ => true,
            };
            dir_ok && d.len.map_or(true, |l| l == p.payload_len)
        };
        let nearest = |want_exact: bool| {
            packets
                .iter()
                .enumerate()
                .filter_map(|(i, p)| p.as_ref().map(|p| (i, p)))
                .filter(|(_, p)| in_flow(p) && (!want_exact || exact(p)))
                .map(|(i, p)| (i, p.t_us.abs_diff(t_us)))
                .filter(|&(_, dt)| !want_exact || dt <= 2_000_000)
                .min_by_key(|&(_, dt)| dt)
                .map(|(i, _)| i)
        };
        if let Some(i) = nearest(true) {
            comments[i].push(d.text.clone());
            sum.on_packet += 1;
        } else if let Some(i) = nearest(false) {
            comments[i].push(format!("{} (made on a packet that is not in this capture: dropped before reaching the client side)", d.text));
            sum.on_flow += 1;
        } else {
            unplaced.push(format!("{} {}", d.t_ms, d.text));
            sum.unplaced += 1;
        }
    }

    let mut section = comment.to_string();
    if !other.is_empty() || !unplaced.is_empty() {
        section.push_str("\n\nCensor events not tied to a packet here (unix ms, event):\n");
        for l in other.iter().chain(&unplaced) {
            section.push_str(l);
            section.push('\n');
        }
    }
    let snaplen = records.iter().map(|r| r.frame.len() as u32).max().unwrap_or(65535).max(65535);
    let mut w = PcapngFrames::new(BufWriter::new(fs::File::create(out)?), linktype, snaplen, &section)?;
    for (r, c) in records.iter().zip(&comments) {
        w.write_frame(r.t_us, r.orig_len, &r.frame, c)?;
    }
    w.finish()?;
    Ok(sum)
}

/// Pack a session folder into `out` (.tar.gz). The capture is converted to
/// pcapng with the censor's decisions first, and the lab's description and
/// compose file are copied in, so the archive stands on its own.
pub fn archive_session(lab_dir: &Path, session: &Path, out: &Path) -> Result<PcapngSummary> {
    if !session.is_dir() {
        bail!("no session folder {}", session.display());
    }
    let mut sum = PcapngSummary::default();
    let pcap = session.join("wire.pcap");
    if pcap.is_file() {
        let log = session.join("censor.jsonl");
        let note = format!("wirelab session {}", session.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default());
        sum = pcapng_with_decisions(&pcap, log.is_file().then_some(log.as_path()), &session.join("wire.pcapng"), &note)?;
    }
    for f in ["lab.json", "compose.yml"] {
        if lab_dir.join(f).is_file() {
            fs::copy(lab_dir.join(f), session.join(f))?;
        }
    }
    for node in ["client", "server"] {
        let log = lab_dir.join(node).join("setup.log");
        if log.is_file() {
            fs::copy(&log, session.join(format!("{node}-setup.log")))?;
        }
    }
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    let status = tar_command()
        .arg("-czf")
        .arg(out)
        .arg("-C")
        .arg(session)
        .arg(".")
        .status()
        .context("running tar")?;
    if !status.success() {
        bail!("tar failed ({status}) packing {}", session.display());
    }
    Ok(sum)
}

/// Windows' own tar (bsdtar) takes drive-letter paths; a GNU tar earlier on
/// PATH (Git for Windows) would read `D:` as a remote host.
fn tar_command() -> Command {
    if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        Command::new(PathBuf::from(root).join("System32").join("tar.exe"))
    } else {
        Command::new("tar")
    }
}

/// The session a name refers to: a unix-time folder name, or `latest`.
pub fn find_session(lab_dir: &Path, which: &str) -> Result<PathBuf> {
    let sessions = lab_dir.join("sessions");
    if which != "latest" {
        let p = sessions.join(which);
        if !p.is_dir() {
            bail!("no session {which} in {}", sessions.display());
        }
        return Ok(p);
    }
    let mut names: Vec<u64> = fs::read_dir(&sessions)
        .with_context(|| format!("reading {}", sessions.display()))?
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
        .collect();
    names.sort();
    let last = names.last().with_context(|| format!("no sessions in {}", sessions.display()))?;
    Ok(sessions.join(last.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flows_parse() {
        let (p, c, s) = parse_flow("tcp 10.77.1.3:40000 > 10.77.2.3:443").unwrap();
        assert_eq!(p, 6);
        assert_eq!(c, ("10.77.1.3".parse().unwrap(), 40000));
        assert_eq!(s, ("10.77.2.3".parse().unwrap(), 443));
        assert!(parse_flow("routing eth0 <-> eth1").is_none());
    }

    /// Two TCP packets of one flow in a raw-IPv4 pcap; a decision on the
    /// second one by direction and length lands on it, and one whose packet
    /// is missing lands on the flow.
    #[test]
    fn decisions_land_on_their_packets() {
        let dir = std::env::temp_dir().join(format!("wl-export-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let ip = |src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: usize| {
            let total = 20 + 20 + payload;
            let mut v = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, 6, 0, 0];
            v.extend(src);
            v.extend(dst);
            v.extend(sp.to_be_bytes());
            v.extend(dp.to_be_bytes());
            v.extend([0u8; 8]);
            v.extend([0x50, 0x18, 0, 0, 0, 0, 0, 0]);
            v.extend(vec![0xAB; payload]);
            v
        };
        let (c, s) = ([10, 77, 1, 3], [10, 77, 2, 3]);
        let frames = [(1_000_000u64, ip(c, s, 40000, 443, 0)), (1_005_000, ip(c, s, 40000, 443, 517))];
        let mut pcap = Vec::new();
        pcap.extend(0xa1b2_c3d4u32.to_le_bytes());
        pcap.extend([2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        pcap.extend(65535u32.to_le_bytes());
        pcap.extend(101u32.to_le_bytes());
        for (t, f) in &frames {
            pcap.extend(((t / 1_000_000) as u32).to_le_bytes());
            pcap.extend(((t % 1_000_000) as u32).to_le_bytes());
            pcap.extend((f.len() as u32).to_le_bytes());
            pcap.extend((f.len() as u32).to_le_bytes());
            pcap.extend(f);
        }
        fs::write(dir.join("w.pcap"), &pcap).unwrap();
        fs::write(
            dir.join("c.jsonl"),
            concat!(
                r#"{"t":1000,"rule":"-","action":"start","detail":"routing"}"#, "\n",
                r#"{"t":1005,"rule":"ru-sni-1","action":"rst_s2c","flow":"tcp 10.77.1.3:40000 > 10.77.2.3:443","dir":"c2s","len":517,"detail":"SNI x"}"#, "\n",
                r#"{"t":1007,"rule":"ru-x","action":"drop_s2c","flow":"tcp 10.77.1.3:40000 > 10.77.2.3:443","dir":"s2c","len":1200}"#, "\n",
            ),
        )
        .unwrap();
        let sum = pcapng_with_decisions(&dir.join("w.pcap"), Some(&dir.join("c.jsonl")), &dir.join("w.pcapng"), "test").unwrap();
        assert_eq!((sum.packets, sum.decisions, sum.on_packet, sum.on_flow, sum.unplaced), (2, 2, 1, 1, 0));
        let out = fs::read(dir.join("w.pcapng")).unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("wl-censor ru-sni-1: rst_s2c"));
        assert!(text.contains("wl-censor start"));
        let _ = fs::remove_dir_all(&dir);
    }
}
