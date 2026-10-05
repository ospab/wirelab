//! The local panel: two consoles and the wire between them.
//!
//! Binds to 127.0.0.1 only and requires the token printed at start: the
//! consoles are root shells in the lab, so any page or local process that
//! could reach the panel would otherwise own them.

use crate::docker::Docker;
use crate::lab::{self, LabInfo};
use anyhow::{bail, Context, Result};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::io::Write as _;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;
use wirelab_wire::byte_entropy;
use wirelab_wire::capture::{find_all, icmp_quoted_target, parse_client_hello, PcapStream, Transport};

const INDEX: &str = include_str!("panel.html");
const RECENT_ROWS: usize = 400;
const ROWS_PER_TICK: usize = 300;

struct Panel {
    info: LabInfo,
    /// Censor presets shipped in the checkout (`containers/censor/presets`).
    presets: std::path::PathBuf,
    docker: Docker,
    token: String,
    origins: [String; 2],
    /// Egress interfaces in the wire container: towards the server (carries
    /// c2s) and towards the client (carries s2c).
    if_to_server: String,
    if_to_client: String,
    wire: Mutex<WireState>,
    events: broadcast::Sender<String>,
}

#[derive(Default, Clone, Copy, Serialize)]
struct DirCount {
    packets: u64,
    ip_bytes: u64,
    payload_bytes: u64,
}

#[derive(Clone, Serialize)]
struct Row {
    n: u64,
    t_ms: f64,
    dir: &'static str,
    proto: &'static str,
    sport: u16,
    dport: u16,
    len: usize,
    payload: usize,
    entropy: Option<f64>,
    note: Option<String>,
    alarm: bool,
}

#[derive(Clone, Deserialize, Serialize)]
struct Needle {
    label: String,
    text: String,
}

#[derive(Default)]
struct WireState {
    first_us: Option<u64>,
    counts: [DirCount; 2],
    seen: u64,
    recent: VecDeque<Row>,
    pending: Vec<Row>,
    dropped_rows: u64,
    needles: Vec<(Needle, Vec<Vec<u8>>)>,
    alarms: Vec<String>,
    capture: String,
    censor_recent: VecDeque<serde_json::Value>,
    censor_pending: Vec<serde_json::Value>,
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

pub async fn serve(root: std::path::PathBuf, id: String, port: u16) -> Result<()> {
    let info = lab::load(&root, &id)?;
    let docker = Docker::detect();
    let ifaces = docker
        .run(&["exec", &info.wire, "cat", "/tmp/ifaces"])
        .with_context(|| format!("reading the wire's interfaces; is lab {id:?} running?"))?;
    let mut it = ifaces.split_whitespace();
    let (Some(if_c), Some(if_s)) = (it.next(), it.next()) else { bail!("unexpected /tmp/ifaces in the wire: {ifaces:?}") };

    let mut raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut raw);
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let (events, _) = broadcast::channel(64);
    let panel = Arc::new(Panel {
        origins: [format!("http://127.0.0.1:{port}"), format!("http://localhost:{port}")],
        if_to_server: if_s.to_string(),
        if_to_client: if_c.to_string(),
        presets: root.join("containers/censor/presets"),
        info,
        docker,
        token,
        wire: Mutex::new(WireState { capture: "starting".into(), ..Default::default() }),
        events,
    });

    tokio::spawn(capture(panel.clone()));
    if panel.info.censor {
        tokio::spawn(censor_tail(panel.clone()));
    }
    tokio::spawn(ticker(panel.clone()));

    let app = Router::new()
        .route("/", get(index))
        .route("/api/lab", get(api_lab))
        .route("/api/status", get(api_status))
        .route("/api/netem", post(api_netem))
        .route("/api/needles", post(api_needles))
        .route("/api/censor", get(api_censor_get).post(api_censor_set))
        .route("/ws/wire", get(ws_wire))
        .route("/ws/term/:zone", get(ws_term))
        .with_state(panel.clone());
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.with_context(|| format!("binding 127.0.0.1:{port}"))?;
    println!("panel for lab {}: http://127.0.0.1:{port}/?t={}", panel.info.id, panel.token);
    println!("session records: {}", panel.info.session.display());
    println!("Ctrl+C stops the panel; the lab keeps running until `wirelab lab down`.");
    axum::serve(listener, app).await?;
    Ok(())
}

impl Panel {
    fn authorized(&self, q: &HashMap<String, String>, h: &HeaderMap) -> bool {
        let given = q.get("t").map(String::as_str).or_else(|| h.get("x-wirelab-token").and_then(|v| v.to_str().ok()));
        given == Some(self.token.as_str())
    }

    /// Browsers send Origin on WebSocket handshakes; a page from anywhere else
    /// must not be able to open a console even if it guessed the port.
    fn same_origin(&self, h: &HeaderMap) -> bool {
        match h.get("origin").and_then(|v| v.to_str().ok()) {
            Some(o) => self.origins.iter().any(|a| a == o),
            None => false,
        }
    }

    fn session_append(&self, file: &str, line: &str) {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(self.info.session.join(file)) {
            let _ = writeln!(f, "{} {line}", now_ms());
        }
    }

    fn qdisc(&self) -> HashMap<&'static str, String> {
        let show = |dev: &str| {
            self.docker
                .run(&["exec", &self.info.wire, "tc", "qdisc", "show", "dev", dev])
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|e| format!("error: {e}"))
        };
        HashMap::from([("c2s", show(&self.if_to_server)), ("s2c", show(&self.if_to_client))])
    }
}

fn deny() -> Response {
    (StatusCode::FORBIDDEN, "wrong or missing token: open the link the panel printed").into_response()
}

async fn index(State(p): State<Arc<Panel>>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> Response {
    if !p.authorized(&q, &h) {
        return deny();
    }
    Html(INDEX).into_response()
}

async fn api_lab(State(p): State<Arc<Panel>>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> Response {
    if !p.authorized(&q, &h) {
        return deny();
    }
    let p2 = p.clone();
    let qdisc = tokio::task::spawn_blocking(move || p2.qdisc()).await.unwrap_or_default();
    Json(serde_json::json!({
        "id": p.info.id,
        "base": p.info.base,
        "port": p.info.server_port,
        "client": {"ip": lab::CLIENT_IP, "folder": p.info.dir.join("client"), "connect": format!("{}:{}", lab::SERVER_IP, p.info.server_port)},
        "server": {"ip": lab::SERVER_IP, "folder": p.info.dir.join("server"), "listen": format!("0.0.0.0:{}", p.info.server_port), "target": lab::TARGET_URL},
        "wire": {"client_side": lab::WIRE_CLIENT_SIDE, "server_side": lab::WIRE_SERVER_SIDE},
        "session": p.info.session,
        "qdisc": qdisc,
    }))
    .into_response()
}

/// Whether the server listens on the lab port and how many connections the
/// client holds to it, read from the containers' own socket tables.
async fn api_status(State(p): State<Arc<Panel>>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> Response {
    if !p.authorized(&q, &h) {
        return deny();
    }
    let p2 = p.clone();
    let status = tokio::task::spawn_blocking(move || {
        let port = p2.info.server_port;
        let suffix = format!(":{port}");
        // Columns of `ss -H -tun`: Netid State Recv-Q Send-Q Local Peer.
        let listening = p2.docker.run(&["exec", &p2.info.server, "ss", "-Hltun"]).map(|out| {
            out.lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split_whitespace().collect();
                    (f.len() > 4 && f[4].ends_with(&suffix)).then(|| format!("{} {}", f[0], f[4]))
                })
                .collect::<Vec<_>>()
        });
        // A UDP socket counts only when connected to the server; an
        // unconnected one sending with sendto() has no peer to attribute.
        let peer = format!("{}:{port}", lab::SERVER_IP);
        let connections = p2.docker.run(&["exec", &p2.info.client, "ss", "-Htun"]).map(|out| {
            out.lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split_whitespace().collect();
                    (f.len() > 5 && f[5] == peer && f[1] == "ESTAB").then(|| f[0].to_string())
                })
                .collect::<Vec<_>>()
        });
        serde_json::json!({
            "listening": listening.as_ref().ok(),
            "listening_error": listening.as_ref().err().map(|e| e.to_string()),
            "client_connections": connections.as_ref().ok(),
            "client_error": connections.as_ref().err().map(|e| e.to_string()),
        })
    })
    .await
    .unwrap_or_else(|e| serde_json::json!({ "listening_error": e.to_string(), "client_error": e.to_string() }));
    Json(status).into_response()
}

#[derive(Deserialize)]
struct NetemReq {
    dir: String,
    #[serde(default)]
    delay_ms: f64,
    #[serde(default)]
    jitter_ms: f64,
    #[serde(default)]
    loss_pct: f64,
    #[serde(default)]
    duplicate_pct: f64,
    #[serde(default)]
    corrupt_pct: f64,
    #[serde(default)]
    rate_kbit: f64,
}

fn netem_args(r: &NetemReq) -> Result<Vec<String>> {
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
    Ok(a)
}

async fn api_netem(State(p): State<Arc<Panel>>, Query(q): Query<HashMap<String, String>>, h: HeaderMap, Json(r): Json<NetemReq>) -> Response {
    if !p.authorized(&q, &h) {
        return deny();
    }
    let dev = match r.dir.as_str() {
        "c2s" => p.if_to_server.clone(),
        "s2c" => p.if_to_client.clone(),
        _ => return (StatusCode::BAD_REQUEST, "dir must be c2s or s2c").into_response(),
    };
    let args = match netem_args(&r) {
        Ok(a) => a,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let p2 = p.clone();
    let dir = r.dir.clone();
    let result = tokio::task::spawn_blocking(move || {
        let mut cmd: Vec<String> = vec!["exec".into(), p2.info.wire.clone(), "tc".into(), "qdisc".into()];
        let clearing = args.is_empty();
        if clearing {
            cmd.extend(["del".into(), "dev".into(), dev.clone(), "root".into()]);
        } else {
            cmd.extend(["replace".into(), "dev".into(), dev.clone(), "root".into(), "netem".into()]);
            cmd.extend(args);
        }
        let refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
        let shown = cmd[2..].join(" ");
        let res = p2.docker.run(&refs);
        // Deleting a qdisc that is not there is the state we wanted anyway.
        let res = match res {
            Err(e) if clearing && e.to_string().contains("No such file") => Ok(String::new()),
            other => other,
        };
        p2.session_append("wire-changes.log", &format!("{dir}: {shown} -> {}", match &res {
            Ok(_) => "ok".to_string(),
            Err(e) => format!("error: {e}"),
        }));
        res.map(|_| p2.qdisc())
    })
    .await;
    match result {
        Ok(Ok(qdisc)) => Json(serde_json::json!({ "qdisc": qdisc })).into_response(),
        Ok(Err(e)) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Byte forms a secret can take on the wire: as typed, and when it reads as
/// a UUID or as hex, the raw bytes it stands for.
fn needle_forms(text: &str) -> Vec<Vec<u8>> {
    let mut forms = vec![text.as_bytes().to_vec()];
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if hex.len() >= 8 && hex.len() % 2 == 0 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        let raw: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        forms.push(raw);
    }
    forms
}

async fn api_needles(State(p): State<Arc<Panel>>, Query(q): Query<HashMap<String, String>>, h: HeaderMap, Json(list): Json<Vec<Needle>>) -> Response {
    if !p.authorized(&q, &h) {
        return deny();
    }
    let list: Vec<Needle> = list.into_iter().filter(|n| n.text.len() >= 4).collect();
    let mut w = p.wire.lock().unwrap();
    w.needles = list.iter().map(|n| (n.clone(), needle_forms(&n.text))).collect();
    p.session_append("wire-changes.log", &format!("watching for {} secret(s) in clear", w.needles.len()));
    Json(serde_json::json!({ "watching": list.len() })).into_response()
}

async fn capture(p: Arc<Panel>) {
    let set = |s: String| p.wire.lock().unwrap().capture = s;
    let mut child = match p
        .docker
        .tokio_command(&["exec", &p.info.wire, "tcpdump", "-i", &p.if_to_client, "-U", "-s", "0", "-B", "65536", "-w", "-", "net 10.77.0.0/16"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return set(format!("could not start tcpdump: {e}")),
    };
    let mut stderr = child.stderr.take().unwrap();
    let session = p.info.session.clone();
    tokio::spawn(async move {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s).await;
        let _ = std::fs::write(session.join("wire-tcpdump.log"), s);
    });

    let mut out = child.stdout.take().unwrap();
    let mut file = match std::fs::File::create(p.info.session.join("wire.pcap")) {
        Ok(f) => f,
        Err(e) => return set(format!("could not create wire.pcap: {e}")),
    };
    set("capturing".into());
    let mut stream = PcapStream::default();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = match out.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return set(format!("capture read failed: {e}")),
        };
        let _ = file.write_all(&buf[..n]);
        match stream.push(&buf[..n]) {
            Ok(pkts) => {
                let mut w = p.wire.lock().unwrap();
                for pkt in pkts {
                    observe(&mut w, pkt);
                }
            }
            Err(e) => return set(format!("capture is unreadable: {e}")),
        }
    }
    let status = child.wait().await.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
    set(format!("capture ended ({status}); see wire-tcpdump.log in the session folder"));
}

fn observe(w: &mut WireState, pkt: wirelab_wire::capture::Packet) {
    let o = pkt.src.octets();
    let (dir, idx) = match (o[0], o[1], o[2]) {
        (10, 77, 1) => ("c2s", 0),
        (10, 77, 2) => ("s2c", 1),
        _ => return,
    };
    let first = *w.first_us.get_or_insert(pkt.t_us);
    w.seen += 1;
    let c = &mut w.counts[idx];
    c.packets += 1;
    c.ip_bytes += pkt.ip_len as u64;
    c.payload_bytes += pkt.payload.len() as u64;

    let mut note = None;
    if let Transport::Icmp(ty, code) = pkt.transport {
        note = Some(match (ty, code, icmp_quoted_target(&pkt.payload)) {
            (3, 3, Some((proto, dst, port))) => format!("ICMP port unreachable: nothing listens on {proto} {dst}:{port}"),
            (3, _, Some((proto, dst, port))) => format!("ICMP destination unreachable (code {code}) for {proto} {dst}:{port}"),
            _ => format!("ICMP type {ty} code {code}"),
        });
    }
    if pkt.transport == Transport::Tcp && !pkt.payload.is_empty() {
        if let Some(h) = parse_client_hello(&pkt.payload) {
            note = Some(format!(
                "TLS ClientHello, SNI {}, ALPN {}",
                h.sni.as_deref().unwrap_or("none"),
                if h.alpn.is_empty() { "none".into() } else { h.alpn.join(",") }
            ));
        } else if pkt.payload.len() > 5 && pkt.payload[0] == 0x16 && pkt.payload[5] == 2 {
            note = Some("TLS ServerHello".into());
        }
    }
    let mut alarm = false;
    for (needle, forms) in &w.needles {
        for form in forms {
            if let Some(off) = find_all(&pkt.payload, form).first() {
                alarm = true;
                let msg = format!("{} found in clear: {dir} packet #{} at payload offset {off}", needle.label, w.seen);
                note = Some(msg.clone());
                w.alarms.push(msg);
            }
        }
    }

    let row = Row {
        n: w.seen,
        t_ms: (pkt.t_us - first) as f64 / 1000.0,
        dir,
        proto: match pkt.transport {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
            Transport::Icmp(..) => "icmp",
        },
        sport: pkt.sport,
        dport: pkt.dport,
        len: pkt.ip_len,
        payload: pkt.payload.len(),
        // Below ~32 bytes the estimate says more about the sample size than
        // about the data.
        entropy: (pkt.payload.len() >= 32).then(|| (byte_entropy(&pkt.payload) * 100.0).round() / 100.0),
        note,
        alarm,
    };
    w.recent.push_back(row.clone());
    if w.recent.len() > RECENT_ROWS {
        w.recent.pop_front();
    }
    if w.pending.len() < ROWS_PER_TICK || row.alarm || row.note.is_some() {
        w.pending.push(row);
    } else {
        w.dropped_rows += 1;
    }
}

async fn ticker(p: Arc<Panel>) {
    let mut iv = tokio::time::interval(Duration::from_millis(300));
    loop {
        iv.tick().await;
        let msg = {
            let mut w = p.wire.lock().unwrap();
            let rows = std::mem::take(&mut w.pending);
            let dropped = std::mem::take(&mut w.dropped_rows);
            let censor = std::mem::take(&mut w.censor_pending);
            serde_json::json!({
                "type": "tick", "counts": w.counts, "rows": rows, "dropped_rows": dropped,
                "capture": w.capture, "alarms": w.alarms.len(), "censor": censor,
            })
        };
        let _ = p.events.send(msg.to_string());
    }
}

const ACTIVE_PRESET: &str = "censor-preset.json";

/// Follows the censor's decision log in the session folder. The censor
/// writes it from inside the wire container through the bind mount.
async fn censor_tail(p: Arc<Panel>) {
    let path = p.info.session.join("censor.jsonl");
    let mut offset = 0u64;
    let mut partial = String::new();
    let mut iv = tokio::time::interval(Duration::from_millis(300));
    loop {
        iv.tick().await;
        let Ok(bytes) = std::fs::read(&path) else { continue };
        if (bytes.len() as u64) < offset {
            offset = 0; // the file was replaced
        }
        if bytes.len() as u64 == offset {
            continue;
        }
        partial.push_str(&String::from_utf8_lossy(&bytes[offset as usize..]));
        offset = bytes.len() as u64;
        let mut w = p.wire.lock().unwrap();
        while let Some(nl) = partial.find('\n') {
            let line: String = partial.drain(..=nl).collect();
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim()) {
                w.censor_recent.push_back(v.clone());
                if w.censor_recent.len() > 200 {
                    w.censor_recent.pop_front();
                }
                w.censor_pending.push(v);
            }
        }
    }
}

fn read_presets(dir: &std::path::Path) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return out };
    let mut files: Vec<_> = entries.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "json")).collect();
    files.sort();
    for f in files {
        let file = f.file_name().unwrap().to_string_lossy().into_owned();
        match std::fs::read(&f).map_err(|e| e.to_string()).and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).map_err(|e| e.to_string())) {
            Ok(mut v) => {
                v["file"] = serde_json::Value::String(file);
                out.push(v);
            }
            Err(e) => out.push(serde_json::json!({ "file": file, "error": e })),
        }
    }
    out
}

async fn api_censor_get(State(p): State<Arc<Panel>>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> Response {
    if !p.authorized(&q, &h) {
        return deny();
    }
    let active = std::fs::read(p.info.session.join(ACTIVE_PRESET)).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    Json(serde_json::json!({
        "available": p.info.censor,
        "presets": read_presets(&p.presets),
        "active": active,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct CensorReq {
    /// Preset file name, or none to turn the censor off.
    file: Option<String>,
    /// Rule ids to switch off in this session.
    #[serde(default)]
    disabled: Vec<String>,
}

async fn api_censor_set(State(p): State<Arc<Panel>>, Query(q): Query<HashMap<String, String>>, h: HeaderMap, Json(r): Json<CensorReq>) -> Response {
    if !p.authorized(&q, &h) {
        return deny();
    }
    if !p.info.censor {
        return (StatusCode::CONFLICT, "this lab was started without the censor; build wl-censor, then lab down and lab up").into_response();
    }
    let target = p.info.session.join(ACTIVE_PRESET);
    let Some(file) = r.file else {
        let _ = std::fs::remove_file(&target);
        p.session_append("wire-changes.log", "censor: off");
        return Json(serde_json::json!({ "active": null })).into_response();
    };
    if file.contains(['/', '\\']) || !file.ends_with(".json") {
        return (StatusCode::BAD_REQUEST, "preset must be a file name from containers/censor/presets").into_response();
    }
    let mut preset: serde_json::Value = match std::fs::read(p.presets.join(&file)).map_err(|e| e.to_string()).and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string())) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("{file}: {e}")).into_response(),
    };
    if let Some(rules) = preset["rules"].as_array_mut() {
        for rule in rules {
            let id = rule["id"].as_str().unwrap_or_default().to_string();
            rule["disabled"] = serde_json::Value::Bool(r.disabled.contains(&id));
        }
    }
    // Written whole and renamed, so the censor never reads half a file.
    let tmp = p.info.session.join("censor-preset.json.tmp");
    let write = std::fs::write(&tmp, serde_json::to_vec_pretty(&preset).unwrap()).and_then(|_| std::fs::rename(&tmp, &target));
    if let Err(e) = write {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    p.session_append("wire-changes.log", &format!("censor: {file}, rules off: {}", if r.disabled.is_empty() { "none".into() } else { r.disabled.join(",") }));
    Json(serde_json::json!({ "active": preset })).into_response()
}

async fn ws_wire(State(p): State<Arc<Panel>>, Query(q): Query<HashMap<String, String>>, h: HeaderMap, ws: WebSocketUpgrade) -> Response {
    if !p.authorized(&q, &h) || !p.same_origin(&h) {
        return deny();
    }
    ws.on_upgrade(move |mut socket| async move {
        let snapshot = {
            let w = p.wire.lock().unwrap();
            serde_json::json!({
                "type": "snapshot", "counts": w.counts, "rows": w.recent, "capture": w.capture,
                "alarms": w.alarms, "needles": w.needles.iter().map(|(n, _)| n).collect::<Vec<_>>(),
                "censor": w.censor_recent,
            })
        };
        if socket.send(Message::Text(snapshot.to_string())).await.is_err() {
            return;
        }
        let mut rx = p.events.subscribe();
        loop {
            tokio::select! {
                ev = rx.recv() => match ev {
                    Ok(text) => if socket.send(Message::Text(text)).await.is_err() { break },
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                },
                msg = socket.recv() => if !matches!(msg, Some(Ok(_))) { break },
            }
        }
    })
}

async fn ws_term(
    State(p): State<Arc<Panel>>,
    UrlPath(zone): UrlPath<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !p.authorized(&q, &h) || !p.same_origin(&h) {
        return deny();
    }
    let container = match zone.as_str() {
        "client" => p.info.client.clone(),
        "server" => p.info.server.clone(),
        _ => return (StatusCode::NOT_FOUND, "zone must be client or server").into_response(),
    };
    let dim = |k: &str, d: u16| q.get(k).and_then(|v| v.parse::<u16>().ok()).filter(|v| (10..=500).contains(v)).unwrap_or(d);
    let (cols, rows) = (dim("cols", 100), dim("rows", 30));
    ws.on_upgrade(move |socket| term_session(p, zone, container, cols, rows, socket))
}

async fn term_session(p: Arc<Panel>, zone: String, container: String, cols: u16, rows: u16, socket: WebSocket) {
    let (mut tx, mut rx) = socket.split();
    let spawned = p
        .docker
        .tty_exec(&container, "/lab", "bash", cols, rows)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(Message::Text(format!("\r\ncould not open a console: {e}\r\n"))).await;
            return;
        }
    };
    p.session_append(&format!("{zone}-console.log"), &format!("--- console opened, {cols}x{rows}"));
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let log_path = p.info.session.join(format!("{zone}-console.log"));

    // stdout and stderr (where wsl and script report their own failures) both
    // reach the browser and, raw, the session log.
    let (chunk_tx, mut chunks) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let etx = chunk_tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok(n) = stderr.read(&mut buf).await {
            if n == 0 || etx.send(buf[..n].to_vec()).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        while let Ok(n) = stdout.read(&mut buf).await {
            if n == 0 || chunk_tx.send(buf[..n].to_vec()).await.is_err() {
                break;
            }
        }
    });
    let out_task = tokio::spawn(async move {
        let mut log = std::fs::OpenOptions::new().create(true).append(true).open(&log_path).ok();
        while let Some(chunk) = chunks.recv().await {
            if let Some(f) = log.as_mut() {
                let _ = f.write_all(&chunk);
            }
            if tx.send(Message::Binary(chunk)).await.is_err() {
                break;
            }
        }
        let _ = tx.send(Message::Text("\r\n[console closed]\r\n".into())).await;
    });

    while let Some(Ok(msg)) = rx.next().await {
        let data = match msg {
            Message::Text(t) => t.into_bytes(),
            Message::Binary(b) => b,
            Message::Close(_) => break,
            _ => continue,
        };
        if stdin.write_all(&data).await.is_err() {
            break;
        }
    }
    drop(stdin);
    let _ = child.kill().await;
    out_task.abort();
    p.session_append(&format!("{zone}-console.log"), "--- console closed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netem_line_names_only_what_is_set() {
        let r = NetemReq { dir: "c2s".into(), delay_ms: 40.0, jitter_ms: 0.0, loss_pct: 1.5, duplicate_pct: 0.0, corrupt_pct: 0.0, rate_kbit: 10000.0 };
        assert_eq!(netem_args(&r).unwrap().join(" "), "delay 40ms loss 1.5% rate 10000kbit");
        let empty = NetemReq { delay_ms: 0.0, loss_pct: 0.0, rate_kbit: 0.0, ..r };
        assert!(netem_args(&empty).unwrap().is_empty());
    }

    #[test]
    fn netem_rejects_nonsense() {
        let r = NetemReq { dir: "c2s".into(), delay_ms: 0.0, jitter_ms: 5.0, loss_pct: 0.0, duplicate_pct: 0.0, corrupt_pct: 0.0, rate_kbit: 0.0 };
        assert!(netem_args(&r).is_err());
        let r = NetemReq { jitter_ms: 0.0, loss_pct: 150.0, ..r };
        assert!(netem_args(&r).is_err());
    }

    #[test]
    fn uuid_needle_matches_raw_bytes_too() {
        let forms = needle_forms("01234567-89ab-cdef-0123-456789abcdef");
        assert_eq!(forms.len(), 2);
        assert_eq!(forms[1].len(), 16);
        assert_eq!(forms[1][0], 0x01);
    }
}
