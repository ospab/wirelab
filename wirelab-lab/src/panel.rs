//! The local panel: two consoles and the wire between them.
//!
//! Binds to 127.0.0.1 only and requires the token printed at start: the
//! consoles are root shells in the lab, so any page or local process that
//! could reach the panel would otherwise own them.

use crate::docker::Docker;
use crate::lab::{self, LabInfo};
use crate::wirectl::{self, PathReq, Wire};
use anyhow::{Context, Result};
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
use wirelab_wire::analyze::{TcpRtt, Way};
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
    ctl: Wire,
    wire: Mutex<WireState>,
    events: broadcast::Sender<String>,
    /// The ping from client to server, while it is on.
    ping: Mutex<Option<tokio::task::JoinHandle<()>>>,
    root: std::path::PathBuf,
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
    /// One point per second of capture time, for the charts.
    series: VecDeque<SecPoint>,
    rtt: TcpRtt,
}

/// One second on the charts: IP bytes each way and the RTT samples taken
/// in it (passive TCP from the capture, and ping when it is on).
#[derive(Clone, Default, Serialize)]
struct SecPoint {
    /// Unix seconds, capture clock.
    t: u64,
    c2s: u64,
    s2c: u64,
    /// Median of the TCP samples in this second, ms.
    tcp_rtt: Option<f64>,
    #[serde(skip)]
    tcp_samples: Vec<f64>,
    ping: Option<f64>,
}

const SERIES_SECONDS: usize = 300;

impl WireState {
    fn point(&mut self, t: u64) -> &mut SecPoint {
        if self.series.back().map_or(true, |p| p.t < t) {
            // Seconds without packets are zeros, not gaps.
            let mut next = self.series.back().map_or(t, |p| p.t + 1).max(t.saturating_sub(SERIES_SECONDS as u64));
            while next <= t {
                self.series.push_back(SecPoint { t: next, ..Default::default() });
                next += 1;
            }
            while self.series.len() > SERIES_SECONDS {
                self.series.pop_front();
            }
        }
        let i = self.series.iter().rposition(|p| p.t == t).unwrap_or(self.series.len() - 1);
        &mut self.series[i]
    }
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

pub async fn serve(root: std::path::PathBuf, id: String, port: u16) -> Result<()> {
    let info = lab::load(&root, &id)?;
    let docker = Docker::detect();
    let ctl = Wire::open(&docker, &info)?;

    let mut raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut raw);
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let (events, _) = broadcast::channel(64);
    let panel = Arc::new(Panel {
        origins: [format!("http://127.0.0.1:{port}"), format!("http://localhost:{port}")],
        ctl,
        presets: root.join("containers/censor/presets"),
        info,
        docker,
        token,
        wire: Mutex::new(WireState { capture: "starting".into(), ..Default::default() }),
        events,
        ping: Mutex::new(None),
        root: root.clone(),
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
        .route("/api/ping", post(api_ping))
        .route("/api/export", get(api_export))
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
    let qdisc = tokio::task::spawn_blocking(move || p2.ctl.qdisc()).await.unwrap_or_default();
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

async fn api_netem(State(p): State<Arc<Panel>>, Query(q): Query<HashMap<String, String>>, h: HeaderMap, Json(r): Json<PathReq>) -> Response {
    if !p.authorized(&q, &h) {
        return deny();
    }
    if let Err(e) = wirectl::netem_args(&r.one_way()) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    let p2 = p.clone();
    let result = tokio::task::spawn_blocking(move || {
        p2.ctl.apply(&r, |line| p2.session_append("wire-changes.log", line))?;
        Ok::<_, anyhow::Error>(p2.ctl.qdisc())
    })
    .await;
    match result {
        Ok(Ok(qdisc)) => Json(serde_json::json!({ "qdisc": qdisc })).into_response(),
        Ok(Err(e)) => {
            // Stopped at the first failure: show the qdiscs as they really are.
            let qdisc = p.ctl.qdisc();
            (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": e.to_string(), "qdisc": qdisc }))).into_response()
        }
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
        .tokio_command(&["exec", &p.info.wire, "tcpdump", "-i", &p.ctl.if_to_client, "-U", "-s", "0", "-B", "65536", "-w", "-", "net 10.77.0.0/16"])
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
    let way = if idx == 0 { Way::C2s } else { Way::S2c };
    let sample = w.rtt.push(way, &pkt);
    let pt = w.point(pkt.t_us / 1_000_000);
    match way {
        Way::C2s => pt.c2s += pkt.ip_len as u64,
        Way::S2c => pt.s2c += pkt.ip_len as u64,
    }
    if let Some(us) = sample {
        pt.tcp_samples.push(us as f64 / 1000.0);
        let mut v = pt.tcp_samples.clone();
        v.sort_by(|a, b| a.total_cmp(b));
        pt.tcp_rtt = Some(v[v.len() / 2]);
    }
    let c = &mut w.counts[idx];
    c.packets += 1;
    c.ip_bytes += pkt.ip_len as u64;
    c.payload_bytes += pkt.payload_len as u64;

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
        payload: pkt.payload_len,
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
            // The last few seconds: earlier ones do not change any more.
            let series: Vec<&SecPoint> = w.series.iter().rev().take(5).collect();
            serde_json::json!({
                "type": "tick", "counts": w.counts, "rows": rows, "dropped_rows": dropped,
                "capture": w.capture, "alarms": w.alarms.len(), "censor": censor, "series": series,
            })
        };
        let _ = p.events.send(msg.to_string());
    }
}

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
    let active = std::fs::read(p.info.session.join(wirectl::ACTIVE_PRESET)).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
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
    /// Hypothesis id -> chosen value; absent ones take the preset default.
    #[serde(default)]
    hypotheses: HashMap<String, bool>,
}

async fn api_censor_set(State(p): State<Arc<Panel>>, Query(q): Query<HashMap<String, String>>, h: HeaderMap, Json(r): Json<CensorReq>) -> Response {
    if !p.authorized(&q, &h) {
        return deny();
    }
    if !p.info.censor {
        return (StatusCode::CONFLICT, "this lab was started without the censor; build wl-censor, then lab down and lab up").into_response();
    }
    let Some(file) = r.file else {
        let _ = wirectl::activate_preset(&p.info.session, None);
        p.session_append("wire-changes.log", "censor: off");
        return Json(serde_json::json!({ "active": null })).into_response();
    };
    let (preset, note) = match wirectl::build_preset(&p.presets, &file, &r.disabled, &r.hypotheses) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("{e:#}")).into_response(),
    };
    if let Err(e) = wirectl::activate_preset(&p.info.session, Some(&preset)) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    p.session_append("wire-changes.log", &note);
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
                "censor": w.censor_recent, "series": w.series,
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

#[derive(Deserialize)]
struct PingReq {
    on: bool,
}

/// RTT for any protocol, UDP included: ping from the client to the server
/// once a second. Its ICMP shows up on the wire, so it is off by default.
async fn api_ping(State(p): State<Arc<Panel>>, Query(q): Query<HashMap<String, String>>, h: HeaderMap, Json(r): Json<PingReq>) -> Response {
    if !p.authorized(&q, &h) {
        return deny();
    }
    {
        let mut slot = p.ping.lock().unwrap();
        if let Some(t) = slot.take() {
            t.abort();
        }
        if r.on {
            *slot = Some(tokio::spawn(ping_loop(p.clone())));
        }
    }
    p.session_append("wire-changes.log", if r.on { "ping client -> server: on" } else { "ping client -> server: off" });
    Json(serde_json::json!({ "on": r.on })).into_response()
}

async fn ping_loop(p: Arc<Panel>) {
    use tokio::io::AsyncBufReadExt;
    let child = p
        .docker
        .tokio_command(&["exec", &p.info.client, "ping", "-n", "-i", "1", lab::SERVER_IP])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let Ok(mut child) = child else { return };
    let mut out = tokio::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    while out.read_line(&mut line).await.map(|n| n > 0).unwrap_or(false) {
        // "64 bytes from 10.77.2.3: seq=3 ttl=63 time=35.412 ms"
        if let Some(ms) = line.split("time=").nth(1).and_then(|r| r.split_whitespace().next()).and_then(|v| v.parse::<f64>().ok()) {
            let t = (now_ms() / 1000) as u64;
            let mut w = p.wire.lock().unwrap();
            w.point(t).ping = Some(ms);
        }
        line.clear();
    }
    drop(child);
}

/// The session as a .tar.gz download (see `wirelab lab export`).
async fn api_export(State(p): State<Arc<Panel>>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> Response {
    if !p.authorized(&q, &h) {
        return deny();
    }
    let p2 = p.clone();
    let built = tokio::task::spawn_blocking(move || {
        let name = format!("{}-{}.tar.gz", p2.info.id, p2.info.started_unix);
        let out = p2.root.join("lab").join(&p2.info.id).join("exports").join(&name);
        crate::export::archive_session(&p2.info.dir, &p2.info.session, &out).map(|_| (name, out))
    })
    .await;
    match built {
        Ok(Ok((name, out))) => match tokio::fs::read(&out).await {
            Ok(bytes) => (
                [
                    (axum::http::header::CONTENT_TYPE, "application/gzip".to_string()),
                    (axum::http::header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
                ],
                bytes,
            )
                .into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_needle_matches_raw_bytes_too() {
        let forms = needle_forms("01234567-89ab-cdef-0123-456789abcdef");
        assert_eq!(forms.len(), 2);
        assert_eq!(forms[1].len(), 16);
        assert_eq!(forms[1][0], 0x01);
    }
}
