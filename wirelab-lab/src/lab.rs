//! A lab: client, wire and server containers left running for a person to
//! work in. Lives in `lab/<id>/` under the wirelab root.

use crate::docker::Docker;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CLIENT_IP: &str = "10.77.1.3";
pub const SERVER_IP: &str = "10.77.2.3";
pub const WIRE_CLIENT_SIDE: &str = "10.77.1.2";
pub const WIRE_SERVER_SIDE: &str = "10.77.2.2";
pub const TARGET_URL: &str = "http://127.0.0.1:8080/blob";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Base {
    /// musl: statically linked binaries (most Go builds) run as is.
    Alpine,
    /// glibc: for binaries linked against it.
    Debian,
}

impl Base {
    pub fn parse(s: &str) -> Result<Base> {
        match s {
            "alpine" => Ok(Base::Alpine),
            "debian" => Ok(Base::Debian),
            other => bail!("base {other:?}: expected alpine or debian"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Base::Alpine => "alpine",
            Base::Debian => "debian",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabInfo {
    pub id: String,
    pub base: Base,
    pub project: String,
    pub client: String,
    pub wire: String,
    pub server: String,
    pub dir: PathBuf,
    /// Where this run of the lab records consoles, wire changes and capture.
    pub session: PathBuf,
    pub started_unix: u64,
    /// The port the server is expected to listen on and the client to dial.
    /// Labs started before this field existed were told nothing, hence 443.
    #[serde(default = "default_port")]
    pub server_port: u16,
    /// The wire routes through wl-censor rather than the kernel. Set when
    /// the censor binary was built at `lab up` time.
    #[serde(default)]
    pub censor: bool,
}

pub const DEFAULT_PORT: u16 = 443;
pub const CENSOR_BIN: &str = "containers/wire/bin/wl-censor";

fn default_port() -> u16 {
    DEFAULT_PORT
}

impl LabInfo {
    pub fn summary(&self) -> String {
        format!(
            "lab {id} ({base}) is up\n\n\
             client   {CLIENT_IP}   folder {client_dir} is /lab inside\n\
             server   {SERVER_IP}   folder {server_dir} is /lab inside\n\
             wire     {WIRE_CLIENT_SIDE} (client side), {WIRE_SERVER_SIDE} (server side)\n\n\
             server listens on   0.0.0.0:{port}   (env WL_SERVER_PORT)\n\
             client connects to  {SERVER_IP}:{port}   (env WL_SERVER_ADDR, WL_SERVER_PORT)\n\n\
             Behind the server: {TARGET_URL} (20 MB, sha256 in /srv/www/blob.sha256).\n\
             Session records go to {session}\n\n\
             Panel:  wirelab lab panel --id {id}\n\
             Stop:   wirelab lab down --id {id}",
            id = self.id,
            base = self.base.name(),
            client_dir = self.dir.join("client").display(),
            server_dir = self.dir.join("server").display(),
            session = self.session.display(),
            port = self.server_port,
        )
    }
}

/// The wirelab checkout: the nearest ancestor of the working directory that
/// holds `containers/wire/Dockerfile`, or `WIRELAB_ROOT`.
pub fn find_root() -> Result<PathBuf> {
    if let Ok(r) = std::env::var("WIRELAB_ROOT") {
        return Ok(PathBuf::from(r));
    }
    let mut dir = std::env::current_dir()?;
    loop {
        if dir.join("containers/wire/Dockerfile").is_file() {
            return Ok(dir);
        }
        if !dir.pop() {
            bail!("not inside a wirelab checkout (no containers/wire/Dockerfile above the current directory); set WIRELAB_ROOT");
        }
    }
}

fn lab_dir(root: &Path, id: &str) -> Result<PathBuf> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        bail!("lab id {id:?}: use letters, digits and '-'");
    }
    Ok(root.join("lab").join(id))
}

pub fn load(root: &Path, id: &str) -> Result<LabInfo> {
    let path = lab_dir(root, id)?.join("lab.json");
    let text = fs::read_to_string(&path).with_context(|| format!("no lab {id:?} here ({} missing); start it with `wirelab lab up`", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

pub fn up(docker: &Docker, root: &Path, id: &str, base: Base, server_port: u16) -> Result<LabInfo> {
    if server_port == 0 {
        bail!("--port 0: pick the port the server will listen on");
    }
    let dir = lab_dir(root, id)?;
    let started_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let session = dir.join("sessions").join(started_unix.to_string());
    for d in [dir.join("client"), dir.join("server"), session.clone()] {
        fs::create_dir_all(&d).with_context(|| format!("creating {}", d.display()))?;
    }

    // --network host: inside WSL's mirrored networking the default bridge
    // cannot reach a resolver, so package downloads during a build fail.
    let containers = root.join("containers");
    let ctx = |p: &str| docker.daemon_path(&containers.join(p));
    docker.run_visible(&["build", "-q", "--network", "host", "-t", "wl-wire", &ctx("wire")?])?;
    let node_image = format!("wl-node-{}", base.name());
    let dockerfile = format!("{}/Dockerfile.{}", ctx("node")?, base.name());
    docker.run_visible(&["build", "-q", "--network", "host", "-t", &node_image, "-f", &dockerfile, &ctx("node")?])?;

    let project = format!("wl-lab-{id}");
    let info = LabInfo {
        id: id.to_string(),
        base,
        client: format!("{project}-client"),
        wire: format!("{project}-wire"),
        server: format!("{project}-server"),
        project,
        dir: dir.clone(),
        session: session.clone(),
        started_unix,
        server_port,
        censor: root.join(CENSOR_BIN).is_file(),
    };
    if !info.censor {
        println!("note: {} is not built, so the wire forwards in the kernel and has no censor", CENSOR_BIN);
    }

    let compose = dir.join("compose.yml");
    fs::write(&compose, compose_file(&info, &node_image))?;
    let compose_path = docker.daemon_path(&compose)?;
    docker.run_visible(&["compose", "-p", &info.project, "-f", &compose_path, "up", "-d", "--force-recreate"])?;

    let ready = session.join("wire.ready");
    for _ in 0..100 {
        if ready.exists() {
            fs::write(dir.join("lab.json"), serde_json::to_vec_pretty(&info)?)?;
            return Ok(info);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    bail!("wire container did not report ready within 10 s; see `docker logs {}`", info.wire)
}

pub fn down(docker: &Docker, root: &Path, id: &str) -> Result<()> {
    let info = load(root, id)?;
    let compose = docker.daemon_path(&info.dir.join("compose.yml"))?;
    docker.run_visible(&["compose", "-p", &info.project, "-f", &compose, "down", "-t", "3"])?;
    fs::remove_file(info.dir.join("lab.json"))?;
    Ok(())
}

fn compose_file(info: &LabInfo, node_image: &str) -> String {
    // nat-unprotected: since Docker 28 the default gateway mode drops packets
    // addressed to a container from outside its own network, and with
    // br_netfilter that includes our routed client→wire→server path.
    let net_opts = "driver_opts: {com.docker.network.bridge.gateway_mode_ipv4: nat-unprotected}";
    format!(
        r#"name: {project}
networks:
  net_c:
    {net_opts}
    ipam: {{config: [{{subnet: 10.77.1.0/24}}]}}
  net_s:
    {net_opts}
    ipam: {{config: [{{subnet: 10.77.2.0/24}}]}}
services:
  wire:
    image: wl-wire
    container_name: {wire}
    cap_add: [NET_ADMIN, NET_RAW]
    # The script and the censor come from the checkout rather than the image,
    # so changing them needs no rebuild.
    entrypoint: ["/bin/sh", "/wl-wire/entrypoint.sh"]
    sysctls: {{net.ipv4.ip_forward: "{forward}"}}
    environment: {{WIRE_CAPTURE: "0", WIRE_CENSOR: "{censor}"}}
    networks: {{net_c: {{ipv4_address: {wc}}}, net_s: {{ipv4_address: {ws}}}}}
    volumes: ["./sessions/{session}:/out", "../../containers/wire:/wl-wire:ro"]
  client:
    image: {node_image}
    container_name: {client}
    hostname: client
    cap_add: [NET_ADMIN]
    environment: {{ROLE: client, WL_SERVER_ADDR: "{sip}", WL_SERVER_PORT: "{port}"}}
    networks: {{net_c: {{ipv4_address: {cip}}}}}
    volumes: ["./client:/lab"]
    depends_on: [wire]
  server:
    image: {node_image}
    container_name: {server}
    hostname: server
    cap_add: [NET_ADMIN]
    environment: {{ROLE: server, WL_SERVER_ADDR: "{sip}", WL_SERVER_PORT: "{port}"}}
    networks: {{net_s: {{ipv4_address: {sip}}}}}
    volumes: ["./server:/lab"]
    depends_on: [wire]
"#,
        project = info.project,
        wire = info.wire,
        client = info.client,
        server = info.server,
        session = info.started_unix,
        wc = WIRE_CLIENT_SIDE,
        ws = WIRE_SERVER_SIDE,
        cip = CLIENT_IP,
        sip = SERVER_IP,
        port = info.server_port,
        forward = if info.censor { 0 } else { 1 },
        censor = if info.censor { 1 } else { 0 },
    )
}
