//! OSTP adapter: the real `ostp-core::ProtocolMachine`, driven sans-io.
//!
//! Defaults mirror production: the client side as `ostp-client/src/bridge.rs`
//! builds its machine, the server side as `ostp-server/src/lib.rs` does.
//! Admission control is the one the production callers apply around the
//! machine (`bridge.rs` and `dispatcher.rs`): in-flight below the congestion
//! window clamped to 16..=1024, and the pacing bucket open.
//!
//! What is not here: handshake retransmission. `ostp-core` does not resend a
//! lost handshake datagram; the client bridge does that a layer up. A lossy
//! scenario that should still connect sets `impair_from_ms` past the handshake.

use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use ostp_core::crypto::derive_all_secrets;
use ostp_core::framing::PaddingStrategy;
use ostp_core::{NoiseRole, OstpEvent, OstpState, ProtocolAction, ProtocolConfig, ProtocolMachine, TrafficProfile};
use serde::Deserialize;
use wirelab_core::{ClockKind, Endpoint, Output, Side, SimTime};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    #[allow(dead_code)]
    name: String,
    #[serde(default = "default_key")]
    access_key: String,
    #[serde(default = "default_session_id")]
    session_id: u32,
    /// Client MTU. The server side always uses its production 1350.
    #[serde(default = "default_mtu")]
    mtu: usize,
    /// Client padding profile: json_rpc (the client's default), https_burst
    /// or video_stream. The server pads adaptively, as in production.
    #[serde(default = "default_profile")]
    client_profile: String,
}

fn default_key() -> String {
    "wirelab-default-access-key".into()
}
fn default_session_id() -> u32 {
    0x0001_0001
}
fn default_mtu() -> usize {
    1350
}
fn default_profile() -> String {
    "json_rpc".into()
}

const SERVER_MTU: usize = 1350;

pub struct OstpEndpoint {
    side: Side,
    machine: ProtocolMachine,
}

/// Build a connected-to-be client/server pair from a scenario's `[protocol]`.
pub fn build_pair(table: &toml::value::Table) -> Result<(Box<dyn Endpoint>, Box<dyn Endpoint>)> {
    let p: Params = toml::Value::Table(table.clone()).try_into().map_err(|e| anyhow!("[protocol] for ostp: {e}"))?;
    let secrets = derive_all_secrets(p.access_key.as_bytes());
    let profile = match p.client_profile.as_str() {
        "json_rpc" => TrafficProfile::JsonRpc,
        "https_burst" => TrafficProfile::HttpsBurst,
        "video_stream" => TrafficProfile::VideoStream,
        other => bail!("client_profile = {other:?}: expected json_rpc, https_burst or video_stream"),
    };

    // Same layout as bridge.rs: unix seconds, session id, access key. The
    // machine pair does not validate it (the server's dispatcher does), but it
    // sets the size of the first datagram an observer sees.
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut hello = Vec::with_capacity(12 + p.access_key.len());
    hello.extend_from_slice(&ts.to_be_bytes());
    hello.extend_from_slice(&p.session_id.to_be_bytes());
    hello.extend_from_slice(p.access_key.as_bytes());

    let common = |role, mtu, max_padding, padding_strategy, handshake_payload| ProtocolConfig {
        role,
        psk: secrets.psk,
        session_id: p.session_id,
        handshake_payload,
        max_padding,
        padding_strategy,
        obfuscation_key: secrets.obfuscation_key,
        max_reorder: 16384,
        max_reorder_buffer: 8192,
        ack_delay_ms: 5,
        rto_ms: 100,
        max_retries: 8,
        max_sent_history: 32768,
        handshake_pad_min: secrets.handshake_pad_min,
        handshake_pad_max: secrets.handshake_pad_max,
        mtu,
    };
    let client = common(NoiseRole::Initiator, p.mtu, p.mtu.saturating_sub(48).max(256), PaddingStrategy::Profile(profile), hello);
    let server = common(NoiseRole::Responder, SERVER_MTU, 256, PaddingStrategy::Adaptive, Vec::new());

    let build = |side, cfg| -> Result<Box<dyn Endpoint>> {
        let machine = ProtocolMachine::new(cfg).map_err(|e| anyhow!("building {side:?} machine: {e}"))?;
        Ok(Box::new(OstpEndpoint { side, machine }))
    };
    Ok((build(Side::Client, client)?, build(Side::Server, server)?))
}

impl OstpEndpoint {
    fn apply(&mut self, result: Result<ProtocolAction, ostp_core::protocol::ProtocolError>, what: &str, out: &mut Output) {
        match result {
            Ok(action) => walk(action, out),
            // Expected under corruption and replay; the endpoint carries on,
            // so it is recorded rather than propagated.
            Err(e) => out.note("rejected", format!("{what}: {e}")),
        }
    }
}

fn walk(action: ProtocolAction, out: &mut Output) {
    match action {
        ProtocolAction::SendDatagram(d) => out.datagrams.push(d),
        ProtocolAction::DeliverApp(stream, data) => out.delivered.push((stream as u32, data)),
        ProtocolAction::HandshakePayload(_, Some(d)) => out.datagrams.push(d),
        ProtocolAction::HandshakePayload(_, None) | ProtocolAction::Noop => {}
        ProtocolAction::Multiple(list) => list.into_iter().for_each(|a| walk(a, out)),
    }
}

impl Endpoint for OstpEndpoint {
    fn protocol(&self) -> &'static str {
        "ostp"
    }

    fn clock(&self) -> ClockKind {
        // ostp-core reads Instant::now() for RTO, delayed ACKs, pacing and
        // gap recovery; it has no clock injection.
        ClockKind::Wall
    }

    fn start(&mut self, _now: SimTime, out: &mut Output) {
        let r = self.machine.on_event(OstpEvent::Start);
        self.apply(r, "start", out);
    }

    fn on_datagram(&mut self, _now: SimTime, data: Bytes, out: &mut Output) {
        let r = self.machine.on_event(OstpEvent::Inbound(data));
        self.apply(r, "inbound", out);
    }

    fn tick(&mut self, _now: SimTime, out: &mut Output) {
        if matches!(self.machine.state(), OstpState::Established | OstpState::Closing) {
            let r = self.machine.on_event(OstpEvent::Tick);
            self.apply(r, "tick", out);
        }
    }

    fn is_established(&self) -> bool {
        self.machine.state() == OstpState::Established
    }

    fn state(&self) -> String {
        format!("{:?}", self.machine.state())
    }

    fn can_send(&self) -> bool {
        self.is_established()
            && self.machine.in_flight_count() < self.machine.cwnd_packets().clamp(16, 1024)
            && self.machine.can_pace_packet()
    }

    fn send(&mut self, _now: SimTime, stream: u32, data: Bytes, out: &mut Output) -> Result<()> {
        let stream = u16::try_from(stream).map_err(|_| anyhow!("{:?}: OSTP stream ids are 16-bit, got {stream}", self.side))?;
        let action = self.machine.on_event(OstpEvent::Outbound(stream, data)).map_err(|e| anyhow!("outbound: {e}"))?;
        walk(action, out);
        Ok(())
    }

    fn metrics(&self) -> Vec<(&'static str, f64)> {
        vec![
            ("cwnd_packets", self.machine.cwnd_packets() as f64),
            ("in_flight", self.machine.in_flight_count() as f64),
            ("authenticated_recv", self.machine.authenticated_recv_count() as f64),
        ]
    }
}
