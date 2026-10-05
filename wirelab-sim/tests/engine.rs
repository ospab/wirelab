//! Engine properties, checked with a minimal endpoint on the virtual clock:
//! one app chunk per datagram, no reliability, no state beyond "started".

use bytes::Bytes;
use wirelab_core::{ClockKind, Endpoint, Output, SimTime};
use wirelab_sim::{Pace, ResolvedPace, Scenario};

struct Plain {
    started: bool,
}

impl Endpoint for Plain {
    fn protocol(&self) -> &'static str {
        "plain"
    }
    fn clock(&self) -> ClockKind {
        ClockKind::Virtual
    }
    fn start(&mut self, _: SimTime, _: &mut Output) {
        self.started = true;
    }
    fn on_datagram(&mut self, _: SimTime, data: Bytes, out: &mut Output) {
        out.delivered.push((1, data));
    }
    fn tick(&mut self, _: SimTime, _: &mut Output) {}
    fn is_established(&self) -> bool {
        self.started
    }
    fn state(&self) -> String {
        if self.started { "up" } else { "init" }.into()
    }
    fn can_send(&self) -> bool {
        true
    }
    fn send(&mut self, _: SimTime, _: u32, data: Bytes, out: &mut Output) -> anyhow::Result<()> {
        out.datagrams.push(data);
        Ok(())
    }
}

fn scenario(wire: &str) -> Scenario {
    let text = format!(
        "name = \"t\"\nseed = 42\n[protocol]\nname = \"plain\"\n[wire]\n{wire}\n[[transfer]]\nfrom = \"client\"\nbytes = 200000\n"
    );
    let sc: Scenario = toml::from_str(&text).unwrap();
    sc.validate().unwrap();
    sc
}

fn run(sc: &Scenario) -> wirelab_sim::RunOutput {
    wirelab_sim::run(sc, Box::new(Plain { started: false }), Box::new(Plain { started: false }), Pace::Auto)
}

#[test]
fn virtual_endpoints_run_on_virtual_time() {
    let out = run(&scenario("latency_ms = 30.0"));
    assert_eq!(out.pace, ResolvedPace::Virtual);
    assert!(out.timing_valid);
    let t = &out.transfers[0];
    assert_eq!(t.delivered, 200_000);
    assert_eq!(t.first_mismatch, None);
    // Everything leaves at 0 on an unlimited link and lands 30 ms later.
    assert_eq!(t.completed_at, Some(SimTime::from_ms(30)));
}

#[test]
fn same_seed_same_recording() {
    let sc = scenario("latency_ms = 20.0\njitter_ms = 5.0\nloss = 0.1\nduplicate = 0.05\ncorrupt = 0.05\nreorder = 0.1\nreorder_delay_ms = 8.0");
    let a = format!("{:?}", run(&sc).records);
    let b = format!("{:?}", run(&sc).records);
    assert_eq!(a, b);
}

#[test]
fn loss_shows_up_as_a_shortfall_not_a_pass() {
    let out = run(&scenario("loss = 0.2"));
    let report = wirelab_sim::report::build(&scenario("loss = 0.2"), &out);
    assert!(report.has_failures());
    assert!(out.transfers[0].delivered < 200_000);
}
