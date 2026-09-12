//! A two-endpoint tunnel simulator, and the tests that pin down the two things an
//! integration most easily gets wrong.
//!
//! 1. **The loop must be closed.** Machines advance on their own effects, not just on
//!    real traffic. A tunnel that never reports `PaddingSent` / `BlockingBegin` back into
//!    the framework runs a defense that mostly does nothing.
//! 2. **The defense is two-sided.** `interspace_client`'s start state transitions on
//!    `PaddingRecv` — padding arriving *from the peer*. With no server-side machines it
//!    never leaves state 0. Downstream traffic carries most of the website-fingerprinting
//!    signal anyway, so a client-only deployment defends the direction that matters least.
//!
//! Both are asserted below against the real Maybenot machines.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tad_engine::{Action, DefenseLevel, Engine, Policy, PolicySource, Role, TriggerEvent};

const TICK_MS: u64 = 1;
const HALF_RTT_TICKS: u64 = 15;

#[derive(Default, Debug, Clone, Copy, PartialEq)]
struct Stats {
    padding_sent: u64,
    normal_sent: u64,
    blocks_started: u64,
}

struct Endpoint {
    engine: Engine,
    padding_due: HashMap<usize, u64>,
    block_due: HashMap<usize, (u64, u64)>,
    blocking_until: Option<u64>,
    stats: Stats,
    /// Normal packets this endpoint owes the peer (server replies to a request).
    reply_queue: u64,
    /// When false, the endpoint deliberately withholds feedback events — the broken
    /// integration modelled as a negative control.
    closed_loop: bool,
}

impl Endpoint {
    fn new(level: DefenseLevel, role: Role, closed_loop: bool) -> Self {
        let policy = Policy {
            level,
            enforced: true,
            source: PolicySource::Profile,
            ..Default::default()
        };
        let engine = Engine::start_with_role(&policy, level, true, role).expect("engine starts");
        Self {
            engine,
            padding_due: HashMap::new(),
            block_due: HashMap::new(),
            blocking_until: None,
            stats: Stats::default(),
            reply_queue: 0,
            closed_loop,
        }
    }

    /// Expire this endpoint's timers, emitting the events a real tunnel would emit and
    /// returning the packets it puts on the wire as `(is_padding)`.
    fn expire(&mut self, tick: u64, events: &mut Vec<TriggerEvent>, wire: &mut Vec<bool>) {
        if let Some(until) = self.blocking_until
            && tick >= until
        {
            self.blocking_until = None;
            if self.closed_loop {
                events.push(TriggerEvent::BlockingEnd);
            }
        }

        let due: Vec<usize> = self
            .padding_due
            .iter()
            .filter(|&(_, &due)| due <= tick)
            .map(|(&m, _)| m)
            .collect();
        for m in due {
            self.padding_due.remove(&m);
            self.stats.padding_sent += 1;
            wire.push(true);
            if self.closed_loop {
                events.push(TriggerEvent::PaddingSent {
                    machine: maybenot::MachineId::from_raw(m),
                });
                events.push(TriggerEvent::TunnelSent);
            }
        }

        let due: Vec<(usize, u64)> = self
            .block_due
            .iter()
            .filter(|&(_, &(due, _))| due <= tick)
            .map(|(&m, &(_, dur))| (m, dur))
            .collect();
        for (m, dur) in due {
            self.block_due.remove(&m);
            self.stats.blocks_started += 1;
            self.blocking_until = Some(tick + dur.max(1));
            if self.closed_loop {
                events.push(TriggerEvent::BlockingBegin {
                    machine: maybenot::MachineId::from_raw(m),
                });
            }
        }
    }

    fn send_normal(&mut self, events: &mut Vec<TriggerEvent>, wire: &mut Vec<bool>) {
        self.stats.normal_sent += 1;
        wire.push(false);
        events.push(TriggerEvent::NormalSent);
        events.push(TriggerEvent::TunnelSent);
    }

    fn receive(&mut self, is_padding: bool, events: &mut Vec<TriggerEvent>) {
        events.push(TriggerEvent::TunnelRecv);
        events.push(if is_padding {
            TriggerEvent::PaddingRecv
        } else {
            TriggerEvent::NormalRecv
        });
    }

    fn pump(&mut self, events: &[TriggerEvent], tick: u64, now: Instant) {
        if events.is_empty() {
            return;
        }
        for action in self.engine.on_events(events, now) {
            match action {
                Action::SendPadding {
                    machine, timeout, ..
                } => {
                    self.padding_due.insert(machine, tick + ms(timeout).max(1));
                }
                Action::BlockOutgoing {
                    machine,
                    timeout,
                    duration,
                    ..
                } => {
                    self.block_due
                        .insert(machine, (tick + ms(timeout), ms(duration)));
                }
                Action::Cancel { machine, .. } => {
                    self.padding_due.remove(&machine);
                    self.block_due.remove(&machine);
                }
                // A real tunnel arms a timer here and feeds TimerBegin/TimerEnd back.
                Action::UpdateTimer { .. } => {}
            }
        }
    }
}

/// A tunnel between a phone and a VPN server, with or without server-side machines.
struct Link {
    client: Endpoint,
    server: Option<Endpoint>,
    /// (arrival_tick, to_client, is_padding)
    in_flight: Vec<(u64, bool, bool)>,
    t0: Instant,
}

impl Link {
    fn new(level: DefenseLevel, with_server: bool, closed_loop: bool) -> Self {
        Self {
            client: Endpoint::new(level, Role::Client, closed_loop),
            server: with_server
                .then(|| Endpoint::new(level, Role::Server, closed_loop))
                // A level whose server machine list is empty still yields a valid engine
                // only if it has machines; Light has none server-side, so callers pass
                // with_server = false for it.
                .filter(|_| !level.server_machines().is_empty()),
            in_flight: Vec::new(),
            t0: Instant::now(),
        }
    }

    fn run(&mut self, ticks: u64) {
        for tick in 0..ticks {
            let now = self.t0 + Duration::from_millis(tick * TICK_MS);
            let mut c_events = Vec::new();
            let mut s_events = Vec::new();
            let mut c_wire: Vec<bool> = Vec::new();
            let mut s_wire: Vec<bool> = Vec::new();

            // Deliver what arrived this tick.
            let arrived: Vec<(u64, bool, bool)> = self
                .in_flight
                .iter()
                .copied()
                .filter(|&(at, _, _)| at == tick)
                .collect();
            self.in_flight.retain(|&(at, _, _)| at > tick);
            for (_, to_client, is_padding) in arrived {
                if to_client {
                    self.client.receive(is_padding, &mut c_events);
                } else if let Some(s) = self.server.as_mut() {
                    s.receive(is_padding, &mut s_events);
                    if !is_padding {
                        s.reply_queue += 3; // downstream is heavier than upstream
                    }
                }
            }

            self.client.expire(tick, &mut c_events, &mut c_wire);
            if let Some(s) = self.server.as_mut() {
                s.expire(tick, &mut s_events, &mut s_wire);
            }

            // The phone's real traffic: a short burst every 10s, then idle. A flat
            // packet-every-20ms pattern is unrealistic and actively suppresses
            // idle-driven defenses like NetFlow padding, whose timer every real packet
            // resets.
            let in_burst = tick % 10_000 < 600;
            if in_burst && tick % 20 == 0 && self.client.blocking_until.is_none() {
                self.client.send_normal(&mut c_events, &mut c_wire);
            }
            if let Some(s) = self.server.as_mut()
                && s.reply_queue > 0
                && tick % 5 == 0
                && s.blocking_until.is_none()
            {
                s.reply_queue -= 1;
                s.send_normal(&mut s_events, &mut s_wire);
            }

            self.client.pump(&c_events, tick, now);
            if let Some(s) = self.server.as_mut() {
                s.pump(&s_events, tick, now);
            }

            let arrival = tick + HALF_RTT_TICKS;
            for is_padding in c_wire {
                self.in_flight.push((arrival, false, is_padding));
            }
            for is_padding in s_wire {
                self.in_flight.push((arrival, true, is_padding));
            }
        }
    }
}

fn ms(d: Duration) -> u64 {
    d.as_millis().min(u64::MAX as u128) as u64
}

#[test]
fn interspace_is_inert_without_a_peer_and_alive_with_one() {
    let mut alone = Link::new(DefenseLevel::Moderate, false, true);
    alone.run(60_000);

    let mut paired = Link::new(DefenseLevel::Moderate, true, true);
    paired.run(60_000);

    assert!(
        paired.server.is_some(),
        "Moderate must define server-side machines"
    );
    assert_eq!(
        alone.client.stats.padding_sent, 0,
        "client-only Interspace should emit no padding — its start state waits on \
         PaddingRecv. Got {:?}",
        alone.client.stats
    );
    assert!(
        paired.client.stats.padding_sent > 0,
        "with a peer running interspace_server the client should pad; got {:?}",
        paired.client.stats
    );
}

#[test]
fn closing_the_feedback_loop_changes_the_outcome() {
    let mut closed = Link::new(DefenseLevel::Moderate, true, true);
    closed.run(60_000);

    let mut open = Link::new(DefenseLevel::Moderate, true, false);
    open.run(60_000);

    assert!(
        closed.client.stats.padding_sent > open.client.stats.padding_sent,
        "a tunnel that withholds PaddingSent/BlockingBegin should defend less: \
         closed={:?} open={:?}",
        closed.client.stats,
        open.client.stats
    );
}

#[test]
fn netflow_padding_needs_no_peer_and_fires_when_idle() {
    // Light is the one level with no server-side counterpart: it coarsens NetFlow
    // records by padding during idle periods, which one endpoint can do alone.
    assert!(!DefenseLevel::Light.requires_peer());

    let mut link = Link::new(DefenseLevel::Light, false, true);
    link.run(60_000);
    assert!(
        link.client.stats.padding_sent > 0,
        "NetFlow padding should fire during the idle gaps; got {:?}",
        link.client.stats
    );
}

#[test]
fn heavy_shapes_traffic_with_a_peer() {
    let mut link = Link::new(DefenseLevel::Heavy, true, true);
    link.run(60_000);
    let acted = link.client.stats.padding_sent + link.client.stats.blocks_started;
    assert!(
        acted > 0,
        "Heavy should pad or block on the client; got {:?}",
        link.client.stats
    );
}
