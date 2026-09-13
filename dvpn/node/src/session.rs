//! The session loop, shared by both ends.
//!
//! This is the closed feedback loop that `tad-engine`'s tests insist on, wired to a real
//! socket: every action the engine returns is carried out by the transport, and every
//! action carried out is reported back as an event. The client and the server run the
//! *same* loop — only the role, and where traffic originates, differ. That symmetry is the
//! point: a traffic-analysis defense with one end implemented is not a defense.

use std::time::{Duration, Instant};

use dvpn_transport::{ChaChaSeal, Emitted, Endpoint, Received, TransportError};
use tad_engine::{Action, DefenseLevel, Engine, Role, TriggerEvent};

use crate::timers::{Block, Padding, Timers};

/// How long the loop may sleep when nothing is scheduled. Short enough to stay responsive,
/// long enough that an idle tunnel is not a busy loop burning a phone battery.
const MAX_IDLE: Duration = Duration::from_millis(5);

pub struct Session {
    pub engine: Engine,
    pub endpoint: Endpoint<ChaChaSeal>,
    timers: Timers,
    pending: Vec<TriggerEvent>,
    blocking_active: bool,
}

/// Traffic this end originates, independent of the defense.
pub trait Source {
    /// Packets to send at `now`, if any.
    fn packets(&mut self, now: Instant) -> Vec<Vec<u8>>;
    /// Told about inbound real packets, so a server can answer them.
    fn on_received(&mut self, _payload: &[u8], _now: Instant) {}
    /// Whether the workload has finished.
    fn done(&self, _now: Instant) -> bool {
        false
    }
}

impl Session {
    pub fn new(engine: Engine, endpoint: Endpoint<ChaChaSeal>) -> Self {
        Self {
            engine,
            endpoint,
            timers: Timers::default(),
            pending: Vec::new(),
            blocking_active: false,
        }
    }

    pub fn level(&self) -> DefenseLevel {
        self.engine.level()
    }
    pub fn role(&self) -> Role {
        self.engine.role()
    }

    /// Run until `deadline`, or until the source says it is finished.
    pub fn run(&mut self, source: &mut dyn Source, deadline: Instant) -> Result<(), TransportError> {
        while Instant::now() < deadline && !source.done(Instant::now()) {
            let now = Instant::now();

            self.drain_socket(source, now)?;
            self.fire_timers(now)?;
            self.originate(source, now)?;
            self.pump(now);

            // Sleep until the next scheduled action rather than spinning.
            let wake = self
                .timers
                .next_deadline()
                .map(|t| t.saturating_duration_since(Instant::now()))
                .unwrap_or(MAX_IDLE)
                .min(MAX_IDLE);
            if !wake.is_zero() {
                std::thread::sleep(wake);
            }
        }
        Ok(())
    }

    /// Read everything currently waiting, turning each datagram into the pair of events the
    /// framework expects: `TunnelRecv` first, before the frame is classified, then
    /// `NormalRecv` or `PaddingRecv` once it is.
    fn drain_socket(&mut self, source: &mut dyn Source, now: Instant) -> Result<(), TransportError> {
        for _ in 0..64 {
            match self.endpoint.recv(now)? {
                Some(Received::Data(payload)) => {
                    self.pending.push(TriggerEvent::TunnelRecv);
                    self.pending.push(TriggerEvent::NormalRecv);
                    source.on_received(&payload, now);
                }
                Some(Received::Padding) => {
                    self.pending.push(TriggerEvent::TunnelRecv);
                    self.pending.push(TriggerEvent::PaddingRecv);
                }
                Some(Received::Control(_)) | Some(Received::Close) => {}
                None => break,
            }
        }
        Ok(())
    }

    fn fire_timers(&mut self, now: Instant) -> Result<(), TransportError> {
        // Blocking that has run its course.
        if self.blocking_active && !self.endpoint.is_blocked(now) {
            self.blocking_active = false;
            self.pending.push(TriggerEvent::BlockingEnd);
            // Traffic held during the block leaves now.
            for e in self.endpoint.flush(now)? {
                self.report_emitted(e);
            }
        }

        for (machine, p) in self.timers.due_padding(now) {
            // `replace` means an already-queued real packet may stand in for this padding.
            // The engine still wants PaddingSent either way — omitting it stalls the
            // machine, which is the single most common way this integration is got wrong.
            let replaced = p.replace && self.endpoint.has_queued();
            if replaced {
                for e in self.endpoint.flush(now)? {
                    self.report_emitted(e);
                }
                self.pending.push(TriggerEvent::PaddingSent { machine: mid(machine) });
            } else if self.endpoint.send_padding(now, p.bypass)? {
                self.pending.push(TriggerEvent::PaddingSent { machine: mid(machine) });
                self.pending.push(TriggerEvent::TunnelSent);
            }
        }

        for (machine, b) in self.timers.due_blocks(now) {
            self.endpoint.block_outgoing(now, b.duration, b.bypass);
            self.blocking_active = true;
            self.pending.push(TriggerEvent::BlockingBegin { machine: mid(machine) });
        }

        for (machine, _) in self.timers.due_internal(now) {
            self.pending.push(TriggerEvent::TimerEnd { machine: mid(machine) });
        }
        Ok(())
    }

    fn originate(&mut self, source: &mut dyn Source, now: Instant) -> Result<(), TransportError> {
        for packet in source.packets(now) {
            self.endpoint.queue(&packet)?;
        }
        for e in self.endpoint.flush(now)? {
            self.report_emitted(e);
        }
        Ok(())
    }

    fn report_emitted(&mut self, e: Emitted) {
        match e {
            Emitted::Data => {
                self.pending.push(TriggerEvent::NormalSent);
                self.pending.push(TriggerEvent::TunnelSent);
            }
            Emitted::Padding => self.pending.push(TriggerEvent::TunnelSent),
            Emitted::Control => {}
        }
    }

    /// Hand the batch to the engine and schedule whatever it asks for.
    ///
    /// Batched deliberately: the framework evaluates a whole batch against one timestamp,
    /// and a later event may supersede an action an earlier one produced.
    fn pump(&mut self, now: Instant) {
        if self.pending.is_empty() {
            return;
        }
        let events = std::mem::take(&mut self.pending);
        for action in self.engine.on_events(&events, now) {
            match action {
                Action::SendPadding { machine, timeout, replace, bypass } => {
                    self.timers.schedule_padding(
                        machine,
                        Padding { at: now + timeout, bypass, replace },
                    );
                }
                Action::BlockOutgoing { machine, timeout, duration, bypass, .. } => {
                    self.timers
                        .schedule_block(machine, Block { at: now + timeout, duration, bypass });
                }
                Action::Cancel { machine, timer } => match timer {
                    tad_engine::Timer::Action => self.timers.cancel(machine),
                    tad_engine::Timer::Internal => self.timers.cancel_internal(machine),
                    tad_engine::Timer::All => {
                        self.timers.cancel(machine);
                        self.timers.cancel_internal(machine);
                    }
                },
                Action::UpdateTimer { machine, duration, .. } => {
                    self.timers.schedule_internal(machine, now + duration);
                    self.pending.push(TriggerEvent::TimerBegin { machine: mid(machine) });
                }
            }
        }
    }
}

fn mid(raw: usize) -> tad_engine::MachineId {
    tad_engine::MachineId::from_raw(raw)
}
