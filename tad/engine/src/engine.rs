//! The defense engine — a thin, testable shell around a Maybenot [`Framework`].
//!
//! The engine owns no I/O. The packet tunnel feeds it events and executes the actions it
//! returns; that separation is what makes the whole thing testable off-device.
//!
//! The contract the tunnel must honour (from Maybenot's own docs — get this wrong and the
//! machines mis-schedule):
//!
//! - `TunnelRecv` for every incoming tunnel packet, before decryption or queueing.
//! - `NormalRecv` / `PaddingRecv` once the packet has been classified, after `TunnelRecv`.
//! - `NormalSent` when a real outgoing packet is queued, `TunnelSent` when it leaves.
//! - `PaddingSent { machine }` whenever a `SendPadding` action is honoured — **including
//!   when the padding was replaced** by an already-queued packet.
//! - `BlockingBegin` / `BlockingEnd` around honoured `BlockOutgoing` actions.

use std::time::Instant;

use maybenot::{Framework, Machine, MachineId, Timer, TriggerAction, TriggerEvent};
use maybenot_machines::{StaticMachine, get_machine};
use rand::rngs::ThreadRng;

use crate::policy::{DefenseLevel, Policy, PolicyError, Role};

/// An action the tunnel must carry out, owned so it can cross the FFI boundary.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Action {
    Cancel {
        machine: usize,
        timer: Timer,
    },
    /// Inject a padding packet after `timeout`.
    SendPadding {
        machine: usize,
        timeout: std::time::Duration,
        replace: bool,
        bypass: bool,
    },
    /// Hold outgoing traffic for `duration`, starting after `timeout`.
    BlockOutgoing {
        machine: usize,
        timeout: std::time::Duration,
        duration: std::time::Duration,
        replace: bool,
        bypass: bool,
    },
    UpdateTimer {
        machine: usize,
        duration: std::time::Duration,
        replace: bool,
    },
}

#[derive(Debug)]
pub enum EngineError {
    Policy(PolicyError),
    /// A machine specification in the level definition did not parse or validate.
    Machines(String),
    /// The level has no machines, so there is nothing to run.
    NothingToRun,
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(e) => write!(f, "{e}"),
            Self::Machines(s) => write!(f, "machine error: {s}"),
            Self::NothingToRun => write!(f, "defense level has no machines"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<PolicyError> for EngineError {
    fn from(e: PolicyError) -> Self {
        Self::Policy(e)
    }
}

pub struct Engine {
    framework: Framework<Vec<Machine>, ThreadRng>,
    level: DefenseLevel,
    role: Role,
    constant_packet_size: bool,
    locked: bool,
}

impl Engine {
    /// Build the machine set for a level.
    ///
    /// Exposed separately so the server side can build its counterpart set from the same
    /// definitions, and so tests can assert the pairing.
    pub fn machines_for(specs: &[&str]) -> Result<Vec<Machine>, EngineError> {
        let mut rng = rand::rng();
        let parsed: Result<Vec<StaticMachine>, _> =
            specs.iter().map(|s| s.parse::<StaticMachine>()).collect();
        let parsed = parsed.map_err(|e| EngineError::Machines(e.to_string()))?;
        Ok(get_machine(&parsed, &mut rng))
    }

    /// Start a client-side engine at `requested`, subject to `policy`.
    ///
    /// Returns [`PolicyError::BelowEnforcedFloor`] if the request undercuts an enforced
    /// floor, and [`PolicyError::PeerUnsupported`] if the peer cannot hold up its half.
    pub fn start(
        policy: &Policy,
        requested: DefenseLevel,
        peer_supports: bool,
    ) -> Result<Self, EngineError> {
        Self::start_with_role(policy, requested, peer_supports, Role::Client)
    }

    /// Start an engine for either end of the tunnel.
    ///
    /// The VPN server runs this crate too, with [`Role::Server`]; that is what makes the
    /// defense two-sided, and it is why this is a feature of a VPN you operate rather
    /// than something a client can bolt on alone.
    pub fn start_with_role(
        policy: &Policy,
        requested: DefenseLevel,
        peer_supports: bool,
        role: Role,
    ) -> Result<Self, EngineError> {
        let level = policy.resolve(requested)?;
        if role == Role::Client {
            policy.preflight(level, peer_supports)?;
        }

        let specs = level.machines(role);
        if specs.is_empty() {
            return Err(EngineError::NothingToRun);
        }
        let machines = Self::machines_for(specs)?;

        let framework = Framework::new(
            machines,
            policy.max_padding_frac,
            policy.max_blocking_frac,
            Instant::now(),
            rand::rng(),
        )
        .map_err(|e| EngineError::Machines(e.to_string()))?;

        Ok(Self {
            framework,
            level,
            role,
            constant_packet_size: policy.constant_packet_size,
            locked: policy.is_locked(),
        })
    }

    pub fn level(&self) -> DefenseLevel {
        self.level
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// Whether the tunnel should pad every packet to a constant size.
    pub fn constant_packet_size(&self) -> bool {
        self.constant_packet_size
    }

    /// Whether a profile pinned this configuration, i.e. the UI control is locked.
    pub fn locked(&self) -> bool {
        self.locked
    }

    pub fn num_machines(&self) -> usize {
        self.framework.num_machines()
    }

    /// Feed tunnel events in, get actions out.
    ///
    /// `now` is passed explicitly rather than read inside so that tests can drive time
    /// deterministically.
    pub fn on_events(&mut self, events: &[TriggerEvent], now: Instant) -> Vec<Action> {
        self.framework
            .trigger_events(events, now)
            .map(convert)
            .collect()
    }
}

fn convert(a: &TriggerAction<Instant>) -> Action {
    match *a {
        TriggerAction::Cancel { machine, timer } => Action::Cancel {
            machine: id(machine),
            timer,
        },
        TriggerAction::SendPadding {
            machine,
            timeout,
            replace,
            bypass,
        } => Action::SendPadding {
            machine: id(machine),
            timeout,
            replace,
            bypass,
        },
        TriggerAction::BlockOutgoing {
            machine,
            timeout,
            duration,
            replace,
            bypass,
        } => Action::BlockOutgoing {
            machine: id(machine),
            timeout,
            duration,
            replace,
            bypass,
        },
        TriggerAction::UpdateTimer {
            machine,
            duration,
            replace,
        } => Action::UpdateTimer {
            machine: id(machine),
            duration,
            replace,
        },
    }
}

fn id(m: MachineId) -> usize {
    m.into_raw()
}
