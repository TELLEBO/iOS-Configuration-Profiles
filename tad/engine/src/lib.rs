//! Traffic-Analysis Defense (TAD) engine.
//!
//! A traffic-analysis defense for a mobile VPN, built on the Maybenot framework, with one
//! addition Mullvad's DAITA does not have: the defense is **policy-enforceable**. A
//! configuration profile can pin it on, and the app honours that pin because the app is
//! built to read it. See ../ARCHITECTURE.md.
//!
//! This crate is the portable core. It performs no I/O and knows nothing about WireGuard,
//! NetworkExtension or sockets — the host tunnel feeds it events and executes its actions.

pub mod engine;
pub mod ffi;
pub mod policy;

pub use engine::{Action, Engine, EngineError};
pub use policy::{DefenseLevel, Policy, PolicyError, PolicySource, Role};

/// Re-exported so the host can build events without depending on maybenot directly.
pub use maybenot::{MachineId, Timer, TriggerEvent};
