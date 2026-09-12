//! C ABI for the Swift packet-tunnel extension.
//!
//! Deliberately narrow: the tunnel hands over a JSON policy (Swift serialises
//! `providerConfiguration` to JSON rather than teaching C about plists), starts an
//! engine, then pumps events and drains actions.
//!
//! `TadAction` is a flat struct rather than a tagged union. A union costs a few bytes
//! less per action and considerably more Swift to unpack safely; at the rate a tunnel
//! drains actions the bytes do not matter and the clarity does.
//!
//! The release profile sets `panic = "abort"` because unwinding across an FFI boundary is
//! undefined behaviour. For a VPN extension, aborting on a defense bug is the
//! fail-closed choice — the tunnel dies rather than carrying traffic it is no longer
//! shaping — but it does mean a panic takes the tunnel down, so the Swift side must treat
//! extension restart as a normal event and not loop on it.

use std::ffi::{CStr, c_char};
use std::time::{Duration, Instant};

use maybenot::{MachineId, Timer, TriggerEvent};

use crate::engine::{Action, Engine};
use crate::policy::{DefenseLevel, Policy, PolicyError};

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TadResult {
    Ok = 0,
    NullPointer = 1,
    NotUtf8 = 2,
    MalformedPolicy = 3,
    /// The requested level is below a profile-enforced floor.
    BelowEnforcedFloor = 4,
    /// The peer cannot run the required machines and the policy fails closed.
    PeerUnsupported = 5,
    /// `enforced` was claimed by a non-profile source.
    EnforcedWithoutProfile = 6,
    MachineError = 7,
    NothingToRun = 8,
    /// `actions_out` was too small; call `tad_engine_num_machines` for the needed size.
    BufferTooSmall = 9,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum TadEventType {
    NormalRecv = 0,
    PaddingRecv = 1,
    TunnelRecv = 2,
    NormalSent = 3,
    PaddingSent = 4,
    TunnelSent = 5,
    BlockingBegin = 6,
    BlockingEnd = 7,
    TimerBegin = 8,
    TimerEnd = 9,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TadEvent {
    pub event_type: u32,
    /// Only read for events that carry one: PaddingSent, BlockingBegin, TimerBegin,
    /// TimerEnd. Ignored otherwise.
    pub machine: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TadAction {
    /// 0 = Cancel, 1 = SendPadding, 2 = BlockOutgoing, 3 = UpdateTimer.
    pub tag: u32,
    pub machine: usize,
    /// Cancel only: 0 = Action, 1 = Internal, 2 = All.
    pub timer: u32,
    pub timeout_nanos: u64,
    /// BlockOutgoing: how long to block. UpdateTimer: the new duration.
    pub duration_nanos: u64,
    pub replace: bool,
    pub bypass: bool,
}

impl TadAction {
    fn zeroed() -> Self {
        Self {
            tag: 0,
            machine: 0,
            timer: 0,
            timeout_nanos: 0,
            duration_nanos: 0,
            replace: false,
            bypass: false,
        }
    }
}

fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

fn policy_result(e: &PolicyError) -> TadResult {
    match e {
        PolicyError::BelowEnforcedFloor { .. } => TadResult::BelowEnforcedFloor,
        PolicyError::PeerUnsupported(_) => TadResult::PeerUnsupported,
        PolicyError::EnforcedWithoutProfile => TadResult::EnforcedWithoutProfile,
        _ => TadResult::MalformedPolicy,
    }
}

fn level_from_raw(raw: u32) -> Option<DefenseLevel> {
    match raw {
        0 => Some(DefenseLevel::Off),
        1 => Some(DefenseLevel::Light),
        2 => Some(DefenseLevel::Moderate),
        3 => Some(DefenseLevel::Heavy),
        _ => None,
    }
}

fn level_to_raw(l: DefenseLevel) -> u32 {
    match l {
        DefenseLevel::Off => 0,
        DefenseLevel::Light => 1,
        DefenseLevel::Moderate => 2,
        DefenseLevel::Heavy => 3,
    }
}

/// Parse a JSON policy.
///
/// # Safety
/// `json` must be a null-terminated UTF-8 string. `out` must be a valid, aligned pointer
/// to pointer-sized memory. The returned policy must be freed with [`tad_policy_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tad_policy_parse(
    json: *const c_char,
    out: *mut *mut Policy,
) -> TadResult {
    if json.is_null() || out.is_null() {
        return TadResult::NullPointer;
    }
    let s = match unsafe { CStr::from_ptr(json) }.to_str() {
        Ok(s) => s,
        Err(_) => return TadResult::NotUtf8,
    };
    match Policy::from_json(s) {
        Ok(p) => {
            unsafe { *out = Box::into_raw(Box::new(p)) };
            TadResult::Ok
        }
        Err(e) => policy_result(&e),
    }
}

/// # Safety
/// `policy` must have come from [`tad_policy_parse`] and must not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tad_policy_free(policy: *mut Policy) {
    if !policy.is_null() {
        drop(unsafe { Box::from_raw(policy) });
    }
}

/// Whether the UI must present the defense control as locked.
///
/// # Safety
/// `policy` must have come from [`tad_policy_parse`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tad_policy_is_locked(policy: *const Policy) -> bool {
    if policy.is_null() {
        return false;
    }
    unsafe { &*policy }.is_locked()
}

/// The enforced floor, as a raw level. Only meaningful when locked.
///
/// # Safety
/// `policy` must have come from [`tad_policy_parse`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tad_policy_floor(policy: *const Policy) -> u32 {
    if policy.is_null() {
        return 0;
    }
    level_to_raw(unsafe { &*policy }.level)
}

/// Start an engine.
///
/// # Safety
/// `policy` must have come from [`tad_policy_parse`]; `out` must be a valid, aligned
/// pointer to pointer-sized memory. The engine must be freed with [`tad_engine_stop`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tad_engine_start(
    policy: *const Policy,
    requested_level: u32,
    peer_supports: bool,
    out: *mut *mut Engine,
) -> TadResult {
    if policy.is_null() || out.is_null() {
        return TadResult::NullPointer;
    }
    let Some(level) = level_from_raw(requested_level) else {
        return TadResult::MalformedPolicy;
    };
    match Engine::start(unsafe { &*policy }, level, peer_supports) {
        Ok(e) => {
            unsafe { *out = Box::into_raw(Box::new(e)) };
            TadResult::Ok
        }
        Err(crate::EngineError::Policy(e)) => policy_result(&e),
        Err(crate::EngineError::NothingToRun) => TadResult::NothingToRun,
        Err(crate::EngineError::Machines(_)) => TadResult::MachineError,
    }
}

/// # Safety
/// `engine` must have come from [`tad_engine_start`] and must not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tad_engine_stop(engine: *mut Engine) {
    if !engine.is_null() {
        drop(unsafe { Box::from_raw(engine) });
    }
}

/// The number of running machines, and therefore the capacity `actions_out` needs.
///
/// # Safety
/// `engine` must have come from [`tad_engine_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tad_engine_num_machines(engine: *const Engine) -> usize {
    if engine.is_null() {
        return 0;
    }
    unsafe { &*engine }.num_machines()
}

/// Whether the tunnel should pad every packet to a constant size.
///
/// # Safety
/// `engine` must have come from [`tad_engine_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tad_engine_constant_packet_size(engine: *const Engine) -> bool {
    if engine.is_null() {
        return false;
    }
    unsafe { &*engine }.constant_packet_size()
}

/// Feed events, drain actions.
///
/// # Safety
/// `engine` must have come from [`tad_engine_start`]. `events` must point to
/// `num_events` valid `TadEvent`s. `actions_out` must have capacity for at least
/// [`tad_engine_num_machines`] `TadAction`s. `num_actions_out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tad_engine_on_events(
    engine: *mut Engine,
    events: *const TadEvent,
    num_events: usize,
    actions_out: *mut TadAction,
    actions_capacity: usize,
    num_actions_out: *mut usize,
) -> TadResult {
    if engine.is_null() || num_actions_out.is_null() {
        return TadResult::NullPointer;
    }
    if num_events > 0 && events.is_null() {
        return TadResult::NullPointer;
    }
    let engine = unsafe { &mut *engine };
    if actions_capacity < engine.num_machines() {
        return TadResult::BufferTooSmall;
    }
    if actions_capacity > 0 && actions_out.is_null() {
        return TadResult::NullPointer;
    }

    let raw = if num_events == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(events, num_events) }
    };
    let translated: Vec<TriggerEvent> = raw.iter().filter_map(to_trigger_event).collect();

    let actions = engine.on_events(&translated, Instant::now());
    let n = actions.len().min(actions_capacity);
    for (i, a) in actions.iter().take(n).enumerate() {
        unsafe { *actions_out.add(i) = to_c_action(a) };
    }
    unsafe { *num_actions_out = n };
    TadResult::Ok
}

fn to_trigger_event(e: &TadEvent) -> Option<TriggerEvent> {
    let m = MachineId::from_raw(e.machine);
    Some(match e.event_type {
        0 => TriggerEvent::NormalRecv,
        1 => TriggerEvent::PaddingRecv,
        2 => TriggerEvent::TunnelRecv,
        3 => TriggerEvent::NormalSent,
        4 => TriggerEvent::PaddingSent { machine: m },
        5 => TriggerEvent::TunnelSent,
        6 => TriggerEvent::BlockingBegin { machine: m },
        7 => TriggerEvent::BlockingEnd,
        8 => TriggerEvent::TimerBegin { machine: m },
        9 => TriggerEvent::TimerEnd { machine: m },
        // An unknown event type is dropped rather than guessed at: feeding the framework
        // a wrong event is worse than feeding it none.
        _ => return None,
    })
}

fn to_c_action(a: &Action) -> TadAction {
    let mut out = TadAction::zeroed();
    match *a {
        Action::Cancel { machine, timer } => {
            out.tag = 0;
            out.machine = machine;
            out.timer = match timer {
                Timer::Action => 0,
                Timer::Internal => 1,
                Timer::All => 2,
            };
        }
        Action::SendPadding {
            machine,
            timeout,
            replace,
            bypass,
        } => {
            out.tag = 1;
            out.machine = machine;
            out.timeout_nanos = nanos(timeout);
            out.replace = replace;
            out.bypass = bypass;
        }
        Action::BlockOutgoing {
            machine,
            timeout,
            duration,
            replace,
            bypass,
        } => {
            out.tag = 2;
            out.machine = machine;
            out.timeout_nanos = nanos(timeout);
            out.duration_nanos = nanos(duration);
            out.replace = replace;
            out.bypass = bypass;
        }
        Action::UpdateTimer {
            machine,
            duration,
            replace,
        } => {
            out.tag = 3;
            out.machine = machine;
            out.duration_nanos = nanos(duration);
            out.replace = replace;
        }
    }
    out
}
