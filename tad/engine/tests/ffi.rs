//! Exercises the C ABI the Swift extension calls, including the paths Swift must handle:
//! a locked policy, a refused downgrade, and a peer that cannot hold up its half.

use std::ffi::CString;
use std::ptr;

use tad_engine::engine::Engine;
use tad_engine::ffi::*;
use tad_engine::policy::Policy;

const LEVEL_OFF: u32 = 0;
const LEVEL_MODERATE: u32 = 2;
const LEVEL_HEAVY: u32 = 3;

fn parse(json: &str) -> Result<*mut Policy, TadResult> {
    let c = CString::new(json).unwrap();
    let mut out: *mut Policy = ptr::null_mut();
    let r = unsafe { tad_policy_parse(c.as_ptr(), &mut out) };
    if r == TadResult::Ok { Ok(out) } else { Err(r) }
}

#[test]
fn round_trip_start_pump_stop() {
    let policy = parse(r#"{"level":"moderate","enforced":true,"source":"profile"}"#).unwrap();

    assert!(unsafe { tad_policy_is_locked(policy) });
    assert_eq!(unsafe { tad_policy_floor(policy) }, LEVEL_MODERATE);

    let mut engine: *mut Engine = ptr::null_mut();
    let r = unsafe { tad_engine_start(policy, LEVEL_MODERATE, true, &mut engine) };
    assert_eq!(r, TadResult::Ok);
    assert!(unsafe { tad_engine_constant_packet_size(engine) });

    let cap = unsafe { tad_engine_num_machines(engine) };
    assert!(cap > 0);

    let events = [
        TadEvent { event_type: 2, machine: 0 }, // TunnelRecv
        TadEvent { event_type: 0, machine: 0 }, // NormalRecv
        TadEvent { event_type: 3, machine: 0 }, // NormalSent
        TadEvent { event_type: 5, machine: 0 }, // TunnelSent
    ];
    let mut actions = vec![
        TadAction {
            tag: 0,
            machine: 0,
            timer: 0,
            timeout_nanos: 0,
            duration_nanos: 0,
            replace: false,
            bypass: false,
        };
        cap
    ];
    let mut n: usize = usize::MAX;
    let r = unsafe {
        tad_engine_on_events(
            engine,
            events.as_ptr(),
            events.len(),
            actions.as_mut_ptr(),
            actions.len(),
            &mut n,
        )
    };
    assert_eq!(r, TadResult::Ok);
    assert!(n <= cap, "wrote {n} actions into capacity {cap}");

    unsafe { tad_engine_stop(engine) };
    unsafe { tad_policy_free(policy) };
}

#[test]
fn a_downgrade_is_refused_across_the_boundary() {
    let policy = parse(r#"{"level":"moderate","enforced":true,"source":"profile"}"#).unwrap();
    let mut engine: *mut Engine = ptr::null_mut();
    let r = unsafe { tad_engine_start(policy, LEVEL_OFF, true, &mut engine) };
    assert_eq!(r, TadResult::BelowEnforcedFloor);
    assert!(engine.is_null(), "no engine on refusal");
    unsafe { tad_policy_free(policy) };
}

#[test]
fn an_unsupported_peer_is_refused_across_the_boundary() {
    let policy = parse(r#"{"level":"heavy","enforced":true,"source":"profile"}"#).unwrap();
    let mut engine: *mut Engine = ptr::null_mut();
    let r = unsafe { tad_engine_start(policy, LEVEL_HEAVY, false, &mut engine) };
    assert_eq!(r, TadResult::PeerUnsupported);
    unsafe { tad_policy_free(policy) };
}

#[test]
fn enforcement_claimed_without_a_profile_is_rejected() {
    assert_eq!(
        parse(r#"{"level":"heavy","enforced":true,"source":"user"}"#).unwrap_err(),
        TadResult::EnforcedWithoutProfile
    );
}

#[test]
fn null_and_undersized_buffers_are_handled() {
    let mut out: *mut Policy = ptr::null_mut();
    assert_eq!(
        unsafe { tad_policy_parse(ptr::null(), &mut out) },
        TadResult::NullPointer
    );

    let policy = parse(r#"{"level":"light","source":"user"}"#).unwrap();
    let mut engine: *mut Engine = ptr::null_mut();
    assert_eq!(
        unsafe { tad_engine_start(policy, 1, true, &mut engine) },
        TadResult::Ok
    );

    let mut n: usize = 0;
    let r = unsafe { tad_engine_on_events(engine, ptr::null(), 0, ptr::null_mut(), 0, &mut n) };
    assert_eq!(r, TadResult::BufferTooSmall, "capacity 0 < num_machines");

    unsafe { tad_engine_stop(engine) };
    unsafe { tad_policy_free(policy) };
    // Freeing null is a no-op, not a crash.
    unsafe { tad_policy_free(ptr::null_mut()) };
    unsafe { tad_engine_stop(ptr::null_mut()) };
}
