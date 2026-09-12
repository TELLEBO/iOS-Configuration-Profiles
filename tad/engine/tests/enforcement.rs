//! The enforcement semantics — the part Mullvad's DAITA does not have.
//!
//! DAITA cannot be turned on from outside the Mullvad app, because the app reads its
//! settings from its own keychain and nothing else. This engine instead treats the
//! dictionary iOS hands the tunnel in `providerConfiguration` — populated by a
//! configuration profile's `VendorConfig` — as an authoritative floor.

use tad_engine::{DefenseLevel, Engine, Policy, PolicyError, Role};

const PROFILE_JSON: &str = r#"{
    "level": "moderate",
    "enforced": true,
    "require_peer_support": true,
    "max_padding_frac": 0.5,
    "max_blocking_frac": 0.2,
    "constant_packet_size": true,
    "source": "profile"
}"#;

#[test]
fn a_profile_policy_parses_and_locks() {
    let p = Policy::from_json(PROFILE_JSON).expect("parses");
    assert_eq!(p.level, DefenseLevel::Moderate);
    assert!(p.enforced);
    assert!(p.is_locked(), "a profile-sourced enforced policy locks the UI");
    assert!(p.constant_packet_size);
}

#[test]
fn the_user_may_raise_the_level_but_not_lower_it() {
    let p = Policy::from_json(PROFILE_JSON).unwrap();

    assert_eq!(p.resolve(DefenseLevel::Heavy).unwrap(), DefenseLevel::Heavy);
    assert_eq!(
        p.resolve(DefenseLevel::Moderate).unwrap(),
        DefenseLevel::Moderate
    );

    for below in [DefenseLevel::Light, DefenseLevel::Off] {
        match p.resolve(below) {
            Err(PolicyError::BelowEnforcedFloor { requested, floor }) => {
                assert_eq!(requested, below);
                assert_eq!(floor, DefenseLevel::Moderate);
            }
            other => panic!("expected refusal for {below:?}, got {other:?}"),
        }
    }
}

#[test]
fn refusal_is_explicit_rather_than_a_silent_clamp() {
    // Clamping would be easier and worse: the user would move the control, see it snap
    // back, and learn nothing. An error forces the caller to explain.
    let p = Policy::from_json(PROFILE_JSON).unwrap();
    assert!(p.resolve(DefenseLevel::Off).is_err());
    assert!(Engine::start(&p, DefenseLevel::Off, true).is_err());
}

#[test]
fn only_a_profile_may_claim_enforcement() {
    // Otherwise the app's own settings screen could assert authority over the person
    // using it, which is not enforcement, just a locked door with the key taped to it.
    let sneaky = r#"{"level":"heavy","enforced":true,"source":"user"}"#;
    assert_eq!(
        Policy::from_json(sneaky).unwrap_err(),
        PolicyError::EnforcedWithoutProfile
    );

    // `source` defaults to "default", which is likewise not a profile.
    let also_sneaky = r#"{"level":"heavy","enforced":true}"#;
    assert_eq!(
        Policy::from_json(also_sneaky).unwrap_err(),
        PolicyError::EnforcedWithoutProfile
    );
}

#[test]
fn an_unenforced_policy_lets_the_user_do_anything() {
    let p = Policy::from_json(r#"{"level":"moderate","source":"user"}"#).unwrap();
    assert!(!p.is_locked());
    assert_eq!(p.resolve(DefenseLevel::Off).unwrap(), DefenseLevel::Off);
}

#[test]
fn fail_closed_when_the_peer_cannot_hold_up_its_half() {
    let p = Policy::from_json(PROFILE_JSON).unwrap();
    match Engine::start(&p, DefenseLevel::Moderate, false) {
        Err(e) => assert!(
            e.to_string().contains("peer does not support"),
            "unexpected error: {e}"
        ),
        Ok(_) => panic!("should refuse to run a peer-dependent level against a bare peer"),
    }
    // With require_peer_support off, it runs anyway — the operator's choice, but the
    // client machines will be largely inert (see tests/defense_loop.rs).
    let lenient = Policy::from_json(
        r#"{"level":"moderate","enforced":true,"require_peer_support":false,"source":"profile"}"#,
    )
    .unwrap();
    assert!(Engine::start(&lenient, DefenseLevel::Moderate, false).is_ok());
}

#[test]
fn a_level_with_no_peer_requirement_starts_against_any_peer() {
    let p = Policy::from_json(r#"{"level":"light","enforced":true,"source":"profile"}"#).unwrap();
    assert!(!DefenseLevel::Light.requires_peer());
    assert!(Engine::start(&p, DefenseLevel::Light, false).is_ok());
}

#[test]
fn fractions_are_validated() {
    assert!(matches!(
        Policy::from_json(r#"{"level":"light","max_padding_frac":1.5}"#),
        Err(PolicyError::FractionOutOfRange("max_padding_frac", _))
    ));
    assert!(matches!(
        Policy::from_json(r#"{"level":"light","max_blocking_frac":-0.1}"#),
        Err(PolicyError::FractionOutOfRange("max_blocking_frac", _))
    ));
}

#[test]
fn off_has_nothing_to_run() {
    let p = Policy::from_json(r#"{"level":"off","source":"user"}"#).unwrap();
    assert!(matches!(
        Engine::start(&p, DefenseLevel::Off, true),
        Err(tad_engine::EngineError::NothingToRun)
    ));
}

#[test]
fn every_level_builds_the_machines_it_claims() {
    for level in [
        DefenseLevel::Light,
        DefenseLevel::Moderate,
        DefenseLevel::Heavy,
    ] {
        for role in [Role::Client, Role::Server] {
            let specs = level.machines(role);
            if specs.is_empty() {
                continue;
            }
            let machines = Engine::machines_for(specs)
                .unwrap_or_else(|e| panic!("{} {:?}: {e}", level.as_str(), role));
            assert!(
                !machines.is_empty(),
                "{} {:?} produced no machines",
                level.as_str(),
                role
            );
        }
    }
}

#[test]
fn malformed_json_is_rejected_not_defaulted() {
    assert!(matches!(
        Policy::from_json("{ not json"),
        Err(PolicyError::Malformed(_))
    ));
    assert!(matches!(
        Policy::from_json(r#"{"level":"paranoid"}"#),
        Err(PolicyError::Malformed(_))
    ));
}
