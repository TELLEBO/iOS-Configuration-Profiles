//! Negotiation replaces the hardcoded `peerSupportsDefense = true` that made the
//! fail-closed guarantee decorative. Every test here is a refusal the old code could not
//! make.

use dvpn_wire::*;

const CLIENT_MOD: &[&str] = &["interspace_client"];
const SERVER_MOD: &[&str] = &["interspace_server"];

fn ack(level: u8, server_machines: bool, hash: [u8; 32]) -> HelloAck {
    HelloAck { version: VERSION, accepted_level: level, server_machines, machines_hash: hash }
}

// In a real deployment both ends derive the hash from the same level definition table.
fn our_hash(level: u8) -> [u8; 32] {
    match level {
        2 => machines_hash(SERVER_MOD),
        _ => machines_hash(&[]),
    }
}
fn requires_peer(level: u8) -> bool {
    level >= 2
}

#[test]
fn a_matching_server_is_accepted() {
    let a = ack(2, true, machines_hash(SERVER_MOD));
    assert_eq!(negotiate(&a, 2, our_hash, requires_peer).unwrap(), 2);
}

#[test]
fn the_client_may_run_above_the_floor() {
    let a = ack(2, true, machines_hash(SERVER_MOD));
    assert_eq!(negotiate(&a, 1, our_hash, requires_peer).unwrap(), 2);
}

#[test]
fn a_server_offering_less_than_the_floor_is_refused() {
    let a = ack(1, true, machines_hash(SERVER_MOD));
    assert_eq!(
        negotiate(&a, 2, our_hash, requires_peer).unwrap_err(),
        NegotiationError::BelowFloor { accepted: 1, floor: 2 }
    );
}

#[test]
fn a_server_with_no_counterpart_machines_is_refused() {
    let a = ack(2, false, machines_hash(SERVER_MOD));
    assert_eq!(
        negotiate(&a, 2, our_hash, requires_peer).unwrap_err(),
        NegotiationError::PeerHasNoMachines { level: 2 }
    );
}

#[test]
fn disagreement_about_what_a_level_means_is_refused() {
    // Both ends say "level 2" but the server loaded something else. Accepting this would
    // produce traffic neither side is shaping as intended — the silent-mismatch failure.
    let a = ack(2, true, machines_hash(&["scrambler_server 4.0 2.0 1.0 8.0"]));
    assert_eq!(
        negotiate(&a, 2, our_hash, requires_peer).unwrap_err(),
        NegotiationError::MachineMismatch { level: 2 }
    );
}

#[test]
fn a_level_needing_no_peer_ignores_the_peer_machine_fields() {
    // Level 1 is NetFlow coarsening: one endpoint can do it alone, so a server with no
    // machines is fine and no hash comparison applies.
    let a = ack(1, false, [0xff; 32]);
    assert_eq!(negotiate(&a, 1, our_hash, requires_peer).unwrap(), 1);
}

#[test]
fn a_version_mismatch_is_refused_before_anything_else() {
    let mut a = ack(2, true, machines_hash(SERVER_MOD));
    a.version = VERSION + 1;
    assert!(matches!(
        negotiate(&a, 2, our_hash, requires_peer).unwrap_err(),
        NegotiationError::Version { .. }
    ));
}

#[test]
fn machine_hashes_are_order_independent_and_domain_separated() {
    assert_eq!(
        machines_hash(&["a", "b"]),
        machines_hash(&["b", "a"]),
        "listing order must not change the identity of a machine set"
    );
    assert_ne!(machines_hash(&["ab", "c"]), machines_hash(&["a", "bc"]));
    assert_ne!(machines_hash(&[]), [0u8; 32]);
}

#[test]
fn hello_and_ack_round_trip() {
    let h = Hello {
        version: VERSION,
        desired_level: 3,
        supported: LevelMask::default().with(1).with(2).with(3),
        machines_hash: machines_hash(CLIENT_MOD),
    };
    let mut buf = [0u8; MAX_PAYLOAD];
    let n = h.encode(&mut buf).unwrap();
    assert_eq!(Hello::decode(&buf[..n]).unwrap(), h);

    let a = ack(3, true, machines_hash(SERVER_MOD));
    let n = a.encode(&mut buf).unwrap();
    assert_eq!(HelloAck::decode(&buf[..n]).unwrap(), a);
}

#[test]
fn level_masks_find_the_best_common_level() {
    let client = LevelMask::default().with(1).with(2).with(3);
    let server = LevelMask::default().with(1).with(2);
    assert_eq!(client.best_common(server), Some(2));
    assert_eq!(LevelMask::default().with(3).best_common(LevelMask::default().with(1)), None);
}

#[test]
fn a_truncated_handshake_is_refused() {
    assert!(matches!(Hello::decode(&[0u8; 4]), Err(WireError::ShortBuffer { .. })));
    assert!(matches!(HelloAck::decode(&[]), Err(WireError::ShortBuffer { .. })));
}
