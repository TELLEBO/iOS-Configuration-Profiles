//! The one table both ends must agree on.
//!
//! Levels cross the wire as integers and are hashed into the handshake, so this mapping is
//! protocol, not preference. Changing what a level means without bumping the machine hash
//! would let two peers agree on "level 2" while running different defenses — the
//! silent-mismatch failure the handshake exists to catch.

use dvpn_wire::{LevelMask, machines_hash};
use tad_engine::{DefenseLevel, Role};

pub fn to_u8(l: DefenseLevel) -> u8 {
    match l {
        DefenseLevel::Off => 0,
        DefenseLevel::Light => 1,
        DefenseLevel::Moderate => 2,
        DefenseLevel::Heavy => 3,
    }
}

pub fn from_u8(v: u8) -> Option<DefenseLevel> {
    Some(match v {
        0 => DefenseLevel::Off,
        1 => DefenseLevel::Light,
        2 => DefenseLevel::Moderate,
        3 => DefenseLevel::Heavy,
        _ => return None,
    })
}

pub fn parse(s: &str) -> Option<DefenseLevel> {
    match s.trim().to_ascii_lowercase().as_str() {
        "off" => Some(DefenseLevel::Off),
        "light" => Some(DefenseLevel::Light),
        "moderate" => Some(DefenseLevel::Moderate),
        "heavy" => Some(DefenseLevel::Heavy),
        _ => None,
    }
}

/// Every level this build can run in the given role.
pub fn supported(role: Role) -> LevelMask {
    let mut m = LevelMask::default();
    for l in [DefenseLevel::Light, DefenseLevel::Moderate, DefenseLevel::Heavy] {
        let specs = l.machines(role);
        // A level with no machines for this role is still "supported" by a server when the
        // level needs no counterpart — it simply has nothing to run.
        if !specs.is_empty() || !l.requires_peer() {
            m = m.with(to_u8(l));
        }
    }
    m
}

/// Hash of the machine set a given role runs at a given level.
pub fn hash_for(role: Role, level: u8) -> [u8; 32] {
    match from_u8(level) {
        Some(l) => machines_hash(l.machines(role)),
        None => machines_hash(&[]),
    }
}

pub fn requires_peer(level: u8) -> bool {
    from_u8(level).is_some_and(DefenseLevel::requires_peer)
}
