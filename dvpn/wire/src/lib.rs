//! The wire format, and the two properties the defense depends on it having.
//!
//! **1. Every frame is the same length.** Not "usually", not "when padded" — the encoder's
//! output parameter is `&mut [u8; FRAME_LEN]`, so a short frame is a type error waiting to
//! happen rather than a runtime branch somebody forgets. Constant packet size is one of the
//! three techniques that make traffic-analysis defense work, and it is the one that is
//! cheapest to get wrong by accident: pad the inner IP packets and nothing happens, because
//! the observer measures the sealed datagram.
//!
//! **2. Defense capability is negotiated, not assumed.** A client that cannot verify the
//! server is running the counterpart padding machines cannot know whether it is defended.
//! [`negotiate`] is the function that turns that into a decision, and it fails closed.

#![forbid(unsafe_code)]

use std::fmt;

/// On-wire frame length, before sealing.
///
/// Chosen so the sealed datagram fits inside the IPv6 minimum MTU without fragmentation:
/// 1200 frame + 8 counter + 16 AEAD tag = 1224 bytes of UDP payload, + 48 bytes of
/// IPv6/UDP header = 1272, under 1280. Fragmentation would reintroduce a size signal —
/// a fragmented 1300-byte datagram and an unfragmented 900-byte one look different on the
/// wire no matter how carefully the frame inside them was padded.
pub const FRAME_LEN: usize = 1200;

/// kind (1) + payload length (2).
pub const HEADER_LEN: usize = 3;

/// Largest inner packet a single frame can carry.
pub const MAX_PAYLOAD: usize = FRAME_LEN - HEADER_LEN;

/// Protocol version. Bumped on any change to framing or negotiation.
pub const VERSION: u16 = 1;

const HELLO_LEN: usize = 2 + 1 + 1 + 32;
const ACK_LEN: usize = 2 + 1 + 1 + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    /// Carries a real inner packet.
    Data = 1,
    /// Carries nothing. Exists to occupy a slot in the traffic pattern.
    Padding = 2,
    Hello = 3,
    HelloAck = 4,
    Close = 5,
}

impl FrameKind {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Data,
            2 => Self::Padding,
            3 => Self::Hello,
            4 => Self::HelloAck,
            5 => Self::Close,
            _ => return None,
        })
    }

    /// Whether this frame carries user data, for the `NormalSent`/`PaddingSent`
    /// classification the defense engine needs.
    pub fn is_normal(self) -> bool {
        matches!(self, Self::Data)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    PayloadTooLarge { len: usize },
    UnknownKind(u8),
    /// The declared payload length does not fit in the frame. A peer sending this is
    /// either broken or probing; either way the frame is dropped.
    BadLength { declared: usize },
    /// A frame that must carry no payload carried one.
    UnexpectedPayload(FrameKind),
    ShortBuffer { got: usize, want: usize },
    VersionMismatch { theirs: u16, ours: u16 },
    UnknownLevel(u8),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { len } => {
                write!(f, "payload of {len} exceeds {MAX_PAYLOAD}")
            }
            Self::UnknownKind(k) => write!(f, "unknown frame kind {k}"),
            Self::BadLength { declared } => write!(f, "declared payload length {declared} invalid"),
            Self::UnexpectedPayload(k) => write!(f, "{k:?} frame must carry no payload"),
            Self::ShortBuffer { got, want } => write!(f, "buffer of {got}, need {want}"),
            Self::VersionMismatch { theirs, ours } => {
                write!(f, "peer speaks version {theirs}, we speak {ours}")
            }
            Self::UnknownLevel(l) => write!(f, "unknown defense level {l}"),
        }
    }
}

impl std::error::Error for WireError {}

/// A decoded frame, borrowing from the buffer it was decoded out of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: FrameKind,
    pub payload: &'a [u8],
}

/// Encode a frame into a fixed-size buffer.
///
/// The remainder past the payload is zeroed. That is safe *only because the frame is
/// sealed afterwards* — AEAD ciphertext is indistinguishable from random, so the zeros
/// never reach the wire. Remove the sealing layer and the padding becomes a giveaway.
pub fn encode(
    kind: FrameKind,
    payload: &[u8],
    out: &mut [u8; FRAME_LEN],
) -> Result<(), WireError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(WireError::PayloadTooLarge { len: payload.len() });
    }
    if !payload.is_empty() && !matches!(kind, FrameKind::Data | FrameKind::Hello | FrameKind::HelloAck)
    {
        return Err(WireError::UnexpectedPayload(kind));
    }

    out.fill(0);
    out[0] = kind as u8;
    let len = payload.len() as u16;
    out[1..3].copy_from_slice(&len.to_be_bytes());
    out[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);
    Ok(())
}

pub fn decode(buf: &[u8; FRAME_LEN]) -> Result<Frame<'_>, WireError> {
    let kind = FrameKind::from_u8(buf[0]).ok_or(WireError::UnknownKind(buf[0]))?;
    let declared = u16::from_be_bytes([buf[1], buf[2]]) as usize;
    if declared > MAX_PAYLOAD {
        return Err(WireError::BadLength { declared });
    }
    if declared != 0 && !matches!(kind, FrameKind::Data | FrameKind::Hello | FrameKind::HelloAck) {
        return Err(WireError::UnexpectedPayload(kind));
    }
    Ok(Frame {
        kind,
        payload: &buf[HEADER_LEN..HEADER_LEN + declared],
    })
}

// ── Capability negotiation ───────────────────────────────────────────────────────────

/// Bitmask of the defense levels an endpoint can run. Bit *n* is level *n*.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct LevelMask(pub u8);

impl LevelMask {
    pub fn with(mut self, level: u8) -> Self {
        self.0 |= 1 << level;
        self
    }
    pub fn has(self, level: u8) -> bool {
        self.0 & (1 << level) != 0
    }
    /// The highest level in the mask that the other mask also has.
    pub fn best_common(self, other: Self) -> Option<u8> {
        (0..8).rev().find(|&l| self.has(l) && other.has(l))
    }
}

/// What the client tells the server it wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hello {
    pub version: u16,
    /// The level the client intends to run, already resolved against its policy floor.
    pub desired_level: u8,
    pub supported: LevelMask,
    /// Hash of the client's machine set for `desired_level`. Lets both ends detect that
    /// they believe different things about what the level *is* — a silent mismatch would
    /// produce traffic neither side is shaping as intended.
    pub machines_hash: [u8; 32],
}

/// What the server answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelloAck {
    pub version: u16,
    /// The level the server will actually run. May be lower than requested.
    pub accepted_level: u8,
    /// Whether the server has loaded counterpart machines for `accepted_level`.
    pub server_machines: bool,
    /// Hash of the server's machine set for `accepted_level`.
    pub machines_hash: [u8; 32],
}

impl Hello {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        if out.len() < HELLO_LEN {
            return Err(WireError::ShortBuffer { got: out.len(), want: HELLO_LEN });
        }
        out[0..2].copy_from_slice(&self.version.to_be_bytes());
        out[2] = self.desired_level;
        out[3] = self.supported.0;
        out[4..36].copy_from_slice(&self.machines_hash);
        Ok(HELLO_LEN)
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() < HELLO_LEN {
            return Err(WireError::ShortBuffer { got: buf.len(), want: HELLO_LEN });
        }
        let mut machines_hash = [0u8; 32];
        machines_hash.copy_from_slice(&buf[4..36]);
        Ok(Self {
            version: u16::from_be_bytes([buf[0], buf[1]]),
            desired_level: buf[2],
            supported: LevelMask(buf[3]),
            machines_hash,
        })
    }
}

impl HelloAck {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        if out.len() < ACK_LEN {
            return Err(WireError::ShortBuffer { got: out.len(), want: ACK_LEN });
        }
        out[0..2].copy_from_slice(&self.version.to_be_bytes());
        out[2] = self.accepted_level;
        out[3] = u8::from(self.server_machines);
        out[4..36].copy_from_slice(&self.machines_hash);
        Ok(ACK_LEN)
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() < ACK_LEN {
            return Err(WireError::ShortBuffer { got: buf.len(), want: ACK_LEN });
        }
        let mut machines_hash = [0u8; 32];
        machines_hash.copy_from_slice(&buf[4..36]);
        Ok(Self {
            version: u16::from_be_bytes([buf[0], buf[1]]),
            accepted_level: buf[2],
            server_machines: buf[3] != 0,
            machines_hash,
        })
    }
}

/// A stable identifier for a set of machine specifications.
///
/// Order-independent, so the two ends may list their machines in any order, and
/// domain-separated so a hash from this protocol cannot be replayed as one from another.
pub fn machines_hash(specs: &[&str]) -> [u8; 32] {
    let mut sorted: Vec<&str> = specs.to_vec();
    sorted.sort_unstable();
    let mut h = blake3::Hasher::new();
    h.update(b"dvpn-machines-v1\0");
    for s in sorted {
        h.update(&(s.len() as u32).to_be_bytes());
        h.update(s.as_bytes());
    }
    *h.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NegotiationError {
    Version { theirs: u16, ours: u16 },
    /// The server would run a weaker level than the policy floor allows. The whole point
    /// of an enforced floor is that this is refused rather than accepted quietly.
    BelowFloor { accepted: u8, floor: u8 },
    /// The level needs counterpart machines and the server has none. Connecting here would
    /// produce a tunnel the user believes is defended and is not.
    PeerHasNoMachines { level: u8 },
    /// Both ends claim the same level but disagree about which machines it means.
    MachineMismatch { level: u8 },
}

impl fmt::Display for NegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Version { theirs, ours } => {
                write!(f, "peer speaks protocol {theirs}, we speak {ours}")
            }
            Self::BelowFloor { accepted, floor } => write!(
                f,
                "server offers level {accepted}, policy floor is {floor}; refusing"
            ),
            Self::PeerHasNoMachines { level } => {
                write!(f, "server has no counterpart machines for level {level}; refusing")
            }
            Self::MachineMismatch { level } => {
                write!(f, "client and server disagree on the machines for level {level}")
            }
        }
    }
}

impl std::error::Error for NegotiationError {}

/// Decide whether the server's answer is acceptable.
///
/// Every branch here either returns the level to run or refuses. There is deliberately no
/// "proceed with a warning" path: the caller cannot accidentally carry traffic on a
/// downgraded defense, which is the failure mode that makes a traffic-analysis defense
/// worse than useless — the user changes their behaviour believing they are protected.
///
/// `requires_peer` is supplied by the caller rather than hardcoded, because which levels
/// need a counterpart is a property of the machine library, not of the wire protocol.
pub fn negotiate(
    ack: &HelloAck,
    floor: u8,
    our_machines_hash_for: impl Fn(u8) -> [u8; 32],
    requires_peer: impl Fn(u8) -> bool,
) -> Result<u8, NegotiationError> {
    if ack.version != VERSION {
        return Err(NegotiationError::Version { theirs: ack.version, ours: VERSION });
    }
    if ack.accepted_level < floor {
        return Err(NegotiationError::BelowFloor { accepted: ack.accepted_level, floor });
    }
    if requires_peer(ack.accepted_level) {
        if !ack.server_machines {
            return Err(NegotiationError::PeerHasNoMachines { level: ack.accepted_level });
        }
        if ack.machines_hash != our_machines_hash_for(ack.accepted_level) {
            return Err(NegotiationError::MachineMismatch { level: ack.accepted_level });
        }
    }
    Ok(ack.accepted_level)
}
