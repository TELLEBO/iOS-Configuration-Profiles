//! The datagram transport: the layer that actually makes traffic look different.
//!
//! The defense engine decides *when* to send padding and *when* to hold traffic. This
//! crate is what carries those decisions out, and it owns the one technique the engine
//! cannot express: every datagram it emits is [`DATAGRAM_LEN`] bytes, always.
//!
//! It reports what it did — [`Emitted`] and [`Received`] — rather than producing engine
//! events itself. Mapping those to the framework's vocabulary belongs to whoever owns the
//! loop, and keeping that out of here is what lets the transport be tested without a
//! defense running at all.

#![forbid(unsafe_code)]

pub mod seal;

use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use dvpn_wire::{FRAME_LEN, FrameKind, MAX_PAYLOAD, WireError, decode, encode};
pub use seal::{ChaChaSeal, DATAGRAM_LEN, Direction, SEAL_OVERHEAD, Seal};

#[derive(Debug)]
pub enum TransportError {
    Io(io::Error),
    Wire(WireError),
    SealFailed,
    OpenFailed,
    Replay { counter: u64 },
    WrongDatagramLength { got: usize },
    /// The send counter would wrap. Rekey instead; never reuse a nonce.
    CounterExhausted,
    PacketTooLarge { len: usize },
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Wire(e) => write!(f, "wire: {e}"),
            Self::SealFailed => write!(f, "sealing failed"),
            Self::OpenFailed => write!(f, "datagram failed authentication"),
            Self::Replay { counter } => write!(f, "replayed counter {counter}"),
            Self::WrongDatagramLength { got } => {
                write!(f, "datagram of {got} bytes, expected {DATAGRAM_LEN}")
            }
            Self::CounterExhausted => write!(f, "send counter exhausted; rekey required"),
            Self::PacketTooLarge { len } => write!(f, "packet of {len} exceeds {MAX_PAYLOAD}"),
        }
    }
}

impl std::error::Error for TransportError {}
impl From<io::Error> for TransportError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<WireError> for TransportError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

/// What left the endpoint. One per datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emitted {
    /// A real packet went out.
    Data,
    /// Cover traffic went out.
    Padding,
    /// Handshake.
    Control,
}

/// What arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Received {
    Data(Vec<u8>),
    Padding,
    Control(Vec<u8>),
    Close,
}

/// One line of the trace, in the `time,direction` shape the Maybenot simulator reads.
#[derive(Clone, Copy, Debug)]
pub struct TraceEntry {
    pub at: Duration,
    pub sent: bool,
    pub padding: bool,
    /// Always `DATAGRAM_LEN`. Recorded anyway so the measurement harness can prove it
    /// rather than take the claim on trust.
    pub bytes: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub data_out: u64,
    pub padding_out: u64,
    pub data_in: u64,
    pub padding_in: u64,
    pub dropped: u64,
    /// Real packets currently waiting because outgoing traffic is held.
    pub queue_depth: usize,
    pub blocked_for: Duration,
}

/// A shaped datagram endpoint.
pub struct Endpoint<S: Seal> {
    socket: UdpSocket,
    peer: SocketAddr,
    seal: S,
    /// Real packets waiting to go out. Blocking fills this; it drains when the block lifts.
    egress: VecDeque<Vec<u8>>,
    blocked_until: Option<Instant>,
    /// Blocking may be declared bypassable, meaning padding is still allowed through.
    block_bypassable: bool,
    started: Instant,
    trace: Vec<TraceEntry>,
    stats: Stats,
    scratch: Vec<u8>,
}

impl<S: Seal> Endpoint<S> {
    pub fn new(socket: UdpSocket, peer: SocketAddr, seal: S) -> Self {
        Self {
            socket,
            peer,
            seal,
            egress: VecDeque::new(),
            blocked_until: None,
            block_bypassable: false,
            started: Instant::now(),
            trace: Vec::new(),
            stats: Stats::default(),
            scratch: Vec::with_capacity(DATAGRAM_LEN),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    pub fn set_peer(&mut self, peer: SocketAddr) {
        self.peer = peer;
    }
    pub fn stats(&self) -> Stats {
        Stats { queue_depth: self.egress.len(), ..self.stats }
    }
    pub fn trace(&self) -> &[TraceEntry] {
        &self.trace
    }
    pub fn is_blocked(&self, now: Instant) -> bool {
        self.blocked_until.is_some_and(|t| now < t)
    }

    /// Hold outgoing traffic until `now + duration`.
    ///
    /// Extends an existing block rather than shortening it: two machines asking for
    /// blocking should not have the shorter request cancel the longer one.
    pub fn block_outgoing(&mut self, now: Instant, duration: Duration, bypassable: bool) {
        let until = now + duration;
        match self.blocked_until {
            Some(existing) if existing >= until => {}
            _ => {
                self.blocked_until = Some(until);
                self.stats.blocked_for += duration;
            }
        }
        self.block_bypassable = bypassable;
    }

    /// Queue a real packet for sending. It goes out on the next [`Self::flush`].
    pub fn queue(&mut self, packet: &[u8]) -> Result<(), TransportError> {
        if packet.len() > MAX_PAYLOAD {
            return Err(TransportError::PacketTooLarge { len: packet.len() });
        }
        self.egress.push_back(packet.to_vec());
        Ok(())
    }

    /// Whether a real packet is waiting.
    ///
    /// The defense engine's `replace` flag means a padding packet *may* be replaced by an
    /// already-queued real one; this is how the caller answers that question.
    pub fn has_queued(&self) -> bool {
        !self.egress.is_empty()
    }

    /// Send whatever the block state allows. Returns one [`Emitted`] per datagram.
    pub fn flush(&mut self, now: Instant) -> Result<Vec<Emitted>, TransportError> {
        if self.is_blocked(now) {
            return Ok(Vec::new());
        }
        self.blocked_until = None;

        let mut out = Vec::new();
        while let Some(packet) = self.egress.pop_front() {
            self.emit(FrameKind::Data, &packet, now)?;
            self.stats.data_out += 1;
            out.push(Emitted::Data);
        }
        Ok(out)
    }

    /// Send one cover-traffic datagram.
    ///
    /// `bypass` reflects the engine's flag: padding marked bypass may go out during
    /// blocking, but only if the block was declared bypassable. Honouring bypass against a
    /// non-bypassable block would break the guarantee the blocking machine is relying on.
    pub fn send_padding(&mut self, now: Instant, bypass: bool) -> Result<bool, TransportError> {
        if self.is_blocked(now) && !(bypass && self.block_bypassable) {
            return Ok(false);
        }
        self.emit(FrameKind::Padding, &[], now)?;
        self.stats.padding_out += 1;
        Ok(true)
    }

    /// Send a control frame. Never blocked — the handshake has to complete before there is
    /// a defense to obey.
    pub fn send_control(&mut self, kind: FrameKind, body: &[u8], now: Instant) -> Result<(), TransportError> {
        self.emit(kind, body, now)
    }

    fn emit(&mut self, kind: FrameKind, payload: &[u8], now: Instant) -> Result<(), TransportError> {
        let mut frame = [0u8; FRAME_LEN];
        encode(kind, payload, &mut frame)?;
        self.seal.seal(&frame, &mut self.scratch)?;
        debug_assert_eq!(self.scratch.len(), DATAGRAM_LEN);
        self.socket.send_to(&self.scratch, self.peer)?;
        self.trace.push(TraceEntry {
            at: now.duration_since(self.started),
            sent: true,
            padding: !kind.is_normal(),
            bytes: self.scratch.len(),
        });
        Ok(())
    }

    /// Read one datagram if one is waiting.
    ///
    /// Returns `Ok(None)` on timeout. A datagram that fails authentication, replay or
    /// framing is counted and dropped, never surfaced: a peer that can make us report a
    /// forged frame as real traffic can steer the defense.
    pub fn recv(&mut self, now: Instant) -> Result<Option<Received>, TransportError> {
        let mut buf = [0u8; DATAGRAM_LEN * 2];
        let (n, from) = match self.socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };
        if from != self.peer {
            self.stats.dropped += 1;
            return Ok(None);
        }

        let mut frame = [0u8; FRAME_LEN];
        if self.seal.open(&buf[..n], &mut frame).is_err() {
            self.stats.dropped += 1;
            return Ok(None);
        }
        let decoded = match decode(&frame) {
            Ok(f) => f,
            Err(_) => {
                self.stats.dropped += 1;
                return Ok(None);
            }
        };

        self.trace.push(TraceEntry {
            at: now.duration_since(self.started),
            sent: false,
            padding: !decoded.kind.is_normal(),
            bytes: n,
        });

        Ok(Some(match decoded.kind {
            FrameKind::Data => {
                self.stats.data_in += 1;
                Received::Data(decoded.payload.to_vec())
            }
            FrameKind::Padding => {
                self.stats.padding_in += 1;
                Received::Padding
            }
            FrameKind::Hello | FrameKind::HelloAck => Received::Control(decoded.payload.to_vec()),
            FrameKind::Close => Received::Close,
        }))
    }

    /// Write the trace in the `time,direction` format the Maybenot simulator consumes.
    pub fn trace_csv(&self) -> String {
        let mut s = String::new();
        for e in &self.trace {
            s.push_str(&format!("{},{}\n", e.at.as_nanos(), if e.sent { "s" } else { "r" }));
        }
        s
    }
}
