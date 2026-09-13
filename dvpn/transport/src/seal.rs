//! Datagram sealing.
//!
//! ## What is deliberately not here
//!
//! **Key agreement.** There is no handshake that derives these keys, and there should not
//! be one written here. Use Noise_IK or WireGuard's handshake from a reviewed
//! implementation and feed the resulting keys in. Authenticated key exchange is a solved
//! problem with a long history of subtle breaks, and a traffic-analysis project is not
//! where it should be re-solved.
//!
//! What *is* here is the part the defense depends on: sealing that adds a **constant**
//! number of bytes, so a sealed frame is the same size as every other sealed frame.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use dvpn_wire::FRAME_LEN;

use crate::TransportError;

/// Bytes a sealed datagram adds over the frame: 8-byte counter + 16-byte Poly1305 tag.
pub const SEAL_OVERHEAD: usize = 8 + 16;

/// The size of every datagram this transport puts on the wire. Every one.
pub const DATAGRAM_LEN: usize = FRAME_LEN + SEAL_OVERHEAD;

/// Which direction a key protects. Used as nonce domain separation so the two directions
/// can share a key derivation without ever colliding on a nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    ClientToServer = 1,
    ServerToClient = 2,
}

/// Seals and opens datagrams.
pub trait Seal {
    fn seal(&mut self, frame: &[u8; FRAME_LEN], out: &mut Vec<u8>) -> Result<(), TransportError>;
    fn open(&mut self, datagram: &[u8], out: &mut [u8; FRAME_LEN]) -> Result<(), TransportError>;
}

/// A 64-packet sliding replay window, as WireGuard uses.
///
/// Strict monotonicity would be simpler and wrong: UDP reorders, and dropping every
/// reordered packet would make the transport look lossy in exactly the bursty conditions
/// the defense is trying to shape.
#[derive(Debug, Default)]
struct ReplayWindow {
    highest: u64,
    bitmap: u64,
}

impl ReplayWindow {
    fn accept(&mut self, counter: u64) -> bool {
        const WIDTH: u64 = 64;
        if counter > self.highest {
            let shift = counter - self.highest;
            self.bitmap = if shift >= WIDTH { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.highest = counter;
            true
        } else {
            let back = self.highest - counter;
            if back >= WIDTH {
                return false; // too old to prove it is not a replay
            }
            let bit = 1u64 << back;
            if self.bitmap & bit != 0 {
                return false; // already seen
            }
            self.bitmap |= bit;
            true
        }
    }
}

pub struct ChaChaSeal {
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    send_dir: Direction,
    recv_dir: Direction,
    counter: u64,
    replay: ReplayWindow,
}

impl ChaChaSeal {
    /// `send_key` and `recv_key` must come from a real key exchange, and must differ.
    pub fn new(send_key: &[u8; 32], recv_key: &[u8; 32], send_dir: Direction) -> Self {
        let recv_dir = match send_dir {
            Direction::ClientToServer => Direction::ServerToClient,
            Direction::ServerToClient => Direction::ClientToServer,
        };
        Self {
            send: ChaCha20Poly1305::new(&(*send_key).into()),
            recv: ChaCha20Poly1305::new(&(*recv_key).into()),
            send_dir,
            recv_dir,
            counter: 0,
            replay: ReplayWindow::default(),
        }
    }

    fn nonce(dir: Direction, counter: u64) -> Nonce {
        // 12 bytes: 4-byte direction domain, 8-byte counter. The direction bytes are never
        // transmitted — both ends know which side they are.
        let mut n = [0u8; 12];
        n[0..4].copy_from_slice(&(dir as u32).to_be_bytes());
        n[4..12].copy_from_slice(&counter.to_be_bytes());
        Nonce::from(n)
    }
}

impl Seal for ChaChaSeal {
    fn seal(&mut self, frame: &[u8; FRAME_LEN], out: &mut Vec<u8>) -> Result<(), TransportError> {
        // Nonce reuse with a counter AEAD is catastrophic, not degraded: it leaks the
        // XOR of two plaintexts and forfeits authentication. Refuse rather than wrap.
        let counter = self.counter.checked_add(1).ok_or(TransportError::CounterExhausted)?;
        self.counter = counter;

        let nonce = Self::nonce(self.send_dir, counter);
        let sealed = self
            .send
            .encrypt(&nonce, Payload { msg: frame.as_slice(), aad: &[] })
            .map_err(|_| TransportError::SealFailed)?;

        out.clear();
        out.reserve(DATAGRAM_LEN);
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&sealed);
        debug_assert_eq!(out.len(), DATAGRAM_LEN);
        Ok(())
    }

    fn open(&mut self, datagram: &[u8], out: &mut [u8; FRAME_LEN]) -> Result<(), TransportError> {
        // A datagram of the wrong length cannot be ours. Rejecting on length first also
        // means a size-probing adversary learns nothing beyond what they already see.
        if datagram.len() != DATAGRAM_LEN {
            return Err(TransportError::WrongDatagramLength { got: datagram.len() });
        }
        let counter = u64::from_be_bytes(datagram[0..8].try_into().expect("checked length"));

        let nonce = Self::nonce(self.recv_dir, counter);
        let plain = self
            .recv
            .decrypt(&nonce, Payload { msg: &datagram[8..], aad: &[] })
            .map_err(|_| TransportError::OpenFailed)?;

        if plain.len() != FRAME_LEN {
            return Err(TransportError::OpenFailed);
        }
        // Replay is checked only after authentication, so a forged counter cannot poison
        // the window.
        if !self.replay.accept(counter) {
            return Err(TransportError::Replay { counter });
        }
        out.copy_from_slice(&plain);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_accepts_reordering_but_not_repeats() {
        let mut w = ReplayWindow::default();
        assert!(w.accept(1));
        assert!(w.accept(5));
        assert!(w.accept(3), "reordered but fresh");
        assert!(!w.accept(3), "same counter twice");
        assert!(!w.accept(1), "already seen");
        assert!(w.accept(200));
        assert!(!w.accept(5), "now outside the window");
    }
}
