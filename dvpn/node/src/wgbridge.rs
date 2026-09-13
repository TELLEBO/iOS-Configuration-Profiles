//! Bridges a real WireGuard endpoint into the shaped tunnel.
//!
//! WireGuard has no field for padding machines and no hook to add them — Mullvad
//! implement DAITA inside a fork of wireguard-go, not in a `.conf`. The alternative, which
//! is what this does, is to leave WireGuard entirely alone and carry its datagrams inside
//! a transport that shapes.
//!
//! ```text
//!   wg client ──udp──▶ wg-client relay ══shaped══▶ wg-server relay ──udp──▶ wg server
//!   (Endpoint =            (this)                      (this)
//!    127.0.0.1:51820)
//! ```
//!
//! From WireGuard's point of view nothing unusual is happening: it sends to a UDP address
//! and gets replies. From an observer's point of view the WireGuard handshake and data
//! messages — whose sizes are distinctive and well documented — are gone, replaced by a
//! stream of identical frames mixed with cover traffic.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

use dvpn_wire::MAX_PAYLOAD;

use crate::session::Source;

pub struct WgBridge {
    sock: UdpSocket,
    /// Server side: the real WireGuard endpoint to forward to.
    fixed_target: Option<SocketAddr>,
    /// Client side: where the local WireGuard sends from, learned on first contact.
    learned: Option<SocketAddr>,
    oversize: u64,
    forwarded: u64,
    delivered: u64,
}

impl WgBridge {
    /// Client side: listen for the local WireGuard client and learn its address.
    pub fn listening(bind: &str) -> io::Result<Self> {
        let sock = UdpSocket::bind(bind)?;
        sock.set_nonblocking(true)?;
        Ok(Self {
            sock,
            fixed_target: None,
            learned: None,
            oversize: 0,
            forwarded: 0,
            delivered: 0,
        })
    }

    /// Server side: forward to a known WireGuard endpoint.
    pub fn forwarding(target: SocketAddr) -> io::Result<Self> {
        let sock = UdpSocket::bind("127.0.0.1:0")?;
        sock.set_nonblocking(true)?;
        Ok(Self {
            sock,
            fixed_target: Some(target),
            learned: None,
            oversize: 0,
            forwarded: 0,
            delivered: 0,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    fn target(&self) -> Option<SocketAddr> {
        self.fixed_target.or(self.learned)
    }

    pub fn report(&self) -> String {
        format!(
            "bridge: {} forwarded into the tunnel, {} delivered out, {} dropped as oversize",
            self.forwarded, self.delivered, self.oversize
        )
    }
}

impl Source for WgBridge {
    fn packets(&mut self, _now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = [0u8; 2048];
        // Bounded so one busy peer cannot starve the rest of the session loop — the
        // defense's timers still need to fire on time.
        for _ in 0..32 {
            match self.sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    if self.fixed_target.is_none() {
                        self.learned = Some(from);
                    }
                    if n > MAX_PAYLOAD {
                        // The MTU is wrong. This is the failure that presents as "small
                        // requests work, downloads stall", so it is counted and named
                        // rather than silently dropped.
                        self.oversize += 1;
                        eprintln!(
                            "bridge: dropped a {n}-byte datagram (limit {MAX_PAYLOAD}). \
                             Lower the WireGuard MTU — dvpn-wgconf computes the right value."
                        );
                        continue;
                    }
                    self.forwarded += 1;
                    out.push(buf[..n].to_vec());
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        out
    }

    fn on_received(&mut self, payload: &[u8], _now: Instant) {
        if let Some(target) = self.target() {
            if self.sock.send_to(payload, target).is_ok() {
                self.delivered += 1;
            }
        }
        // Before the local WireGuard has spoken there is nowhere to send. Dropping is
        // correct: WireGuard retries its handshake.
    }
}
