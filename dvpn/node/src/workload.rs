//! Synthetic traffic, so the testbed has something to defend.
//!
//! Shaped like browsing rather than like a benchmark: short bursts with long idle gaps
//! between them, and far more downstream than upstream. That asymmetry matters — most of
//! the website-fingerprinting signal is in the traffic coming *back*, which is exactly why
//! the defense needs a server side, and a flat request/response loop would hide it.

use std::time::{Duration, Instant};

use crate::session::Source;

/// Deterministic so two runs are comparable. Not for anything but traffic shape.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next() as usize) % (hi - lo + 1)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RealPacket {
    pub at: Duration,
    pub sent: bool,
    pub bytes: usize,
}

/// A client that loads a page every few seconds and is idle in between.
pub struct Browsing {
    start: Instant,
    rng: Lcg,
    next_page: Instant,
    burst_left: usize,
    next_packet: Instant,
    page_every: Duration,
    pub real: Vec<RealPacket>,
}

impl Browsing {
    pub fn new(now: Instant, page_every: Duration) -> Self {
        Self {
            start: now,
            rng: Lcg(0x5EED_1234),
            next_page: now + Duration::from_millis(400),
            burst_left: 0,
            next_packet: now,
            page_every,
            real: Vec::new(),
        }
    }
}

impl Source for Browsing {
    fn packets(&mut self, now: Instant) -> Vec<Vec<u8>> {
        if self.burst_left == 0 {
            if now < self.next_page {
                return Vec::new();
            }
            // A page load: a handful of requests.
            self.burst_left = self.rng.range(3, 7);
            self.next_page = now + self.page_every;
            self.next_packet = now;
        }
        if now < self.next_packet {
            return Vec::new();
        }

        self.burst_left -= 1;
        self.next_packet = now + Duration::from_millis(self.rng.range(8, 40) as u64);
        // Requests are small and variable — the size signal a constant-size transport
        // erases.
        let len = self.rng.range(120, 700);
        self.real.push(RealPacket { at: now.duration_since(self.start), sent: true, bytes: len });
        vec![vec![0x41; len]]
    }

    fn on_received(&mut self, payload: &[u8], now: Instant) {
        self.real.push(RealPacket {
            at: now.duration_since(self.start),
            sent: false,
            bytes: payload.len(),
        });
    }
}

/// A server that answers each request with a burst of response packets.
pub struct Responder {
    start: Instant,
    rng: Lcg,
    queue: Vec<usize>,
    next_packet: Instant,
    pub real: Vec<RealPacket>,
}

impl Responder {
    pub fn new(now: Instant) -> Self {
        Self {
            start: now,
            rng: Lcg(0xC0FF_EE01),
            queue: Vec::new(),
            next_packet: now,
            real: Vec::new(),
        }
    }
}

impl Source for Responder {
    fn packets(&mut self, now: Instant) -> Vec<Vec<u8>> {
        if self.queue.is_empty() || now < self.next_packet {
            return Vec::new();
        }
        let len = self.queue.remove(0);
        self.next_packet = now + Duration::from_millis(self.rng.range(1, 6) as u64);
        self.real.push(RealPacket { at: now.duration_since(self.start), sent: true, bytes: len });
        vec![vec![0x42; len]]
    }

    fn on_received(&mut self, payload: &[u8], now: Instant) {
        self.real.push(RealPacket {
            at: now.duration_since(self.start),
            sent: false,
            bytes: payload.len(),
        });
        // Downstream is heavier than upstream, and mostly full-size segments with a
        // short tail — the burst shape a fingerprinting classifier keys on.
        let n = self.rng.range(8, 26);
        for i in 0..n {
            let len = if i + 1 == n { self.rng.range(60, 400) } else { 1100 };
            self.queue.push(len);
        }
    }
}

pub fn trace_csv(real: &[RealPacket]) -> String {
    let mut s = String::new();
    for p in real {
        s.push_str(&format!("{},{},{}\n", p.at.as_nanos(), if p.sent { "s" } else { "r" }, p.bytes));
    }
    s
}
