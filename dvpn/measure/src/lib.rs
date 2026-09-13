//! Trace analysis.
//!
//! ## What this measures, and what it deliberately does not
//!
//! It measures properties of a trace that an observer of the link can compute: packet
//! sizes, counts, timing occupancy, burst structure. Every number here is derived from
//! bytes that actually crossed a socket.
//!
//! It does **not** measure attacker accuracy. That requires a corpus of real traces from
//! many sites and a trained classifier; a number produced without those would be a number
//! about this synthetic workload, not about the defense. The size and occupancy figures
//! below are necessary conditions for a defense to work, not sufficient ones — a trace can
//! have perfect size uniformity and still be fingerprintable by timing alone.

#![forbid(unsafe_code)]

use std::collections::HashMap;

#[derive(Clone, Copy, Debug)]
pub struct Packet {
    pub nanos: u128,
    pub sent: bool,
    pub bytes: usize,
}

pub fn parse(csv: &str) -> Result<Vec<Packet>, String> {
    csv.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut f = l.split(',');
            let nanos = f.next().ok_or("missing time")?.trim();
            let dir = f.next().ok_or("missing direction")?.trim();
            let bytes = f.next().unwrap_or("0").trim();
            Ok(Packet {
                nanos: nanos.parse().map_err(|_| format!("bad time: {nanos}"))?,
                sent: dir == "s",
                bytes: bytes.parse().map_err(|_| format!("bad size: {bytes}"))?,
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct Summary {
    pub packets: usize,
    pub sent: usize,
    pub received: usize,
    pub bytes: u64,
    pub duration_ms: u128,
    pub unique_sizes: usize,
    /// Shannon entropy of the packet-size distribution, in bits.
    ///
    /// This is the number constant packet size exists to drive to zero. A trace with one
    /// size carries no information in its sizes at all.
    pub size_entropy_bits: f64,
    /// Fraction of 100 ms bins containing at least one packet.
    ///
    /// Idle gaps are a strong fingerprinting signal: a link that goes quiet when the user
    /// stops reading tells an observer when the page finished loading. Cover traffic
    /// pushes this toward 1.
    pub occupancy: f64,
    /// Runs of activity separated by gaps of 300 ms or more.
    pub bursts: usize,
}

const BIN_MS: u128 = 100;
const BURST_GAP_MS: u128 = 300;

pub fn summarize(packets: &[Packet]) -> Summary {
    if packets.is_empty() {
        return Summary {
            packets: 0,
            sent: 0,
            received: 0,
            bytes: 0,
            duration_ms: 0,
            unique_sizes: 0,
            size_entropy_bits: 0.0,
            occupancy: 0.0,
            bursts: 0,
        };
    }

    let duration_ms = (packets.last().unwrap().nanos - packets[0].nanos) / 1_000_000;

    let mut counts: HashMap<usize, usize> = HashMap::new();
    for p in packets {
        *counts.entry(p.bytes).or_default() += 1;
    }
    let n = packets.len() as f64;
    let entropy = counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum::<f64>()
        // A single-size trace yields -0.0, which prints as "-0.000" and reads like a bug.
        // Entropy is never negative, so clamping is honest as well as tidy.
        .max(0.0);

    let bins = (duration_ms / BIN_MS).max(1);
    let mut occupied: Vec<bool> = vec![false; bins as usize + 1];
    for p in packets {
        let bin = ((p.nanos - packets[0].nanos) / 1_000_000 / BIN_MS) as usize;
        if bin < occupied.len() {
            occupied[bin] = true;
        }
    }
    let occupancy = occupied.iter().filter(|&&b| b).count() as f64 / occupied.len() as f64;

    let mut bursts = 1;
    for w in packets.windows(2) {
        if (w[1].nanos - w[0].nanos) / 1_000_000 >= BURST_GAP_MS {
            bursts += 1;
        }
    }

    Summary {
        packets: packets.len(),
        sent: packets.iter().filter(|p| p.sent).count(),
        received: packets.iter().filter(|p| !p.sent).count(),
        bytes: packets.iter().map(|p| p.bytes as u64).sum(),
        duration_ms,
        unique_sizes: counts.len(),
        size_entropy_bits: entropy,
        occupancy,
        bursts,
    }
}

/// Bytes-per-second, so traces of different lengths can be compared honestly.
pub fn throughput(s: &Summary) -> f64 {
    if s.duration_ms == 0 {
        return 0.0;
    }
    s.bytes as f64 / (s.duration_ms as f64 / 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_size_trace_has_zero_size_entropy() {
        let packets: Vec<Packet> = (0..100)
            .map(|i| Packet { nanos: i * 1_000_000, sent: true, bytes: 1224 })
            .collect();
        let s = summarize(&packets);
        assert_eq!(s.unique_sizes, 1);
        assert!(s.size_entropy_bits.abs() < 1e-9, "got {}", s.size_entropy_bits);
    }

    #[test]
    fn a_uniform_two_size_trace_has_one_bit() {
        let packets: Vec<Packet> = (0..100)
            .map(|i| Packet {
                nanos: i * 1_000_000,
                sent: true,
                bytes: if i % 2 == 0 { 40 } else { 1500 },
            })
            .collect();
        assert!((summarize(&packets).size_entropy_bits - 1.0).abs() < 1e-9);
    }

    #[test]
    fn bursts_are_counted_by_idle_gaps() {
        let packets = vec![
            Packet { nanos: 0, sent: true, bytes: 100 },
            Packet { nanos: 10_000_000, sent: true, bytes: 100 },
            Packet { nanos: 2_000_000_000, sent: true, bytes: 100 },
        ];
        assert_eq!(summarize(&packets).bursts, 2);
    }

    #[test]
    fn parsing_accepts_the_two_column_simulator_format() {
        let p = parse("0,s\n1000,r\n").unwrap();
        assert_eq!(p.len(), 2);
        assert!(p[0].sent && !p[1].sent);
        assert_eq!(p[0].bytes, 0);
    }

    #[test]
    fn a_malformed_line_is_an_error_not_a_silent_zero() {
        assert!(parse("banana,s,10\n").is_err());
        assert!(parse("0,s,notanumber\n").is_err());
    }
}
