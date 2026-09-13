//! Per-machine timers.
//!
//! Maybenot allows one pending action timer per machine, and a new action for that machine
//! replaces the pending one. Modelling that with a map keyed by machine — rather than a
//! list of pending actions — is what makes the replacement automatic instead of a rule
//! somebody has to remember.

use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct Padding {
    pub at: Instant,
    pub bypass: bool,
    pub replace: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Block {
    pub at: Instant,
    pub duration: Duration,
    pub bypass: bool,
}

#[derive(Default)]
pub struct Timers {
    padding: HashMap<usize, Padding>,
    block: HashMap<usize, Block>,
    internal: HashMap<usize, Instant>,
}

impl Timers {
    pub fn schedule_padding(&mut self, machine: usize, p: Padding) {
        self.padding.insert(machine, p);
    }
    pub fn schedule_block(&mut self, machine: usize, b: Block) {
        self.block.insert(machine, b);
    }
    pub fn schedule_internal(&mut self, machine: usize, at: Instant) {
        self.internal.insert(machine, at);
    }
    pub fn cancel(&mut self, machine: usize) {
        self.padding.remove(&machine);
        self.block.remove(&machine);
    }
    pub fn cancel_internal(&mut self, machine: usize) {
        self.internal.remove(&machine);
    }

    pub fn due_padding(&mut self, now: Instant) -> Vec<(usize, Padding)> {
        drain_due(&mut self.padding, now, |p| p.at)
    }
    pub fn due_blocks(&mut self, now: Instant) -> Vec<(usize, Block)> {
        drain_due(&mut self.block, now, |b| b.at)
    }
    pub fn due_internal(&mut self, now: Instant) -> Vec<(usize, Instant)> {
        drain_due(&mut self.internal, now, |&t| t)
    }

    /// When the loop next has something to do, so it can sleep instead of spinning.
    pub fn next_deadline(&self) -> Option<Instant> {
        let p = self.padding.values().map(|p| p.at);
        let b = self.block.values().map(|b| b.at);
        let i = self.internal.values().copied();
        p.chain(b).chain(i).min()
    }
}

fn drain_due<T: Copy>(
    map: &mut HashMap<usize, T>,
    now: Instant,
    at: impl Fn(&T) -> Instant,
) -> Vec<(usize, T)> {
    let ready: Vec<usize> = map
        .iter()
        .filter(|(_, v)| at(v) <= now)
        .map(|(&k, _)| k)
        .collect();
    ready
        .into_iter()
        .filter_map(|k| map.remove(&k).map(|v| (k, v)))
        .collect()
}
