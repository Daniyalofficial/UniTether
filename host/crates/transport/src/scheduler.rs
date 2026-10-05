//! Channel scheduler (Phase 9): weighted priorities, byte-budget
//! backpressure, starvation-free delivery.
//!
//! Default order: CONTROL > INPUT > AUDIO > VIDEO > FILE (weights 8/4/3/2/1).
//! Mirrors `tests/protocol/scheduler.py` (conformance semantics).

use std::collections::VecDeque;
use std::marker::PhantomData;

pub const PRIO_CONTROL: u8 = 4;
pub const PRIO_INPUT: u8 = 3;
pub const PRIO_AUDIO: u8 = 2;
pub const PRIO_VIDEO: u8 = 1;
pub const PRIO_FILE: u8 = 0;

pub const PRIORITIES: [u8; 5] =
    [PRIO_CONTROL, PRIO_INPUT, PRIO_AUDIO, PRIO_VIDEO, PRIO_FILE];
pub const DEFAULT_WEIGHTS: [usize; 5] = [8, 4, 3, 2, 1];

/// ULP channel → priority (unlisted channels default to FILE).
pub fn prio_of_channel(channel: u8) -> u8 {
    match channel {
        0x00 | 0x07 | 0x08 | 0x0B | 0x0D | 0x06 => PRIO_CONTROL, // control,
        // notification, stats, proxy, user, clipboard
        0x04 => PRIO_INPUT,                                     // input
        0x02 | 0x03 => PRIO_AUDIO,                               // audio in/out
        0x01 | 0x09 | 0x0A | 0x0C => PRIO_VIDEO,                 // video, tun v4/v6,
        // camera
        0x05 => PRIO_FILE,                                       // file
        _ => PRIO_FILE,
    }
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub pending: [usize; 5],
    pub bytes: usize,
    pub dropped_full: u64,
    pub dropped_budget: u64,
    pub delivered: u64,
}

/// Weighted deficit round-robin scheduler with a hard byte budget.
pub struct Scheduler<T> {
    queues: [VecDeque<T>; 5],          // index = 4 - priority
    deficit: [usize; 5],
    weights: [usize; 5],
    bytes: usize,
    items: usize,
    max_items: usize,
    budget: usize,
    dropped_full: u64,
    dropped_budget: u64,
    delivered: u64,
    size_of: Box<dyn Fn(&T) -> usize>,
}

impl<T> Scheduler<T> {
    pub fn new(budget: usize, max_items: usize, size_of: impl Fn(&T) -> usize + 'static)
        -> Self {
        Self {
            queues: Default::default(),
            deficit: [0; 5],
            weights: DEFAULT_WEIGHTS,
            bytes: 0,
            items: 0,
            max_items,
            budget,
            dropped_full: 0,
            dropped_budget: 0,
            delivered: 0,
            size_of: Box::new(size_of),
        }
    }

    fn idx(prio: u8) -> usize {
        4 - prio as usize
    }

    /// Backpressure: full queue or budget ⇒ drop (counted), false.
    pub fn enqueue(&mut self, channel: u8, item: T) -> bool {
        let prio = prio_of_channel(channel);
        let size = (self.size_of)(&item);
        if self.items >= self.max_items {
            self.dropped_full += 1;
            return false;
        }
        if self.bytes + size > self.budget {
            self.dropped_budget += 1;
            return false;
        }
        self.queues[Self::idx(prio)].push_back(item);
        self.bytes += size;
        self.items += 1;
        true
    }

    /// Next item by weighted deficit round-robin; None when empty.
    /// Every non-empty priority is served within max(weights) pops
    /// (starvation bound).
    pub fn pop(&mut self) -> Option<T> {
        if self.items == 0 {
            return None;
        }
        let mut served: Option<usize> = None;
        for i in 0..5 {
            if !self.queues[i].is_empty() && self.deficit[i] >= 1 {
                served = Some(i);
                break;
            }
        }
        if served.is_none() {
            for (i, w) in self.weights.iter().enumerate() {
                self.deficit[i] = *w;
            }
            for i in 0..5 {
                if !self.queues[i].is_empty() {
                    served = Some(i);
                    break;
                }
            }
        }
        let i = served?;
        let item = self.queues[i].pop_front()?;
        let size = (self.size_of)(&item);
        self.deficit[i] -= 1;
        self.bytes -= size;
        self.items -= 1;
        self.delivered += 1;
        Some(item)
    }

    pub fn pending(&self) -> usize {
        self.items
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            pending: [
                self.queues[0].len(),
                self.queues[1].len(),
                self.queues[2].len(),
                self.queues[3].len(),
                self.queues[4].len(),
            ],
            bytes: self.bytes,
            dropped_full: self.dropped_full,
            dropped_budget: self.dropped_budget,
            delivered: self.delivered,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type S = Scheduler<Vec<u8>>;
    fn s(budget: usize, max: usize) -> S {
        S::new(budget, max, |t: &Vec<u8>| t.len())
    }
    const CTRL: u8 = 0x00;
    const FILE: u8 = 0x05;
    const INPUT: u8 = 0x04;
    const AUDIO: u8 = 0x02;
    const VIDEO: u8 = 0x01;

    #[test]
    fn strict_priority_order() {
        let mut s = s(1 << 20, 100);
        s.enqueue(FILE, vec![b'F'; 100]);
        s.enqueue(CTRL, vec![b'C'; 10]);
        s.enqueue(INPUT, vec![b'I'; 50]);
        assert_eq!(s.pop().unwrap()[0], b'C');
        assert_eq!(s.pop().unwrap()[0], b'I');
        assert_eq!(s.pop().unwrap()[0], b'F');
        assert!(s.pop().is_none());
    }

    #[test]
    fn starvation_bound_under_file_flood() {
        let maxw = *DEFAULT_WEIGHTS.iter().max().unwrap();
        for trial in 0..20 {
            let mut s = s(1 << 24, 10_000);
            for i in 0..200 {
                s.enqueue(FILE, vec![b'x'; 48]);
                let _ = i;
            }
            s.enqueue(CTRL, vec![b'C']);
            let mut waited = 0;
            loop {
                let got = s.pop().unwrap();
                if got[0] == b'C' {
                    break;
                }
                waited += 1;
                s.enqueue(FILE, vec![b'y'; 40]);
            }
            assert!(waited <= maxw, "trial {trial}: waited {waited}");
            while s.pop().is_some() {}
        }
    }

    #[test]
    fn backpressure_bounds() {
        let mut s = s(1024, 1000);
        assert!(s.enqueue(FILE, vec![b'x'; 500]));
        assert!(s.enqueue(FILE, vec![b'x'; 500]));
        assert!(!s.enqueue(FILE, vec![b'x'; 500]));
        assert_eq!(s.snapshot().dropped_budget, 1);

        let mut s = s(1 << 30, 5);
        for _ in 0..10 {
            s.enqueue(FILE, vec![b'x'; 10]);
        }
        assert_eq!(s.pending(), 5);
        assert_eq!(s.snapshot().dropped_full, 5);
    }

    #[test]
    fn conservation_and_all_priorities_served() {
        let mut s = s(1 << 20, 10_000);
        let mut enq = 0usize;
        for _ in 0..300 {
            if s.enqueue(FILE, vec![b'q'; 40]) {
                enq += 1;
            }
        }
        for ch in [CTRL, INPUT, AUDIO, VIDEO, FILE] {
            for _ in 0..20 {
                if s.enqueue(ch, vec![b'p'; 10]) {
                    enq += 1;
                }
            }
        }
        let mut delivered = 0;
        while s.pop().is_some() {
            delivered += 1;
        }
        assert_eq!(delivered, enq);
        assert_eq!(s.snapshot().delivered as usize, enq);
        assert_eq!(s.pending(), 0);
    }

    #[test]
    fn channel_prio_mapping() {
        assert_eq!(prio_of_channel(0x00), PRIO_CONTROL);
        assert_eq!(prio_of_channel(0x04), PRIO_INPUT);
        assert_eq!(prio_of_channel(0x02), PRIO_AUDIO);
        assert_eq!(prio_of_channel(0x03), PRIO_AUDIO);
        assert_eq!(prio_of_channel(0x01), PRIO_VIDEO);
        assert_eq!(prio_of_channel(0x09), PRIO_VIDEO);
        assert_eq!(prio_of_channel(0x0A), PRIO_VIDEO);
        assert_eq!(prio_of_channel(0x05), PRIO_FILE);
        assert_eq!(prio_of_channel(0xFF), PRIO_FILE);
    }
}
