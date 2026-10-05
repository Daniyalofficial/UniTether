//! `NullTun` — in-memory TUN for conformance tests, proxy-only mode, and
//! platforms without TUN support. Packets are dropped (or echoed when a
//! loopback peer is attached).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Condvar, Mutex};

use crate::TunDevice;

#[derive(Default)]
struct State {
    rx: Vec<Vec<u8>>,
    rx_cond: Condvar,
    configured: bool,
}

pub struct NullTun {
    state: Arc<Mutex<State>>,
    name: String,
    peer: Option<Arc<Mutex<State>>>,
}

impl NullTun {
    pub fn new() -> Self {
        Self { state: Arc::new(Mutex::new(State::default())), name: "null0".into(), peer: None }
    }

    /// Attach a loopback peer: packets written here appear in `peer`'s rx
    /// and vice versa (used by the e2e-style test harness).
    pub fn link(&mut self, peer: &NullTun) {
        self.peer = Some(peer.state.clone());
        peer.state.lock().unwrap().rx_cond.notify_all();
    }

    /// Push a packet as if it arrived from the wire (test hook).
    pub fn inject(&self, packet: Vec<u8>) {
        let mut s = self.state.lock().unwrap();
        s.rx.push(packet);
        drop(s);
        self.state.lock().unwrap().rx_cond.notify_all();
    }

    /// Drain all pending packets (test hook).
    pub fn drain(&self) -> Vec<Vec<u8>> {
        self.state.lock().unwrap().rx.drain(..).collect()
    }
}

impl TunDevice for NullTun {
    fn name(&self) -> &str { &self.name }
    fn fd(&self) -> Option<std::os::unix::io::RawFd> { None }

    fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        let mut s = self.state.lock().unwrap();
        while s.rx.is_empty() {
            s = s.rx_cond.wait(s).map_err(|e| io::Error::other(e.to_string()))?;
        }
        Ok(s.rx.remove(0))
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let target = self.peer.clone();
        if let Some(t) = target {
            let mut s = t.lock().unwrap();
            s.rx.push(packet.to_vec());
            drop(s);
            t.lock().unwrap().rx_cond.notify_all();
        } else {
            let mut s = self.state.lock().unwrap();
            s.rx.push(packet.to_vec());
            drop(s);
            self.state.lock().unwrap().rx_cond.notify_all();
        }
        Ok(())
    }

    fn configure(&self, _v4: Option<Ipv4Addr>, _v6: Option<Ipv6Addr>) -> io::Result<()> {
        self.state.lock().unwrap().configured = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_drain() {
        let t = NullTun::new();
        t.inject(vec![0x45, 0, 0, 60]);
        assert_eq!(t.drain(), vec![vec![0x45, 0, 0, 60]]);
    }

    #[test]
    fn write_reads_back() {
        let mut t = NullTun::new();
        t.write_packet(&[1, 2, 3]).unwrap();
        let mut s = t.state.lock().unwrap();
        assert_eq!(s.rx.len(), 1);
        drop(s);
        t.state.lock().unwrap().rx_cond.notify_all();
        let pkt = t.read_packet().unwrap();
        assert_eq!(pkt, vec![1, 2, 3]);
    }
}
