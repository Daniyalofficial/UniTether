//! mDNS discovery (RFC 6762 subset) over a raw UDP socket — std only.
//!
//! Advertises `_unilink._tcp.local.` (PTR + SRV + TXT) and answers queries
//! for it; also queries for peers. TXT payload: `v=1`, `role=host|device`,
//! `name=<device name>`, `port=<tcp port>`.

use std::collections::HashMap;
use std::net::{UdpSocket, Ipv4Addr};
use std::time::{Duration, Instant};

const MDNS_ADDR: &str = "224.0.0.251:5353";
const SERVICE_NAME: &str = "_unilink._tcp.local.";

pub const TXT_VERSION: &str = "v=1";

fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out.push(0);
}

fn skip_name(b: &[u8], mut i: usize) -> usize {
    loop {
        if i >= b.len() { return b.len(); }
        let l = b[i] as usize;
        if l == 0 { return i + 1; }
        if l & 0xC0 == 0xC0 { return i + 2; }
        i += 1 + l;
    }
}

fn read_name(b: &[u8], mut i: usize) -> (String, usize) {
    let mut parts = Vec::new();
    let mut jumps: Option<usize> = None;
    loop {
        if i >= b.len() { break; }
        let l = b[i];
        if l & 0xC0 == 0xC0 {
            let ptr = ((b[i] as usize & 0x3F) << 8) | b[i + 1] as usize;
            if jumps.is_none() { jumps = Some(i + 2); }
            i = ptr;
            continue;
        }
        if l == 0 {
            i += 1;
            break;
        }
        i += 1;
        parts.push(String::from_utf8_lossy(&b[i..i + l as usize]).into_owned());
        i += l as usize;
    }
    (parts.join("."), jumps.unwrap_or(i))
}

// ---------------------------------------------------------------- responder
/// Advertises one UniLink endpoint on the LAN and answers mDNS queries.
pub struct MdnsResponder {
    sock: UdpSocket,
    instance: String,          // "<name>._unilink._tcp.local."
    target: String,            // "<host>.local."
    port: u16,
    txt: Vec<u8>,
    host: String,
}

impl MdnsResponder {
    /// Build (does not yet listen); call `start()` to spawn the responder
    /// thread. `host_name` is the machine name for the SRV target.
    pub fn new(name: &str, role: &str, port: u16, host_name: &str) -> Self {
        let safe_name: String = name.chars().take(32)
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
            .collect();
        let instance = format!("{safe_name}._unilink._tcp.local.");
        let target = format!("{host_name}.local.");
        let mut txt = Vec::new();
        for (k, v) in [("v", "1"), ("role", role), ("name", name), ("port", &port.to_string())] {
            let pair = format!("{k}={v}");
            txt.push(pair.len() as u8);
            txt.extend_from_slice(pair.as_bytes());
        }
        Self {
            sock: UdpSocket::bind("0.0.0.0:0").expect("bind mDNS"),
            instance,
            target,
            port,
            txt,
            host: host_name.to_string(),
        }
    }

    pub fn local_port(&self) -> u16 {
        self.sock.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    /// Join the mDNS group and spawn a thread that answers queries and
    /// sends an initial unsolicited announcement. Returns the thread.
    pub fn start(self) -> std::thread::JoinHandle<()> {
        let _ = self.sock.join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 251), &Ipv4Addr::UNSPECIFIED);
        std::thread::spawn(move || {
            let mut last_announce = Instant::now() - Duration::from_secs(10);
            loop {
                let mut buf = [0u8; 4096];
                if self.sock.set_read_timeout(Some(Duration::from_millis(250))).is_err() { break; }
                match self.sock.recv_from(&mut buf) {
                    Err(_) => {
                        // periodic unsolicited announcement (mDNS is eventually
                        // consistent; peers keep records for 60 s)
                        if last_announce.elapsed() > Duration::from_secs(10) {
                            let _ = self.send_announcement();
                            last_announce = Instant::now();
                        }
                        continue;
                    }
                Ok((n, _from)) => {
                    if let Some(qname) = query_names(&buf[..n]) {
                        if qname.iter().any(|q| q == SERVICE_NAME) {
                            let _ = self.send_answer();
                        }
                    }
                }
            }
        })
    }

    pub fn send_announcement(&self) -> std::io::Result<()> {
        self.send_packet(true, &[])
    }

    fn send_answer(&self) -> std::io::Result<()> {
        self.send_packet(true, &[])
    }

    fn send_packet(&self, _aa: bool, _ids: &[u16]) -> std::io::Result<()> {
        let mut pkt = Vec::with_capacity(256);
        pkt.extend_from_slice(&0u16.to_be_bytes()); // id
        pkt.extend_from_slice(&0x8400u16.to_be_bytes()); // QR=1, AA=1, RD=0
        // no questions; 3 answers
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&3u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());

        // PTR answer
        let mut qname = Vec::new();
        encode_name(&mut qname, SERVICE_NAME);
        let mut rec = Vec::new();
        encode_name(&mut rec, &self.instance);
        pkt.extend_from_slice(&qname);
        pkt.extend_from_slice(&12u16.to_be_bytes()); // PTR
        pkt.extend_from_slice(&1u16.to_be_bytes()); // IN
        pkt.extend_from_slice(&60u32.to_be_bytes());
        pkt.extend_from_slice(&(rec.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&rec);

        // SRV answer
        let mut iname = Vec::new();
        encode_name(&mut iname, &self.instance);
        let mut srv = Vec::new();
        srv.extend_from_slice(&0u16.to_be_bytes());
        srv.extend_from_slice(&0u16.to_be_bytes());
        srv.extend_from_slice(&self.port.to_be_bytes());
        encode_name(&mut srv, &self.target);
        pkt.extend_from_slice(&iname);
        pkt.extend_from_slice(&33u16.to_be_bytes()); // SRV
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&60u32.to_be_bytes());
        pkt.extend_from_slice(&(srv.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&srv);

        // TXT answer
        pkt.extend_from_slice(&iname);
        pkt.extend_from_slice(&16u16.to_be_bytes()); // TXT
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&60u32.to_be_bytes());
        pkt.extend_from_slice(&(self.txt.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&self.txt);

        self.sock.send_to(&pkt, MDNS_ADDR)
    }
}

/// All PTR question names in a packet (lowercased).
fn query_names(pkt: &[u8]) -> Option<Vec<String>> {
    if pkt.len() < 12 { return None; }
    let qd = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let mut i = 12usize;
    let mut names = Vec::new();
    for _ in 0..qd {
        let (name, ni) = read_name(pkt, i);
        if ni + 4 > pkt.len() { return None; }
        let qtype = u16::from_be_bytes([pkt[ni], pkt[ni + 1]]);
        i = ni + 4;
        if qtype == 12 { names.push(name.to_lowercase()); }
    }
    Some(names)
}

// ---------------------------------------------------------------- advertiser
#[derive(Debug, Clone, PartialEq)]
pub struct MdnsPeer {
    pub instance: String,
    pub port: u16,
    pub target: String,
    pub txt: HashMap<String, String>,
    pub addr: std::net::SocketAddr,
}

/// Queries mDNS for `_unilink._tcp.local.` peers.
pub struct MdnsAdvertiser {
    sock: UdpSocket,
    peers: HashMap<String, MdnsPeer>,
    seen_at: HashMap<String, Instant>,
}

impl MdnsAdvertiser {
    pub fn new() -> std::io::Result<Self> {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 251), &Ipv4Addr::UNSPECIFIED)?;
        Ok(Self { sock, peers: HashMap::new(), seen_at: HashMap::new() })
    }

    /// Send the PTR query (3 times, 250 ms apart, per mDNS practice).
    pub fn send_query(&self) -> std::io::Result<()> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0x0000u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        let mut q = Vec::new();
        encode_name(&mut q, SERVICE_NAME);
        pkt.extend_from_slice(&q);
        pkt.extend_from_slice(&12u16.to_be_bytes()); // PTR
        pkt.extend_from_slice(&1u16.to_be_bytes()); // IN
        for _ in 0..3 {
            self.sock.send_to(&pkt, MDNS_ADDR)?;
            std::thread::sleep(Duration::from_millis(250));
        }
        Ok(())
    }

    /// Wait up to `timeout` for answers; returns peers seen so far.
    pub fn collect(&mut self, timeout: Duration) -> Vec<MdnsPeer> {
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 4096];
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let _ = self.sock.set_read_timeout(Some(remaining.min(Duration::from_millis(100))));
            let (n, from) = match self.sock.recv_from(&mut buf) {
                Ok(x) => x,
                Err(_) => break,
            };
            self.parse_answers(&buf[..n], from);
        }
        self.peers.values().cloned().collect()
    }

    fn parse_answers(&mut self, pkt: &[u8], from: std::net::SocketAddr) {
        if pkt.len() < 12 { return; }
        let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
        if flags & 0x8000 == 0 { return; } // not a response
        let an = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
        let ns = u16::from_be_bytes([pkt[8], pkt[9]]) as usize;
        let ar = u16::from_be_bytes([pkt[10], pkt[11]]) as usize;
        let mut i = 12usize;
        let skip_q = |i: &mut usize, pkt: &[u8]| {
            let _n = skip_name(pkt, *i);
            *i = _n + 4;
        };
        for _ in 0..u16::from_be_bytes([pkt[4], pkt[5]]) as usize { skip_q(&mut i, pkt); }
        for _ in 0..an + ns + ar {
            if i + 12 > pkt.len() { return; }
            let (name, ni) = read_name(pkt, i);
            if ni + 12 > pkt.len() { return; }
            let rtype = u16::from_be_bytes([pkt[ni], pkt[ni + 1]]);
            let rdlen = u16::from_be_bytes([pkt[ni + 8], pkt[ni + 9]]) as usize;
            let rd = &pkt[ni + 10..ni + 10 + rdlen];
            i = ni + 10 + rdlen;
            let lower = name.to_lowercase();
            if rtype == 33 {
                // SRV
                if rd.len() >= 7 {
                    let port = u16::from_be_bytes([rd[4], rd[5]]);
                    let (target, _) = read_name(rd, 6);
                    let p = self.peers.entry(lower).or_insert_with(|| MdnsPeer {
                        instance: lower.clone(), port, target: target.clone(),
                        txt: HashMap::new(), addr: from,
                    });
                    p.port = port;
                    p.target = target;
                    p.addr = from;
                    self.seen_at.insert(lower, Instant::now());
                }
            } else if rtype == 16 {
                // TXT
                if let Some(p) = self.peers.get_mut(&lower) {
                    let mut j = 0usize;
                    while j < rd.len() {
                        let l = rd[j] as usize;
                        j += 1;
                        if j + l > rd.len() { break; }
                        let s = std::str::from_utf8(&rd[j..j + l]).unwrap_or("");
                        if let Some((k, v)) = s.split_once('=') {
                            p.txt.insert(k.to_string(), v.to_string());
                        }
                        j += l;
                    }
                    self.seen_at.insert(lower, Instant::now());
                }
            }
        }
    }

    pub fn peers(&self) -> Vec<MdnsPeer> {
        self.peers.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_roundtrip() {
        let mut v = Vec::new();
        encode_name(&mut v, "_unilink._tcp.local");
        let (s, i) = read_name(&v, 0);
        assert_eq!(s, "_unilink._tcp.local");
        assert_eq!(i, v.len());
    }

    #[test]
    fn query_parse() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0, 0, 0, 0]);
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 0]);
        let mut q = Vec::new();
        encode_name(&mut q, SERVICE_NAME);
        pkt.extend_from_slice(&q);
        pkt.extend_from_slice(&12u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        let names = query_names(&pkt).unwrap();
        assert_eq!(names, vec!["_unilink._tcp.local"]);
    }
}
