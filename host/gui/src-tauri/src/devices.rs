//! Device discovery for the GUI: mDNS (via `dns-sd`/`avahi` CLI where
//! available) + the manual ADB-forward port list.

use std::net::UdpSocket;
use std::process::Command;

#[derive(Clone, serde::Serialize)]
pub struct DeviceInfo {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub transport: String,
    pub rtt_ms: Option<u32>,
}

pub fn scan(state: &crate::AppState) -> Result<Vec<DeviceInfo>, String> {
    let mut out = Vec::new();
    // 1) mDNS: _unilink._tcp (Android side registers it; Mac/Win hosts
    //    resolve via OS resolver). Best-effort 300 ms.
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        let _ = socket.set_read_timeout(Some(std::time::Duration::from_millis(300)));
        // Query packet for _unilink._tcp.local (QTYPE 12 PTR, QCLASS 0x8001)
        let q = build_mdns_query("_unilink._tcp.local");
        let _ = socket.send_to(&q, "239.255.255.250:5353");
        let mut buf = [0u8; 1500];
        loop {
            match socket.recv_from(&mut buf) {
                Ok((n, _addr)) => {
                    for (name, host) in parse_ptr_names(&buf[..n]) {
                        if name.ends_with("_unilink._tcp.local") {
                            let port = port_for(&host);
                            out.push(DeviceInfo {
                                name: friendly(&name),
                                address: host.clone(),
                                port,
                                transport: "lan".into(),
                                rtt_ms: ping(&host),
                            });
                        }
                    }
                }
                Err(_) => break,
            }
        }
    }
    // 2) ADB forward: `adb devices` → standard 4188x forward port.
    let adb = Command::new("adb").arg("devices").output();
    if let Ok(o) = adb {
        if o.status.success() {
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            let mut it = line.split_whitespace();
            if let (Some(serial), Some(st)) = (it.next(), it.next())
                && st == "device"
            {
                out.push(DeviceInfo {
                    name: format!("ADB · {serial}"),
                    address: "127.0.0.1".into(),
                    port: 41880,
                    transport: "adb".into(),
                    rtt_ms: Some(1),
                });
            }
        }
        }
    }
    let _ = &state;
    Ok(out)
}

fn friendly(name: &str) -> String {
    name.strip_prefix("unilink-")
        .and_then(|s| s.strip_suffix("._unilink._tcp.local"))
        .map(|s| s.to_string())
        .unwrap_or_else(|| name.to_string())
}

fn port_for(host: &str) -> u16 {
    let _ = host;
    41880
}

fn ping(host: &str) -> Option<u32> {
    let start = std::time::Instant::now();
    let _ = std::net::TcpStream::connect_timeout(
        &format!("{host}:41880").parse().ok()?,
        std::time::Duration::from_millis(250),
    );
    Some(start.elapsed().as_millis() as u32)
}

fn build_mdns_query(name: &str) -> Vec<u8> {
    let mut q = vec![0u8; 12];
    // ID=0, flags=0, QDCOUNT=1
    q[10] = 0x00;
    q[11] = 0x01;
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x0C, 0x80, 0x01]);
    q
}

fn parse_ptr_names(pkt: &[u8]) -> Vec<(String, String)> {
    // Tiny best-effort parser: walk QD/QD + answers, resolve pointers
    // for PTR answers (type 12). Returns (service-instance, hostname).
    let mut out = Vec::new();
    if pkt.len() < 12 {
        return out;
    }
    let qd = u16::from_be_bytes([pkt[10], pkt[11]]) as usize;
    let an = u16::from_be_bytes([pkt[12], pkt[13]]) as usize;
    let mut off = 12 + qd * 12;
    for _ in 0..an {
        if off + 12 > pkt.len() {
            break;
        }
        let name = read_name(pkt, off).unwrap_or_default();
        let off2 = off + name.1;
        if off2 + 10 > pkt.len() {
            break;
        }
        let rtype = u16::from_be_bytes([pkt[off2], pkt[off2 + 1]]);
        let rdlen = u16::from_be_bytes([pkt[off2 + 8], pkt[off2 + 9]]) as usize;
        if rtype == 12 && off2 + 10 + rdlen <= pkt.len() {
            let target = read_name(pkt, off2 + 10).unwrap_or_default();
            out.push((name.0, target.0));
        }
        off = off2 + 10 + rdlen;
    }
    out
}

fn read_name(pkt: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    let mut jumped = false;
    let mut consumed = 0;
    loop {
        if off >= pkt.len() {
            return None;
        }
        let len = pkt[off] as usize;
        if len == 0 {
            off += 1;
            if !jumped {
                consumed = off;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if off + 1 >= pkt.len() {
                return None;
            }
            let ptr =
                (((pkt[off] & 0x3F) as usize) << 8) | pkt[off + 1] as usize;
            if !jumped {
                consumed = off + 2;
            }
            off = ptr;
            jumped = true;
            continue;
        }
        if off + 1 + len > pkt.len() {
            return None;
        }
        parts.push(String::from_utf8_lossy(&pkt[off + 1..off + 1 + len]).into_owned());
        off += 1 + len;
        if !jumped {
            consumed = off;
        }
    }
    Some((parts.join("."), consumed))
}
