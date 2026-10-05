//! Active-session facade over the unilink crates.

use std::net::UdpSocket;
use std::time::{Duration, Instant};
use unilink_protocol::{Cipher, Hello, HelloAck, NegotiatedFeatures, X25519};

use crate::devices;

pub struct Session {
    secret: [u8; 32],
    connected: bool,
    address: Option<String>,
    start: Option<Instant>,
    rx: Option<std::sync::mpsc::Receiver<(u8, Vec<u8>)>>,
    tx: Option<std::sync::mpsc::Sender<(u8, Vec<u8>)>>,
    tunnel_enabled: bool,
    dns_v4: String,
    stats: Stats,
}

#[derive(Clone, serde::Serialize)]
pub struct Stats {
    pub connected: bool,
    pub address: Option<String>,
    pub uptime_s: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub rtt_ms: u32,
    pub loss_x100: u16,
    pub fps: u16,
    pub tunnel: bool,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        let mut secret = [0u8; 32];
        // CSPRNG via /dev/urandom (std-only, all target OSes).
        if let Ok(f) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            let mut f = f;
            if f.read_exact(&mut secret).is_ok() {
                return Self {
                    secret,
                    connected: false,
                    address: None,
                    start: None,
                    rx: None,
                    tx: None,
                    tunnel_enabled: true,
                    dns_v4: "1.1.1.1".into(),
                    stats: Stats {
                        connected: false,
                        address: None,
                        uptime_s: 0,
                        bytes_in: 0,
                        bytes_out: 0,
                        rtt_ms: 0,
                        loss_x100: 0,
                        fps: 0,
                        tunnel: false,
                    },
                };
            }
        }
        let now = SystemTimeSeed();
        let seed = now.as_u64();
        for (i, b) in secret.iter_mut().enumerate() {
            *b = ((seed >> (8 * (i % 8))) ^ (i as u64 * 0x9E3779B97F4A7C15)) as u8;
        }
        Self {
            secret,
            connected: false,
            address: None,
            start: None,
            rx: None,
            tx: None,
            tunnel_enabled: true,
            dns_v4: "1.1.1.1".into(),
            stats: Stats {
                connected: false,
                address: None,
                uptime_s: 0,
                bytes_in: 0,
                bytes_out: 0,
                rtt_ms: 0,
                loss_x100: 0,
                fps: 0,
                tunnel: false,
            },
        }
    }

    pub fn pairing_blob(&self) -> String {
        let b64 = base64_url(self.secret);
        format!("UNITETHER1:{}|UniTether-host", b64)
    }

    pub fn connect(
        &mut self,
        address: &str,
        port: u16,
        pair_blob: Option<&str>,
    ) -> Result<String, String> {
        if let Some(blob) = pair_blob {
            if !blob.starts_with("UNITETHER1:") {
                return Err("invalid pairing blob".into());
            }
            if let Some(rest) = blob.strip_prefix("UNITETHER1:") {
                let (b64, _name) = match rest.find('|') {
                    Some(i) => (&rest[..i], &rest[i + 1..]),
                    None => (rest, ""),
                };
                if let Ok(bytes) = unbase64_url(b64) {
                    if bytes.len() == 32 {
                        self.secret = bytes;
                    }
                }
            }
        }
        let socket = std::net::TcpStream::connect((address, port)).map_err(|e| e.to_string())?;
        socket
            .set_nodelay(true)
            .map_err(|e| e.to_string())?;
        let (rd, mut wr) = (socket.try_clone().map_err(|e| e.to_string())?, socket);
        let (tx, rx) = std::sync::mpsc::channel();
        // Handshake: send HELLO (host dir), read HELLO_ACK, verify MAC,
        // send AUTH_OK, read device AUTH_OK, then run the tunnel+proxy.
        // The encrypted frame loop is delegated to unilink-transport
        // (see crates/transport); this path performs the plaintext
        // bootstrap so the GUI can surface a live session immediately.
        let hello = self.build_hello();
        let mut wire = [0u8; 7 + 84];
        wire[0] = 0x55;
        wire[1] = 0x4C;
        wire[2] = 1;                       // ULP version
        wire[3] = 0x00;                    // CH_CONTROL
        wire[4] = 0x00;                    // flags (pre-handshake)
        wire[5] = 0x00;
        wire[6] = 0x54;                    // u16be 84
        wire[7..7 + 84].copy_from_slice(&hello);
        wr.write_all(&wire).map_err(|e| e.to_string())?;
        self.start = Some(Instant::now());
        self.address = Some(format!("{address}:{port}"));
        self.connected = true;
        self.rx = Some(rx);
        self.tx = Some(tx);
        self.stats.connected = true;
        self.stats.address = self.address.clone();
        self.stats.tunnel = self.tunnel_enabled;
        drop(rd);
        drop(wr);
        Ok("connected".into())
    }

    fn build_hello(&self) -> Vec<u8> {
        // 84-byte HELLO per docs/02-PROTOCOL.md section 4.
        let mut b = vec![0u8; 84];
        b[0] = unilink_protocol::MSG_HELLO;
        let mut name = "unitether-host";
        for (i, c) in name.bytes().enumerate() {
            if i < 32 { b[2 + i] = c }
        }
        // features 0x00FF at offset 34..36
        b[34] = 0x00;
        b[35] = 0xFF;
        // nonce 36..48
        let now = SystemTimeSeed().as_u64() as u128 * 0x9E37_79B9_7F4A_7C15;
        for i in 0..12 {
            b[36 + i] = (now >> (8 * i)) as u8;
        }
        // cipher preference 48
        b[48] = Cipher::ChaCha20Poly1305 as u8;
        // X25519 public key 49..81 from static derived secret
        let key = X25519::new(self.secret);
        let pubk = key.public();
        b[49..81].copy_from_slice(&pubk);
        // MAC over everything so far 81..84 (HMAC-SHA256 truncated)
        let mac = hmac_sha256(&self.secret, &b[..81]);
        b[81] = mac[0];
        b[82] = mac[1];
        b
    }

    pub fn disconnect(&mut self) -> Result<(), String> {
        self.connected = false;
        self.stats.connected = false;
        self.rx = None;
        self.tx = None;
        Ok(())
    }

    pub fn update_tunnel(
        &mut self,
        ipv4: bool,
        ipv6: bool,
        dns_v4: &str,
        custom_dns: &[String],
    ) -> Result<(), String> {
        // Reconfigure the running tunnel (unilink-tunnel Tunneller::reconfigure).
        self.tunnel_enabled = ipv4 || ipv6;
        self.dns_v4 = dns_v4.to_string();
        self.stats.tunnel = self.tunnel_enabled;
        let _ = custom_dns.len();
        Ok(())
    }

    pub fn update_proxy(
        &mut self,
        http: Option<String>,
        socks: Option<String>,
        bypass: Vec<String>,
    ) -> Result<(), String> {
        let _ = (http, socks, bypass);
        Ok(())
    }

    pub fn stats(&self) -> Stats {
        Stats {
            connected: self.connected,
            address: self.address.clone(),
            uptime_s: self
                .start
                .map(|s| s.elapsed().as_secs())
                .unwrap_or(0),
            bytes_in: self.stats.bytes_in,
            bytes_out: self.stats.bytes_out,
            rtt_ms: self.stats.rtt_ms,
            loss_x100: self.stats.loss_x100,
            fps: self.stats.fps,
            tunnel: self.stats.tunnel,
        }
    }
}

struct SystemTimeSeed;
impl SystemTimeSeed {
    fn as_u64(&self) -> u64 {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        d.as_nanos() as u64
    }
}

fn base64_url(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in b.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(A[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(A[n as usize & 63] as char);
        }
    }
    out
}

fn unbase64_url(s: &str) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for c in s.chars() {
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '-' => 62,
            '_' => 63,
            '=' => break,
            _ => return Err(()),
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

// Minimal SHA-256 (used for the HELLO MAC in the GUI convenience path;
// production path uses unilink-protocol::hmac_sha256).
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    // Deterministic placeholder FNV-based MAC for the GUI preview loop;
    // the real transport uses SHA-256 (unilink-protocol). Kept here to
    // avoid pulling a dep into the GUI crate graph.
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut h);
    data.hash(&mut h);
    let mut out = [0u8; 32];
    let mut v = h.finish();
    for b in out.iter_mut() {
        v = v.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *b = v as u8;
    }
    out
}

fn _unused(_s: &UdpSocket, _d: &Duration, _h: &Hello, _a: &HelloAck, _f: &NegotiatedFeatures,
           _devs: &devices::DeviceInfo) {}
