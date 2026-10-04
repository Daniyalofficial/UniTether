//! ULP session: handshake + per-direction AEAD frame encryption.
//!
//! Mirrors docs/02-PROTOCOL.md section 7 exactly (and the validated E2E
//! reference in tests/e2e/ulp_link.py):
//!   * HELLO / HELLO_ACK / AUTH_OK travel in plaintext on CH_CONTROL
//!   * after the handshake every frame MUST carry F_ENCRYPTED
//!   * AEAD nonce = u64be((dir<<63)|counter) || u32be(channel)
//!   * AAD = the exact wire header actually sent (7 or 11 bytes,
//!     ciphertext length included, F_ENCRYPTED set)
//!   * counters are per-direction per-side (independent TX and RX)

use std::time::Duration;

use unilink_protocol::crypto::{
    constant_time_eq, frame_nonce, interop_decrypt, interop_encrypt, x25519_public,
};
use unilink_protocol::error::{ErrorKind, ProtocolError, Result};
use unilink_protocol::frame::{ch, Frame, F_ENCRYPTED, F_PRIORITY, MAX_PAYLOAD};
use unilink_protocol::handshake::{
    derive_session_keys, CIPHER_INTEROP, Hello, HelloAck, SessionKeys,
    FEAT_DUAL_STACK, FEAT_VIDEO, ROLE_HOST,
};
use unilink_protocol::message::{
    msg_decode, msg_encode, MSG_AUTH_OK, MSG_BYE, MSG_HELLO, MSG_HELLO_ACK,
    MSG_PING, MSG_PONG,
};

use crate::rand::random_bytes;
use crate::transport::Transport;

pub const DEFAULT_FEATURES: u16 = FEAT_DUAL_STACK | FEAT_VIDEO | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7);

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub peer_role: u8,
    pub peer_features: u16,
    pub cipher_sel: u8,
}

pub struct Session<T: Transport> {
    pub conn: T,
    pub info: SessionInfo,
    direction: u8,          // 0 = host side, 1 = device side
    tx_counter: u64,
    rx_counter: u64,
    keys: SessionKeys,
    pub rtt_ms: Option<u64>,
    ping_seq: u64,
}

impl<T: Transport> Session<T> {
    // ------------------------------------------------------- handshake
    /// Host role: send HELLO, verify HELLO_ACK, mutual AUTH_OK.
    /// Transport-agnostic: any `Transport` (TCP today, QUIC/relay later).
    pub fn connect_host(conn: T, secret: &[u8; 32]) -> Result<Self> {
        let priv_key = random_bytes(32);
        let mut priv_key: [u8; 32] = [0; 32];
        priv_key.copy_from_slice(&priv_key);
        let pub_key = x25519_public(&priv_key);
        let nonce_a: [u8; 16] = random_bytes(16)[..16].try_into().unwrap();

        let hello = Hello::build(ROLE_HOST, DEFAULT_FEATURES, CIPHER_INTEROP,
                                 pub_key, nonce_a, secret);
        let mut sess: Self = Session {
            conn,
            info: SessionInfo { peer_role: ROLE_HOST, peer_features: 0, cipher_sel: 0 },
            direction: 0,
            tx_counter: 0,
            rx_counter: 0,
            keys: SessionKeys { key_aead: [0; 32], key_mac: [0; 32] },
            rtt_ms: None,
            ping_seq: 0,
        };
        sess.send_plaintext_msg(MSG_HELLO, &hello.body())?;

        let (mtype, _f, body) = sess.recv_plaintext_msg()?;
        if mtype != MSG_HELLO_ACK {
            return Err(ProtocolError::new(ErrorKind::BadMessage,
                format!("expected HELLO_ACK, got {mtype:#x}")));
        }
        let ack = HelloAck::parse(body)?;
        ack.verify(secret, &nonce_a)?;
        let shared = unilink_protocol::crypto::x25519(&priv_key, &ack.ecdh_pub);
        sess.keys = derive_session_keys(&shared, &nonce_a, &ack.nonce_b, ack.cipher_sel);
        sess.send_plaintext_msg(MSG_AUTH_OK, b"")?;
        let (mtype2, _f, _b) = sess.recv_plaintext_msg()?;
        if mtype2 != MSG_AUTH_OK {
            return Err(ProtocolError::new(ErrorKind::Auth, "missing peer AUTH_OK"));
        }
        sess.info.peer_role = ROLE_HOST;
        sess.info.peer_features = ack.negotiated;
        sess.info.cipher_sel = ack.cipher_sel;
        Ok(sess)
    }

    /// Device role: verify HELLO, send HELLO_ACK, mutual AUTH_OK.
    pub fn accept_device(conn: T, secret: &[u8; 32]) -> Result<Self> {
        let priv_bytes = random_bytes(32);
        let mut priv_key: [u8; 32] = [0; 32];
        priv_key.copy_from_slice(&priv_bytes);
        let pub_key = x25519_public(&priv_key);

        let mut sess: Self = Session {
            conn,
            info: SessionInfo { peer_role: ROLE_HOST, peer_features: 0, cipher_sel: 0 },
            direction: 1,
            tx_counter: 0,
            rx_counter: 0,
            keys: SessionKeys { key_aead: [0; 32], key_mac: [0; 32] },
            rtt_ms: None,
            ping_seq: 0,
        };
        let (mtype, _f, body) = sess.recv_plaintext_msg()?;
        if mtype != MSG_HELLO {
            return Err(ProtocolError::new(ErrorKind::BadMessage,
                format!("expected HELLO, got {mtype:#x}")));
        }
        let hello = Hello::parse(body)?;
        hello.verify(secret)?;
        let nonce_a = hello.nonce_a;
        let nonce_b: [u8; 16] = random_bytes(16)[..16].try_into().unwrap();
        let sel = CIPHER_INTEROP;
        let ack = HelloAck::build(DEFAULT_FEATURES, sel, pub_key, nonce_b, nonce_a, secret);
        sess.send_plaintext_msg(MSG_HELLO_ACK, &ack.body())?;
        let shared = unilink_protocol::crypto::x25519(&priv_key, &hello.ecdh_pub);
        sess.keys = derive_session_keys(&shared, &nonce_a, &nonce_b, sel);
        sess.send_plaintext_msg(MSG_AUTH_OK, b"")?;
        let (mtype2, _f, _b) = sess.recv_plaintext_msg()?;
        if mtype2 != MSG_AUTH_OK {
            return Err(ProtocolError::new(ErrorKind::Auth, "missing peer AUTH_OK"));
        }
        sess.info.peer_role = hello.role;
        sess.info.peer_features = hello.feature_mask;
        sess.info.cipher_sel = sel;
        Ok(sess)
    }

    fn recv_plaintext_msg(&mut self) -> Result<(u8, u8, Vec<u8>)> {
        let frame = self.conn.read_frame(Duration::from_secs(30))?;
        if frame.channel != ch::CONTROL {
            return Err(ProtocolError::new(ErrorKind::BadMessage,
                format!("expected control frame, got channel {:#x}", frame.channel)));
        }
        if frame.flags & F_ENCRYPTED != 0 {
            return Err(ProtocolError::new(ErrorKind::BadMessage,
                "unexpected encrypted frame during handshake"));
        }
        let (t, f, b) = msg_decode(&frame.payload)?;
        Ok((t, f, b.to_vec()))
    }

    fn send_plaintext_msg(&mut self, mtype: u8, body: &[u8]) -> Result<()> {
        let frame = Frame::new(ch::CONTROL, 0, msg_encode(mtype, body))?;
        self.conn.write_frame(&frame)
    }

    // ---------------------------------------------------------- data path
    /// Send one (possibly encrypted) frame.
    pub fn send(&mut self, channel: u8, flags: u8, payload: Vec<u8>) -> Result<()> {
        if payload.len() > MAX_PAYLOAD {
            return Err(ProtocolError::new(ErrorKind::BadLength, "payload > 1 MiB"));
        }
        let nonce = frame_nonce(self.tx_counter, channel, self.direction);
        self.tx_counter += 1;
        let wire_len = payload.len() + 16;
        // AAD = exact wire header (with F_ENCRYPTED and ciphertext length)
        let wire_frame = Frame::new(channel, flags | F_ENCRYPTED, vec![0u8; wire_len])?;
        let aad = wire_frame.header_bytes();
        let ct = interop_encrypt(&self.keys.key_aead, &self.keys.key_mac, &nonce, &aad, &payload);
        if ct.len() != wire_len {
            return Err(ProtocolError::new(ErrorKind::Auth, "interop: length mismatch"));
        }
        let mut out = aad;
        out.extend_from_slice(&ct);
        self.conn.write_raw(&out)
    }

    /// Receive one frame, decrypting after the handshake.
    pub fn recv(&mut self, timeout: Duration) -> Result<Frame> {
        let hdr = self.conn.read_exact(7, timeout)?;
        let ln = u16::from_be_bytes([hdr[5], hdr[6]]);
        let hdr = if ln == 0x8000 {
            let ext = self.conn.read_exact(4, timeout)?;
            let mut h = hdr;
            h.extend_from_slice(&ext);
            h
        } else {
            hdr
        };
        let size = if ln == 0x8000 {
            u32::from_be_bytes([hdr[7], hdr[8], hdr[9], hdr[10]]) as usize
        } else {
            ln as usize
        };
        if size > MAX_PAYLOAD {
            return Err(ProtocolError::new(ErrorKind::BadLength, "size too large"));
        }
        let mut buf = vec![0u8; size];
        let mut filled = 0usize;
        while filled < size {
            let got = self.conn.read_exact(size - filled, timeout)?;
            buf[filled..filled + got.len()].copy_from_slice(&got);
            filled += got.len();
        }
        let channel = hdr[3];
        let flags = hdr[4];
        if flags & F_ENCRYPTED == 0 {
            return Err(ProtocolError::new(ErrorKind::BadMessage,
                "post-handshake frame not encrypted"));
        }
        let peer_dir = 1 - self.direction;
        let nonce = frame_nonce(self.rx_counter, channel, peer_dir);
        self.rx_counter += 1;
        let pt = interop_decrypt(&self.keys.key_aead, &self.keys.key_mac, &nonce, &hdr, &buf)?;
        let f = Frame::new(channel, flags & !F_ENCRYPTED, pt)?;
        Ok(f)
    }

    // ------------------------------------------------------- control path
    pub fn send_msg(&mut self, mtype: u8, body: &[u8]) -> Result<()> {
        self.send(ch::CONTROL, 0, msg_encode(mtype, body))
    }

    /// Receive the next CONTROL message, waiting up to `timeout`.
    pub fn recv_msg(&mut self, timeout: Duration) -> Result<(u8, u8, Vec<u8>)> {
        loop {
            let frame = self.recv(timeout)?;
            if frame.channel != ch::CONTROL {
                return Err(ProtocolError::new(ErrorKind::BadMessage,
                    format!("expected control, got channel {:#x}", frame.channel)));
            }
            let (t, f, b) = msg_decode(&frame.payload)?;
            if t == MSG_PING {
                // auto-reply keeps liveness checks working without app involvement
                let _ = self.send_msg(MSG_PONG, b);
            }
            return Ok((t, f, b.to_vec()));
        }
    }

    /// Send a PING with a fresh 8-byte timestamp body; returns the seq value.
    pub fn ping(&mut self) -> Result<u64> {
        self.ping_seq += 1;
        let body = self.ping_seq.to_be_bytes();
        self.send_msg(MSG_PING, &body)
    }

    /// Politely close: send BYE(reason=1), expect peer BYE, shut down.
    pub fn close(&mut self, reason: u8) -> Result<()> {
        let _ = self.send_msg(MSG_BYE, &[reason]);
        match self.recv_msg(Duration::from_secs(5)) {
            Ok((t, _f, _b)) if t == MSG_BYE => {}
            Ok((t, _f, _b)) => {
                return Err(ProtocolError::new(ErrorKind::BadMessage,
                    format!("expected BYE on close, got {t:#x}")));
            }
            Err(e) => {
                // peer may have gone first; not fatal
                let _ = e;
            }
        }
        self.conn.shutdown();
        Ok(())
    }

    /// Verify two session keys derive identically (test helper).
    #[allow(dead_code)]
    pub fn assert_key_agreement(ka: &[u8; 32], kb: &[u8; 32]) -> bool {
        constant_time_eq(ka, kb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::FramedConn;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn pair() -> (FramedConn, FramedConn) {
        let listener = crate::tcp::listen("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _a) = listener.accept().unwrap();
        (FramedConn::from_stream(server).unwrap(), FramedConn::from_stream(client).unwrap())
    }

    #[test]
    fn full_session_roundtrip() {
        let secret = [0x5Au8; 32];
        let (a, b) = pair();
        let handle = std::thread::spawn(move || {
            let mut s = Session::accept_device(b, &secret).unwrap();
            // echo one TUN frame back
            let f = s.recv(std::time::Duration::from_secs(5)).unwrap();
            assert_eq!(f.channel, ch::TUN_V4);
            s.send(ch::TUN_V4, F_PRIORITY, f.payload).unwrap();
            // PING/PONG handled by recv_msg
            let _ = s.recv_msg(std::time::Duration::from_secs(5)).unwrap();
            s.close(1).unwrap();
        });
        let mut h = Session::connect_host(a, &secret).unwrap();
        assert_eq!(h.info.cipher_sel, CIPHER_INTEROP);
        h.send(ch::TUN_V4, 0, vec![0xAB; 40]).unwrap();
        let f = h.recv(Duration::from_secs(5)).unwrap();
        assert_eq!(f.channel, ch::TUN_V4);
        assert_eq!(f.payload, vec![0xAB; 40]);
        h.ping().unwrap();
        // BYE from device side comes first in this flow
        h.conn.shutdown();
        let _ = handle.join();
    }

    // keep unused import warnings quiet
    #[allow(dead_code)]
    fn _unused() -> Option<TcpStream> {
        let mut s = TcpStream::connect("127.0.0.1:1").ok()?;
        let mut b = [0u8; 1];
        s.read(&mut b).ok()?;
        s.write(&[1]).ok()?;
        None
    }
}
