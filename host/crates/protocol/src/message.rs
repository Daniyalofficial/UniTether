//! ULP v1 CONTROL messages (docs/02-PROTOCOL.md section 6).

use crate::error::{ProtocolError, Result};

pub const MSG_HELLO: u8 = 0x01;
pub const MSG_HELLO_ACK: u8 = 0x02;
pub const MSG_AUTH_OK: u8 = 0x04;
pub const MSG_PING: u8 = 0x05;
pub const MSG_PONG: u8 = 0x06;
pub const MSG_CONFIG: u8 = 0x07;
pub const MSG_TUN_UP: u8 = 0x08;
pub const MSG_TUN_DOWN: u8 = 0x09;
pub const MSG_STATS_REQ: u8 = 0x0A;
pub const MSG_STATS_RSP: u8 = 0x0B;
pub const MSG_MUTE: u8 = 0x0C;
pub const MSG_QOS: u8 = 0x0D;
pub const MSG_RESUME: u8 = 0x0E;
pub const MSG_BYE: u8 = 0x0F;
pub const MSG_ERROR: u8 = 0x10;

pub const MUTE_VIDEO: u8 = 0x01;
pub const MUTE_AUDIO_IN: u8 = 0x02;
pub const MUTE_AUDIO_OUT: u8 = 0x04;
pub const MUTE_INPUT: u8 = 0x08;

// QOS profiles
pub const QOS_NONE: u8 = 0;
pub const QOS_2G: u8 = 1;
pub const QOS_3G: u8 = 2;
pub const QOS_4G: u8 = 3;
pub const QOS_5G: u8 = 4;
pub const QOS_CUSTOM: u8 = 5;

pub const ERR_AUTH_FAILED: u8 = 11;

/// Encode a control message: type, msg_flags, u16be body_len, body.
pub fn encode(mtype: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![mtype, 0x00];
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Decode a control message; returns (type, flags, body).
pub fn decode(payload: &[u8]) -> Result<(u8, u8, &[u8])> {
    if payload.len() < 4 {
        return Err(ProtocolError::new(crate::error::ErrorKind::BadMessage, "short message"));
    }
    let (mtype, flags) = (payload[0], payload[1]);
    let blen = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if payload.len() < 4 + blen {
        return Err(ProtocolError::new(crate::error::ErrorKind::BadMessage, "short body"));
    }
    Ok((mtype, flags, &payload[4..4 + blen]))
}

// ------------------------------------------------------------ CONFIG
#[derive(Debug, Clone, Default)]
pub struct TunnelConfig {
    pub v4_prefix: u8,
    pub v4_device: [u8; 4],
    pub v4_host: [u8; 4],
    pub v6_prefix: u8,
    pub v6_device: [u8; 16],
    pub v6_host: [u8; 16],
    pub dns: Vec<[u8; 4]>,
    pub routes: Vec<(u8, [u8; 4])>, // (prefix_len, network address)
}

impl TunnelConfig {
    pub fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(64);
        b.push(self.v4_prefix);
        b.extend_from_slice(&self.v4_device);
        b.extend_from_slice(&self.v4_host);
        b.push(self.v6_prefix);
        if self.v6_prefix > 0 {
            b.extend_from_slice(&self.v6_device);
            b.extend_from_slice(&self.v6_host);
        }
        b.extend_from_slice(&(self.dns.len() as u16).to_be_bytes());
        for d in &self.dns { b.extend_from_slice(d); }
        b.extend_from_slice(&(self.routes.len() as u16).to_be_bytes());
        for (p, a) in &self.routes { b.push(*p); b.extend_from_slice(a); }
        b
    }

    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut off = 0usize;
        let take = |n: usize| -> Result<&[u8]> {
            if body.len() < off + n {
                return Err(ProtocolError::new(
                    crate::error::ErrorKind::BadPayload, "config: short"));
            }
            let r = &body[off..off + n];
            off += n;
            Ok(r)
        };
        let mut c = TunnelConfig::default();
        c.v4_prefix = *take(1)?[0] as u8;
        c.v4_device = take(4)?[..].try_into().unwrap();
        c.v4_host = take(4)?[..].try_into().unwrap();
        c.v6_prefix = *take(1)?[0] as u8;
        if c.v6_prefix > 0 {
            c.v6_device = take(16)?[..].try_into().unwrap();
            c.v6_host = take(16)?[..].try_into().unwrap();
        }
        let dns_count = u16::from_be_bytes(take(2)?[..].try_into().unwrap()) as usize;
        for _ in 0..dns_count {
            let d: [u8; 4] = take(4)?[..].try_into().unwrap();
            c.dns.push(d);
        }
        let route_count = u16::from_be_bytes(take(2)?[..].try_into().unwrap()) as usize;
        for _ in 0..route_count {
            let p = *take(1)?[0] as u8;
            let a: [u8; 4] = take(4)?[..].try_into().unwrap();
            c.routes.push((p, a));
        }
        Ok(c)
    }
}

// ------------------------------------------------------------ STATS
pub const STATS_SIZE: usize = 104;

#[derive(Debug, Clone, Default)]
pub struct StatCounters {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub pkts_in: u64,
    pub pkts_out: u64,
    pub bytes_video: u64,
    pub bytes_audio: u64,
    pub bytes_file: u64,
    pub drops: u64,
    pub errors: u64,
    pub frames_video: u64,
    pub rtt_ms: u32,
    pub loss_pct_x100: u32,
    pub cpu_pct_x100: u32,
    pub fps_video: u32,
    pub audio_level: u32,
}

impl StatCounters {
    pub fn body(&self) -> [u8; STATS_SIZE] {
        let mut b = [0u8; STATS_SIZE];
        let u64s = [self.bytes_in, self.bytes_out, self.pkts_in, self.pkts_out,
            self.bytes_video, self.bytes_audio, self.bytes_file, self.drops,
            self.errors, self.frames_video];
        for (i, v) in u64s.iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_be_bytes());
        }
        let u32s = [self.rtt_ms, self.loss_pct_x100, self.cpu_pct_x100,
            self.fps_video, self.audio_level, 0];
        for (i, v) in u32s.iter().enumerate() {
            b[80 + i * 4..80 + i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }
        b
    }

    pub fn parse(body: &[u8]) -> Result<Self> {
        if body.len() != STATS_SIZE {
            return Err(ProtocolError::new(
                crate::error::ErrorKind::BadPayload,
                format!("stats: bad length {}", body.len())));
        }
        let u64 = |o: usize| u64::from_be_bytes(body[o..o + 8].try_into().unwrap());
        let u32 = |o: usize| u32::from_be_bytes(body[o..o + 4].try_into().unwrap());
        Ok(Self {
            bytes_in: u64(0), bytes_out: u64(8), pkts_in: u64(16), pkts_out: u64(24),
            bytes_video: u64(32), bytes_audio: u64(40), bytes_file: u64(48),
            drops: u64(56), errors: u64(64), frames_video: u64(72),
            rtt_ms: u32(80), loss_pct_x100: u32(84), cpu_pct_x100: u32(88),
            fps_video: u32(92), audio_level: u32(96),
        })
    }
}

// ------------------------------------------------------------ QOS
#[derive(Debug, Clone, Copy)]
pub struct QosParams {
    pub profile: u8,
    pub up_kbps: u32,
    pub down_kbps: u32,
    pub latency_ms: u16,
    pub jitter_ms: u8,
    pub loss_pct: u8,
}

impl QosParams {
    pub fn body(&self) -> [u8; 13] {
        let mut b = [0u8; 13];
        b[0] = self.profile;
        b[1..5].copy_from_slice(&self.up_kbps.to_be_bytes());
        b[5..9].copy_from_slice(&self.down_kbps.to_be_bytes());
        b[9..11].copy_from_slice(&self.latency_ms.to_be_bytes());
        b[11] = self.jitter_ms;
        b[12] = self.loss_pct;
        b
    }

    pub fn parse(body: &[u8]) -> Result<Self> {
        if body.len() != 13 {
            return Err(ProtocolError::new(
                crate::error::ErrorKind::BadPayload, "qos: bad length"));
        }
        Ok(Self {
            profile: body[0],
            up_kbps: u32::from_be_bytes(body[1..5].try_into().unwrap()),
            down_kbps: u32::from_be_bytes(body[5..9].try_into().unwrap()),
            latency_ms: u16::from_be_bytes(body[9..11].try_into().unwrap()),
            jitter_ms: body[11],
            loss_pct: body[12],
        })
    }

    /// Built-in profiles (docs/02-PROTOCOL.md section 7.4).
    pub fn from_profile(profile: u8) -> Self {
        match profile {
            QOS_2G => Self { profile, up_kbps: 384, down_kbps: 768, latency_ms: 120, jitter_ms: 20, loss_pct: 2 },
            QOS_3G => Self { profile, up_kbps: 3000, down_kbps: 5000, latency_ms: 40, jitter_ms: 10, loss_pct: 1 },
            QOS_4G => Self { profile, up_kbps: 30000, down_kbps: 50000, latency_ms: 15, jitter_ms: 5, loss_pct: 0 },
            QOS_5G => Self { profile, up_kbps: u32::MAX / 8, down_kbps: u32::MAX / 8, latency_ms: 5, jitter_ms: 2, loss_pct: 0 },
            other => Self { profile: other, up_kbps: 0, down_kbps: 0, latency_ms: 0, jitter_ms: 0, loss_pct: 0 },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_roundtrip() {
        let w = encode(MSG_PING, &42u64.to_be_bytes());
        let (t, _f, b) = decode(&w).unwrap();
        assert_eq!(t, MSG_PING);
        assert_eq!(u64::from_be_bytes(b.try_into().unwrap()), 42);
    }

    #[test]
    fn config_roundtrip() {
        let mut c = TunnelConfig::default();
        c.v4_prefix = 20;
        c.v4_device = [10, 8, 0, 2];
        c.v4_host = [10, 8, 0, 1];
        c.v6_prefix = 64;
        c.v6_device = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        c.v6_host = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        c.dns.push([1, 1, 1, 1]);
        c.routes.push((0, [0, 0, 0, 0]));
        c.routes.push((64, [0, 0, 0, 0]));
        let p = TunnelConfig::parse(&c.body()).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn stats_roundtrip() {
        let s = StatCounters {
            bytes_in: 1, bytes_out: 2, pkts_in: 3, pkts_out: 4,
            bytes_video: 5, bytes_audio: 6, bytes_file: 7, drops: 8,
            errors: 9, frames_video: 10, rtt_ms: 11, loss_pct_x100: 12,
            cpu_pct_x100: 13, fps_video: 14, audio_level: 15,
        };
        let b = s.body();
        assert_eq!(b.len(), 104);
        let p = StatCounters::parse(&b).unwrap();
        assert_eq!(p.fps_video, 14);
        assert_eq!(p.rtt_ms, 11);
        assert_eq!(p.bytes_in, 1);
    }

    #[test]
    fn qos_roundtrip() {
        let q = QosParams::from_profile(QOS_4G);
        let p = QosParams::parse(&q.body()).unwrap();
        assert_eq!(p.profile, QOS_4G);
        assert_eq!(p.up_kbps, 30000);
    }
}
