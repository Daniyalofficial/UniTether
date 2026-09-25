//! ULP v1 frame format (docs/02-PROTOCOL.md section 2-4).
//!
//! ```text
//! base header  (7 bytes): magic0 magic1 version channel flags length(u16)
//! extended     (11 bytes): ... length==0x8000 -> u32be length follows
//! ```

use crate::error::{ProtocolError, Result};

pub const MAGIC0: u8 = 0x55;
pub const MAGIC1: u8 = 0x4C;
pub const VERSION: u8 = 0x01;
pub const MAX_PAYLOAD: usize = 0x0010_0000; // 1 MiB

// ------------------------------------------------------------ channels
pub mod ch {
    pub const CONTROL: u8 = 0x00;
    pub const VIDEO: u8 = 0x01;
    pub const AUDIO_IN: u8 = 0x02;
    pub const AUDIO_OUT: u8 = 0x03;
    pub const INPUT: u8 = 0x04;
    pub const FILE: u8 = 0x05;
    pub const CLIPBOARD: u8 = 0x06;
    pub const NOTIFICATION: u8 = 0x07;
    pub const STATS: u8 = 0x08;
    pub const TUN_V4: u8 = 0x09;
    pub const TUN_V6: u8 = 0x0A;
    pub const PROXY: u8 = 0x0B;
    pub const CAMERA: u8 = 0x0C;
    pub const USER: u8 = 0x0D;
}

// --------------------------------------------------------------- flags
pub const F_COMPRESSED: u8 = 0x01;
pub const F_ENCRYPTED: u8 = 0x02;
pub const F_FRAG: u8 = 0x04;
pub const F_PRIORITY: u8 = 0x08;
pub const F_ACK: u8 = 0x10;

#[derive(Debug, Clone)]
pub struct Frame {
    pub channel: u8,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(channel: u8, flags: u8, payload: Vec<u8>) -> Result<Self> {
        if payload.len() > MAX_PAYLOAD {
            return Err(ProtocolError::new(crate::error::ErrorKind::BadLength,
                "payload exceeds 1 MiB"));
        }
        Ok(Self { channel, flags, payload })
    }

    /// Full wire header (7 or 11 bytes) for the frame as sent.
    pub fn header_bytes(&self) -> Vec<u8> {
        let mut h = vec![MAGIC0, MAGIC1, VERSION, self.channel, self.flags];
        let n = self.payload.len();
        if n >= 0x8000 {
            h.extend_from_slice(&0x8000u16.to_be_bytes());
            h.extend_from_slice(&(n as u32).to_be_bytes());
        } else {
            h.extend_from_slice(&(n as u16).to_be_bytes());
        }
        h
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.header_bytes();
        out.extend_from_slice(&self.payload);
        out
    }
}

/// Decode one frame from `data` at `off`. Returns (frame, new_off).
pub fn decode(data: &[u8], off: usize) -> Result<(Frame, usize)> {
    if data.len() - off < 7 {
        return Err(ProtocolError::new(crate::error::ErrorKind::Incomplete, "short header"));
    }
    let d = |i: usize| data[off + i];
    if d(0) != MAGIC0 || d(1) != MAGIC1 {
        return Err(ProtocolError::new(crate::error::ErrorKind::BadMagic,
            format!("magic {:02x}{:02x}", d(0), d(1))));
    }
    if d(2) != VERSION {
        return Err(ProtocolError::new(crate::error::ErrorKind::BadVersion,
            format!("version {}", d(2))));
    }
    let (channel, flags) = (d(3), d(4));
    let ln = u16::from_be_bytes([d(5), d(6)]);
    let (size, header_len) = if ln < 0x8000 {
        (ln as usize, 7)
    } else if ln == 0x8000 {
        if data.len() - off < 11 {
            return Err(ProtocolError::new(crate::error::ErrorKind::Incomplete,
                "short extended length"));
        }
        let ext = u32::from_be_bytes([d(7), d(8), d(9), d(10)]) as usize;
        if ext > MAX_PAYLOAD {
            return Err(ProtocolError::new(crate::error::ErrorKind::BadLength,
                "extended length too large"));
        }
        (ext, 11)
    } else {
        return Err(ProtocolError::new(crate::error::ErrorKind::BadLength,
            format!("invalid length field {ln:04x}")));
    };
    if data.len() - off < header_len + size {
        return Err(ProtocolError::new(crate::error::ErrorKind::Incomplete,
            "incomplete frame"));
    }
    let payload = data[off + header_len..off + header_len + size].to_vec();
    let frame = Frame { channel, flags, payload };
    Ok((frame, off + header_len + size))
}

/// 12-byte AEAD nonce: u64be(dir bit || counter) || u32be(channel).
pub fn frame_nonce(counter: u64, channel: u8, direction: u8) -> [u8; 12] {
    let hi = ((direction & 1) as u64) << 63 | (counter & ((1 << 63) - 1));
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&hi.to_be_bytes());
    n[8..12].copy_from_slice(&(channel as u32).to_be_bytes());
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_small() {
        let f = Frame::new(ch::TUN_V4, 0, vec![0xAB; 40]).unwrap();
        let wire = f.encode();
        let (d, off) = decode(&wire, 0).unwrap();
        assert_eq!(off, wire.len());
        assert_eq!(d.channel, ch::TUN_V4);
        assert_eq!(d.payload, vec![0xAB; 40]);
    }

    #[test]
    fn roundtrip_extended() {
        let f = Frame::new(ch::VIDEO, F_PRIORITY, vec![0xCD; 50_000]).unwrap();
        let wire = f.encode();
        assert_eq!(&wire[5..7], &0x8000u16.to_be_bytes());
        let (d, _) = decode(&wire, 0).unwrap();
        assert_eq!(d.payload.len(), 50_000);
        assert_eq!(d.flags, F_PRIORITY);
    }

    #[test]
    fn reject_bad_magic() {
        let mut w = Frame::new(ch::CONTROL, 0, b"hi".to_vec()).unwrap().encode();
        w[0] = 0x54;
        assert!(decode(&w, 0).is_err());
    }

    #[test]
    fn reject_bad_extended() {
        let mut w = Frame::new(ch::CONTROL, 0, b"hi".to_vec()).unwrap().encode();
        w[5] = 0x80; w[6] = 0x01;
        assert!(decode(&w, 0).is_err());
    }

    #[test]
    fn back_to_back() {
        let a = Frame::new(ch::TUN_V4, 0, b"one".to_vec()).unwrap().encode();
        let b = Frame::new(ch::TUN_V6, 0, b"two".to_vec()).unwrap().encode();
        let mut all = a.clone();
        all.extend_from_slice(&b);
        let (f1, o1) = decode(&all, 0).unwrap();
        let (f2, o2) = decode(&all, o1).unwrap();
        assert_eq!(f1.payload, b"one");
        assert_eq!(f2.payload, b"two");
        assert_eq!(o2, all.len());
    }

    #[test]
    fn nonce_layout() {
        let n = frame_nonce(7, ch::TUN_V4, 0);
        assert_eq!(&n[8..], &0x0000_0009u32.to_be_bytes());
        let n2 = frame_nonce(7, ch::TUN_V4, 1);
        assert_eq!(n2[0], 0x80);
    }
}
