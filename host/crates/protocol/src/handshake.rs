//! ULP v1 handshake (docs/02-PROTOCOL.md section 7.1-7.2).
//!
//! ```text
//! host                                    device
//!   |--- HELLO (84B, pairing-mac) --------->
//!   |<-- HELLO_ACK (83B, pairing-mac) -----
//!   |--- AUTH_OK (plaintext) -------------->
//!   |<-- AUTH_OK (plaintext) --------------
//!   |== all further frames ENCRYPTED ==
//! ```

use crate::crypto::{hmac_sha256, x25519, constant_time_eq};
use crate::error::{ProtocolError, Result};

pub const AUTH_INFO: &[u8] = b"unilink-auth-v1";
pub const HKDF_INFO: &[u8] = b"unilink-v1";

pub const ROLE_HOST: u8 = 0;
pub const ROLE_DEVICE: u8 = 1;

pub const FEAT_DUAL_STACK: u16 = 1 << 0;
pub const FEAT_VIDEO: u16 = 1 << 1;
pub const FEAT_AUDIO: u16 = 1 << 2;
pub const FEAT_INPUT: u16 = 1 << 3;
pub const FEAT_PROD: u16 = 1 << 4;
pub const FEAT_PROXY: u16 = 1 << 5;
pub const FEAT_CAMERA: u16 = 1 << 6;
pub const FEAT_QOS: u16 = 1 << 7;

pub const CIPHER_NONE: u8 = 0;      // handshake frames only
pub const CIPHER_INTEROP: u8 = 1;   // conformance profile (std-only)
pub const CIPHER_AESGCM: u8 = 2;
pub const CIPHER_CHACHA: u8 = 3;

pub const HELLO_BODY_LEN: usize = 84;
pub const HELLO_ACK_BODY_LEN: usize = 83;

/// HELLO body: role(1) feature_mask(u16be) cipher_pref(1)
///             ecdh_pub(32) nonce_a(16) mac(32)
#[derive(Debug, Clone, PartialEq)]
pub struct Hello {
    pub role: u8,
    pub feature_mask: u16,
    pub cipher_pref: u8,
    pub ecdh_pub: [u8; 32],
    pub nonce_a: [u8; 16],
    pub mac: [u8; 32],
}

impl Hello {
    pub fn pairing_mac(secret: &[u8], ecdh_pub: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
        let mut input = Vec::with_capacity(80);
        input.extend_from_slice(AUTH_INFO);
        input.extend_from_slice(ecdh_pub);
        input.extend_from_slice(nonce);
        hmac_sha256(secret, &input)
    }

    pub fn build(role: u8, feature_mask: u16, cipher_pref: u8,
                 ecdh_pub: [u8; 32], nonce_a: [u8; 16], secret: &[u8]) -> Self {
        let mac = Self::pairing_mac(secret, &ecdh_pub, &nonce_a);
        Self { role, feature_mask, cipher_pref, ecdh_pub, nonce_a, mac }
    }

    pub fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(HELLO_BODY_LEN);
        b.push(self.role);
        b.extend_from_slice(&self.feature_mask.to_be_bytes());
        b.push(self.cipher_pref);
        b.extend_from_slice(&self.ecdh_pub);
        b.extend_from_slice(&self.nonce_a);
        b.extend_from_slice(&self.mac);
        b
    }

    pub fn parse(body: &[u8]) -> Result<Self> {
        if body.len() != HELLO_BODY_LEN {
            return Err(ProtocolError::new(crate::error::ErrorKind::BadPayload,
                format!("hello: bad length {}", body.len())));
        }
        Ok(Self {
            role: body[0],
            feature_mask: u16::from_be_bytes([body[1], body[2]]),
            cipher_pref: body[3],
            ecdh_pub: body[4..36].try_into().unwrap(),
            nonce_a: body[36..52].try_into().unwrap(),
            mac: body[52..84].try_into().unwrap(),
        })
    }

    pub fn verify(&self, secret: &[u8]) -> Result<()> {
        let expect = Self::pairing_mac(secret, &self.ecdh_pub, &self.nonce_a);
        if !constant_time_eq(&expect, &self.mac) {
            return Err(ProtocolError::new(crate::error::ErrorKind::Auth,
                "hello: pairing mac mismatch"));
        }
        Ok(())
    }
}

/// HELLO_ACK body: negotiated(u16be) cipher_sel(1)
///                 ecdh_pub(32) nonce_b(16) mac(32)
#[derive(Debug, Clone, PartialEq)]
pub struct HelloAck {
    pub negotiated: u16,
    pub cipher_sel: u8,
    pub ecdh_pub: [u8; 32],
    pub nonce_b: [u8; 16],
    pub mac: [u8; 32],
}

impl HelloAck {
    fn mac_for(secret: &[u8], ecdh_pub: &[u8; 32], nonce_b: &[u8; 16], nonce_a: &[u8; 16]) -> [u8; 32] {
        let mut input = Vec::with_capacity(96);
        input.extend_from_slice(AUTH_INFO);
        input.extend_from_slice(ecdh_pub);
        input.extend_from_slice(nonce_b);
        input.extend_from_slice(nonce_a);
        hmac_sha256(secret, &input)
    }

    pub fn build(negotiated: u16, cipher_sel: u8, ecdh_pub: [u8; 32],
                 nonce_b: [u8; 16], nonce_a: [u8; 16], secret: &[u8]) -> Self {
        let mac = Self::mac_for(secret, &ecdh_pub, &nonce_b, &nonce_a);
        Self { negotiated, cipher_sel, ecdh_pub, nonce_b, mac }
    }

    pub fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(HELLO_ACK_BODY_LEN);
        b.extend_from_slice(&self.negotiated.to_be_bytes());
        b.push(self.cipher_sel);
        b.extend_from_slice(&self.ecdh_pub);
        b.extend_from_slice(&self.nonce_b);
        b.extend_from_slice(&self.mac);
        b
    }

    pub fn parse(body: &[u8]) -> Result<Self> {
        if body.len() != HELLO_ACK_BODY_LEN {
            return Err(ProtocolError::new(crate::error::ErrorKind::BadPayload,
                format!("hello_ack: bad length {}", body.len())));
        }
        Ok(Self {
            negotiated: u16::from_be_bytes([body[0], body[1]]),
            cipher_sel: body[2],
            ecdh_pub: body[3..35].try_into().unwrap(),
            nonce_b: body[35..51].try_into().unwrap(),
            mac: body[51..83].try_into().unwrap(),
        })
    }

    pub fn verify(&self, secret: &[u8], nonce_a: &[u8; 16]) -> Result<()> {
        let expect = Self::mac_for(secret, &self.ecdh_pub, &self.nonce_b, nonce_a);
        if !constant_time_eq(&expect, &self.mac) {
            return Err(ProtocolError::new(crate::error::ErrorKind::Auth,
                "hello_ack: pairing mac mismatch"));
        }
        Ok(())
    }
}

/// Session keys: HKDF-SHA256(ikm=X25519 shared, salt=nonce_a||nonce_b,
/// info="unilink-v1"||u8(cipher), L=64) -> (key_aead, key_mac).
#[derive(Debug, Clone, PartialEq)]
pub struct SessionKeys {
    pub key_aead: [u8; 32],
    pub key_mac: [u8; 32],
}

pub fn derive_session_keys(shared: &[u8; 32], nonce_a: &[u8; 16],
                           nonce_b: &[u8; 16], cipher_sel: u8) -> SessionKeys {
    let salt = {
        let mut s = Vec::with_capacity(32);
        s.extend_from_slice(nonce_a);
        s.extend_from_slice(nonce_b);
        s
    };
    let info = {
        let mut i = HKDF_INFO.to_vec();
        i.push(cipher_sel);
        i
    };
    let keys = crate::crypto::hkdf_sha256(shared, &salt, &info, 64);
    let mut key_aead = [0u8; 32];
    let mut key_mac = [0u8; 32];
    key_aead.copy_from_slice(&keys[0..32]);
    key_mac.copy_from_slice(&keys[32..64]);
    SessionKeys { key_aead, key_mac }
}

/// Convenience: full derivation (both roles call the same fn).
///
/// `secret` (the pairing secret) is part of the API for symmetry with the
/// reference implementation, but the KDF input is ECDH-only — the pairing
/// secret authenticates the HELLO/HELLO_ACK MACs, not the session keys
/// (spec: keys = HKDF(X25519, nonce_a||nonce_b, "unilink-v1"||cipher)).
pub fn derive(_secret: &[u8], priv_key: &[u8; 32], peer_pub: &[u8; 32],
              nonce_a: &[u8; 16], nonce_b: &[u8; 16], cipher_sel: u8) -> SessionKeys {
    let shared = x25519(priv_key, peer_pub);
    derive_session_keys(&shared, nonce_a, nonce_b, cipher_sel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrip_and_verify() {
        let secret = [0x42u8; 32];
        let nonce = [7u8; 16];
        let h = Hello::build(ROLE_HOST, FEAT_DUAL_STACK | FEAT_VIDEO,
            CIPHER_INTEROP, [1u8; 32], nonce, &secret);
        let b = h.body();
        assert_eq!(b.len(), 84);
        let p = Hello::parse(&b).unwrap();
        assert_eq!(p, h);
        p.verify(&secret).unwrap();
        assert!(p.verify(&[0x43; 32]).is_err());
    }

    #[test]
    fn hello_ack_roundtrip_and_verify() {
        let secret = [0x99u8; 32];
        let nonce_a = [1u8; 16];
        let nonce_b = [2u8; 16];
        let a = HelloAck::build(0x00FF, CIPHER_INTEROP, [3u8; 32], nonce_b, nonce_a, &secret);
        let b = a.body();
        assert_eq!(b.len(), 83);
        let p = HelloAck::parse(&b).unwrap();
        p.verify(&secret, &nonce_a).unwrap();
        assert!(p.verify(&secret, &[9u8; 16]).is_err());
        assert!(p.verify(&[0x43; 32], &nonce_a).is_err());
    }

    #[test]
    fn both_roles_derive_same_keys() {
        let secret = [0x11u8; 32];
        let priv_h = [5u8; 32];
        let priv_d = [9u8; 32];
        let pub_h = crate::crypto::x25519_public(&priv_h);
        let pub_d = crate::crypto::x25519_public(&priv_d);
        let nonce_a = [0xAA; 16];
        let nonce_b = [0xBB; 16];
        let kh = derive(&secret, &priv_h, &pub_d, &nonce_a, &nonce_b, CIPHER_INTEROP);
        let kd = derive(&secret, &priv_d, &pub_h, &nonce_a, &nonce_b, CIPHER_INTEROP);
        assert_eq!(kh, kd);
    }
}
