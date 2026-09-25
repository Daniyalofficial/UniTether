//! Pairing blob: `UNITETHER1:` + base64url(secret, 32 B) + `|` + name (<=32 B).

use crate::error::{ProtocolError, Result};

pub const BLOB_PREFIX: &str = "UNITETHER1:";
const MAX_NAME: usize = 32;

const ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url encode WITH '=' padding (matches Python base64.urlsafe_b64encode).
pub fn base64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a') as u32 + 26),
        b'0'..=b'9' => Some((c - b'0') as u32 + 52),
        b'-' | b'+' => Some(62),
        b'_' | b'/' => Some(63),
        _ => None,
    }
}

/// Base64url decode; accepts url-safe or standard alphabet, with or without
/// trailing '=' padding.
pub fn base64url_decode(s: &str) -> Result<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut n = bytes.len();
    while n > 0 && bytes[n - 1] == b'=' { n -= 1; }
    if n % 4 == 1 {
        return Err(ProtocolError::new(crate::error::ErrorKind::BadPayload,
            "base64: invalid length"));
    }
    let mut out = Vec::with_capacity(n * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in &bytes[..n] {
        let v = val(c).ok_or_else(|| ProtocolError::new(
            crate::error::ErrorKind::BadPayload,
            format!("base64: bad char 0x{c:02x}")))?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

pub fn pairing_blob(secret: &[u8; 32], name: &str) -> String {
    let name_bytes = name.as_bytes();
    let name = std::str::from_utf8(&name_bytes[..name_bytes.len().min(MAX_NAME)]).unwrap_or("");
    format!("{BLOB_PREFIX}{}|{}", base64url_encode(secret), name)
}

pub fn pairing_parse(blob: &str) -> Result<([u8; 32], String)> {
    let rest = blob.strip_prefix(BLOB_PREFIX).ok_or_else(|| {
        ProtocolError::new(crate::error::ErrorKind::BadPayload, "pairing: bad prefix")
    })?;
    let (b64, name) = match rest.find('|') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    let secret = base64url_decode(b64)?;
    if secret.len() != 32 {
        return Err(ProtocolError::new(crate::error::ErrorKind::BadPayload,
            "pairing: secret must be 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&secret);
    Ok((out, name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_roundtrip() {
        for len in 0..=40 {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let enc = base64url_encode(&data);
            let dec = base64url_decode(&enc).unwrap();
            assert_eq!(dec, data, "len {len}");
        }
    }

    #[test]
    fn known_vector() {
        // Python: base64.urlsafe_b64encode(b"unilink pairing secret 32B!")
        let s = b"unilink pairing secret 32B!";
        let enc = base64url_encode(s);
        assert_eq!(enc, "dW5pbGluayBwYWlyaW5nIHNlY3JldCAzMkIh");
        assert_eq!(base64url_decode(&enc).unwrap(), s.to_vec());
    }

    #[test]
    fn blob_roundtrip() {
        let secret = [0xA5u8; 32];
        let blob = pairing_blob(&secret, "Pixel 8");
        let (s, name) = pairing_parse(&blob).unwrap();
        assert_eq!(s, secret);
        assert_eq!(name, "Pixel 8");
    }
}
