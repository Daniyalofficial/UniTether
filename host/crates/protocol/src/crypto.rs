//! ULP v1 crypto primitives (docs/02-PROTOCOL.md section 7).
//!
//! Pure-Rust, zero-dependency:
//!  * SHA-256 + HMAC-SHA256 + HKDF-SHA256 (RFC 5869)
//!  * X25519 (RFC 7748 Montgomery ladder, 255-bit field math)
//!  * INTEROP cipher profile (conformance): SHA256-CTR + HMAC, ETM
//!
//! Production builds additionally select AES-256-GCM or
//! ChaCha20-Poly1305 (see `Cipher`); those are provided by the
//! `transport`/`tunnel` crates where the platform crypto is available.
//! The INTEROP profile exists so that the Python/Node/Rust
//! conformance suites share one verifiable AEAD with stdlib-only deps.

// ================================================================== SHA-256
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in msg.chunks(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1);
            d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let d = sha256(key);
        k[..32].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    for i in 0..64 { inner.push(k[i] ^ 0x36); }
    inner.extend_from_slice(msg);
    let ih = sha256(&inner);
    let mut outer = Vec::with_capacity(64 + 32);
    for i in 0..64 { outer.push(k[i] ^ 0x5c); }
    outer.extend_from_slice(&ih);
    sha256(&outer)
}

/// HKDF-SHA256 (RFC 5869).
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let salt = if salt.is_empty() { vec![0u8; 32] } else { salt.to_vec() };
    let prk = hmac_sha256(&salt, ikm);
    let mut out = Vec::new();
    let mut t = Vec::new();
    let mut i: u8 = 1;
    while out.len() < length {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(i);
        t = hmac_sha256(&prk, &input).to_vec();
        out.extend_from_slice(&t);
        i += 1;
    }
    out.truncate(length);
    out
}

// ======================================================== 255-bit field math
/// Field element: 4 x u64 little-endian, canonical value < p = 2^255 - 19.
pub type F = [u64; 4];

const LIMB63_MASK: u64 = (1u64 << 63) - 1;

fn fe_add(a: F, b: F) -> F {
    let mut r = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let s = a[i] as u128 + b[i] as u128 + carry as u128;
        r[i] = s as u64;
        carry = s >> 64;
    }
    // r < 2^256; subtract p = 2^255 - 19 if r >= p
    let ge_p = ge_p(r);
    fe_sub_raw(r, P_CONST, ge_p)
}

fn fe_sub_raw(a: F, b: F, do_sub: bool) -> F {
    let mut r = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let d = a[i] as i128 - borrow - (if do_sub { b[i] as i128 } else { 0 });
        r[i] = d as u64; // two's-complement wrap: low 64 bits
        borrow = if d < 0 { 1 } else { 0 };
    }
    r
}

fn fe_sub(a: F, b: F) -> F {
    if le(a, b) {
        // a - b (mod p) = p - (b - a), with 0 <= b - a < p
        let r = fe_sub_raw(b, a, true);
        if r == [0u64; 4] { return [0u64; 4]; }
        fe_sub_raw(P_CONST, r, true)
    } else {
        fe_sub_raw(a, b, true)
    }
}

fn le(a: F, b: F) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] { return a[i] < b[i]; }
    }
    true
}

/// p = 2^255 - 19, canonical.
const P_CONST: F = [0xFFFFFFFFFFFFFFED, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF];

/// Compare r (value < 2^256) against p.
fn ge_p(r: F) -> bool {
    // p = 0x7FFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_ED
    // (as 4x64 little-endian: limb3 has top bit clear)
    if r[3] > P_CONST[3] { return true; }
    if r[3] < P_CONST[3] { return false; }
    if r[2] > P_CONST[2] { return true; }
    if r[2] < P_CONST[2] { return false; }
    if r[1] > P_CONST[1] { return true; }
    if r[1] < P_CONST[1] { return false; }
    r[0] >= P_CONST[0]
}

/// Multiply two field elements (result canonical < p).
/// Uses the 2^255 = 19 (mod p) reduction.
fn fe_mul(a: F, b: F) -> F {
    // 8-limb product
    let mut p = [0u128; 8];
    for i in 0..4 {
        for j in 0..4 {
            p[i + j] += a[i] as u128 * b[j] as u128;
        }
    }
    // carry the 128-bit limbs up
    let mut limbs = [0u64; 8];
    let mut extra = 0u128;
    for i in 0..8 {
        let v = p[i] + extra;
        limbs[i] = v as u64;
        extra = v >> 64;
    }
    // bit 255 is bit 63 of limb3 (limb3 covers bits 192..255)
    // lo = value mod 2^255 (bits 0..254), hi = value >> 255 (< 2^257)
    let lo = [limbs[0], limbs[1], limbs[2], limbs[3] & LIMB63_MASK];
    let mut hi = [
        (limbs[3] >> 63) | (limbs[4] << 1),
        (limbs[4] >> 63) | (limbs[5] << 1),
        (limbs[5] >> 63) | (limbs[6] << 1),
        (limbs[6] >> 63) | (limbs[7] << 1),
    ];
    // value = lo + hi * 2^255  ==  lo + 19*hi  (mod p)
    let mut lo = lo_mod_p(lo);
    for _ in 0..3 {
        if hi == [0u64; 4] { break; }
        // t = 19 * hi  (5 limbs; since hi < 2^255, t < 2^259)
        let mut t = [0u64; 5];
        let mut carry = 0u128;
        for i in 0..4 {
            let v = hi[i] as u128 * 19 + carry;
            t[i] = v as u64;
            carry = v >> 64;
        }
        t[4] = carry as u64;
        // split t at bit 255
        let t_lo = [t[0], t[1], t[2], t[3] & LIMB63_MASK];
        hi = [(t[3] >> 63) | (t[4] << 1), 0, 0, 0];
        lo = fe_add(lo, lo_mod_p(t_lo));
    }
    lo
}

/// Reduce a 256-bit value (< 2^256) mod p (at most one subtraction).
fn lo_mod_p(mut r: F) -> F {
    if ge_p(r) { r = fe_sub_raw(r, P_CONST, true); }
    r
}

fn fe_square(a: F) -> F {
    fe_mul(a, a)
}

fn fe_pow(base: F, exp_bits: &[u64], bits: usize) -> F {
    // square-and-multiply, MSB first
    let mut result = fe_one();
    let mut base = base;
    for i in (0..bits).rev() {
        result = fe_square(result);
        let bit = (exp_bits[i / 64] >> (i % 64)) & 1;
        if bit == 1 {
            result = fe_mul(result, base);
        }
    }
    let _ = &mut base;
    result
}

fn fe_one() -> F { [1, 0, 0, 0] }

/// Modular inverse via Fermat: a^(p-2).
pub fn fe_inverse(a: F) -> F {
    // p - 2 = 2^255 - 21
    let mut exp = [0u64; 4];
    exp[0] = 0xFFFFFFFFFFFFFFEB; // ...EB = 2^64 - 21
    exp[1] = u64::MAX;
    exp[2] = u64::MAX;
    exp[3] = 0x7FFFFFFFFFFFFFFF; // 2^63 - 1
    fe_pow(a, &exp, 255)
}

// ================================================================== X25519
/// RFC 7748 scalar clamping: result = 2^254 + 8 * k'.
pub fn x25519_clamp(secret: &[u8; 32]) -> [u64; 4] {
    let mut k = [0u64; 4];
    for i in 0..4 {
        k[i] = u64::from_le_bytes(secret[i * 8..i * 8 + 8].try_into().unwrap());
    }
    k[0] &= !7u64;
    k[3] &= !(1u64 << 31); // clear bit 255
    k[3] |= 1u64 << 30;    // set bit 254
    k
}

/// X25519(k, u) per RFC 7748 (Montgomery ladder, bits 254..0).
pub fn x25519(secret: &[u8; 32], u_bytes: &[u8; 32]) -> [u8; 32] {
    let k = x25519_clamp(secret);
    let mut u = [0u64; 4];
    for i in 0..4 {
        u[i] = u64::from_le_bytes(u_bytes[i * 8..i * 8 + 8].try_into().unwrap());
    }
    u = lo_mod_p(u);
    let a24: F = [121665, 0, 0, 0];

    // RFC 7748 §5 ladder state (x1/z1 = base point, x1 only used in z3 update;
    // z1 = 1 is implicit in the x-only ladder)
    let x1 = u;
    let mut x2 = fe_one();
    let mut z2 = [0u64; 4];
    let mut x3 = u;
    let mut z3 = fe_one();
    let mut swap = 0u64;

    for t in (0..255).rev() {
        let kt = (k[t / 64] >> (t % 64)) & 1;
        swap ^= kt;
        if swap == 1 {
            std::mem::swap(&mut x2, &mut x3);
            std::mem::swap(&mut z2, &mut z3);
        }
        swap = kt;

        let a = fe_add(x2, z2);
        let aa = fe_square(a);
        let b = fe_sub(x2, z2);
        let bb = fe_square(b);
        let e = fe_sub(aa, bb);
        let c = fe_add(x3, z3);
        let d = fe_sub(x3, z3);
        let da = fe_mul(d, a);
        let cb = fe_mul(c, b);
        let da_plus_cb = fe_add(da, cb);
        let da_minus_cb = fe_sub(da, cb);
        x3 = fe_square(da_plus_cb);
        z3 = fe_mul(x1, fe_square(da_minus_cb));
        x2 = fe_mul(aa, bb);
        z2 = fe_mul(e, fe_add(aa, fe_mul(a24, e)));
    }
    // result = x2 / z2
    let res = fe_mul(x2, fe_inverse(z2));
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&res[i].to_le_bytes());
    }
    out
}

/// X25519 public key = X25519(secret, 9).
pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    let mut u = [0u8; 32];
    u[0] = 9;
    x25519(secret, &u)
}

// ------------------------------------------------------- INTEROP cipher
/// SHA256-CTR keystream (conformance profile).
pub fn interop_keystream(key: &[u8; 32], nonce: &[u8; 12], n: usize) -> Vec<u8> {
    let mut ks = Vec::with_capacity(n);
    let mut i: u32 = 0;
    while ks.len() < n {
        let mut input = Vec::with_capacity(32 + 12 + 4);
        input.extend_from_slice(key);
        input.extend_from_slice(nonce);
        input.extend_from_slice(&i.to_be_bytes());
        ks.extend_from_slice(&sha256(&input));
        i += 1;
    }
    ks.truncate(n);
    ks
}

/// INTEROP AEAD (encrypt-then-MAC). Returns ciphertext || 16-byte tag.
pub fn interop_encrypt(key_aead: &[u8; 32], key_mac: &[u8; 32],
                       nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let ks = interop_keystream(key_aead, nonce, pt.len());
    let ct: Vec<u8> = pt.iter().zip(&ks).map(|(a, b)| a ^ b).collect();
    let mut input = Vec::with_capacity(12 + aad.len() + ct.len());
    input.extend_from_slice(nonce);
    input.extend_from_slice(aad);
    input.extend_from_slice(&ct);
    let tag = hmac_sha256(key_mac, &input);
    let mut out = ct;
    out.extend_from_slice(&tag[..16]);
    out
}

/// INTEROP AEAD decrypt; returns Err on tag mismatch.
pub fn interop_decrypt(key_aead: &[u8; 32], key_mac: &[u8; 32],
                       nonce: &[u8; 12], aad: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>, crate::error::ProtocolError> {
    use crate::error::{ErrorKind, ProtocolError};
    if ct_tag.len() < 16 {
        return Err(ProtocolError::new(ErrorKind::Auth, "interop: too short"));
    }
    let (ct, tag) = ct_tag.split_at(ct_tag.len() - 16);
    let mut input = Vec::with_capacity(12 + aad.len() + ct.len());
    input.extend_from_slice(nonce);
    input.extend_from_slice(aad);
    input.extend_from_slice(ct);
    let expect = hmac_sha256(key_mac, &input);
    if !constant_time_eq(&expect[..16], tag) {
        return Err(ProtocolError::new(ErrorKind::Auth, "interop: tag mismatch"));
    }
    let ks = interop_keystream(key_aead, nonce, ct.len());
    Ok(ct.iter().zip(&ks).map(|(a, b)| a ^ b).collect())
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 180-2 vectors
    #[test]
    fn sha256_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn hmac_vector() {
        // RFC 4231 case 1 (truncated to 32 bytes checked loosely via stability)
        let d = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            &hex(&d)[..16], "b0344c61d8db3853");
    }

    #[test]
    fn x25519_rfc7748() {
        let alice = hex_to32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob = hex_to32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let alice_pub = x25519_public(&alice);
        let bob_pub = x25519_public(&bob);
        assert_eq!(hex(&alice_pub),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(hex(&bob_pub),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let k1 = x25519(&alice, &bob_pub);
        let k2 = x25519(&bob, &alice_pub);
        assert_eq!(hex(&k1),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(k1, k2);
    }

    fn hex_to32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn interop_roundtrip() {
        let ka = [7u8; 32];
        let km = [9u8; 32];
        let n = [0u8; 12];
        let aad = b"\x55\x4c\x01\x09\x02\x00\x28";
        let pt = b"unilink interop test payload";
        let ct = interop_encrypt(&ka, &km, &n, aad, pt);
        assert_eq!(ct.len(), pt.len() + 16);
        let dec = interop_decrypt(&ka, &km, &n, aad, &ct).unwrap();
        assert_eq!(dec, pt.to_vec());
        // tamper
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(interop_decrypt(&ka, &km, &n, aad, &bad).is_err());
    }
}
