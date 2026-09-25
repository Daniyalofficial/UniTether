//! Golden-vector conformance test.
//!
//! Asserts that the pure-Rust ULP codecs produce byte-identical output to
//! the Python reference (tests/protocol/reference_framing.py) for all
//! vectors in protocol/vectors/*.json. This is the Rust<->Python interop
//! gate (and, transitively, the Rust<->Node gate once the Node codec is
//! checked against the same files).

use unilink_protocol::{
    base64url_decode, base64url_encode, pairing_blob,
    channel::{AudioFrame, ClipboardUpdate, FileOp, InputEvent, Notification, VideoFrame},
    crypto::{frame_nonce, hkdf_sha256, interop_encrypt, x25519, x25519_public},
    frame::{decode, Frame},
    handshake::{Hello, HelloAck},
    message::{msg_decode, msg_encode, QosParams, StatCounters, TunnelConfig,
        MSG_ERROR, MSG_MUTE, MSG_PING, MSG_BYE, MSG_AUTH_OK},
};

// ---------------------------------------------------------------- mini JSON
#[derive(Debug, Clone)]
enum J {
    Num(i64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
    Null,
}

impl J {
    fn get(&self, key: &str) -> Option<&J> {
        match self {
            J::Obj(map) => map.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    fn as_str(&self) -> String {
        match self { J::Str(s) => s.clone(), other => panic!("expected string: {other:?}") }
    }
    fn as_u64(&self) -> u64 {
        match self { J::Num(n) => *n as u64, other => panic!("expected number: {other:?}") }
    }
    fn as_arr(&self) -> &Vec<J> {
        match self { J::Arr(a) => a, other => panic!("expected array: {other:?}") }
    }
}

fn json_parse(s: &str) -> J {
    let b = s.as_bytes();
    let (v, _) = parse_value(b, 0).expect("json parse");
    v
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r') { i += 1; }
    i
}

fn parse_value(b: &[u8], mut i: usize) -> Result<(J, usize), ()> {
    i = skip_ws(b, i);
    match b[i] {
        b'{' => parse_obj(b, i),
        b'[' => parse_arr(b, i),
        b'"' => { let (s, ni) = parse_str(b, i)?; Ok((J::Str(s), ni)) }
        b't' => { expect_lit(b, i, b"true"); Ok((J::Num(1), i + 4)) }
        b'f' => { expect_lit(b, i, b"false"); Ok((J::Num(0), i + 5)) }
        b'n' => { expect_lit(b, i, b"null"); Ok((J::Null, i + 4)) }
        _ => parse_num(b, i),
    }
}

fn expect_lit(b: &[u8], i: usize, lit: &[u8]) {
    if &b[i..i + lit.len()] != lit { panic!("bad literal at {i}"); }
}

fn parse_num(b: &[u8], i: usize) -> Result<(J, usize), ()> {
    let start = i;
    while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'-' || b[i] == b'+' || b[i] == b'.' || b[i] == b'e' || b[i] == b'E') { i += 1; }
    let s = std::str::from_utf8(&b[start..i]).map_err(|_| ())?;
    let n: i64 = s.parse().map_err(|_| ())?;
    Ok((J::Num(n), i))
}

fn parse_str(b: &[u8], mut i: usize) -> Result<(String, usize), ()> {
    // b[i] == b'"'
    i += 1;
    let mut out = String::new();
    let mut rest: &[u8] = &b[i..];
    while !rest.is_empty() {
        let c = rest[0];
        if c == b'"' { return Ok((out, i + rest.len())); }
        if c == b'\\' {
            i += 1; rest = &rest[1..];
            match rest[0] {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'n' => out.push('\n'),
                b't' => out.push('\t'),
                b'r' => out.push('\r'),
                b'b' => out.push('\u{0008}'),
                b'f' => out.push('\u{000C}'),
                b'u' => {
                    let hex = std::str::from_utf8(&rest[1..5]).map_err(|_| ())?;
                    let cp = u32::from_str_radix(hex, 16).map_err(|_| ())?;
                    out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                    i += 4; rest = &rest[5..];
                    continue;
                }
                _ => return Err(()),
            }
        } else {
            // raw UTF-8: find the end of this code point's byte sequence
            let len = if c < 0x80 { 1 } else if c >= 0xF0 { 4 } else if c >= 0xE0 { 3 } else { 2 };
            if rest.len() < len { return Err(()); }
            let chunk = std::str::from_utf8(&rest[..len]).map_err(|_| ())?;
            out.push_str(chunk);
            i += len; rest = &rest[len..];
            continue;
        }
        i += 1; rest = &rest[1..];
    }
    Err(())
}

fn parse_arr(b: &[u8], i: usize) -> Result<(J, usize), ()> {
    let mut i = i + 1; // '['
    let mut items = Vec::new();
    i = skip_ws(b, i);
    if b[i] == b']' { return Ok((J::Arr(items), i + 1)); }
    loop {
        let (v, ni) = parse_value(b, i)?;
        items.push(v);
        i = skip_ws(b, ni);
        match b[i] {
            b',' => i += 1,
            b']' => return Ok((J::Arr(items), i + 1)),
            _ => return Err(()),
        }
    }
}

fn parse_obj(b: &[u8], i: usize) -> Result<(J, usize), ()> {
    let mut i = i + 1; // '{'
    let mut map = Vec::new();
    i = skip_ws(b, i);
    if b[i] == b'}' { return Ok((J::Obj(map), i + 1)); }
    loop {
        i = skip_ws(b, i);
        let (k, ni) = parse_str(b, i)?;
        i = skip_ws(b, ni);
        if b[i] != b':' { return Err(()); }
        i += 1;
        let (v, ni) = parse_value(b, i)?;
        map.push((k, v));
        i = skip_ws(b, ni);
        match b[i] {
            b',' => i += 1,
            b'}' => return Ok((J::Obj(map), i + 1)),
            _ => return Err(()),
        }
    }
}

// ---------------------------------------------------------------- helpers
fn hx(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn load(name: &str) -> J {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../protocol/vectors").join(name);
    let s = std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("cannot read {:?}: {e}", p));
    json_parse(&s)
}
fn vectors(d: &J) -> Vec<J> {
    d.get("vectors").expect("no vectors key").as_arr().clone()
}
fn check(name: &str, got: &[u8], want: &str) {
    assert_eq!(hex(got), want, "vector {name}: output mismatch");
}

// ------------------------------------------------------------------- tests
#[test]
fn frames_match_golden() {
    for v in vectors(&load("frames.json")) {
        let name = v.get("name").unwrap().as_str();
        let channel = v.get("channel").unwrap().as_u64() as u8;
        let flags = v.get("flags").unwrap().as_u64() as u8;
        let payload = hx(&v.get("payload").unwrap().as_str());
        let expected = v.get("expected").unwrap().as_str();
        let f = Frame::new(channel, flags, payload).unwrap();
        check(&name, &f.encode(), &expected);
        let (d, off) = decode(&hx(&expected), 0).unwrap();
        assert_eq!(off, expected.len() / 2);
        assert_eq!(d.channel, channel);
        assert_eq!(d.flags, flags);
        assert_eq!(hex(&d.payload), v.get("payload").unwrap().as_str());
    }
}

#[test]
fn crypto_matches_golden() {
    for v in vectors(&load("crypto.json")) {
        let name = v.get("name").unwrap().as_str();
        match v.get("kind").unwrap().as_str().as_str() {
            "x25519_pub" => {
                let secret: [u8; 32] = hx(&v.get("secret").unwrap().as_str())[..32].try_into().unwrap();
                check(&name, &x25519_public(&secret), v.get("expected").unwrap().as_str().as_str());
            }
            "x25519" => {
                let secret: [u8; 32] = hx(&v.get("secret").unwrap().as_str())[..32].try_into().unwrap();
                let pubk: [u8; 32] = hx(&v.get("pub").unwrap().as_str())[..32].try_into().unwrap();
                check(&name, &x25519(&secret, &pubk), v.get("expected").unwrap().as_str().as_str());
            }
            "hkdf" => {
                let ikm = hx(&v.get("ikm").unwrap().as_str());
                let salt = hx(&v.get("salt").unwrap().as_str());
                let info = hx(&v.get("info").unwrap().as_str());
                let len = v.get("length").unwrap().as_u64() as usize;
                check(&name, &hkdf_sha256(&ikm, &salt, &info, len), v.get("expected").unwrap().as_str().as_str());
            }
            "interop" => {
                let ka: [u8; 32] = hx(&v.get("key_aead").unwrap().as_str())[..32].try_into().unwrap();
                let km: [u8; 32] = hx(&v.get("key_mac").unwrap().as_str())[..32].try_into().unwrap();
                let nonce: [u8; 12] = hx(&v.get("nonce").unwrap().as_str())[..12].try_into().unwrap();
                let aad = hx(&v.get("aad").unwrap().as_str());
                let pt = hx(&v.get("pt").unwrap().as_str());
                check(&name, &interop_encrypt(&ka, &km, &nonce, &aad, &pt),
                    v.get("expected").unwrap().as_str().as_str());
            }
            "frame_nonce" => {
                let counter = v.get("counter").unwrap().as_u64();
                let channel = v.get("channel").unwrap().as_u64() as u8;
                let direction = v.get("direction").unwrap().as_u64() as u8;
                check(&name, &frame_nonce(counter, channel, direction),
                    v.get("expected").unwrap().as_str().as_str());
            }
            other => panic!("unknown crypto kind {other}"),
        }
    }
}

#[test]
fn messages_match_golden() {
    for v in vectors(&load("messages.json")) {
        let name = v.get("name").unwrap().as_str();
        let expected = v.get("expected").unwrap().as_str();
        match v.get("kind").unwrap().as_str().as_str() {
            "hello" => {
                let role = v.get("role").unwrap().as_u64() as u8;
                let fm = v.get("feature_mask").unwrap().as_u64() as u16;
                let cp = v.get("cipher_pref").unwrap().as_u64() as u8;
                let pubk: [u8; 32] = hx(&v.get("ecdh_pub").unwrap().as_str())[..32].try_into().unwrap();
                let nonce_a: [u8; 16] = hx(&v.get("nonce_a").unwrap().as_str())[..16].try_into().unwrap();
                let secret = hx(&v.get("secret").unwrap().as_str());
                let h = Hello::build(role, fm, cp, pubk, nonce_a, &secret);
                check(&name, &h.body(), &expected);
                Hello::parse(&hx(&expected)).unwrap().verify(&secret).unwrap();
            }
            "hello_ack" => {
                let neg = v.get("negotiated").unwrap().as_u64() as u16;
                let cs = v.get("cipher_sel").unwrap().as_u64() as u8;
                let pubk: [u8; 32] = hx(&v.get("ecdh_pub").unwrap().as_str())[..32].try_into().unwrap();
                let nonce_b: [u8; 16] = hx(&v.get("nonce_b").unwrap().as_str())[..16].try_into().unwrap();
                let nonce_a: [u8; 16] = hx(&v.get("nonce_a").unwrap().as_str())[..16].try_into().unwrap();
                let secret = hx(&v.get("secret").unwrap().as_str());
                let a = HelloAck::build(neg, cs, pubk, nonce_b, nonce_a, &secret);
                check(&name, &a.body(), &expected);
                HelloAck::parse(&hx(&expected)).unwrap().verify(&secret, &nonce_a).unwrap();
            }
            "config" => {
                let mut c = TunnelConfig::default();
                c.v4_prefix = v.get("v4_prefix").unwrap().as_u64() as u8;
                c.v4_device = hx(&v.get("v4_device").unwrap().as_str())[..4].try_into().unwrap();
                c.v4_host = hx(&v.get("v4_host").unwrap().as_str())[..4].try_into().unwrap();
                c.v6_prefix = v.get("v6_prefix").unwrap().as_u64() as u8;
                c.v6_device = hx(&v.get("v6_device").unwrap().as_str())[..16].try_into().unwrap();
                c.v6_host = hx(&v.get("v6_host").unwrap().as_str())[..16].try_into().unwrap();
                for d in v.get("dns").unwrap().as_arr() {
                    c.dns.push(hx(&d.as_str())[..4].try_into().unwrap());
                }
                for r in v.get("routes").unwrap().as_arr() {
                    c.routes.push((r.as_arr()[0].as_u64() as u8,
                        hx(&r.as_arr()[1].as_str())[..4].try_into().unwrap()));
                }
                check(&name, &c.body(), &expected);
                let p = TunnelConfig::parse(&c.body()).unwrap();
                assert_eq!(p, c);
            }
            "qos" => {
                let q = QosParams {
                    profile: v.get("profile").unwrap().as_u64() as u8,
                    up_kbps: v.get("up_kbps").unwrap().as_u64() as u32,
                    down_kbps: v.get("down_kbps").unwrap().as_u64() as u32,
                    latency_ms: v.get("latency_ms").unwrap().as_u64() as u16,
                    jitter_ms: v.get("jitter_ms").unwrap().as_u64() as u8,
                    loss_pct: v.get("loss_pct").unwrap().as_u64() as u8,
                };
                check(&name, &q.body(), &expected);
                assert_eq!(QosParams::parse(&q.body()).unwrap(), q);
            }
            "stats" => {
                let s = StatCounters {
                    bytes_in: v.get("bytes_in").unwrap().as_u64(),
                    bytes_out: v.get("bytes_out").unwrap().as_u64(),
                    pkts_in: v.get("pkts_in").unwrap().as_u64(),
                    pkts_out: v.get("pkts_out").unwrap().as_u64(),
                    bytes_video: v.get("bytes_video").unwrap().as_u64(),
                    bytes_audio: v.get("bytes_audio").unwrap().as_u64(),
                    bytes_file: v.get("bytes_file").unwrap().as_u64(),
                    drops: v.get("drops").unwrap().as_u64(),
                    errors: v.get("errors").unwrap().as_u64(),
                    frames_video: v.get("frames_video").unwrap().as_u64(),
                    rtt_ms: v.get("rtt_ms").unwrap().as_u64() as u32,
                    loss_pct_x100: v.get("loss_pct_x100").unwrap().as_u64() as u32,
                    cpu_pct_x100: v.get("cpu_pct_x100").unwrap().as_u64() as u32,
                    fps_video: v.get("fps_video").unwrap().as_u64() as u32,
                    audio_level: v.get("audio_level").unwrap().as_u64() as u32,
                };
                check(&name, &s.body(), &expected);
            }
            "mute" => {
                let mask = v.get("mask").unwrap().as_u64() as u8;
                check(&name, &msg_encode(MSG_MUTE, &[mask]), &expected);
            }
            "msg" => {
                let wire = hx(&expected);
                let (t, _f, body) = msg_decode(&wire).unwrap();
                let (want_t, want_len) = match name.as_str() {
                    "auth_ok" => (MSG_AUTH_OK, 0),
                    "ping" => (MSG_PING, 8),
                    "bye" => (MSG_BYE, 1),
                    "error_auth" => (MSG_ERROR, 14),
                    other => panic!("unknown msg vector {other}"),
                };
                assert_eq!(t, want_t, "vector {name}: type");
                assert_eq!(body.len(), want_len, "vector {name}: body len");
            }
            other => panic!("unknown message kind {other}"),
        }
    }
}

#[test]
fn channels_match_golden() {
    for v in vectors(&load("channels.json")) {
        let name = v.get("name").unwrap().as_str();
        let expected = v.get("expected").unwrap().as_str();
        match v.get("kind").unwrap().as_str().as_str() {
            "video" => {
                let f = VideoFrame {
                    kind: v.get("kind_field").unwrap().as_u64() as u8,
                    codec: v.get("codec").unwrap().as_u64() as u8,
                    width: v.get("width").unwrap().as_u64() as u16,
                    height: v.get("height").unwrap().as_u64() as u16,
                    fps: v.get("fps").unwrap().as_u64() as u8,
                    pts_ms: v.get("pts_ms").unwrap().as_u64() as u32,
                    seq: v.get("seq").unwrap().as_u64() as u32,
                    nal: hx(&v.get("nal").unwrap().as_str()),
                };
                check(&name, &f.body(), &expected);
            }
            "audio" => {
                let f = AudioFrame {
                    codec: v.get("codec").unwrap().as_u64() as u8,
                    rate: v.get("rate").unwrap().as_u64() as u16,
                    ch: v.get("ch").unwrap().as_u64() as u8,
                    seq: v.get("seq").unwrap().as_u64() as u32,
                    pts_ms: v.get("pts_ms").unwrap().as_u64() as u32,
                    data: hx(&v.get("data").unwrap().as_str()),
                };
                check(&name, &f.body(), &expected);
            }
            "input" => {
                let mut f = InputEvent {
                    ty: v.get("type_field").unwrap().as_u64() as u8,
                    action: v.get("action").unwrap().as_u64() as u8,
                    x: v.get("x").unwrap().as_u64() as u16,
                    y: v.get("y").unwrap().as_u64() as u16,
                    key: 0,
                    text: String::new(),
                };
                if let Some(t) = v.get("text") { f.text = t.as_str(); }
                check(&name, &f.body(), &expected);
            }
            "file_meta" => {
                let f = FileOp::Meta {
                    direction: v.get("direction").unwrap().as_u64() as u8,
                    file_id: v.get("file_id").unwrap().as_u64() as u32,
                    total_size: v.get("total_size").unwrap().as_u64(),
                    name: v.get("name").unwrap().as_str(),
                };
                check(&name, &f.body(), &expected);
            }
            "file_data" => {
                let f = FileOp::Data {
                    direction: v.get("direction").unwrap().as_u64() as u8,
                    file_id: v.get("file_id").unwrap().as_u64() as u32,
                    seq: v.get("seq").unwrap().as_u64() as u32,
                    offset: v.get("offset").unwrap().as_u64(),
                    chunk: hx(&v.get("chunk").unwrap().as_str()),
                };
                check(&name, &f.body(), &expected);
            }
            "clipboard" => {
                let f = ClipboardUpdate {
                    direction: v.get("direction").unwrap().as_u64() as u8,
                    kind: v.get("kind_field").unwrap().as_u64() as u8,
                    data: v.get("data").unwrap().as_str().as_bytes().to_vec(),
                };
                check(&name, &f.body(), &expected);
            }
            "notification" => {
                let f = Notification {
                    id: v.get("id").unwrap().as_u64() as u32,
                    ts_ms: v.get("ts_ms").unwrap().as_u64(),
                    action: v.get("action").unwrap().as_u64() as u8,
                    app: v.get("app").unwrap().as_str(),
                    title: v.get("title").unwrap().as_str(),
                    body: v.get("body").unwrap().as_str(),
                };
                check(&name, &f.body(), &expected);
            }
            other => panic!("unknown channel kind {other}"),
        }
    }
}

#[test]
fn pairing_matches_golden() {
    for v in vectors(&load("pairing.json")) {
        let name = v.get("name").unwrap().as_str();
        let secret: [u8; 32] = hx(&v.get("secret").unwrap().as_str())[..32].try_into().unwrap();
        let blob = pairing_blob(&secret, &name);
        assert_eq!(blob, v.get("expected").unwrap().as_str(), "vector {name}");
        let (s, n) = unilink_protocol::pairing_parse(&blob).unwrap();
        assert_eq!(s, secret);
        assert_eq!(n, name);
    }
    // base64url must match Python base64.urlsafe_b64encode exactly
    let secret = [0u8; 32];
    assert_eq!(base64url_encode(&secret), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    assert_eq!(base64url_decode("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=").unwrap(), secret.to_vec());
}
