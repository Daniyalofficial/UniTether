//! `unilink-protocol` — UniLink Protocol (ULP) v1.
//!
//! The single source of truth for the wire format is
//! [`docs/02-PROTOCOL.md`](../../docs/02-PROTOCOL.md). This crate is the
//! host-side Rust implementation; it is intentionally dependency-free so
//! the conformance toolchain works on any toolchain, air-gapped or not.
//!
//! ```
//! use unilink_protocol::frame::{Frame, decode, ch};
//! let f = Frame::new(ch::TUN_V4, 0, b"abcd".to_vec()).unwrap();
//! let wire = f.encode();
//! let (d, off) = decode(&wire, 0).unwrap();
//! assert_eq!(d.payload, b"abcd");
//! assert_eq!(off, wire.len());
//! ```

pub mod channel;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod message;
pub mod pairing;

pub use error::{ErrorKind, ProtocolError};
pub use frame::{ch, decode, Frame, MAGIC0, MAGIC1, MAX_PAYLOAD, VERSION};
pub use handshake::{
    derive, derive_session_keys, CIPHER_AESGCM, CIPHER_CHACHA, CIPHER_INTEROP,
    CIPHER_NONE, Hello, HelloAck, SessionKeys, FEAT_AUDIO, FEAT_CAMERA,
    FEAT_DUAL_STACK, FEAT_INPUT, FEAT_PROXY, FEAT_PROD, FEAT_QOS, FEAT_VIDEO,
    HELLO_ACK_BODY_LEN, HELLO_BODY_LEN, ROLE_DEVICE, ROLE_HOST,
};
pub use message::{
    decode as msg_decode, encode as msg_encode, QosParams, StatCounters,
    TunnelConfig, MSG_AUTH_OK, MSG_BYE, MSG_CONFIG, MSG_ERROR, MSG_HELLO,
    MSG_HELLO_ACK, MSG_MUTE, MSG_PING, MSG_PONG, MSG_QOS, MSG_RESUME,
    MSG_STATS_REQ, MSG_STATS_RSP, MSG_TUN_DOWN, MSG_TUN_UP,
};
pub use pairing::{base64url_decode, base64url_encode, pairing_blob, pairing_parse};
