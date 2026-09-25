//! `unilink-transport` — ULP transports: TCP framing, ULP session
//! (handshake + AEAD), ADB port forwarding, mDNS discovery.

pub mod adb;
pub mod mdns;
pub mod rand;
pub mod session;
pub mod tcp;

pub use adb::{adb_available, AdbForward};
pub use mdns::{MdnsAdvertiser, MdnsPeer, MdnsResponder};
pub use session::{Session, SessionInfo};
pub use tcp::{listen, FramedConn};
