//! `unilink-tunnel` — host-side TUN device management for the reverse
//! tether.
//!
//! * Linux: `/dev/net/tun` + `TUNSETIFF` (IFF_NO_PI, IFF_TUN, IFF_MULTI_CAST off)
//! * macOS: `utun` via `utun(4)` (IFF_TUN, IFF_NO_PI unsupported → MTU handling)
//! * Windows: `TAP` via the Win32 TUN API (Wintun-compatible)
//! * Fallback: [`NullTun`] for conformance tests and proxy-only mode
//!
//! The tunnel carries both IPv4 and IPv6 (dual-stack) — the same file
//! descriptor carries packets of either family; family is inferred from
//! the first nibble (Gnirehtet-compatible, spec section 8).

pub mod null_tun;
#[cfg(target_os = "linux")]
pub mod tun_linux;
#[cfg(target_os = "macos")]
pub mod tun_macos;
#[cfg(windows)]
pub mod tun_windows;

pub use null_tun::NullTun;

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A host-side virtual network interface.
pub trait TunDevice: Send {
    /// Interface name (tun0, utun3, ...).
    fn name(&self) -> &str;
    fn fd(&self) -> Option<std::os::unix::io::RawFd>;

    /// Read one packet (IPv4 or IPv6).
    fn read_packet(&mut self) -> io::Result<Vec<u8>>;
    /// Write one packet.
    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()>;

    /// Bring the interface up and assign addresses.
    fn configure(&self, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> io::Result<()>;
    /// MTU to use for outgoing frames (default 1500).
    fn mtu(&self) -> u16 { 1500 }
}

/// Detect the packet family from the first nibble.
pub fn packet_family(packet: &[u8]) -> u8 {
    if packet.is_empty() { return 0; }
    (packet[0] >> 4) & 0x0F
}

/// Default ULP tunnel network (spec section 7.3).
pub const DEFAULT_V4_PREFIX: u8 = 20;
pub const DEFAULT_V4_DEVICE: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
pub const DEFAULT_V4_HOST: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 1);
pub const DEFAULT_V6_PREFIX: u8 = 64;
pub const DEFAULT_V6_DEVICE: Ipv6Addr = Ipv6Addr::new(0xfd, 0, 0, 0, 0, 0, 0, 2);
pub const DEFAULT_V6_HOST: Ipv6Addr = Ipv6Addr::new(0xfd, 0, 0, 0, 0, 0, 0, 1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_detection() {
        assert_eq!(packet_family(&[0x45, 0, 0, 60, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]), 4);
        assert_eq!(packet_family(&[0x60, 0, 0, 0, 0x3c, 58, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]), 6);
        assert_eq!(packet_family(&[]), 0);
    }

    #[test]
    fn defaults_match_spec() {
        assert_eq!(DEFAULT_V4_PREFIX, 20);
        assert_eq!(DEFAULT_V4_DEVICE, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(DEFAULT_V4_HOST, Ipv4Addr::new(10, 8, 0, 1));
    }
}
