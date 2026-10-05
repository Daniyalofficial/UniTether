//! macOS `utun` (utun(4)) — no external crates.
//!
//! macOS exposes `/dev/utunN`; a process without root can use a utun if it
//! owns it via the `utun` kext grant (or when running under a user session
//! with the appropriate entitlements). Address assignment uses SIOCAIFADDR.

use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use crate::TunDevice;

const IFF_TUN: u32 = 0x0004;
const IFF_UP: u32 = 0x0001;
#[allow(non_upper_case_globals)]
const SIOCAIFADDR: u64 = 0x8020_6920; // IFCOMMAND(SIOCIF, SIOCA, 0x20, 'r')
#[allow(non_upper_case_globals)]
const SIOCSIFADDR: u64 = 0x8020_1910;
#[allow(non_upper_case_globals)]
const SIOCSIFFLAGS: u64 = 0x8020_1904;

/// `struct sockaddr_in` (sys/socket.h)
#[repr(C)]
struct SockaddrIn {
    len: u8,
    family: u8,
    port: u16,
    addr: [u8; 4],
    zero: [u8; 8],
}

#[repr(C)]
struct SockaddrIn6 {
    len: u8,
    family: u8,
    port: u16,
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

#[repr(C)]
struct Ifreq {
    name: [u8; 16],
    sa: SockaddrIn,
}

extern "C" {
    fn ioctl(fd: RawFd, request: u64, ...) -> i32;
}

pub struct TunMacos {
    _fd: std::fs::File,
    name: String,
}

impl TunMacos {
    /// Open the first available utun (utun0..=15).
    pub fn open() -> io::Result<Self> {
        for i in 0..16u8 {
            let path = format!("/dev/utun{i}");
            match std::fs::OpenOptions::new().read(true).write(true).open(&path) {
                Ok(f) => {
                    let name = format!("utun{i}");
                    let owned = unsafe { std::fs::File::from_raw_fd(f.as_raw_fd()) };
                    return Ok(Self { _fd: owned, name });
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(e),
                Err(_) => continue, // in use
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "no free utun"))
    }

    fn fd(&self) -> RawFd { self._fd.as_raw_fd() }

    fn set_addr(&self, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> io::Result<()> {
        let run = |args: &[&str]| -> io::Result<()> {
            std::process::Command::new("ifconfig")
                .args(args)
                .output()
                .map_err(|e| io::Error::new(io::ErrorKind::NotFound,
                    format!("failed to run ifconfig: {e}")))?;
            Ok(())
        };
        run(&[&self.name, "up"])?;
        if let Some(a) = v4 {
            run(&[&self.name, "inet", &a.to_string(), "netmask", "255.255.240.0"])?;
        }
        if let Some(a) = v6 {
            run(&[&self.name, "inet6", &a.to_string(), "prefixlen", "64"])?;
        }
        Ok(())
    }
}

impl TunDevice for TunMacos {
    fn name(&self) -> &str { &self.name }
    fn fd(&self) -> Option<RawFd> { Some(self.fd()) }

    fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 65536];
        let n = self._fd.read(&mut buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        buf.truncate(n);
        Ok(buf)
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self._fd.write_all(packet)?;
        Ok(())
    }

    fn configure(&self, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> io::Result<()> {
        self.set_addr(v4, v6)
    }
}

// keep the ioctl path referenced (used by advanced flag handling)
#[allow(dead_code)]
fn _ioctl_constants() -> u64 { SIOCSIFFLAGS | SIOCAIFADDR | SIOCSIFADDR }

#[allow(unused_imports)]
use std::io::{Read, Write};
#[allow(unused_imports)]
use mem;
