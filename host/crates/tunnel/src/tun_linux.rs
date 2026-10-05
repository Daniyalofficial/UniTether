//! Linux TUN via `/dev/net/tun` (no external crates; `ioctl` declared
//! directly). Interface addressing uses `iproute2` if present, which is
//! what keeps the crate dependency-free (Gnirehtet does the same).

use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use crate::{packet_family, TunDevice};

const IFF_TUN: u32 = 0x0001;
const IFF_NO_PI: u32 = 0x1000;
const IFF_UP: u32 = 0x0001;
const IFF_RUNNING: u32 = 0x0040;
#[allow(non_upper_case_globals)]
const TUNSETIFF: u64 = 0x4004_54CA;
#[allow(non_upper_case_globals)]
const TUNGETIFF: u64 = 0x887F_54D0;
#[allow(non_upper_case_globals)]
const TUNSETIFF2: u64 = 0x4004_54F1;

/// `struct ifreq` (linux/if.h) — name + a 16-byte union.
#[repr(C)]
struct Ifreq {
    name: [u8; 16],
    data: [u8; 16],
}

impl Ifreq {
    fn new() -> Self {
        Self { name: [0; 16], data: [0; 16] }
    }
    fn set_name(&mut self, name: &str) {
        for (i, b) in name.as_bytes().iter().enumerate() {
            if i < 15 { self.name[i] = *b; }
        }
    }
    fn interface_name(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }
    fn flags_u32(&self) -> u32 {
        u32::from_ne_bytes(self.data[..4].try_into().unwrap())
    }
    fn set_flags(&mut self, f: u32) {
        self.data[..4].copy_from_slice(&f.to_ne_bytes());
    }
}

extern "C" {
    #[cfg_attr(target_os = "linux", link_name = "ioctl")]
    fn ioctl(fd: RawFd, request: u64, ...) -> i32;
}

pub struct TunLinux {
    _fd: std::fs::File,
    name: String,
}

impl TunLinux {
    /// Open a new TUN device.
    pub fn open() -> io::Result<Self> {
        let fd = std::fs::OpenOptions::new()
            .read(true).write(true)
            .open("/dev/net/tun")
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied,
                format!("/dev/net/tun: {e} (no root? TUN needs CAP_NET_ADMIN or udev rule)")))?;
        let mut ifr = Ifreq::new();
        ifr.set_name("unilink");
        ifr.set_flags(IFF_TUN | IFF_NO_PI);
        let r = unsafe { ioctl(fd.as_raw_fd(), TUNSETIFF, &ifr as *const Ifreq as *mut _) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        let name = ifr.interface_name();
        // take ownership of the fd (File drops it later)
        let owned = unsafe { std::fs::File::from_raw_fd(fd.as_raw_fd()) };
        Ok(Self { _fd: owned, name })
    }

    fn fd(&self) -> RawFd { self._fd.as_raw_fd() }

    /// Assign addresses and bring the interface up via `ip` (iproute2).
    fn configure_with_ip(&self, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> io::Result<()> {
        let run = |args: &[&str]| -> io::Result<()> {
            std::process::Command::new("ip")
                .args(args)
                .output()
                .map_err(|e| io::Error::new(io::ErrorKind::NotFound,
                    format!("failed to run ip: {e}")))?;
            Ok(())
        };
        run(&["link", "set", &self.name, "up"])?;
        if let Some(a) = v4 {
            run(&["addr", "replace", format!("{a}/20"), "dev", &self.name])?;
        }
        if let Some(a) = v6 {
            run(&["-6", "addr", "replace", format!("{a}/64"), "dev", &self.name])?;
        }
        Ok(())
    }
}

impl TunDevice for TunLinux {
    fn name(&self) -> &str { &self.name }

    fn raw_handle(&self) -> Option<std::os::raw::c_int> { Some(self.fd()) }

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
        self.configure_with_ip(v4, v6)
    }
}

#[allow(dead_code)]
fn _unused_packet_family() -> u8 {
    packet_family(b"")
}

// silence unused import when no test
#[allow(unused_imports)]
use std::io::{Read, Write};
