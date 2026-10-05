//! Windows TUN via the WinTun C API (raw FFI — zero external dependencies).
//!
//! WinTun is the standard TUN driver on Windows (the WireGuard ecosystem's
//! reference implementation). No root required: WinTun registers its own
//! driver when the first adapter is created.
//!
//! Build/run requirements (see the official bundle,
//! <https://github.com/wireguard/win-tun/releases>):
//! * link time : `wintun.lib` in the linker search path
//! * run time  : `wintun.dll` next to the executable or on `PATH`
//!   (override with the `WINTUN_PATH` env var pointing at the install dir).
//!
//! NOTE: this module is `cfg(windows)` — it is not compiled by the Linux
//! CI, and it has not yet been executed on a Windows machine (see
//! docs/27, desktop matrix). Written against the stable WinTun C API
//! (wintun.h, >= 0.13): plain C-ABI functions, UTF-16 string parameters.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::raw::{c_int, c_uint, c_void};

use crate::TunDevice;

/// WinTun C API. Signatures mirror wintun.h; strings are UTF-16 (LPCWSTR).
#[link(name = "wintun")]
extern "system" {
    fn wintun_version() -> c_uint;
    fn wintun_create(
        path: *const u16,
        name: *const u16,
        guid: *mut u16,
        mtu: *mut c_uint,
    ) -> *mut c_void;
    fn wintun_open(name: *const u16, guid: *mut u16, mtu: *mut c_uint) -> *mut c_void;
    fn wintun_close(adapter: *mut c_void);
    fn wintun_read(adapter: *mut c_void, buffer: *mut u8, size: c_uint) -> c_uint;
    fn wintun_write(adapter: *mut c_void, buffer: *const u8, size: c_uint) -> c_uint;
}

/// WinTun version this code was written against (0.13 => 0x0103).
const MIN_WINTUN: c_uint = 0x0103;

/// Encode `s` as a NUL-terminated UTF-16 string (LPCWSTR-compatible).
fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

pub struct TunWindows {
    adapter: *mut c_void,
    name: String,
    mtu: u16,
}

unsafe impl Send for TunWindows {}

impl TunWindows {
    pub fn open(name: &str) -> io::Result<Self> {
        let version = unsafe { wintun_version() };
        if version < MIN_WINTUN {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("wintun version {version:#06x} < required {MIN_WINTUN:#06x}"),
            ));
        }

        let name_w = to_wide(name);
        let mut guid = [0u16; 39]; // "xxxxxxxx-xxxx-...." + NUL
        let mut mtu: c_uint = 0;

        // Reuse an existing adapter if present, otherwise create one.
        let adapter = unsafe { wintun_open(name_w.as_ptr(), guid.as_mut_ptr(), &mut mtu) };
        let adapter = if !adapter.is_null() {
            adapter
        } else {
            let path = std::env::var("WINTUN_PATH")
                .unwrap_or_else(|_| "C:\\Program Files\\wintun".to_string());
            let path_w = to_wide(&path);
            let a = unsafe {
                wintun_create(path_w.as_ptr(), name_w.as_ptr(), guid.as_mut_ptr(), &mut mtu)
            };
            if a.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("wintun_create({name}) failed — is wintun.dll available?"),
                ));
            }
            a
        };

        Ok(Self {
            adapter,
            name: name.to_string(),
            mtu: (mtu as u16).max(1500),
        })
    }

    fn configure_with_netsh(&self, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> io::Result<()> {
        let run = |args: &[&str]| -> io::Result<()> {
            let st = std::process::Command::new("netsh")
                .args(args)
                .status()
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::NotFound, format!("failed to run netsh: {e}"))
                })?;
            if !st.success() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("netsh failed: args={args:?}"),
                ));
            }
            Ok(())
        };
        if let Some(a) = v4 {
            run(&[
                "interface",
                "ipv4",
                "set",
                "address",
                &self.name,
                &a.to_string(),
                "255.255.240.0",
                "none",
            ])?;
        }
        if let Some(a) = v6 {
            run(&["interface", "ipv6", "set", "address", &self.name, &format!("{a}/64")])?;
        }
        Ok(())
    }
}

impl TunDevice for TunWindows {
    fn name(&self) -> &str {
        &self.name
    }

    fn raw_handle(&self) -> Option<c_int> {
        None // opaque WinTun adapter handle, not an OS fd
    }

    fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 65536];
        let n = unsafe { wintun_read(self.adapter, buf.as_mut_ptr(), buf.len() as c_uint) };
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wintun_read returned 0 — adapter closed",
            ));
        }
        buf.truncate(n as usize);
        Ok(buf)
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let n = unsafe { wintun_write(self.adapter, packet.as_ptr(), packet.len() as c_uint) };
        if n as usize != packet.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short write to TUN"));
        }
        Ok(())
    }

    fn configure(&self, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> io::Result<()> {
        self.configure_with_netsh(v4, v6)
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }
}

impl Drop for TunWindows {
    fn drop(&mut self) {
        unsafe { wintun_close(self.adapter) }
    }
}
