//! Windows TUN via the Win32 TUN API (Wintun-compatible, no root).
//!
//! Uses the `windows` crate for FFI (Windows-target only). Address
//! assignment goes through `netsh` (no admin elevation needed for TUN
//! interfaces created by the same user session).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use windows::core::GUID;
use windows::Win32::Networking::Tun::{
    CloseTunnelInterface, CreateTunnelInterface, SetTunnelInterfaceEnableLasso,
};

use crate::TunDevice;

pub struct TunWindows {
    handle: windows::Win32::Foundation::HANDLE,
    guid: GUID,
    name: String,
    mtu: u16,
}

impl TunWindows {
    pub fn open(name: &str) -> io::Result<Self> {
        use windows::Win32::Networking::WindowsSock2::WSAStartup;
        use windows::Win32::Networking::WindowsSock2::WSADATA;
        let mut data = WSADATA::default();
        unsafe {
            WSAStartup(0x0202, &mut data)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("WSAStartup: {e}")))?;
        }
        let mut guid = GUID::default();
        let mut mtu: u16 = 0;
        let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe {
            CreateTunnelInterface(&name_w, &mut guid, &mut mtu).map_err(|e| {
                io::Error::new(io::ErrorKind::PermissionDenied,
                    format!("CreateTunnelInterface: {e}"))
            })?
        };
        Ok(Self { handle, guid, name: name.to_string(), mtu: mtu.max(1500) })
    }

    /// Enable Lasso mode so the TUN receives broadcast/multicast (needed
    /// for DNS over the tunnel); disabled by default for performance.
    pub fn set_lasso(&self, enabled: bool) -> io::Result<()> {
        unsafe {
            SetTunnelInterfaceEnableLasso(&self.guid, enabled)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
        }
    }

    fn configure_with_netsh(&self, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> io::Result<()> {
        let run = |args: &[&str]| -> io::Result<()> {
            let st = std::process::Command::new("netsh")
                .args(args)
                .status()
                .map_err(|e| io::Error::new(io::ErrorKind::NotFound,
                    format!("failed to run netsh: {e}")))?;
            if !st.success() {
                return Err(io::Error::new(io::ErrorKind::Other,
                    format!("netsh failed: args={args:?}")));
            }
            Ok(())
        };
        if let Some(a) = v4 {
            run(&["interface", "ipv4", "set", "address", &self.name,
                  &a.to_string(), "255.255.240.0", "none"])?;
        }
        if let Some(a) = v6 {
            run(&["interface", "ipv6", "set", "address", &self.name,
                  format!("{a}/64")])?;
        }
        Ok(())
    }
}

impl TunDevice for TunWindows {
    fn name(&self) -> &str { &self.name }
    fn fd(&self) -> Option<std::os::unix::io::RawFd> { None }

    fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        use windows::Win32::Storage::FileSystem::ReadFile;
        let mut buf = vec![0u8; 65536];
        let mut bytes = 0u32;
        unsafe {
            ReadFile(Some(self.handle), buf.as_mut_ptr(), buf.len() as u32,
                &mut bytes, None)
                .map_err(|e| io::Error::new(io::ErrorKind::Other,
                    format!("ReadFile: {e}")))?;
        };
        buf.truncate(bytes as usize);
        Ok(buf)
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        use windows::Win32::Storage::FileSystem::WriteFile;
        let mut written = 0u32;
        unsafe {
            WriteFile(Some(self.handle), packet.as_ptr(), packet.len() as u32,
                &mut written, None)
                .map_err(|e| io::Error::new(io::ErrorKind::Other,
                    format!("WriteFile: {e}")))?;
        };
        if written as usize != packet.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero,
                "short write to TUN"));
        }
        Ok(())
    }

    fn configure(&self, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> io::Result<()> {
        self.configure_with_netsh(v4, v6)
    }

    fn mtu(&self) -> u16 { self.mtu }
}

impl Drop for TunWindows {
    fn drop(&mut self) {
        unsafe { let _ = CloseTunnelInterface(&self.guid); }
    }
}
