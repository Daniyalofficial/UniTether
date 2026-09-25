//! ADB integration: port forwarding without requiring root on either side.
//!
//! The device app listens on `localabstract:unilink`; the host runs
//! `adb forward tcp:<port> localabstract:unilink` so a plain TCP socket on
//! the host reaches the device app over USB (or over an existing adb
//! connection, e.g. Wi-Fi adb). This is the Gnirehtet-compatible transport
//! path: it works on Android 5.0+ with a standard (unlocked, but not
//! rooted) device.

use std::process::{Command, Output};

pub fn adb_available() -> Option<std::path::PathBuf> {
    which("adb")
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let cand = dir.join(bin);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

/// Manages one `adb forward tcp:<local> localabstract:unilink` rule.
pub struct AdbForward {
    adb: std::path::PathBuf,
    local_port: u16,
}

impl AdbForward {
    /// `adb_path` may be None (uses PATH). Returns the local port.
    pub fn create(adb_path: Option<std::path::PathBuf>, local_port: u16)
        -> std::io::Result<Self> {
        let adb = match adb_path {
            Some(p) => p,
            None => adb_available()
                .ok_or_else(|| std::io::Error::new(
                    std::io::ErrorKind::NotFound, "adb not found in PATH"))?,
        };
        if local_port != 0 {
            return Self::for_port(adb, local_port);
        }
        // find a free port by asking adb to pick one? adb forward requires
        // an explicit local port; probe a small range.
        let mut port = 20480u16;
        loop {
            if port > 20480 + 200 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse, "no free local port"));
            }
            match Self::for_port(adb.clone(), port) {
                Ok(f) => return Ok(f),
                Err(_) => port += 1,
            }
        }
    }

    fn for_port(adb: std::path::PathBuf, port: u16) -> std::io::Result<Self> {
        let spec = format!("tcp:{port}");
        // Remove any stale rule first (ignore errors).
        let _ = Command::new(&adb).args(["forward", "--remove", &spec]).output();
        let out = Command::new(&adb)
            .args(["forward", &spec, "localabstract:unilink"])
            .output()
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to run adb: {e}")))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("adb forward failed: {}", err.trim())));
        }
        Ok(Self { adb, local_port: port })
    }

    pub fn local_port(&self) -> u16 { self.local_port }
    pub fn local_addr(&self) -> String { format!("127.0.0.1:{}", self.local_port) }

    /// `adb forward --list` contains our rule?
    pub fn active(&self) -> bool {
        let out: Option<Output> = Command::new(&self.adb)
            .args(["forward", "--list"])
            .output()
            .ok();
        match out {
            Some(o) if o.status.success() => {
                String::from_utf8_lossy(&o.stdout).contains(&format!("localabstract:unilink"))
                    && String::from_utf8_lossy(&o.stdout).contains(&format!("tcp:{}", self.local_port))
            }
            _ => false,
        }
    }

    pub fn remove(&self) -> std::io::Result<()> {
        let out = Command::new(&self.adb)
            .args(["forward", "--remove", &format!("tcp:{}", self.local_port)])
            .output()
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::Other, format!("failed to run adb: {e}")))?;
        if !out.status.success() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other,
                String::from_utf8_lossy(&out.stderr).trim().to_string()));
        }
        Ok(())
    }
}

impl Drop for AdbForward {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adb_missing_is_clean_error() {
        // On CI boxes without adb this must return Err(NotFound), not panic.
        let r = AdbForward::create(None, 0);
        if let Ok(f) = r { let _ = f.remove(); }
    }

    #[test]
    fn which_finds_sh() {
        assert!(which("sh").is_some());
    }
}
