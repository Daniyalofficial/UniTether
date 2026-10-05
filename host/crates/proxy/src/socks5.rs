//! Minimal RFC 1928 SOCKS5 server (no-auth, CONNECT only).

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::AtomicU64;

use crate::{pump, Tunneler};

pub fn handle(mut stream: TcpStream, tunnel: &dyn Tunneler, forwarded: &AtomicU64) -> std::io::Result<()> {
    // --- greeting
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr)?;
    if hdr[0] != 5 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
            "not SOCKS5"));
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods)?;
    if !methods.contains(&0x00) {
        let _ = stream.write_all(&[5, 0xFF]); // no acceptable method
        return Ok(());
    }
    stream.write_all(&[5, 0, 0, 0])?;

    // --- request
    let mut req = [0u8; 6];
    stream.read_exact(&mut req)?;
    if req[0] != 5 || req[1] != 1 {
        let cmd = req[1];
        let _ = stream.write_all(&[5, if cmd == 1 { 7 } else { 1 }, 0, 0, 0, 0, 0, 0, 0]);
        return Ok(());
    }
    let (host, port) = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a)?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p)?;
            (IpAddr::from(a), u16::from_be_bytes(p))
        }
        4 => {
            let mut a = [0u8; 16];
            stream.read_exact(&mut a)?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p)?;
            (IpAddr::from(a), u16::from_be_bytes(p))
        }
        _ => {
            let _ = stream.write_all(&[5, 8, 0, 0, 0, 0, 0, 0, 0]);
            return Ok(());
        }
    };

    // --- connect through the tunnel
    let mut tstream = match tunnel.connect(host, port) {
        Ok(s) => s,
        Err(e) => {
            let _ = stream.write_all(&[5, 5, 0, 0, 0, 0, 0, 0, 0]); // host unreachable
            return Err(e);
        }
    };
    // reply: bound addr 0.0.0.0:0
    stream.write_all(&[5, 0, 0, 0, 0, 0, 0, 0, 0])?;
    stream.flush()?;

    pump(&mut stream, &mut tstream, forwarded, std::time::Duration::from_secs(300))
}
