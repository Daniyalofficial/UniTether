//! `unilink-proxy` — local SOCKS5 + HTTP proxies whose outbound traffic
//! is forwarded into the ULP session (device-side NAT, Gnirehtet-style).
//!
//! Both proxies are thread-per-connection, std only.

pub mod http;
pub mod socks5;
pub mod wire;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use unilink_protocol::frame::{ch, F_PRIORITY};

/// Forwards raw TCP bytes from a local client into the tunnel.
pub trait Tunneler: Send + Sync {
    /// Open a tunnel-side stream to (ip:port); returns the tunnel byte
    /// sink. `ProxyTunneler` implements this by opening a new CH_PROXY
    /// connection id.
    fn connect(&self, host: std::net::IpAddr, port: u16) -> Result<Box<dyn TunnelerStream>, std::io::Error>;
    fn bytes_forwarded(&self) -> u64;
}

pub trait TunnelerStream: Send {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<()>;
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    fn close(&mut self) -> std::io::Result<()>;
}

/// A proxy server (SOCKS5 or HTTP) listening on 127.0.0.1.
pub struct ProxyServer {
    listener: TcpListener,
    pub mode: ProxyMode,
    tunnel: Arc<dyn Tunneler>,
    pub forwarded: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProxyMode { Socks5, Http }

impl ProxyServer {
    pub fn new(addr: &str, mode: ProxyMode, tunnel: Arc<dyn Tunneler>) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        Ok(Self { listener, mode, tunnel, forwarded: Arc::new(AtomicU64::new(0)) })
    }

    pub fn local_addr(&self) -> SocketAddr { self.listener.local_addr().unwrap() }

    /// Run until the listener is closed (blocking; one thread per conn).
    pub fn serve(&self) -> std::io::Result<()> {
        for stream in self.listener.incoming() {
            let stream = stream?;
            stream.set_nodelay(true).ok();
            stream.set_keepalive(true).ok();
            let mode = self.mode;
            let tunnel = Arc::clone(&self.tunnel);
            let forwarded = Arc::clone(&self.forwarded);
            std::thread::spawn(move || {
                if let Err(e) = match mode {
                    ProxyMode::Socks5 => socks5::handle(stream, &*tunnel, &forwarded),
                    ProxyMode::Http => http::handle(stream, &*tunnel, &forwarded),
                } {
                    eprintln!("[proxy] {e}");
                }
            });
        }
        Ok(())
    }
}

/// Pump bytes between a TCP stream and a tunnel stream (bidirectional).
pub fn pump(stream: &mut TcpStream, tstream: &mut dyn TunnelerStream,
            forwarded: &AtomicU64, idle_timeout: Duration) -> std::io::Result<()> {
    let mut lbuf = [0u8; 16 * 1024];
    let mut rbuf = [0u8; 16 * 1024];
    let mut last = std::time::Instant::now();
    let mut closed = false;
    loop {
        if last.elapsed() > idle_timeout { break; }
        let mut progress = false;
        if !closed {
            match stream.read(&mut lbuf) {
                Ok(0) => { closed = true; }
                Ok(n) => {
                    tstream.write(&lbuf[..n])?;
                    forwarded.fetch_add(n as u64, Ordering::Relaxed);
                    last = std::time::Instant::now();
                    progress = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        match tstream.read(&mut rbuf) {
            Ok(0) => { tstream.close().ok(); break; }
            Ok(n) => {
                stream.write_all(&rbuf[..n])?;
                last = std::time::Instant::now();
                progress = true;
            }
            Err(e) => return Err(e),
        }
        if !progress {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    Ok(())
}

/// Helper to build a "tunnel byte sink" for the CLI's direct-tunnel mode
/// (proxy-only, no TUN): forwards into a CH_PROXY connection.
pub use wire::ProxyTunneler;
