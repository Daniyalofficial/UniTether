//! Framed ULP transport over a TCP stream (byte-stream reassembly).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use unilink_protocol::error::{ErrorKind, ProtocolError, Result};
use unilink_protocol::frame::{decode, Frame};

const MAX_READ: usize = 256 * 1024;

pub struct FramedConn {
    stream: TcpStream,
    rx: Vec<u8>,
}

impl FramedConn {
    pub fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        stream.set_keepalive(true)?;
        Ok(Self { stream, rx: Vec::with_capacity(64 * 1024) })
    }

    pub fn from_stream(stream: TcpStream) -> std::io::Result<Self> {
        stream.set_nodelay(true)?;
        stream.set_keepalive(true)?;
        Ok(Self { stream, rx: Vec::with_capacity(64 * 1024) })
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.stream.local_addr()
    }
    pub fn remote_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.stream.peer_addr()
    }

    /// Read exactly one frame, waiting up to `timeout` for data.
    pub fn read_frame(&mut self, timeout: Duration) -> Result<Frame> {
        loop {
            match decode(&self.rx, 0) {
                Ok((frame, off)) => {
                    self.rx.drain(..off);
                    if self.rx.len() > 1024 * 1024 { self.rx.shrink_to_fit(); }
                    return Ok(frame);
                }
                Err(e) if e.kind == ErrorKind::Incomplete => {}
                Err(e) => return Err(e),
            }
            if self.rx.len() > MAX_READ * 2 {
                return Err(ProtocolError::new(ErrorKind::BadLength,
                    "rx buffer overgrown (peer not speaking ULP?)"));
            }
            self.stream
                .set_read_timeout(Some(timeout))
                .map_err(|e| ProtocolError::new(ErrorKind::Io, e.to_string()))?;
            let mut buf = vec![0u8; MAX_READ];
            match self.stream.read(&mut buf) {
                Ok(0) => {
                    return Err(ProtocolError::new(ErrorKind::Io,
                        "connection closed by peer"));
                }
                Ok(n) => self.rx.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(ProtocolError::new(ErrorKind::Timeout,
                        "read timeout"));
                }
                Err(e) => return Err(ProtocolError::new(ErrorKind::Io, e.to_string())),
            }
        }
    }

    pub fn write_frame(&mut self, frame: &Frame) -> Result<()> {
        let wire = frame.encode();
        self.stream
            .write_all(&wire)
            .map_err(|e| ProtocolError::new(ErrorKind::Io, e.to_string()))?;
        self.stream
            .flush()
            .map_err(|e| ProtocolError::new(ErrorKind::Io, e.to_string()))
    }

    /// Send the exact raw bytes (used for the encrypted send path).
    pub fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        self.stream
            .write_all(data)
            .map_err(|e| ProtocolError::new(ErrorKind::Io, e.to_string()))?;
        self.stream
            .flush()
            .map_err(|e| ProtocolError::new(ErrorKind::Io, e.to_string()))
    }

    /// Read exactly `n` raw bytes (handshake path).
    pub fn read_exact(&mut self, n: usize, timeout: Duration) -> Result<Vec<u8>> {
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| ProtocolError::new(ErrorKind::Io, e.to_string()))?;
        let mut out = vec![0u8; n];
        let mut filled = 0usize;
        while filled < n {
            match self.stream.read(&mut out[filled..]) {
                Ok(0) => {
                    return Err(ProtocolError::new(ErrorKind::Io,
                        "connection closed by peer"));
                }
                Ok(k) => filled += k,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(ProtocolError::new(ErrorKind::Timeout,
                        "read timeout"));
                }
                Err(e) => {
                    return Err(ProtocolError::new(ErrorKind::Io, e.to_string()))
                }
            }
        }
        Ok(out)
    }

    pub fn shutdown(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
    pub fn into_stream(self) -> TcpStream { self.stream }
}

pub fn listen(addr: &str) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(false)?;
    Ok(listener)
}
