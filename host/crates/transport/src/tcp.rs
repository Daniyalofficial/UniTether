//! Framed ULP transport over a TCP stream (byte-stream reassembly).
//!
//! The framing itself lives in [`crate::transport::Framed`] (shared
//! with any future byte-stream transport); this module is the TCP
//! adapter: connect/listen + address accessors + real shutdown.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use unilink_protocol::error::Result;
use unilink_protocol::frame::Frame;

use crate::transport::{Framed, Transport};

pub struct FramedConn {
    inner: Framed<TcpStream>,
}

impl FramedConn {
    pub fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        stream.set_keepalive(true)?;
        Ok(Self { inner: Framed::new(stream, "tcp") })
    }

    pub fn from_stream(stream: TcpStream) -> std::io::Result<Self> {
        stream.set_nodelay(true)?;
        stream.set_keepalive(true)?;
        Ok(Self { inner: Framed::new(stream, "tcp") })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.as_stream().local_addr()
    }
    pub fn remote_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.as_stream().peer_addr()
    }
    pub fn into_stream(self) -> TcpStream { self.inner.into_inner() }
}

impl Transport for FramedConn {
    fn read_frame(&mut self, timeout: Duration) -> Result<Frame> {
        self.inner.read_frame(timeout)
    }
    fn write_frame(&mut self, frame: &Frame) -> Result<()> {
        self.inner.write_frame(frame)
    }
    fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        self.inner.write_raw(data)
    }
    fn read_exact(&mut self, n: usize, timeout: Duration) -> Result<Vec<u8>> {
        self.inner.read_exact(n, timeout)
    }
    fn shutdown(&mut self) {
        let _ = self
            .inner
            .as_stream_mut()
            .shutdown(std::net::Shutdown::Both);
    }
    fn name(&self) -> &'static str {
        "tcp"
    }
}

pub fn listen(addr: &str) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(false)?;
    Ok(listener)
}
