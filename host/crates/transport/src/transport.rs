//! Transport abstraction — the ULP session speaks ONLY this trait.
//!
//! docs/02 (protocol) is byte-oriented but transport-agnostic: the
//! same frames run over TCP today, ADB reverse tunnels, and (later,
//! experimental) QUIC streams or an encrypted relay. `Transport` is
//! the contract; `Framed<S>` provides byte-stream framing for any
//! `Read + Write` stream, so a new transport is an adapter, not a
//! rewrite of the session or protocol layers.
//!
//! Byte reservoir invariant: both `read_frame` and `read_exact`
//! consume from the SAME internal buffer before touching the stream.
//! This matters because a single stream read can contain multiple
//! frames (TCP coalescing); an implementation that lets the frame
//! path and the raw path read independently would silently drop the
//! coalesced bytes.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use unilink_protocol::error::{ErrorKind, ProtocolError, Result};
use unilink_protocol::frame::{decode, Frame};

const MAX_READ: usize = 256 * 1024;

/// Frame-level bidirectional ULP transport.
pub trait Transport {
    /// Read exactly one frame (reassembly handled by the transport).
    fn read_frame(&mut self, timeout: Duration) -> Result<Frame>;
    /// Write exactly one frame.
    fn write_frame(&mut self, frame: &Frame) -> Result<()>;
    /// Send raw wire bytes (encrypted data path; AAD||ciphertext).
    fn write_raw(&mut self, data: &[u8]) -> Result<()>;
    /// Read exactly `n` raw wire bytes (handshake / encrypted header).
    fn read_exact(&mut self, n: usize, timeout: Duration) -> Result<Vec<u8>>;
    /// Close the underlying channel (best effort).
    fn shutdown(&mut self);
    /// Stable identifier for logs/telemetry: "tcp", "adb", "quic".
    fn name(&self) -> &'static str;
}

/// Optional read-deadline support on the underlying stream.
/// Default: unsupported (reads are blocking). `TcpStream` opts in.
pub trait StreamDeadline {
    fn set_read_timeout(&mut self, _deadline: Option<Duration>) {}
}

impl StreamDeadline for TcpStream {
    fn set_read_timeout(&mut self, deadline: Option<Duration>) {
        let _ = TcpStream::set_read_timeout(self, deadline);
    }
}

/// Generic byte-stream framer: `Transport` over any `Read + Write`
/// stream with the (single) reassembly implementation.
pub struct Framed<S: Read + Write + StreamDeadline> {
    stream: S,
    rx: Vec<u8>,
    name: &'static str,
}

impl<S: Read + Write + StreamDeadline> Framed<S> {
    pub fn new(stream: S, name: &'static str) -> Self {
        Self { stream, rx: Vec::with_capacity(64 * 1024), name }
    }

    pub fn as_stream(&self) -> &S { &self.stream }
    pub fn as_stream_mut(&mut self) -> &mut S { &mut self.stream }
    pub fn into_inner(self) -> S { self.stream }

    fn fill(&mut self, deadline: Option<Duration>) -> Result<()> {
        self.stream.set_read_timeout(deadline);
        let mut buf = vec![0u8; MAX_READ];
        match self.stream.read(&mut buf) {
            Ok(0) => {
                Err(ProtocolError::new(ErrorKind::Io,
                    "connection closed by peer"))
            }
            Ok(n) => {
                self.rx.extend_from_slice(&buf[..n]);
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Err(ProtocolError::new(ErrorKind::Timeout, "read timeout"))
            }
            Err(e) => Err(ProtocolError::new(ErrorKind::Io, e.to_string())),
        }
    }

    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        let mut off = 0usize;
        while off < data.len() {
            match self.stream.write(&data[off..]) {
                Ok(0) => {
                    return Err(ProtocolError::new(ErrorKind::Io,
                        "zero-byte write"))
                }
                Ok(n) => off += n,
                Err(e) => {
                    return Err(ProtocolError::new(ErrorKind::Io, e.to_string()))
                }
            }
        }
        self.stream
            .flush()
            .map_err(|e| ProtocolError::new(ErrorKind::Io, e.to_string()))
    }
}

impl<S: Read + Write + StreamDeadline> Transport for Framed<S> {
    fn read_frame(&mut self, timeout: Duration) -> Result<Frame> {
        loop {
            match decode(&self.rx, 0) {
                Ok((frame, off)) => {
                    self.rx.drain(..off);
                    if self.rx.len() > 1024 * 1024 {
                        self.rx.shrink_to_fit();
                    }
                    return Ok(frame);
                }
                Err(e) if e.kind == ErrorKind::Incomplete => {}
                Err(e) => return Err(e),
            }
            if self.rx.len() > MAX_READ * 2 {
                return Err(ProtocolError::new(
                    ErrorKind::BadLength,
                    "rx buffer overgrown (peer not speaking ULP?)"));
            }
            self.fill(Some(timeout))?;
        }
    }

    fn write_frame(&mut self, frame: &Frame) -> Result<()> {
        let wire = frame.encode();
        self.write_all(&wire)
    }

    fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        self.write_all(data)
    }

    fn read_exact(&mut self, n: usize, timeout: Duration) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let take = (n - out.len()).min(self.rx.len());
            out.extend_from_slice(&self.rx[..take]);
            self.rx.drain(..take);
            if out.len() < n {
                self.fill(Some(timeout))?;
            }
        }
        Ok(out)
    }

    fn shutdown(&mut self) {
        // Generic streams have no portable close; concrete transports
        // (e.g. FramedConn) override this with a real shutdown.
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Condvar, Mutex};

    /// In-memory byte channel with a per-read byte cap: forces
    /// partial reads so the framer's reassembly is actually exercised.
    struct Chan {
        buf: Mutex<Vec<u8>>,
        cv: Condvar,
        read_cap: usize,
    }

    struct DuplexEnd {
        in_: Arc<Chan>,
        out: Arc<Chan>,
    }

    fn duplex(read_cap: usize) -> (DuplexEnd, DuplexEnd) {
        let a_to_b = Arc::new(Chan { buf: Mutex::new(Vec::new()), cv: Condvar::new(), read_cap });
        let b_to_a = Arc::new(Chan { buf: Mutex::new(Vec::new()), cv: Condvar::new(), read_cap });
        (
            DuplexEnd { in_: b_to_a.clone(), out: a_to_b.clone() },
            DuplexEnd { in_: a_to_b, out: b_to_a },
        )
    }

    impl Read for DuplexEnd {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let (data, n) = {
                let mut guard = self.in_.buf.lock().unwrap();
                while guard.is_empty() {
                    guard = self.in_.cv.wait(guard).unwrap();
                }
                let n = self.in_.read_cap.min(buf.len()).min(guard.len());
                (guard[..n].to_vec(), n)
            };
            let mut guard = self.in_.buf.lock().unwrap();
            guard.drain(..n);
            buf[..n].copy_from_slice(&data);
            Ok(n)
        }
    }

    impl Write for DuplexEnd {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            {
                let mut guard = self.out.buf.lock().unwrap();
                guard.extend_from_slice(buf);
            }
            self.out.cv.notify_one();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }

    impl StreamDeadline for DuplexEnd {}

impl Framed<DuplexEnd> {
    /// test helper: write several slices in ONE write() call
    /// (single pipe delivery => coalescing)
    fn write_all_for_test(&mut self, slices: &[&[u8]]) {
        let mut all = Vec::new();
        for s in slices {
            all.extend_from_slice(s);
        }
        self.write_all(&all).unwrap();
    }
}

    fn frame(ch: u8, flags: u8, payload: Vec<u8>) -> Frame {
        Frame::new(ch, flags, payload).unwrap()
    }

    #[test]
    fn framed_roundtrip_over_pipe() {
        let (a, b) = duplex(7); // brutal 7-byte reads
        let mut ta = Framed::new(a, "pipe");
        let mut tb = Framed::new(b, "pipe");
        let handle = std::thread::spawn(move || {
            let mut out = Vec::new();
            for i in 0..3u8 {
                let f = tb
                    .read_frame(Duration::from_secs(5))
                    .unwrap();
                assert_eq!(f.channel, 0x05);
                assert_eq!(f.payload[0], i);
                out.push(f.payload.len());
            }
            out
        });
        ta.write_frame(&frame(0x05, 0, vec![0u8])).unwrap();
        ta.write_frame(&frame(0x05, 0, vec![1, 2, 3, 4, 5])).unwrap();
        ta.write_frame(&frame(0x05, 0, vec![6u8; 40_000])).unwrap();
        assert_eq!(handle.join().unwrap(), vec![1, 5, 40_000]);
    }

    #[test]
    fn framed_ext_length_frame_over_pipe() {
        // payload >= 0x8000 exercises the 11-byte extended header
        let (a, b) = duplex(3);
        let mut ta = Framed::new(a, "pipe");
        let mut tb = Framed::new(b, "pipe");
        let big = vec![0xA5u8; 0x8000 + 123];
        ta.write_frame(&frame(0x01, 0, big.clone())).unwrap();
        let f = tb.read_frame(Duration::from_secs(5)).unwrap();
        assert_eq!(f.payload, big);
    }

    #[test]
    fn framed_coalesced_frames_then_raw_path() {
        // reservoir invariant: two frames in one write, consumed via
        // read_frame twice, then the raw path sees ONLY subsequent bytes
        let (a, b) = duplex(1);
        let mut ta = Framed::new(a, "pipe");
        let mut tb = Framed::new(b, "pipe");
        let f1 = frame(0x00, 0, vec![0xDE]).encode();
        let f2 = frame(0x00, 0, vec![0xAD, 0xBE]).encode();
        ta.write_all_for_test(&[&f1[..], &f2[..]]);
        let g1 = tb.read_frame(Duration::from_secs(5)).unwrap();
        assert_eq!(g1.payload, vec![0xDE]);
        let g2 = tb.read_frame(Duration::from_secs(5)).unwrap();
        assert_eq!(g2.payload, vec![0xAD, 0xBE]);
        // raw write + raw read must not be contaminated by the
        // frame path's buffer
        ta.write_raw(b"RAWRAW").unwrap();
        let raw = tb.read_exact(6, Duration::from_secs(5)).unwrap();
        assert_eq!(raw, b"RAWRAW");
    }

    #[test]
    fn framed_garbage_rejected() {
        let (a, b) = duplex(64);
        let mut ta = Framed::new(a, "pipe");
        let mut tb = Framed::new(b, "pipe");
        // bad magic
        ta.write_raw(&[0x56, 0x4C, 0x01, 0x00, 0x00, 0x00, 0x00])
            .unwrap();
        let e = tb.read_frame(Duration::from_secs(5)).unwrap_err();
        assert_eq!(e.kind, ErrorKind::BadMagic);
    }

    #[test]
    fn framed_name() {
        let (a, _b) = duplex(64);
        let t = Framed::new(a, "unit-test");
        assert_eq!(t.name(), "unit-test");
    }
}
