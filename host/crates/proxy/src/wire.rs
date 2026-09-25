//! CH_PROXY wire layout (channel 0x0B) — connection-multiplexed TCP over
//! the ULP session.
//!
//! ```text
//! u8  op        0x01 connect_req | 0x02 connect_ok | 0x03 connect_err
//!               0x04 data        | 0x05 close
//! u32 conn_id   BE   (assigned by the device side; 0 in connect_req)
//! connect_req: u8 family (0=IPv4, 1=IPv6)
//!               4/16 B addr
//!               u16be port
//! connect_err: u8 reason
//! data:        raw bytes
//! ```

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use unilink_protocol::frame::ch;
use unilink_transport::session::Session;

use crate::{Tunneler, TunnelerStream};

const OP_CONNECT_REQ: u8 = 0x01;
const OP_CONNECT_OK: u8 = 0x02;
const OP_CONNECT_ERR: u8 = 0x03;
const OP_DATA: u8 = 0x04;
const OP_CLOSE: u8 = 0x05;

enum In {
    NewConn(IpAddr, u16, Sender<io::Result<ProxyStream>>),
}
enum Out {
    Data(u32, Vec<u8>),
    Close(u32),
}

pub struct ProxyStream {
    id: u32,
    rx: Receiver<Vec<u8>>,
    tx: Sender<Out>,
}

impl TunnelerStream for ProxyStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.tx.send(Out::Data(self.id, buf.to_vec())).map_err(|_| io::Error::new(
            io::ErrorKind::BrokenPipe, "proxy dispatcher gone"))
    }
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let data = self.rx.recv().map_err(|_| io::Error::new(
            io::ErrorKind::ConnectionAborted, "proxy connection closed"))?;
        if data.is_empty() { return Ok(0); }
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }
    fn close(&mut self) -> io::Result<()> {
        let _ = self.tx.send(Out::Close(self.id));
        Ok(())
    }
}

/// Tunneler backed by a live ULP session. One dispatcher thread owns the
/// session and routes CH_PROXY frames to per-connection channels.
pub struct ProxyTunneler {
    in_tx: Sender<In>,
    _handle: std::thread::JoinHandle<()>,
}

impl ProxyTunneler {
    pub fn new(session: Arc<Mutex<Session>>) -> Self {
        let (in_tx, in_rx) = channel::<In>();
        let (out_tx, out_rx) = channel::<Out>();
        let out_tx_clone = out_tx.clone();
        let handle = std::thread::spawn(move || {
            let mut session = session.lock().unwrap();
            let mut pending: Vec<(IpAddr, u16, Sender<io::Result<ProxyStream>>)> = Vec::new();
            let mut streams: HashMap<u32, Receiver<Vec<u8>>> = HashMap::new();
            loop {
                // 1) new connections
                while let Ok(In::NewConn(addr, port, reply)) = in_rx.try_recv() {
                    pending.push((addr, port, reply));
                }
                while let Some((addr, port, reply)) = pending.pop() {
                    let mut body = Vec::with_capacity(12);
                    body.push(OP_CONNECT_REQ);
                    body.extend_from_slice(&0u32.to_be_bytes());
                    match addr {
                        IpAddr::V4(a) => { body.push(0); body.extend_from_slice(&a.octets()); }
                        IpAddr::V6(a) => { body.push(1); body.extend_from_slice(&a.octets()); }
                    }
                    body.extend_from_slice(&port.to_be_bytes());
                    if let Err(e) = session.send(ch::PROXY, 0, body) {
                        let _ = reply.send(Err(io::Error::new(
                            io::ErrorKind::Other, format!("proxy: {e}"))));
                        continue;
                    }
                    // wait for connect_ok / connect_err
                    let deadline = Instant::now() + Duration::from_secs(10);
                    let mut answered = false;
                    while !answered && Instant::now() < deadline {
                        let remain = deadline.saturating_duration_since(Instant::now());
                        match session.recv(remain) {
                            Ok(f) if f.channel == ch::PROXY && f.payload.len() >= 5 => {
                                let op = f.payload[0];
                                let id = u32::from_be_bytes(f.payload[1..5].try_into().unwrap());
                                match op {
                                    OP_CONNECT_OK => {
                                        let (srx, srx_t) = channel::<Vec<u8>>();
                                        streams.insert(id, srx);
                                        let _ = reply.send(Ok(ProxyStream {
                                            id, rx: srx_t, tx: out_tx_clone.clone(),
                                        }));
                                        answered = true;
                                    }
                                    OP_CONNECT_ERR => {
                                        let reason = f.payload.get(5).copied().unwrap_or(1);
                                        let _ = reply.send(Err(io::Error::new(
                                            io::ErrorKind::ConnectionRefused,
                                            format!("proxy: device refused (reason {reason})"))));
                                        answered = true;
                                    }
                                    OP_DATA => {
                                        if let Some(r) = streams.get(&id) {
                                            let _ = r.try_send(f.payload[5..].to_vec());
                                        }
                                    }
                                    OP_CLOSE => {
                                        if let Some(r) = streams.remove(&id) {
                                            let _ = r.try_send(Vec::new());
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            Ok(_) => {} // other channels
                            Err(e) if e.kind == unilink_protocol::error::ErrorKind::Timeout => {}
                            Err(_) => {
                                let _ = reply.send(Err(io::Error::new(
                                    io::ErrorKind::BrokenPipe, "proxy: session closed")));
                                return;
                            }
                        }
                    }
                    if !answered {
                        let _ = reply.send(Err(io::Error::new(
                            io::ErrorKind::TimedOut, "proxy: connect timeout")));
                    }
                }
                // 2) outbound writes / closes
                while let Ok(msg) = out_rx.try_recv() {
                    let ok = match msg {
                        Out::Data(id, bytes) => {
                            let mut body = Vec::with_capacity(5 + bytes.len());
                            body.push(OP_DATA);
                            body.extend_from_slice(&id.to_be_bytes());
                            body.extend_from_slice(&bytes);
                            session.send(ch::PROXY, 0, body).is_ok()
                        }
                        Out::Close(id) => {
                            streams.remove(&id);
                            let mut body = vec![OP_CLOSE];
                            body.extend_from_slice(&id.to_be_bytes());
                            session.send(ch::PROXY, 0, body).is_ok()
                        }
                    };
                    if !ok { return; }
                }
                // 3) incoming frames
                match session.recv(Duration::from_millis(25)) {
                    Ok(f) if f.channel == ch::PROXY && f.payload.len() >= 5 => {
                        let op = f.payload[0];
                        let id = u32::from_be_bytes(f.payload[1..5].try_into().unwrap());
                        if let Some(r) = streams.get(&id) {
                            let payload = if op == OP_DATA {
                                f.payload[5..].to_vec()
                            } else {
                                Vec::new()
                            };
                            if op != OP_DATA { streams.remove(&id); }
                            let _ = r.try_send(payload);
                        }
                    }
                    Ok(_) => {}
                    Err(e) if e.kind == unilink_protocol::error::ErrorKind::Timeout => {}
                    Err(_) => return, // session dead
                }
            }
        });
        Self { in_tx, _handle: handle }
    }
}

impl Tunneler for ProxyTunneler {
    fn connect(&self, host: IpAddr, port: u16) -> Result<Box<dyn TunnelerStream>, io::Error> {
        let (tx, rx) = channel::<io::Result<ProxyStream>>();
        self.in_tx.send(In::NewConn(host, port, tx)).map_err(|_| io::Error::new(
            io::ErrorKind::BrokenPipe, "proxy dispatcher gone"))?;
        let stream = rx.recv().map_err(|_| io::Error::new(
            io::ErrorKind::BrokenPipe, "proxy dispatcher gone"))??;
        Ok(Box::new(stream))
    }

    fn bytes_forwarded(&self) -> u64 {
        0 // the ProxyServer's `forwarded` counter tracks real bytes
    }
}
