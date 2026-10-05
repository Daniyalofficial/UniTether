//! Minimal HTTP proxy: CONNECT tunneling + absolute-URI GET/POST
//! forwarding (enough for browser + curl use against the phone).

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::AtomicU64;

use crate::{pump, Tunneler};

const MAX_HEAD: usize = 64 * 1024;

pub fn handle(mut stream: TcpStream, tunnel: &dyn Tunneler, forwarded: &AtomicU64) -> std::io::Result<()> {
    // read request head
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    loop {
        if buf.len() > MAX_HEAD {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
                "request head too large"));
        }
        let n = stream.read(&mut tmp)?;
        if n == 0 { break; }
        buf.extend_from_slice(&tmp[..n]);
        if head_complete(&buf) { break; }
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let _version = parts.next().unwrap_or("");

    if method == "CONNECT" {
        let (host, port) = parse_connect_target(target)?;
        let mut tstream = tunnel.connect(host, port).map_err(|e| {
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
            e
        })?;
        stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
        stream.flush()?;
        return pump(&mut stream, &mut tstream, forwarded, std::time::Duration::from_secs(300));
    }

    if method != "GET" && method != "POST" && method != "PUT" && method != "HEAD" && method != "DELETE" {
        return write_err(&mut stream, "501 Not Implemented");
    }

    // absolute-form target: http://host[:port]/path
    let (host, port, path) = parse_absolute_target(target)?;
    let mut tstream = tunnel.connect(host, port).map_err(|e| {
        let _ = write_err(&mut stream, "502 Bad Gateway");
        e
    })?;
    // rewrite to origin-form
    let mut rewritten = head;
    if let Some(pos) = rewritten.find(target) {
        rewritten.replace_range(pos..pos + target.len(), path);
    }
    tstream.write_all(rewritten.as_bytes())?;
    // forward the request body if any (content-length known)
    let content_length = head
        .lines()
        .find_map(|l| {
            let l = l.trim_end();
            let lower = l.to_ascii_lowercase();
            lower.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    if content_length > 0 {
        let mut body = vec![0u8; content_length.min(16 * 1024 * 1024)];
        stream.read_exact(&mut body)?;
        tstream.write_all(&body)?;
    }
    // pump response back
    pump(&mut stream, &mut tstream, forwarded, std::time::Duration::from_secs(300))
}

fn head_complete(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"\r\n\r\n")
}

fn parse_connect_target(target: &str) -> std::io::Result<(IpAddr, u16)> {
    let (host, port) = target.rsplit_once(':').unwrap_or((target, "443"));
    let port: u16 = port.parse().map_err(|_| bad("port"))?;
    let host = host.to_string();
    let ip = resolve_host(&host)?;
    Ok((ip, port))
}

fn parse_absolute_target(target: &str) -> std::io::Result<(IpAddr, u16, String)> {
    let after_scheme = target.strip_prefix("http://").ok_or_else(|| bad("scheme"))?;
    let (hostport, path) = match after_scheme.find('/') {
        Some(i) => (&after_scheme[..i], &after_scheme[i..]),
        None => (after_scheme, "/"),
    };
    let (host, port) = hostport.rsplit_once(':').unwrap_or((hostport, "80"));
    let port: u16 = port.parse().map_err(|_| bad("port"))?;
    let ip = resolve_host(host)?;
    Ok((ip, port, path.to_string()))
}

fn resolve_host(host: &str) -> std::io::Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    std::net::ToSocketAddrs::to_socket_addrs(&(host.to_string(), 0))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput,
            format!("dns: {e}")))?
        .next()
        .map(|a: SocketAddr| a.ip())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput,
            "dns: no result"))
}

fn bad(what: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput,
        format!("http proxy: bad {what}"))
}

fn write_err(stream: &mut TcpStream, status: &str) -> std::io::Result<()> {
    stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
}
