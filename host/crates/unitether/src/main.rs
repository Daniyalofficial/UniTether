//! UniTether CLI — host-side entry point.

mod cli;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use unilink_protocol::channel::VideoFrame;
use unilink_protocol::frame::ch;
use unilink_protocol::message::{
    StatCounters, TunnelConfig, MSG_BYE, MSG_CONFIG, MSG_PONG, MSG_STATS_REQ,
    MSG_STATS_RSP, MSG_TUN_UP,
};
use unilink_protocol::pairing::{pairing_blob, pairing_parse};
use unilink_proxy::{ProxyMode, ProxyServer, ProxyTunneler};
use unilink_transport::adb::AdbForward;
use unilink_transport::mdns::{MdnsAdvertiser, MdnsPeer};
use unilink_transport::session::Session;
use unilink_transport::tcp::FramedConn;
use unilink_tunnel::{packet_family, TunDevice};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = cli::parse(&args);
    let code = match cmd {
        cli::SubCommand::Version => {
            println!("unitether {}", env!("CARGO_PKG_VERSION"));
            0
        }
        cli::SubCommand::Help => {
            cli::print_usage();
            0
        }
        cli::SubCommand::Pair { name } => cmd_pair(name),
        cli::SubCommand::Discover { timeout_secs } => cmd_discover(timeout_secs),
        cli::SubCommand::Connect { address, secret, proxy, http_proxy, no_tunnel, stats } => {
            cmd_connect(address, secret, proxy, http_proxy, no_tunnel, stats)
        }
    };
    std::process::exit(code);
}

// ------------------------------------------------------------------ pair
fn cmd_pair(name: String) -> i32 {
    let secret_bytes = unilink_transport::rand::random_bytes(32);
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);
    let blob = pairing_blob(&secret, &name);
    println!("Pairing secret (32 B, hex):");
    println!("  {}", hex(&secret));
    println!();
    println!("Pairing blob (show as QR on the host, scan from the device):");
    println!("  {blob}");
    println!();
    println!("Then run: unitether connect <device-addr> <blob-or-hex>");
    0
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_secret(input: &str) -> std::io::Result<[u8; 32]> {
    // Accept the full pairing blob or a bare 64-char hex secret.
    if input.starts_with("UNITETHER1:") {
        let (s, _name) = pairing_parse(input).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
        })?;
        return Ok(s);
    }
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() == 64 {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad hex")
            })?;
        }
        return Ok(out);
    }
    // bare base64url secret
    let b = unilink_protocol::base64url_decode(&clean).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
    })?;
    if b.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&b);
        return Ok(out);
    }
    Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
        "secret must be a pairing blob, 64-hex, or base64url(32 B)"))
}

// -------------------------------------------------------------- discover
fn cmd_discover(timeout_secs: u64) -> i32 {
    println!("Scanning for UniLink peers (mDNS, _unilink._tcp.local) ...");
    let mut adv = match MdnsAdvertiser::new() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("mDNS unavailable: {e}");
            return 1;
        }
    };
    if let Err(e) = adv.send_query() {
        eprintln!("mDNS query failed: {e}");
        return 1;
    }
    let peers: Vec<MdnsPeer> = adv.collect(Duration::from_secs(timeout_secs));
    if peers.is_empty() {
        println!("no peers found.");
        return 1;
    }
    for p in peers {
        let name = p.txt.get("name").map(|s| s.as_str()).unwrap_or(&p.instance);
        let role = p.txt.get("role").map(|s| s.as_str()).unwrap_or("?");
        println!("  {:<24} role={:<7} port={:<5} at {}", name, role, p.port, p.addr);
    }
    0
}

// --------------------------------------------------------------- connect
fn cmd_connect(address: String, secret: String,
               socks: Option<u16>, http_port: Option<u16>,
               no_tunnel: bool, stats: bool) -> i32 {
    let secret = match parse_secret(&secret) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    // 1) transport
    let (addr, _adb) = match address.strip_prefix("ADB:") {
        Some(spec) => {
            let forward = match AdbForward::create(None, parse_port(spec)) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("adb forward failed: {e}");
                    return 3;
                }
            };
            (forward.local_addr(), Some(forward))
        }
        None => (address.clone(), None),
    };
    println!("connecting to {addr} ...");
    let conn = match FramedConn::connect(&addr) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("connect failed: {e}");
            return 3;
        }
    };
    let session = match Session::connect_host(conn, &secret) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("handshake failed: {e}");
            return 4;
        }
    };
    println!("handshake OK (cipher={:#x}, peer features={:#06x})",
        session.info.cipher_sel, session.info.peer_features);
    let session = Arc::new(Mutex::new(session));

    // 2) tunnel
    let mut tunnel_up = false;
    if !no_tunnel {
        match open_tun() {
            Ok(tun) => {
                if let Err(e) = configure_tun(&tun) {
                    eprintln!("tun configure failed ({e}); continuing proxy-only");
                } else {
                    let cfg = default_config();
                    let _ = { session.lock().unwrap().send_msg(MSG_CONFIG, &cfg.body()) };
                    let _ = { session.lock().unwrap().send_msg(MSG_TUN_UP, &[]) };
                    spawn_tun_pumps(Arc::clone(&session), tun);
                    tunnel_up = true;
                    println!("tunnel up (10.8.0.0/20, fd00:4c:55:01::/64)");
                }
            }
            Err(e) => {
                eprintln!("tunnel unavailable ({e}); continuing proxy-only");
            }
        }
    }

    // 3) proxies
    let mut proxy_threads = Vec::new();
    for (mode, port) in [(ProxyMode::Socks5, socks), (ProxyMode::Http, http_port)] {
        if let Some(port) = port {
            let addr = format!("127.0.0.1:{port}");
            match ProxyServer::new(&addr, mode, Arc::new(ProxyTunneler::new(Arc::clone(&session)))) {
                Ok(server) => {
                    let laddr = server.local_addr();
                    println!("{} proxy on {laddr}", match mode {
                        ProxyMode::Socks5 => "SOCKS5",
                        ProxyMode::Http => "HTTP",
                    });
                    proxy_threads.push(std::thread::spawn(move || { let _ = server.serve(); }));
                }
                Err(e) => eprintln!("proxy {port} failed: {e}"),
            }
        }
    }

    // 4) stats / liveness loop. When stats is enabled THIS thread owns
    // session message consumption; the wait loop below must not recv
    // (two consumers would steal each other's control frames). It polls
    // the `session_over` flag the stats thread raises on BYE / error.
    let session_over = Arc::new(std::sync::atomic::AtomicBool::new(false));
    if stats {
        println!("live stats (peer disconnect ends the session):");
        let s_stats = Arc::clone(&session);
        let over_stats = Arc::clone(&session_over);
        std::thread::spawn(move || loop {
            match s_stats.lock().unwrap().recv_msg(Duration::from_secs(1)) {
                Ok((MSG_STATS_RSP, _f, body)) => {
                    if let Ok(s) = StatCounters::parse(&body) {
                        println!("  in={:>10} B  out={:>10} B  video={:>10} B  audio={:>8} B  rtt={} ms  fps={}",
                            s.bytes_in, s.bytes_out, s.bytes_video, s.bytes_audio, s.rtt_ms, s.fps_video);
                    }
                }
                Ok((MSG_PONG, _f, _body)) => {}
                Ok((MSG_BYE, _f, _body)) => {
                    println!("device closed the session");
                    over_stats.store(true, std::sync::atomic::Ordering::SeqCst);
                    break;
                }
                Ok((other, _f, _b)) => {
                    println!("  (unhandled control {other:#x}, {} B)", _b.len());
                }
                Err(_) => {
                    over_stats.store(true, std::sync::atomic::Ordering::SeqCst);
                    break;
                }
            }
        });
        // periodic STATS_REQ + PING
        let s2 = Arc::clone(&session);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(5));
            let mut s = s2.lock().unwrap();
            let _ = s.send_msg(MSG_STATS_REQ, &[]);
            let _ = s.ping();
        });
    }

    // 5) wait for the session to end. With `--stats` the stats thread
    // consumes control frames, so this loop only polls the flag;
    // without it, it owns the receive side itself.
    println!("running. Peer disconnect or SIGTERM ends the session.");
    let _ = tunnel_up;
    let _ = proxy_threads;
    loop {
        if stats {
            if session_over.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        let result = {
            let mut s = session.lock().unwrap();
            s.recv_msg(Duration::from_secs(1))
        };
        match result {
            Ok((MSG_BYE, _f, _body)) => { println!("peer said BYE"); break; }
            Ok((other, _f, _body)) => {
                if other != MSG_STATS_RSP && other != MSG_PONG {
                    println!("control {other:#x} ({} B)", _body.len());
                }
            }
            Err(e) => { println!("session ended: {e}"); break; }
        }
    }
    let _ = { session.lock().unwrap().close(1) };
    0
}

fn parse_port(spec: &str) -> u16 { spec.parse().unwrap_or(0) }

fn default_config() -> TunnelConfig {
    TunnelConfig {
        v4_prefix: unilink_tunnel::DEFAULT_V4_PREFIX,
        v4_device: unilink_tunnel::DEFAULT_V4_DEVICE.octets(),
        v4_host: unilink_tunnel::DEFAULT_V4_HOST.octets(),
        v6_prefix: unilink_tunnel::DEFAULT_V6_PREFIX,
        v6_device: unilink_tunnel::DEFAULT_V6_DEVICE.octets(),
        v6_host: unilink_tunnel::DEFAULT_V6_HOST.octets(),
        dns: vec![[1, 1, 1, 1], [8, 8, 8, 8]],
        routes: vec![(0, [0, 0, 0, 0]), (64, [0, 0, 0, 0])],
    }
}

#[cfg(target_os = "linux")]
fn open_tun() -> std::io::Result<Box<dyn TunDevice>> {
    unilink_tunnel::tun_linux::TunLinux::open().map(|t| -> Box<dyn TunDevice> { Box::new(t) })
}

#[cfg(target_os = "macos")]
fn open_tun() -> std::io::Result<Box<dyn TunDevice>> {
    unilink_tunnel::tun_macos::TunMacos::open().map(|t| -> Box<dyn TunDevice> { Box::new(t) })
}

#[cfg(windows)]
fn open_tun() -> std::io::Result<Box<dyn TunDevice>> {
    unilink_tunnel::tun_windows::TunWindows::open("UniTether")
        .map(|t| -> Box<dyn TunDevice> { Box::new(t) })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn open_tun() -> std::io::Result<Box<dyn TunDevice>> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported,
        "native TUN not implemented on this OS; use --no-tunnel"))
}

fn configure_tun(tun: &Box<dyn TunDevice>) -> std::io::Result<()> {
    tun.configure(Some(Ipv4Addr::new(10, 8, 0, 1)), Some(Ipv6Addr::new(0xfd, 0, 0, 0, 0, 0, 0, 1)))
}

fn spawn_tun_pumps(session: Arc<Mutex<Session<FramedConn>>>,
                        mut tun: Box<dyn TunDevice>) {
    // TUN -> ULP
    let s1 = Arc::clone(&session);
    std::thread::spawn(move || loop {
        let packet = match tun.read_packet() {
            Ok(p) => p,
            Err(_) => break,
        };
        let ch = match packet_family(&packet) {
            4 => ch::TUN_V4,
            6 => ch::TUN_V6,
            _ => continue,
        };
        if s1.lock().unwrap().send(ch, 0, packet).is_err() { break; }
    });
    // ULP -> TUN
    std::thread::spawn(move || loop {
        let frame = match session.lock().unwrap().recv(Duration::from_secs(1)) {
            Ok(f) => f,
            Err(_) => break,
        };
        match frame.channel {
            ch::TUN_V4 | ch::TUN_V6 => { let _ = tun.write_packet(&frame.payload); }
            ch::VIDEO => {
                if let Ok(v) = VideoFrame::parse(&frame.payload) {
                    eprintln!("[video] {}x{} codec={:#x} seq={} {} B",
                        v.width, v.height, v.codec, v.seq, v.nal.len());
                }
            }
            ch::CLIPBOARD => {
                if let Ok(c) = unilink_protocol::channel::ClipboardUpdate::parse(&frame.payload) {
                    if c.direction == 0 {
                        println!("[clipboard] device -> host: {}",
                            String::from_utf8_lossy(&c.data));
                    }
                }
            }
            ch::NOTIFICATION => {
                if let Ok(n) = unilink_protocol::channel::Notification::parse(&frame.payload) {
                    println!("[notification] {} — {}: {}", n.app, n.title, n.body);
                }
            }
            _ => {}
        }
    });
}
