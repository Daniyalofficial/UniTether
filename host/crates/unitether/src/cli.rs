//! Hand-rolled CLI argument parsing (no external deps).

#[derive(Debug, Clone, PartialEq)]
pub enum SubCommand {
    Connect {
        address: String,
        secret: String,
        proxy: Option<u16>,
        http_proxy: Option<u16>,
        no_tunnel: bool,
        stats: bool,
    },
    Discover {
        timeout_secs: u64,
    },
    Pair {
        name: String,
    },
    Version,
    Help,
}

fn usage() -> String {
    "UniTether — production reverse tethering (IPv4+IPv6, video, audio, files)

usage:
  unitether connect <addr> <pairing-secret> [--socks-port N] [--http-port N]
                    [--no-tunnel] [--stats]
      Connect to a device (tcp addr or ADB: for adb forward) using the
      pairing secret from `unitether pair`.

  unitether discover [--timeout N]
      Find UniLink peers on the LAN via mDNS.

  unitether pair [--name NAME]
      Print a pairing secret + QR-encodable blob (scan from the device).

  unitether version
  unitether help
"
    .to_string()
}

fn parse_value<'a>(args: &'a [String], i: &mut usize, flag: &str) -> Option<String> {
    let a = args.get(*i)?;
    if let Some(rest) = a.strip_prefix("--").and_then(|s| s.strip_prefix(flag)) {
        if rest.starts_with('=') {
            Some(rest[1..].to_string())
        } else if rest.is_empty() {
            *i += 1;
            args.get(*i).cloned()
        } else {
            None
        }
    } else {
        None
    }
}

pub fn parse(args: &[String]) -> SubCommand {
    let mut i = 1usize;
    if i >= args.len() {
        return SubCommand::Help;
    }
    let cmd = args[i].clone();
    i += 1;
    match cmd.as_str() {
        "connect" => {
            let address = args.get(i).cloned().unwrap_or_default();
            i += 1;
            let secret = args.get(i).cloned().unwrap_or_default();
            i += 1;
            let mut proxy = None;
            let mut http_proxy = None;
            let mut no_tunnel = false;
            let mut stats = false;
            while i < args.len() {
                let a = args[i].clone();
                if let Some(v) = parse_value(&args, &mut i, "socks-port") {
                    proxy = v.parse().ok();
                } else if let Some(v) = parse_value(&args, &mut i, "http-port") {
                    http_proxy = v.parse().ok();
                } else if a == "--no-tunnel" {
                    no_tunnel = true;
                } else if a == "--stats" {
                    stats = true;
                } else {
                    eprintln!("warning: unknown flag {a}");
                }
                i += 1;
            }
            SubCommand::Connect { address, secret, proxy, http_proxy, no_tunnel, stats }
        }
        "discover" => {
            let mut timeout = 3;
            while i < args.len() {
                if let Some(v) = parse_value(&args, &mut i, "timeout") {
                    timeout = v.parse().unwrap_or(3);
                }
                i += 1;
            }
            SubCommand::Discover { timeout_secs: timeout }
        }
        "pair" => {
            let mut name = "UniTether Host".to_string();
            while i < args.len() {
                if let Some(v) = parse_value(&args, &mut i, "name") {
                    name = v;
                }
                i += 1;
            }
            SubCommand::Pair { name }
        }
        "version" | "-V" | "--version" => SubCommand::Version,
        "help" | "-h" | "--help" => SubCommand::Help,
        other => {
            eprintln!("unknown command: {other}\n");
            eprintln!("{}", usage());
            SubCommand::Help
        }
    }
}

pub fn print_usage() {
    println!("{}", usage());
}
