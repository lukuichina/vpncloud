// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;

#[cfg(test)]
extern crate tempfile;

#[macro_use]
pub mod util;
#[cfg(test)]
#[macro_use]
mod tests;
pub mod beacon;
pub mod channel_io;
pub mod cloud;
pub mod config;
pub mod crypto;
pub mod device;
pub mod error;
#[cfg(feature = "installer")]
pub mod installer;
pub mod messages;
pub mod net;
pub mod oldconfig;
pub mod payload;
pub mod poll;
pub mod port_forwarding;
pub mod table;
pub mod traffic;
pub mod types;
#[cfg(feature = "wizard")]
pub mod wizard;
#[cfg(feature = "websocket")]
pub mod wsproxy;

use structopt::StructOpt;

use std::{
    fs::{self, File, Permissions},
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, UdpSocket},
    path::Path,
    process,
    str::FromStr,
    sync::Mutex,
    thread,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::{
    cloud::GenericCloud,
    config::{Args, Command, Config, DEFAULT_PORT},
    crypto::Crypto,
    device::{Device, TunTapDevice, Type},
    net::Socket,
    oldconfig::OldConfigFile,
    payload::Protocol,
    util::SystemTimeSource,
    types::Address,
};

#[cfg(feature = "websocket")]
use crate::wsproxy::ProxyConnection;

struct DualLogger {
    file: Option<Mutex<File>>,
}

impl DualLogger {
    pub fn new<P: AsRef<Path>>(path: Option<P>) -> Result<Self, io::Error> {
        if let Some(path) = path {
            let path = path.as_ref();
            if path.exists() {
                fs::remove_file(path)?
            }
            let file = File::create(path)?;
            Ok(DualLogger { file: Some(Mutex::new(file)) })
        } else {
            Ok(DualLogger { file: None })
        }
    }
}

impl log::Log for DualLogger {
    #[inline]
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    #[inline]
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
            if let Some(ref file) = self.file {
                let mut file = file.lock().expect("Lock poisoned");
                let time = chrono::Local::now().format("%F %H:%M:%S");
                writeln!(file, "{} - {} - {}", time, record.level(), record.args())
                    .expect("Failed to write to logfile");
            }
        }
    }

    #[inline]
    fn flush(&self) {
        if let Some(ref file) = self.file {
            let mut file = file.lock().expect("Lock poisoned");
            try_fail!(file.flush(), "Logging error: {}");
        }
    }
}

fn run_script(script: &str, ifname: &str) {
    let mut cmd = process::Command::new("sh");
    cmd.arg("-c").arg(script).env("IFNAME", ifname);
    debug!("Running script: {:?}", cmd);
    match cmd.status() {
        Ok(status) => {
            if !status.success() {
                error!("Script returned with error: {:?}", status.code())
            }
        }
        Err(e) => error!("Failed to execute script {:?}: {}", script, e),
    }
}

fn parse_ip_netmask(addr: &str) -> Result<(std::net::IpAddr, std::net::IpAddr), String> {
    let (ip_str, len_str) = match addr.find('/') {
        Some(pos) => (&addr[..pos], &addr[pos + 1..]),
        None => (addr, ""),
    };
    let ip = std::net::IpAddr::from_str(ip_str).map_err(|_| format!("Invalid ip address: {}", ip_str))?;
    let prefix_len = if len_str.is_empty() {
        match ip {
            std::net::IpAddr::V4(_) => 24,
            std::net::IpAddr::V6(_) => 64,
        }
    } else {
        u8::from_str(len_str).map_err(|_| format!("Invalid prefix length: {}", len_str))?
    };
    match ip {
        std::net::IpAddr::V4(_) => {
            if prefix_len > 32 {
                return Err(format!("Invalid prefix length: {}", prefix_len));
            }
            let netmask = std::net::Ipv4Addr::from(u32::max_value().checked_shl(32 - prefix_len as u32).unwrap());
            Ok((ip, std::net::IpAddr::V4(netmask)))
        }
        std::net::IpAddr::V6(_) => {
            if prefix_len > 128 {
                return Err(format!("Invalid prefix length: {}", prefix_len));
            }
            // IPv6 使用前缀长度表示，掩码地址用全 1 前缀 + 全 0 后缀构造
            let mut octets = [0u8; 16];
            let full_bytes = prefix_len / 8;
            let rem_bits = prefix_len % 8;
            for i in 0..full_bytes as usize {
                octets[i] = 0xff;
            }
            if rem_bits > 0 {
                octets[full_bytes as usize] = !(0xff >> rem_bits);
            }
            let netmask = std::net::Ipv6Addr::from(octets);
            Ok((ip, std::net::IpAddr::V6(netmask)))
        }
    }
}

fn setup_device(config: &Config) -> TunTapDevice {
    let mut device = try_fail!(
        TunTapDevice::new(&config.device_name, config.device_type, config.device_path.as_ref().map(|s| s as &str)),
        "Failed to open virtual {} interface {}: {}",
        config.device_type,
        config.device_name
    );
    info!("Opened device {}", device.ifname());
    config.call_hook("device_setup", vec![("IFNAME", device.ifname())], true);
    if let Err(err) = device.set_mtu(None) {
        error!("Error setting optimal MTU on {}: {}", device.ifname(), err);
    }
    // Configure interface addresses. Support dual-stack by applying --ip and, when
    // different, --ipv6 as an additional address on the same device.
    let mut configured_addrs: Vec<std::net::IpAddr> = Vec::new();
    let mut primary_addr: Option<String> = config.ip.clone();
    if primary_addr.is_none() {
        primary_addr = config.ipv6.clone();
    }
    if let Some(ref ip_str) = primary_addr {
        let (ip, netmask) = try_fail!(parse_ip_netmask(ip_str), "Invalid ip address given: {}");
        info!("Configuring device with primary ip {}, netmask {}", ip, netmask);
        if let Err(e) = device.configure(ip, netmask) {
            fail!("Failed to configure device: {}: {}", ip, e);
        }
        configured_addrs.push(ip);

        // Add IPv6 route for primary IPv6 claims (legacy behavior).
        if let IpAddr::V6(_) = ip {
            for claim_str in &config.claims {
                if let Ok(claim) = crate::types::Range::from_str(claim_str) {
                    if let Address { data, len: 16 } = claim.base {
                        let ip6 = std::net::Ipv6Addr::from(data);
                        let prefix = claim.prefix_len;
                        if prefix > 0 && prefix <= 128 {
                            let ifname = device.ifname();
                            let status = std::process::Command::new("ip")
                                .args(["route", "add", &format!("{}/{}", ip6, prefix), "dev", ifname])
                                .status();
                            match status {
                                Ok(s) if s.success() => {
                                    info!("Added IPv6 route {}/{} via dev {}", ip6, prefix, ifname);
                                }
                                Ok(s) => {
                                    warn!("Failed to add IPv6 route {}/{} via dev {}: status {:?}", ip6, prefix, ifname, s);
                                }
                                Err(e) => {
                                    warn!("Failed to add IPv6 route {}/{} via dev {}: {}", ip6, prefix, ifname, e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(ref ipv6_addr) = config.ipv6 {
        let already = config.ip.as_ref().map(|s| s == ipv6_addr).unwrap_or(false);
        if !already {
            let (ip, netmask) = try_fail!(parse_ip_netmask(ipv6_addr), "Invalid ipv6 address given: {}");
            if !configured_addrs.iter().any(|a| *a == ip) {
                info!("Configuring device with additional IPv6 address {}, netmask {}", ip, netmask);
                #[cfg(unix)]
                {
                    // Best-effort add secondary IPv6 on Unix/Linux TUN.
                    let prefix = match netmask {
                        IpAddr::V6(mask) => mask.octets().iter().map(|b| b.count_ones() as u32).sum::<u32>(),
                        _ => 64,
                    };
                    let ifname = device.ifname();
                    let status = std::process::Command::new("ip")
                        .args(["addr", "add", &format!("{}/{}", match ip { IpAddr::V6(v)=>v, _=>unreachable!() }, prefix), "dev", ifname])
                        .status();
                    match status {
                        Ok(s) if s.success() => info!("Added IPv6 address {}/{} to dev {}", match ip { IpAddr::V6(v)=>v.to_string(), _=>ip.to_string() }, prefix, ifname),
                        Ok(s) => warn!("Failed to add IPv6 address to dev {} via ip addr add: status {:?}", ifname, s),
                        Err(e) => warn!("Failed to add IPv6 address to dev {}: {}", ifname, e),
                    }
                }
                #[cfg(windows)]
                {
                    // Best-effort add secondary IPv6 on Windows Wintun adapter.
                    let prefix = match netmask {
                        IpAddr::V6(mask) => mask.octets().iter().map(|b| b.count_ones() as u32).sum::<u32>(),
                        _ => 64,
                    };
                    let ifname = device.ifname();
                    let ip_str = match ip { IpAddr::V6(v)=>v.to_string(), _=>ip.to_string() };
                    let output = std::process::Command::new("netsh")
                        .args([
                            "interface", "ipv6", "add", "address",
                            &format!("interface={}", ifname),
                            &format!("address={}", ip_str),
                            "type=unicast",
                            &format!("store=active"),
                        ])
                        .output();
                    match output {
                        Ok(o) if o.status.success() => {
                            info!("Added IPv6 address {}/{} to Windows interface {}", ip_str, prefix, ifname);
                        }
                        Ok(o) => {
                            warn!(
                                "Failed to add IPv6 address {} to Windows interface {}: status={:?} stdout='{}' stderr='{}'",
                                ip_str, ifname, o.status,
                                String::from_utf8_lossy(&o.stdout).trim(),
                                String::from_utf8_lossy(&o.stderr).trim()
                            );
                        }
                        Err(e) => warn!("Failed to add IPv6 address {} to Windows interface {}: {}", ip_str, ifname, e),
                    }
                }
                configured_addrs.push(ip);
            }
        }
    }
    if let Some(script) = &config.ifup {
        run_script(script, device.ifname());
    }
    if config.fix_rp_filter {
        try_fail!(device.fix_rp_filter(), "Failed to change rp_filter settings: {}");
    }
    if let Ok(val) = device.get_rp_filter() {
        if val != 1 {
            warn!("Your networking configuration might be affected by a vulnerability (https://vpncloud.ddswd.de/docs/security/cve-2019-14899/), please change your rp_filter setting to 1 (currently {}).", val);
        }
    }
    config.call_hook("device_configured", vec![("IFNAME", device.ifname())], true);
    device
}

#[allow(clippy::cognitive_complexity)]
fn run<P: Protocol>(config: Config, socket: UdpSocket) {
    info!("run: setup_device starting");
    let device = setup_device(&config);
    let device_ifname = device.ifname().to_string();
    info!("run: setup_device done, ifname={}", device_ifname);

    let port_forwarding = if config.port_forwarding { socket.create_port_forwarding() } else { None };
    if port_forwarding.is_some() {
        info!("run: port_forwarding enabled (UPnP/NAT-PMP setup attempted)");
    }

    let stats_file = match config.stats_file {
        None => None,
        Some(ref name) => {
            let path = Path::new(name);
            if path.exists() {
                try_fail!(fs::remove_file(path), "Failed to remove file {}: {}", name);
            }
            let file = try_fail!(File::create(name), "Failed to create stats file: {}");
            #[cfg(unix)]
            try_fail!(
                fs::set_permissions(name, Permissions::from_mode(0o644)),
                "Failed to set permissions on stats file: {}"
            );
            Some(file)
        }
    };
    info!("run: creating GenericCloud (single-threaded native fast path, direct socket+tun)");
    let mut cloud =
        GenericCloud::<TunTapDevice, P, UdpSocket, SystemTimeSource>::new(&config, socket, device, port_forwarding, stats_file);
    info!("run: GenericCloud created (fast path)");
    for mut addr in config.peers.iter().cloned() {
        let orig = addr.clone();
        if addr.find(':').unwrap_or(0) <= addr.find(']').unwrap_or(0) {
            // : not present or only in IPv6 address
            addr = format!("{}:{}", addr, DEFAULT_PORT)
        }
        info!("run: connecting to configured peer orig={} effective={}", orig, addr);
        try_fail!(cloud.connect(&addr as &str), "Failed to send message to {}: {}", &addr);
        cloud.add_reconnect_peer(addr);
    }
    #[cfg(unix)]
    if config.daemonize {
        info!("Running process as daemon");
        let mut daemonize = daemonize::Daemonize::new();
        if let Some(user) = config.user {
            daemonize = daemonize.user(&user as &str);
        }
        if let Some(group) = config.group {
            daemonize = daemonize.group(&group as &str);
        }
        if let Some(pid_file) = config.pid_file {
            daemonize = daemonize.pid_file(pid_file).chown_pid_file(true);
        }
        try_fail!(daemonize.start(), "Failed to daemonize: {}");
    } else {
        #[cfg(unix)]
        if config.user.is_some() || config.group.is_some() {
            info!("Dropping privileges");
            let mut pd = privdrop::PrivDrop::default();
            if let Some(user) = config.user {
                pd = pd.user(user);
            }
            if let Some(group) = config.group {
                pd = pd.group(group);
            }
            try_fail!(pd.apply(), "Failed to drop privileges: {}");
        }
    }
    #[cfg(not(unix))]
    if config.daemonize {
        info!("Daemonize is not supported on this platform");
    }
    // Native fast path: run_legacy() returns false when the underlying
    // socket dies (disconnection). Reconnect the socket and re-establish the
    // peer connections instead of exiting the process.
    loop {
        let ok = cloud.run_legacy();
        if ok {
            break;
        }
        info!("run: socket connection lost, attempting reconnect...");
        if let Err(e) = cloud.socket_reconnect() {
            error!("run: socket reconnect failed: {}, exiting", e);
            break;
        }
        // Re-establish peer connections.
        for mut addr in config.peers.iter().cloned() {
            let orig = addr.clone();
            if addr.find(':').unwrap_or(0) <= addr.find(']').unwrap_or(0) {
                addr = format!("{}:{}", addr, DEFAULT_PORT)
            }
            info!("run: reconnecting to configured peer orig={} effective={}", orig, addr);
            if let Err(e) = cloud.connect(&addr as &str) {
                error!("run: failed to reconnect to {}: {}, exiting", addr, e);
                break;
            }
            cloud.add_reconnect_peer(addr);
        }
        info!("run: socket reconnected, resuming event loop");
    }
    if let Some(script) = config.ifdown {
        run_script(&script, &device_ifname);
    }
}

fn log_binary_md5() {
    if let Ok(path) = std::env::current_exe() {
        if let Ok(mut file) = File::open(&path) {
            use md5::Digest;
            let mut hasher = md5::Md5::new();
            let mut buf = [0u8; 8192];
            loop {
                match file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => hasher.update(&buf[..n]),
                    Err(_) => return,
                }
            }
            let digest = hasher.finalize();
            info!("Binary path: {}, MD5: {:x}", path.display(), digest);
        }
    }
}

fn main() {
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::Media::timeBeginPeriod(1);
    }
    let args: Args = Args::from_args();
    if args.version {
        println!("VpnCloud v{}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let logger = try_fail!(DualLogger::new(args.log_file.as_ref()), "Failed to open logfile: {}");
    log::set_boxed_logger(Box::new(logger)).unwrap();
    assert!(!args.verbose || !args.quiet);
    log::set_max_level(if args.verbose {
        log::LevelFilter::Debug
    } else if args.quiet {
        log::LevelFilter::Error
    } else {
        log::LevelFilter::Info
    });

    // Capture panics in logs for easier remote debugging (esp. on Windows background runs).
    std::panic::set_hook(Box::new(|info| {
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "non-string panic payload".to_string()
        };
        let loc = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown location".to_string());
        error!("PANIC at {}: {}", loc, payload);
        eprintln!("PANIC at {}: {}", loc, payload);
    }));

    log_binary_md5();
    if let Some(cmd) = args.cmd {
        match cmd {
            Command::GenKey { password } => {
                let (privkey, pubkey) = Crypto::generate_keypair(password.as_deref());
                println!("Private key: {}\nPublic key: {}\n", privkey, pubkey);
                println!(
                    "Attention: Keep the private key secret and use only the public key on other nodes to establish trust."
                );
            }
            Command::MigrateConfig { config_file } => {
                info!("Trying to convert from old config format");
                let f = try_fail!(File::open(&config_file), "Failed to open config file: {:?}");
                let config_file_old: OldConfigFile =
                    try_fail!(serde_yaml::from_reader(f), "Config file not valid for version 1: {:?}");
                let new_config = config_file_old.convert();
                info!("Successfully converted from old format");
                info!("Renaming original file to {}.orig", config_file);
                try_fail!(
                    fs::rename(&config_file, format!("{}.orig", config_file)),
                    "Failed to rename original file: {:?}"
                );
                info!("Writing new config back into {}", config_file);
                let f = try_fail!(File::create(&config_file), "Failed to open config file: {:?}");
                #[cfg(unix)]
                try_fail!(
                    fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)),
                    "Failed to set permissions on file: {:?}"
                );
                try_fail!(serde_yaml::to_writer(f, &new_config), "Failed to write converted config: {:?}");
            }
            Command::Completion { shell } => {
                Args::clap().gen_completions_to(env!("CARGO_PKG_NAME"), shell, &mut io::stdout());
            }
            #[cfg(feature = "websocket")]
            Command::WsProxy { listen } => {
                try_fail!(wsproxy::run_proxy(&listen), "Failed to run websocket proxy: {:?}");
            }
            #[cfg(feature = "wizard")]
            Command::Config { name } => {
                try_fail!(wizard::configure(name), "Wizard failed: {}");
            }
            #[cfg(feature = "installer")]
            Command::Install { uninstall } => {
                if uninstall {
                    try_fail!(installer::uninstall(), "Uninstall failed: {}");
                } else {
                    try_fail!(installer::install(), "Install failed: {}");
                }
            }
        }
        return;
    }
    let mut config = Config::default();
    if let Some(ref file) = args.config {
        info!("Reading config file '{}'", file);
        let f = try_fail!(File::open(file), "Failed to open config file: {:?}");
        let config_file = match serde_yaml::from_reader(f) {
            Ok(config) => config,
            Err(err) => {
                error!("Failed to read config file: {}", err);
                info!("Trying to convert from old config format");
                let f = try_fail!(File::open(file), "Failed to open config file: {:?}");
                let config_file_old: OldConfigFile =
                    try_fail!(serde_yaml::from_reader(f), "Config file is neither version 2 nor version 1: {:?}");
                let new_config = config_file_old.convert();
                info!("Successfully converted from old format, please migrate your config using migrate-config");
                new_config
            }
        };
        config.merge_file(config_file)
    }
    let listen_was_explicit = args.listen.is_some();
    config.merge_args(args);

    // --ip and --ipv6 can be specified together for dual-stack (IPv4+IPv6).
    // If only --ipv6 is provided, keep legacy behavior: treat it as the primary interface address.
    if config.ip.is_none() {
        if let Some(ref ipv6_addr) = config.ipv6 {
            info!("Using IPv6 address {} due to --ipv6 (no --ip provided)", ipv6_addr);
            config.ip = Some(ipv6_addr.clone());
        }
    }

    if !listen_was_explicit && config.ws_proxy.is_some() {
        if let Some(ref ws_proxy) = config.ws_proxy {
            let port = ws_proxy.rsplit(':').next().unwrap_or(ws_proxy);
            config.listen = port.to_string();
            info!("Auto-set listen port {} from --ws-proxy", port);
        }
    }
    debug!("Config: {:?}", config);
    if config.crypto.password.is_none() && config.crypto.private_key.is_none() {
        error!("Either password or private key must be set in config or given as parameter");
        return;
    }
    #[cfg(feature = "websocket")]
    {
        info!("=== WEBSOCKET FEATURE IS ENABLED AT COMPILE TIME ===");
    }
    #[cfg(not(feature = "websocket"))]
    {
        info!("=== WEBSOCKET FEATURE IS DISABLED AT COMPILE TIME ===");
    }
    #[cfg(feature = "websocket")]
    if config.listen.starts_with("ws://") || config.listen.starts_with("wss://") {
        info!("=== ENTERING RUN_WS PATH (websocket feature enabled) ===");
        info!("Opening websocket/proxy socket for listen={}", config.listen);
        let socket = if config.insecure {
            try_fail!(ProxyConnection::connect(&config.listen, config.sni.as_deref(), true), "Failed to open socket {}: {}", config.listen)
        } else {
            try_fail!(ProxyConnection::listen(&config.listen), "Failed to open socket {}: {}", config.listen)
        };
        // In WebSocket mode, the proxy assigns a UDP address to this client.
        // Use that assigned address as the local address (for routing).
        let mut ws_proxy_peer = socket.address().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        info!("Socket opened for listen={}, WebSocket proxy assigned peer={}, starting cloud", config.listen, ws_proxy_peer);

        // Websocket-proxy branch: single-threaded WaitImpl event loop (legacy mode),
        // because ProxyConnection is not a plain UdpSocket and the dual-thread
        // channel mode does not apply.
        info!("run_ws: setup_device starting");
        let device = setup_device(&config);
        let device_ifname = device.ifname().to_string();
        info!("run_ws: setup_device done, ifname={}", device_ifname);
        info!("run_ws: port_forwarding requested={} (disabled in legacy mode)", config.port_forwarding);
        let port_forwarding: Option<crate::port_forwarding::PortForwarding> = None;
        let stats_file = match config.stats_file {
            None => None,
            Some(ref name) => {
                let path = Path::new(name);
                if path.exists() {
                    try_fail!(fs::remove_file(path), "Failed to remove file {}: {}", name);
                }
                let file = try_fail!(File::create(name), "Failed to create stats file: {}");
                #[cfg(unix)]
                try_fail!(
                    fs::set_permissions(name, Permissions::from_mode(0o644)),
                    "Failed to set permissions on stats file: {}"
                );
                Some(file)
            }
        };
        info!("run_ws: creating GenericCloud");
        match config.device_type {
            Type::Tap => {
                let mut cloud =
                    GenericCloud::<TunTapDevice, payload::Frame, ProxyConnection, SystemTimeSource>::new(&config, socket, device, port_forwarding, stats_file);
                info!("run_ws: GenericCloud created");
                // In WebSocket mode, the proxy's assigned UDP address is our local transport address.
                // The -c/peer address is used for INIT and as the destination for send().
                // Cloud's initialize() already adds socket address to own_addresses.
                // Add virtual IPs with the WebSocket proxy's UDP port for routing.
                let proxy_port = ws_proxy_peer.port();
                let mut own_addrs = Vec::new();
                if let Some(ip_str) = &config.ip {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        own_addrs.push(SocketAddr::new(ip, proxy_port));
                    }
                }
                if let Some(ipv6_str) = &config.ipv6 {
                    if let Ok(ipv6) = ipv6_str.parse::<IpAddr>() {
                        own_addrs.push(SocketAddr::new(ipv6, proxy_port));
                    }
                }
                for addr in &config.advertise_addresses {
                    own_addrs.push(addr.parse().unwrap());
                }
                cloud.set_own_addresses(own_addrs);
                // Use configured peer (-c) as gateway for INIT (original vpncloud design).
                // The proxy will forward to the destination specified in each packet.
                let gateway_peer = if !config.peers.is_empty() {
                    let mut peer = config.peers[0].clone();
                    if peer.find(':').unwrap_or(0) <= peer.find(']').unwrap_or(0) {
                        peer = format!("{}:{}", peer, DEFAULT_PORT);
                    }
                    peer
                } else {
                    ws_proxy_peer.to_string()
                };
                info!("run_ws: using configured peer as gateway: {}", gateway_peer);
                try_fail!(cloud.connect(&gateway_peer), "Failed to send message to {}: {}", &gateway_peer);
                cloud.add_reconnect_peer(gateway_peer.clone());
                // Add configured peers for mesh discovery through the proxy
                for mut addr in config.peers.iter().cloned() {
                    let orig = addr.clone();
                    if addr.find(':').unwrap_or(0) <= addr.find(']').unwrap_or(0) {
                        addr = format!("{}:{}", addr, DEFAULT_PORT);
                    }
                    info!("run_ws: adding configured peer for mesh discovery orig={} effective={}", orig, addr);
                    cloud.add_reconnect_peer(addr);
                }
                #[cfg(unix)]
                if config.daemonize {
                    info!("Running process as daemon");
                    let mut daemonize = daemonize::Daemonize::new();
                    if let Some(user) = config.user {
                        daemonize = daemonize.user(&user as &str);
                    }
                    if let Some(group) = config.group {
                        daemonize = daemonize.group(&group as &str);
                    }
                    if let Some(pid_file) = config.pid_file {
                        daemonize = daemonize.pid_file(pid_file).chown_pid_file(true);
                    }
                    try_fail!(daemonize.start(), "Failed to daemonize: {}");
                } else {
                    #[cfg(unix)]
                    if config.user.is_some() || config.group.is_some() {
                        info!("Dropping privileges");
                        let mut pd = privdrop::PrivDrop::default();
                        if let Some(user) = config.user {
                            pd = pd.user(user);
                        }
                        if let Some(group) = config.group {
                            pd = pd.group(group);
                        }
                        try_fail!(pd.apply(), "Failed to drop privileges: {}");
                    }
                }
                #[cfg(not(unix))]
                if config.daemonize {
                    info!("Daemonize is not supported on this platform");
                }
                // WebSocket proxy mode: run_legacy() returns false when the underlying
                // socket dies (disconnection). Reconnect the socket and re-establish the
                // peer connection instead of exiting the process.
                // Similar to v0.0.5's housekeep(): periodic retry loop instead of one-shot.
                loop {
                    let ok = cloud.run_legacy();
                    if ok {
                        break;
                    }
                    info!("run_ws: WebSocket connection lost, entering reconnect loop...");
                    
                    // Retry loop: keep trying every 5 seconds until reconnect succeeds
                    loop {
                        info!("run_ws: attempting WebSocket reconnect...");
                        match cloud.socket_reconnect() {
                            Ok(_) => {
                                info!("run_ws: socket reconnected, re-establishing gateway...");
                                // Update ws_proxy_peer with new address from reconnected socket
                                if let Ok(new_addr) = cloud.socket_address() {
                                    ws_proxy_peer = new_addr;
                                    // Update own_addresses with new proxy port
                                    let proxy_port = ws_proxy_peer.port();
                                    let mut own_addrs = Vec::new();
                                    if let Some(ip_str) = &config.ip {
                                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                                            own_addrs.push(SocketAddr::new(ip, proxy_port));
                                        }
                                    }
                                    if let Some(ipv6_str) = &config.ipv6 {
                                        if let Ok(ipv6) = ipv6_str.parse::<IpAddr>() {
                                            own_addrs.push(SocketAddr::new(ipv6, proxy_port));
                                        }
                                    }
                                    for addr in &config.advertise_addresses {
                                        own_addrs.push(addr.parse().unwrap());
                                    }
                                    cloud.set_own_addresses(own_addrs);
                                    info!("run_ws: updated own_addresses with new proxy port {}", proxy_port);
                                }
                                let gateway_peer = if !config.peers.is_empty() {
                                    let mut peer = config.peers[0].clone();
                                    if peer.find(':').unwrap_or(0) <= peer.find(']').unwrap_or(0) {
                                        peer = format!("{}:{}", peer, DEFAULT_PORT);
                                    }
                                    peer
                                } else {
                                    ws_proxy_peer.to_string()
                                };
                                match cloud.connect(&gateway_peer) {
                                    Ok(_) => {
                                        info!("run_ws: gateway reconnected, resuming event loop");
                                        break; // Reconnect successful, resume run_legacy loop
                                    }
                                    Err(e) => {
                                        error!("run_ws: failed to reconnect to gateway {}: {}", gateway_peer, e);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("run_ws: socket reconnect failed: {}", e);
                            }
                        }
                        // Wait 5 seconds before next retry
                        info!("run_ws: reconnect failed, retrying in 5 seconds...");
                        thread::sleep(Duration::from_secs(5));
                    }
                    info!("run_ws: reconnect successful, resuming event loop");
                }
                if let Some(script) = config.ifdown {
                    run_script(&script, &device_ifname);
                }
            }
            Type::Tun => {
                let mut cloud =
                    GenericCloud::<TunTapDevice, payload::Packet, ProxyConnection, SystemTimeSource>::new(&config, socket, device, port_forwarding, stats_file);
                info!("run_ws: GenericCloud created");
                // In WebSocket mode, ALL traffic goes to the WebSocket proxy's assigned UDP address.
                // The -c/peer address is only used to establish the WebSocket connection.
                // Cloud's initialize() already adds socket address to own_addresses.
                // Add virtual IPs with the WebSocket proxy's UDP port for routing.
                let proxy_port = ws_proxy_peer.port();
                let mut own_addrs = Vec::new();
                if let Some(ip_str) = &config.ip {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        own_addrs.push(SocketAddr::new(ip, proxy_port));
                    }
                }
                if let Some(ipv6_str) = &config.ipv6 {
                    if let Ok(ipv6) = ipv6_str.parse::<IpAddr>() {
                        own_addrs.push(SocketAddr::new(ipv6, proxy_port));
                    }
                }
                for addr in &config.advertise_addresses {
                    own_addrs.push(addr.parse().unwrap());
                }
                cloud.set_own_addresses(own_addrs);
                // Use configured peer (-c) as gateway for INIT (original vpncloud design).
                // The proxy will forward to the destination specified in each packet.
                let gateway_peer = if !config.peers.is_empty() {
                    let mut peer = config.peers[0].clone();
                    if peer.find(':').unwrap_or(0) <= peer.find(']').unwrap_or(0) {
                        peer = format!("{}:{}", peer, DEFAULT_PORT);
                    }
                    peer
                } else {
                    ws_proxy_peer.to_string()
                };
                info!("run_ws: using configured peer as gateway: {}", gateway_peer);
                try_fail!(cloud.connect(&gateway_peer), "Failed to send message to {}: {}", &gateway_peer);
                cloud.add_reconnect_peer(gateway_peer.clone());
                // Add configured peers for mesh discovery through the proxy
                for mut addr in config.peers.iter().cloned() {
                    let orig = addr.clone();
                    if addr.find(':').unwrap_or(0) <= addr.find(']').unwrap_or(0) {
                        addr = format!("{}:{}", addr, DEFAULT_PORT);
                    }
                    info!("run_ws: adding configured peer for mesh discovery orig={} effective={}", orig, addr);
                    cloud.add_reconnect_peer(addr);
                }
                #[cfg(unix)]
                if config.daemonize {
                    info!("Running process as daemon");
                    let mut daemonize = daemonize::Daemonize::new();
                    if let Some(user) = config.user {
                        daemonize = daemonize.user(&user as &str);
                    }
                    if let Some(group) = config.group {
                        daemonize = daemonize.group(&group as &str);
                    }
                    if let Some(pid_file) = config.pid_file {
                        daemonize = daemonize.pid_file(pid_file).chown_pid_file(true);
                    }
                    try_fail!(daemonize.start(), "Failed to daemonize: {}");
                } else {
                    #[cfg(unix)]
                    if config.user.is_some() || config.group.is_some() {
                        info!("Dropping privileges");
                        let mut pd = privdrop::PrivDrop::default();
                        if let Some(user) = config.user {
                            pd = pd.user(user);
                        }
                        if let Some(group) = config.group {
                            pd = pd.group(group);
                        }
                        try_fail!(pd.apply(), "Failed to drop privileges: {}");
                    }
                }
                #[cfg(not(unix))]
                if config.daemonize {
                    info!("Daemonize is not supported on this platform");
                }
                // WebSocket proxy mode: run_legacy() returns false when the underlying
                // socket dies (disconnection). Reconnect the socket and re-establish the
                // peer connection instead of exiting the process.
                // Similar to v0.0.5's housekeep(): periodic retry loop instead of one-shot.
                loop {
                    let ok = cloud.run_legacy();
                    if ok {
                        break;
                    }
                    info!("run_ws: WebSocket connection lost, entering reconnect loop...");
                    
                    // Retry loop: keep trying every 5 seconds until reconnect succeeds
                    loop {
                        info!("run_ws: attempting WebSocket reconnect...");
                        match cloud.socket_reconnect() {
                            Ok(_) => {
                                info!("run_ws: socket reconnected, re-establishing gateway...");
                                // Update ws_proxy_peer with new address from reconnected socket
                                if let Ok(new_addr) = cloud.socket_address() {
                                    ws_proxy_peer = new_addr;
                                    // Update own_addresses with new proxy port
                                    let proxy_port = ws_proxy_peer.port();
                                    let mut own_addrs = Vec::new();
                                    if let Some(ip_str) = &config.ip {
                                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                                            own_addrs.push(SocketAddr::new(ip, proxy_port));
                                        }
                                    }
                                    if let Some(ipv6_str) = &config.ipv6 {
                                        if let Ok(ipv6) = ipv6_str.parse::<IpAddr>() {
                                            own_addrs.push(SocketAddr::new(ipv6, proxy_port));
                                        }
                                    }
                                    for addr in &config.advertise_addresses {
                                        own_addrs.push(addr.parse().unwrap());
                                    }
                                    cloud.set_own_addresses(own_addrs);
                                    info!("run_ws: updated own_addresses with new proxy port {}", proxy_port);
                                }
                                let gateway_peer = if !config.peers.is_empty() {
                                    let mut peer = config.peers[0].clone();
                                    if peer.find(':').unwrap_or(0) <= peer.find(']').unwrap_or(0) {
                                        peer = format!("{}:{}", peer, DEFAULT_PORT);
                                    }
                                    peer
                                } else {
                                    ws_proxy_peer.to_string()
                                };
                                match cloud.connect(&gateway_peer) {
                                    Ok(_) => {
                                        info!("run_ws: gateway reconnected, resuming event loop");
                                        break; // Reconnect successful, resume run_legacy loop
                                    }
                                    Err(e) => {
                                        error!("run_ws: failed to reconnect to gateway {}: {}", gateway_peer, e);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("run_ws: socket reconnect failed: {}", e);
                            }
                        }
                        // Wait 5 seconds before next retry
                        info!("run_ws: reconnect failed, retrying in 5 seconds...");
                        thread::sleep(Duration::from_secs(5));
                    }
                    info!("run_ws: reconnect successful, resuming event loop");
                }
                if let Some(script) = config.ifdown {
                    run_script(&script, &device_ifname);
                }
            }
        }
        return;
    }
    info!("=== ENTERING REGULAR RUN PATH ===");
    info!("Opening UDP socket for listen={}", config.listen);
    let socket = try_fail!(UdpSocket::listen(&config.listen), "Failed to open socket {}: {}", config.listen);
    let vpncloud_udp_addr = try_fail!(socket.address(), "Failed to get socket address: {}");
    info!("UDP socket opened for listen={}, vpncloud UDP address={}", config.listen, vpncloud_udp_addr);

    #[cfg(feature = "websocket")]
    if let Some(ref ws_proxy_addr) = config.ws_proxy {
        let ws_proxy_listen = if ws_proxy_addr.starts_with(':') {
            format!("0.0.0.0{}", ws_proxy_addr)
        } else if ws_proxy_addr.parse::<u16>().is_ok() {
            format!("0.0.0.0:{}", ws_proxy_addr)
        } else {
            ws_proxy_addr.clone()
        };
        let ws_proxy_listen_clone = ws_proxy_listen.clone();
        thread::spawn(move || {
            if let Err(err) = wsproxy::run_proxy(&ws_proxy_listen_clone) {
                error!("WebSocket proxy error: {}", err);
            }
        });
        info!("Embedded WebSocket proxy spawned, listening on {}", ws_proxy_listen);
    }

    match config.device_type {
        Type::Tap => run::<payload::Frame>(config, socket),
        Type::Tun => run::<payload::Packet>(config, socket),
    }
}
