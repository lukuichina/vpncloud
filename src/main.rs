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
    channel_io::{
        spawn_io_threads, spawn_ws_thread, ChannelDevice, ChannelSocket, NetWake,
    },
    cloud::GenericCloud,
    config::{Args, Command, Config, DEFAULT_PORT, ListenMode, first_udp_addr, first_ws_url, has_websocket},
    crypto::Crypto,
    device::{Device, TunTapDevice, Type},
    net::{Socket, TransportId},
    oldconfig::OldConfigFile,
    payload::Protocol,
    util::SystemTimeSource,
    types::Address,
};

use crossbeam_channel::{bounded, Receiver, Sender};
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

/// Add or delete a route that steers a claimed prefix into the tunnel device.
/// Uses the platform-native tool so claim routes work on both platforms:
///   - Unix:    `ip route add|del <net>/<prefix> dev <ifname>` (v4 or v6)
///   - Windows: `netsh interface ipv4|ipv6 add|delete route prefix=<net>/<prefix>
///               interface=<ifname> store=active`
fn ip_route(ifname: &str, addr: std::net::IpAddr, prefix: u8, add: bool) -> Result<(), String> {
    try_ip_route(ifname, addr, prefix, add).map_err(|e| {
        format!(
            "failed to {} route {}/{} via dev {}: {}",
            if add { "add" } else { "delete" },
            addr,
            prefix,
            ifname,
            e
        )
    })
}

fn try_ip_route(ifname: &str, addr: std::net::IpAddr, prefix: u8, add: bool) -> Result<(), String> {
    #[cfg(unix)]
    {
        let op = if add { "add" } else { "del" };
        let out = process::Command::new("ip")
            .args(["route", op, &format!("{}/{}", addr, prefix), "dev", ifname])
            .output()
            .map_err(|e| format!("failed to run `ip route {}`: {}", op, e))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "`ip route {}` status={:?} stderr='{}'",
                op,
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
    #[cfg(windows)]
    {
        let family = match addr {
            std::net::IpAddr::V4(_) => "ipv4",
            std::net::IpAddr::V6(_) => "ipv6",
        };
        let route = format!("prefix={}/{}", addr, prefix);
        let iface = format!("interface={}", ifname);
        let out = if add {
            process::Command::new("netsh")
                .args(["interface", family, "add", "route", &route, &iface, "store=active"])
                .output()
        } else {
            process::Command::new("netsh")
                .args(["interface", family, "delete", "route", &route, &iface, "store=active"])
                .output()
        }
        .map_err(|e| format!("failed to run `netsh interface {} route`: {}", family, e))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "`netsh interface {} {} route` status={:?} stdout='{}' stderr='{}'",
                family,
                if add { "add" } else { "delete" },
                out.status,
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
}

/// Windows: add a secondary IPv6 address **with its prefix length** and verify
/// that the address really landed on the interface (netsh silently accepts
/// `address=<ip>` without a prefix and then uses a default prefix, so we must
/// both pass and verify the prefix).
#[cfg(windows)]
fn windows_add_ipv6_address(ifname: &str, ip_str: &str, prefix: u8) -> Result<(), String> {
    let out = process::Command::new("netsh")
        .args([
            "interface",
            "ipv6",
            "add",
            "address",
            &format!("interface={}", ifname),
            &format!("address={}/{}", ip_str, prefix),
            "type=unicast",
            "store=active",
        ])
        .output()
        .map_err(|e| format!("failed to run netsh add address: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "netsh add address status={:?} stdout='{}' stderr='{}'",
            out.status,
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    // Read back the actual address list to confirm address and prefix length.
    let show = process::Command::new("netsh")
        .args(["interface", "ipv6", "show", "addresses", &format!("interface={}", ifname)])
        .output()
        .map_err(|e| format!("failed to run netsh show addresses: {}", e))?;
    let text = String::from_utf8_lossy(&show.stdout).to_string();
    let lower = text.to_lowercase();
    if !lower.contains(&ip_str.to_lowercase()) {
        return Err(format!("address {} not present after add; netsh output:\n{}", ip_str, text));
    }
    if !text.contains(&format!("/{}", prefix)) {
        warn!(
            "Windows IPv6 address {} is present but prefix /{} was not confirmed; netsh output:\n{}",
            ip_str, prefix, text
        );
    } else {
        debug!("Windows IPv6 address {} confirmed with prefix /{}: {}", ip_str, prefix, text.trim());
    }
    Ok(())
}

/// Windows: delete a secondary IPv6 address (address/prefix form).
#[cfg(windows)]
fn windows_del_ipv6_address(ifname: &str, ip_str: &str, prefix: u8) -> Result<(), String> {
    let out = process::Command::new("netsh")
        .args([
            "interface",
            "ipv6",
            "delete",
            "address",
            &format!("interface={}", ifname),
            &format!("address={}/{}", ip_str, prefix),
            "store=active",
        ])
        .output()
        .map_err(|e| format!("failed to run netsh delete address: {}", e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "netsh delete address status={:?} stdout='{}' stderr='{}'",
            out.status,
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Remove claim routes / secondary addresses installed at startup, so the host
/// does not keep stale routes pointing at a dead tunnel interface.
fn cleanup_tunnel_config(config: &Config, ifname: &str) {
    for claim_str in &config.claims {
        if let Ok(claim) = crate::types::Range::from_str(claim_str) {
            let addr = match claim.base {
                Address { data, len: 4 } => std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    data[0], data[1], data[2], data[3],
                )),
                Address { data, len: 16 } => std::net::IpAddr::V6(std::net::Ipv6Addr::from(data)),
                _ => continue,
            };
            if claim.prefix_len > 0 && (claim.prefix_len as u16) <= (if addr.is_ipv4() { 32 } else { 128 }) {
                match ip_route(ifname, addr, claim.prefix_len, false) {
                    Ok(()) => debug!("Removed route {}/{} via dev {}", addr, claim.prefix_len, ifname),
                    Err(e) => debug!("Could not remove route {}/{}: {}", addr, claim.prefix_len, e),
                }
            }
        }
    }
    #[cfg(windows)]
    {
        // Mirror setup_device(): the secondary address exists only when both
        // --ip and --ipv6 are set and they differ.
        if let (Some(ref ip), Some(ref ipv6_addr)) = (&config.ip, &config.ipv6) {
            if ip != ipv6_addr {
                if let Ok((IpAddr::V6(v6), netmask)) = parse_ip_netmask(ipv6_addr) {
                    let prefix = match netmask {
                        IpAddr::V6(mask) => mask.octets().iter().map(|b| b.count_ones() as u32).sum::<u32>(),
                        _ => 64,
                    };
                    let _ = windows_del_ipv6_address(ifname, &v6.to_string(), prefix as u8);
                }
            }
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
    if let Err(err) = device.set_mtu(config.mtu) {
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
                    // Add secondary IPv6 on Windows Wintun adapter. The prefix
                    // length MUST be passed and then verified by reading back the
                    // interface address list (netsh would otherwise default it).
                    let prefix = match netmask {
                        IpAddr::V6(mask) => mask.octets().iter().map(|b| b.count_ones() as u32).sum::<u32>() as u8,
                        _ => 64u8,
                    };
                    let ifname = device.ifname().to_string();
                    let ip_str = match ip { IpAddr::V6(v)=>v.to_string(), _=>ip.to_string() };
                    match windows_add_ipv6_address(&ifname, &ip_str, prefix) {
                        Ok(()) => info!("Added IPv6 address {}/{} to Windows interface {}", ip_str, prefix, ifname),
                        Err(e) => warn!("Failed to add IPv6 address {}/{} to Windows interface {}: {}", ip_str, prefix, ifname, e),
                    }
                }
                configured_addrs.push(ip);
            }
        }
    }
    // Install host routes for every claim (IPv4 and IPv6) so the OS actually
    // sends traffic for the claimed prefix into the tunnel. This is independent
    // of which family the primary address uses (previously only ran when the
    // primary address was IPv6, which broke dual-stack claims).
    for claim_str in &config.claims {
        if let Ok(claim) = crate::types::Range::from_str(claim_str) {
            let addr = match claim.base {
                Address { data, len: 4 } => std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    data[0], data[1], data[2], data[3],
                )),
                Address { data, len: 16 } => std::net::IpAddr::V6(std::net::Ipv6Addr::from(data)),
                _ => continue,
            };
            let max_prefix: u16 = if addr.is_ipv4() { 32 } else { 128 };
            if claim.prefix_len > 0 && (claim.prefix_len as u16) <= max_prefix {
                let ifname = device.ifname();
                match ip_route(ifname, addr, claim.prefix_len, true) {
                    Ok(()) => info!("Added route {}/{} via dev {}", addr, claim.prefix_len, ifname),
                    Err(e) => warn!("{}", e),
                }
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
fn run<P: Protocol>(mut config: Config, socket: UdpSocket) {
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
        if let Some(user) = config.user.take() {
            daemonize = daemonize.user(&user as &str);
        }
        if let Some(group) = config.group.take() {
            daemonize = daemonize.group(&group as &str);
        }
        if let Some(pid_file) = config.pid_file.take() {
            daemonize = daemonize.pid_file(pid_file).chown_pid_file(true);
        }
        try_fail!(daemonize.start(), "Failed to daemonize: {}");
    } else {
        #[cfg(unix)]
        if config.user.is_some() || config.group.is_some() {
            info!("Dropping privileges");
            let mut pd = privdrop::PrivDrop::default();
            if let Some(user) = config.user.take() {
                pd = pd.user(user);
            }
            if let Some(group) = config.group.take() {
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
    // Remove IPv6 claim routes / secondary addresses we installed so the host
    // does not keep stale routes pointing at a dead tunnel interface.
    cleanup_tunnel_config(&config, &device_ifname);
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
    #[cfg(windows)]
    {
        // Ensure timeEndPeriod is called on exit so the timer resolution
        // is restored and other processes are not affected.
        let _guard = TimerGuard;
        run_inner();
    }
    #[cfg(not(windows))]
    {
        run_inner();
    }
}

/// RAII guard that calls timeEndPeriod(1) on drop.
#[cfg(windows)]
struct TimerGuard;
#[cfg(windows)]
impl Drop for TimerGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Media::timeEndPeriod(1);
        }
    }
}

fn run_inner() {
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
    let listen_was_explicit = !args.listen.is_empty();
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
            let addr = format!("0.0.0.0:{port}");
            config.listen.push(ListenMode::Udp(
                try_fail!(
                    addr.parse::<SocketAddr>(),
                    "Invalid ws-proxy port '{}': {}",
                    port
                ),
            ));
            info!("Auto-set UDP listen {addr} from --ws-proxy");
        }
    }
    debug!("Config: {:?}", config);
    if config.crypto.password.is_none() && config.crypto.private_key.is_none() {
        error!("Either password or private key must be set in config or given as parameter");
        return;
    }

    // Multi-transport channel mode: when multiple listen entries are configured
    // (e.g. UDP + WebSocket simultaneously, or multiple UDP addresses), use
    // dual-thread I/O with per-transport workers feeding a shared channel that
    // run_channel() processes.
    let has_ws = has_websocket(&config.listen);
    let has_udp = config.listen.iter().any(|m| matches!(m, ListenMode::Udp(_)));
    if (has_udp && has_ws) || config.listen.len() > 1 {
        info!("=== ENTERING CHANNEL MODE (multi-transport) ===");

        // Create UDP sockets for all UDP listen entries.
        let mut udp_sockets: Vec<(UdpSocket, TransportId)> = Vec::new();
        let mut udp_idx: u8 = 0;
        for mode in &config.listen {
            if let ListenMode::Udp(addr) = mode {
                let socket = try_fail!(
                    UdpSocket::listen(&addr.to_string()),
                    "Failed to open UDP socket {}: {}",
                    addr
                );
                info!("UDP socket opened for listen={}", addr);
                udp_sockets.push((socket, TransportId::Udp(udp_idx)));
                udp_idx += 1;
            }
        }
        assert!(!udp_sockets.is_empty(), "channel mode requires at least one UDP socket");

        // Setup device (shared across all transports).
        info!("channel mode: setup_device starting");
        let device = setup_device(&config);
        let device_ifname = device.ifname().to_string();
        info!("channel mode: setup_device done, ifname={}", device_ifname);

        let port_forwarding: Option<crate::port_forwarding::PortForwarding> = None;
        let stats_file = None;

        // Spawn net + device threads.
        let (mut channel_socket, channel_device, _net_stop, _dev_stop, net_tx) =
            spawn_io_threads(udp_sockets, device, None, config.poll_timeout_ms as u64);

        // Spawn WS threads for each WebSocket listen entry.
        #[cfg(feature = "websocket")]
        {
            let mut ws_idx: u8 = 0;
            for mode in &config.listen {
                if let ListenMode::WebSocket { url } = mode {
                    let socket = if config.insecure {
                        try_fail!(
                            ProxyConnection::connect(url, config.sni.as_deref(), true),
                            "Failed to open socket {}: {}",
                            url
                        )
                    } else {
                        try_fail!(ProxyConnection::listen(url), "Failed to open socket {}: {}", url)
                    };
                    let ws_proxy_peer = socket
                        .address()
                        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
                    info!(
                        "WS socket opened for listen={}, proxy assigned peer={}",
                        url, ws_proxy_peer
                    );

                    let transport_id = TransportId::WebSocket(ws_idx);
                    let (_ws_tx, ws_cmd_rx) = bounded::<crate::net::NetPacket>(4096);
                    let ws_stop = _net_stop.clone();
                    let ws_wake = NetWake::new().expect("failed to create net wake event");
                    let ws_health = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));

                    channel_socket.register_transport(
                        transport_id,
                        _ws_tx,
                        ws_wake.clone(),
                        ws_health.clone(),
                    );

                    let net_tx_for_ws = net_tx.clone();
                    thread::Builder::new()
                        .name(format!("vpncloud-ws-{}", ws_idx))
                        .spawn(move || {
                            spawn_ws_thread(
                                socket,
                                transport_id,
                                net_tx_for_ws,
                                ws_cmd_rx,
                                ws_stop,
                                config.poll_timeout_ms as u64,
                                ws_wake,
                            )
                        })
                        .expect("failed to spawn WS thread");
                    ws_idx += 1;
                }
            }
        }

        // Create GenericCloud with ChannelSocket.
        match config.device_type {
            Type::Tap => {
                let mut cloud = GenericCloud::<
                    ChannelDevice,
                    payload::Frame,
                    ChannelSocket,
                    SystemTimeSource,
                >::new(&config, channel_socket, channel_device, port_forwarding, stats_file);
                run_channel_mode(&mut cloud, &config, &device_ifname);
            }
            Type::Tun => {
                let mut cloud = GenericCloud::<
                    ChannelDevice,
                    payload::Packet,
                    ChannelSocket,
                    SystemTimeSource,
                >::new(&config, channel_socket, channel_device, port_forwarding, stats_file);
                run_channel_mode(&mut cloud, &config, &device_ifname);
            }
        }
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
    if has_websocket(&config.listen) {
        info!("=== ENTERING RUN_WS PATH (websocket feature enabled) ===");
        let ws_url = first_ws_url(&config.listen)
            .expect("has_websocket guarantees a WebSocket listen entry");
        info!("Opening websocket/proxy socket for listen={}", ws_url);
        let socket = if config.insecure {
            try_fail!(ProxyConnection::connect(&ws_url, config.sni.as_deref(), true), "Failed to open socket {}: {}", ws_url)
        } else {
            try_fail!(ProxyConnection::listen(&ws_url), "Failed to open socket {}: {}", ws_url)
        };
        // In WebSocket mode, the proxy assigns a UDP address to this client.
        // Use that assigned address as the local address (for routing).
        let mut ws_proxy_peer = socket.address().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        info!("Socket opened for listen={}, WebSocket proxy assigned peer={}, starting cloud", ws_url, ws_proxy_peer);

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
    let listen_addr = first_udp_addr(&config.listen).unwrap_or_else(|| {
        error!("no UDP listen address configured");
        process::exit(-1)
    });
    info!("Opening UDP socket for listen={}", listen_addr);
    let socket = try_fail!(
        UdpSocket::listen(&listen_addr.to_string()),
        "Failed to open socket {}: {}",
        listen_addr
    );
    let vpncloud_udp_addr = try_fail!(socket.address(), "Failed to get socket address: {}");
    info!("UDP socket opened for listen={}, vpncloud UDP address={}", listen_addr, vpncloud_udp_addr);

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

/// Channel-mode event loop with reconnect. Drives `run_legacy()` (which dispatches
/// to `run_channel()`) and re-establishes peer connections when the transport
/// signals a disconnect (e.g. WebSocket proxy closed).
fn run_channel_mode<D: Device, S: Socket + 'static, P: Protocol>(
    cloud: &mut GenericCloud<D, P, S, SystemTimeSource>,
    config: &Config,
    device_ifname: &str,
) {
    for mut addr in config.peers.iter().cloned() {
        let orig = addr.clone();
        if addr.find(':').unwrap_or(0) <= addr.find(']').unwrap_or(0) {
            addr = format!("{}:{}", addr, DEFAULT_PORT);
        }
        info!("channel mode: connecting to configured peer orig={} effective={}", orig, addr);
        try_fail!(cloud.connect(&addr as &str), "Failed to send message to {}: {}", &addr);
        cloud.add_reconnect_peer(addr);
    }

    loop {
        let ok = cloud.run_legacy();
        if ok {
            break;
        }
        info!("channel mode: transport connection lost, attempting reconnect...");
        if let Err(e) = cloud.socket_reconnect() {
            error!("channel mode: socket reconnect failed: {}, exiting", e);
            break;
        }
        for mut addr in config.peers.iter().cloned() {
            let orig = addr.clone();
            if addr.find(':').unwrap_or(0) <= addr.find(']').unwrap_or(0) {
                addr = format!("{}:{}", addr, DEFAULT_PORT);
            }
            info!("channel mode: reconnecting to configured peer orig={} effective={}", orig, addr);
            if let Err(e) = cloud.connect(&addr as &str) {
                error!("channel mode: failed to reconnect to {}: {}, exiting", addr, e);
                break;
            }
            cloud.add_reconnect_peer(addr);
        }
        info!("channel mode: reconnected, resuming event loop");
    }

    cleanup_tunnel_config(config, device_ifname);
    if let Some(script) = config.ifdown.as_deref() {
        run_script(script, device_ifname);
    }
}
