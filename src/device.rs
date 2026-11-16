// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    cmp,
    collections::VecDeque,
    convert::TryInto,
    fmt,
    fs::{self, File},
    io::{self, BufRead, BufReader, Cursor, Error as IoError, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
    str,
    str::FromStr
};

#[cfg(unix)]
use std::os::{unix::io::AsRawFd, fd::RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};

use crate::{crypto, error::Error, util::MsgBuffer};

#[cfg(unix)]
mod unix_ifreq {
    use super::*;

    pub static TUNSETIFF: libc::c_ulong = 1074025674;

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct IfReqDataAddr {
        pub af: libc::c_int,
        pub addr: Ipv4Addr
    }

    #[repr(C)]
    pub union IfReqData {
        pub flags: libc::c_short,
        pub value: libc::c_int,
        pub addr: IfReqDataAddr,
        pub _dummy: [u8; 24],
    }

    #[repr(C)]
    pub struct IfReq {
        pub ifr_name: [u8; libc::IF_NAMESIZE],
        pub data: IfReqData,
    }

    impl IfReq {
        pub fn new(name: &str) -> Self {
            assert!(name.len() < libc::IF_NAMESIZE);
            let mut ifr_name = [0; libc::IF_NAMESIZE];
            ifr_name[..name.len()].clone_from_slice(name.as_bytes());
            Self { ifr_name, data: IfReqData { _dummy: [0; 24] } }
        }
    }
}
#[cfg(unix)]
use unix_ifreq::{IfReq, TUNSETIFF};

/// The type of a tun/tap device
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum Type {
    /// Tun interface: This interface transports IP packets.
    #[serde(rename = "tun")]
    Tun,
    /// Tap interface: This interface transports Ethernet frames.
    #[serde(rename = "tap")]
    Tap,
}

impl fmt::Display for Type {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Type::Tun => write!(formatter, "tun"),
            Type::Tap => write!(formatter, "tap"),
        }
    }
}

impl FromStr for Type {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(match &text.to_lowercase() as &str {
            "tun" => Self::Tun,
            "tap" => Self::Tap,
            _ => return Err("Unknown device type"),
        })
    }
}

pub trait Device {
    /// Returns the type of this device
    fn get_type(&self) -> Type;

    /// Returns the interface name of this device.
    fn ifname(&self) -> &str;

    /// Reads a packet/frame from the device
    fn read(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error>;

    /// Writes a packet/frame to the device
    fn write(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error>;

    /// Returns the number of packets waiting in the receive channel (0 for non-channel devices).
    fn pending(&self) -> usize { 0 }
    /// Channel-mode inbound receiver for low-latency blocking waits in main loop.
    fn channel_dev_rx(&self) -> Option<&crossbeam_channel::Receiver<Vec<u8>>> { None }

    fn get_ip(&self) -> Result<IpAddr, Error>;

    #[cfg(unix)]
    fn as_raw_fd(&self) -> RawFd;
    #[cfg(windows)]
    fn as_raw_socket(&self) -> RawSocket;
}

#[cfg(unix)]
mod unix_device {
use super::*;
use std::os::unix::io::{AsRawFd, RawFd};

/// Represents a tun/tap device
pub struct TunTapDevice {
    fd: File,
    ifname: String,
    type_: Type,
}

impl TunTapDevice {
    /// Creates a new tun/tap device
    ///
    /// This method creates a new device of the `type_` kind with the name `ifname`.
    ///
    /// The `ifname` must be an interface name not longer than 31 bytes. It can contain the string
    /// `%d` which will be replaced with the next free index number that guarantees that the
    /// interface name will be free. In this case, the `ifname()` method can be used to obtain the
    /// final interface name.
    ///
    /// # Errors
    /// This method will return an error when the underlying system call fails. Common cases are:
    /// - The special device file `/dev/net/tun` does not exist or is not accessible by the current user.
    /// - The interface name is invalid or already in use.
    /// - The current user does not have enough permissions to create tun/tap devices (this requires root permissions).
    ///
    /// # Panics
    /// This method panics if the interface name is longer than 31 bytes.
    #[allow(clippy::useless_conversion)]
    pub fn new(ifname: &str, type_: Type, path: Option<&str>) -> io::Result<Self> {
        let path = path.unwrap_or_else(|| Self::default_path(type_));
        let fd = fs::OpenOptions::new().read(true).write(true).open(path)?;
        // Set O_NONBLOCK so read() does not block the event loop when no data is available.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags >= 0 {
            let _ = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        }
        let tun_flags = match type_ {
            Type::Tun => libc::IFF_TUN | libc::IFF_NO_PI,
            Type::Tap => libc::IFF_TAP | libc::IFF_NO_PI,
        };
        let mut ifreq = IfReq::new(ifname);
        ifreq.data.flags = tun_flags as libc::c_short;
        let res = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF.try_into().unwrap(), &mut ifreq) };
        match res {
            0 => {
                let mut ifname = String::with_capacity(32);
                let mut cursor = Cursor::new(ifreq.ifr_name);
                cursor.read_to_string(&mut ifname)?;
                ifname = ifname.trim_end_matches('\0').to_owned();
                Ok(Self { fd, ifname, type_ })
            }
            _ => Err(IoError::last_os_error()),
        }
    }

    /// Returns the default device path for a given type
    #[inline]
    pub fn default_path(type_: Type) -> &'static str {
        match type_ {
            Type::Tun | Type::Tap => "/dev/net/tun",
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[inline]
    fn correct_data_after_read(&mut self, _buffer: &mut MsgBuffer) {}

    #[cfg(any(
        target_os = "bitrig",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    #[inline]
    fn correct_data_after_read(&mut self, buffer: &mut MsgBuffer) {
        if self.type_ == Type::Tun {
            // BSD-based systems add a 4-byte header containing the Ethertype for TUN
            buffer.set_start(buffer.get_start() + 4);
        } else {
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[inline]
    fn correct_data_before_write(&mut self, _buffer: &mut MsgBuffer) {}

    #[cfg(any(
        target_os = "bitrig",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    #[inline]
    fn correct_data_before_write(&mut self, buffer: &mut MsgBuffer) {
        if self.type_ == Type::Tun {
            // BSD-based systems add a 4-byte header containing the Ethertype for TUN
            buffer.set_start(buffer.get_start() - 4);
            match buffer.message()[4] >> 4 {
                // IP version
                4 => buffer.message_mut()[0..4].copy_from_slice(&[0x00, 0x00, 0x08, 0x00]),
                6 => buffer.message_mut()[0..4].copy_from_slice(&[0x00, 0x00, 0x86, 0xdd]),
                _ => unreachable!(),
            }
        }
    }

    pub fn get_overhead(&self) -> usize {
        40 /* for outer IPv6 header, can't be sure to only have IPv4 peers */
        + 8 /* for outer UDP header */
        + crypto::EXTRA_LEN + crypto::TAG_LEN /* crypto overhead */
        + 1 /* message type header */
        + match self.type_ {
            Type::Tap => 14, /* inner ethernet header */
            Type::Tun => 0
        }
    }

    pub fn set_mtu(&self, value: Option<usize>) -> io::Result<()> {
        let value = match value {
            Some(value) => value,
            None => {
                let default_device = get_default_device()?;
                get_device_mtu(&default_device)? - self.get_overhead()
            }
        };
        info!("Setting MTU {} on device {}", value, self.ifname);
        set_device_mtu(&self.ifname, value)
    }

    pub fn configure(&self, addr: IpAddr, netmask: IpAddr) -> io::Result<()> {
        match addr {
            IpAddr::V4(addr) => {
                if let IpAddr::V4(mask) = netmask {
                    set_device_addr(&self.ifname, addr)?;
                    set_device_netmask(&self.ifname, mask)?;
                } else {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "IPv4 address requires IPv4 netmask"));
                }
            }
            IpAddr::V6(addr) => {
                set_device_addr_v6(&self.ifname, addr, netmask)?;
            }
        }
        set_device_enabled(&self.ifname, true)
    }

    pub fn get_rp_filter(&self) -> io::Result<u8> {
        Ok(cmp::max(get_rp_filter("all")?, get_rp_filter(&self.ifname)?))
    }

    pub fn fix_rp_filter(&self) -> io::Result<()> {
        if get_rp_filter("all")? > 1 {
            info!("Setting net.ipv4.conf.all.rp_filter=1");
            set_rp_filter("all", 1)?
        }
        if get_rp_filter(&self.ifname)? != 1 {
            info!("Setting net.ipv4.conf.{}.rp_filter=1", self.ifname);
            set_rp_filter(&self.ifname, 1)?
        }
        Ok(())
    }
}

impl Device for TunTapDevice {
    fn get_type(&self) -> Type {
        self.type_
    }

    fn ifname(&self) -> &str {
        &self.ifname
    }

    fn read(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        use std::io::ErrorKind;
        buffer.clear();
        match self.fd.read(buffer.buffer()) {
            Ok(read) => {
                buffer.set_length(read);
                self.correct_data_after_read(buffer);
                Ok(())
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                Err(Error::Device("empty".to_string()))
            }
            Err(e) => Err(Error::DeviceIo("Read error".to_string(), e)),
        }
    }

    fn write(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        self.correct_data_before_write(buffer);
        match self.fd.write_all(buffer.message()) {
            Ok(_) => self.fd.flush().map_err(|e| Error::DeviceIo("Flush error".to_string(), e)),
            Err(e) => Err(Error::DeviceIo("Write error".to_string(), e)),
        }
    }

    fn get_ip(&self) -> Result<IpAddr, Error> {
        get_device_addr(&self.ifname).map_err(|e| Error::DeviceIo("Error getting IP address".to_string(), e))
    }

    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(unix)]
impl AsRawFd for TunTapDevice {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

pub struct MockDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
}

impl MockDevice {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn put_inbound(&mut self, data: Vec<u8>) {
        self.inbound.push_back(data)
    }

    pub fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    pub fn has_inbound(&self) -> bool {
        !self.inbound.is_empty()
    }
}

impl Device for MockDevice {
    fn get_type(&self) -> Type {
        Type::Tun
    }

    fn ifname(&self) -> &str {
        "mock0"
    }

    fn read(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        if let Some(data) = self.inbound.pop_front() {
            buffer.clear();
            buffer.set_length(data.len());
            buffer.message_mut().copy_from_slice(&data);
            Ok(())
        } else {
            Err(Error::Device("empty".to_string()))
        }
    }

    fn write(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        self.outbound.push_back(buffer.message().into());
        Ok(())
    }

    fn get_ip(&self) -> Result<IpAddr, Error> {
        Err(Error::Device("Dummy devices have no IP address".to_string()))
    }

    fn as_raw_fd(&self) -> RawFd {
        unimplemented!()
    }
}

impl Default for MockDevice {
    fn default() -> Self {
        Self { outbound: VecDeque::with_capacity(10), inbound: VecDeque::with_capacity(10) }
    }
}

#[cfg(unix)]
impl AsRawFd for MockDevice {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        unimplemented!()
    }
}

#[cfg(windows)]
impl AsRawSocket for MockDevice {
    fn as_raw_socket(&self) -> RawSocket {
        unimplemented!()
    }
}

#[allow(clippy::useless_conversion)]
fn set_device_mtu(ifname: &str, mtu: usize) -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    ifreq.data.value = mtu as libc::c_int;
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFMTU.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => Ok(()),
        _ => Err(IoError::last_os_error()),
    }
}

#[allow(clippy::useless_conversion)]
fn get_device_mtu(ifname: &str) -> io::Result<usize> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFMTU.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => Ok(unsafe { ifreq.data.value as usize }),
        _ => Err(IoError::last_os_error()),
    }
}

#[allow(clippy::useless_conversion)]
fn get_device_addr(ifname: &str) -> io::Result<IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFADDR.try_into().unwrap(), &mut ifreq) };
    if res == 0 {
        let af = unsafe { ifreq.data.addr.af };
        match af as libc::c_int {
            libc::AF_INET => {
                let ip = unsafe { ifreq.data.addr.addr };
                return Ok(IpAddr::V4(ip));
            }
            libc::AF_INET6 => {
                return get_device_addr_v6_fallback(ifname);
            }
            _ => {}
        }
    }
    // SIOCGIFADDR may fail for IPv6-only interfaces; fall back to /proc/net/if_inet6
    get_device_addr_v6_fallback(ifname)
}

fn get_device_addr_v6_fallback(ifname: &str) -> io::Result<IpAddr> {
    // Try reading /proc/net/if_inet6 for IPv6 addresses on this interface
    if let Ok(contents) = fs::read_to_string("/proc/net/if_inet6") {
        let mut global_addr: Option<Ipv6Addr> = None;
        let mut any_addr: Option<Ipv6Addr> = None;
        for line in contents.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }
            // if_inet6 format: addr(32 hex) plen(2) scope(2) dad_status(2) flags(4) ifname
            let addr_hex = parts[0];
            let if_name = parts[5];
            if if_name != ifname {
                continue;
            }
            if let Ok(addr) = parse_inet6_addr(addr_hex) {
                // Skip link-local addresses (fe80::/10) if we can find a better one
                if addr.is_unicast_link_local() {
                    if any_addr.is_none() {
                        any_addr = Some(addr);
                    }
                    continue;
                }
                if global_addr.is_none() {
                    global_addr = Some(addr);
                }
            }
        }
        // Prefer global/unicast address over link-local
        if let Some(addr) = global_addr {
            return Ok(IpAddr::V6(addr));
        }
        if let Some(addr) = any_addr {
            return Ok(IpAddr::V6(addr));
        }
    }
    Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "No IPv6 address found on interface".to_owned()))
}

fn parse_inet6_addr(hex: &str) -> io::Result<Ipv6Addr> {
    if hex.len() != 32 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid IPv6 address length in if_inet6"));
    }
    let mut octets = [0u8; 16];
    for i in 0..16 {
        octets[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid hex in if_inet6"))?;
    }
    Ok(Ipv6Addr::from(octets))
}

#[allow(clippy::useless_conversion)]
fn set_device_addr(ifname: &str, addr: Ipv4Addr) -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    ifreq.data.addr.af = libc::AF_INET as libc::c_int;
    ifreq.data.addr.addr = addr;
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFADDR.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => Ok(()),
        _ => Err(IoError::last_os_error()),
    }
}

fn set_device_addr_v6(ifname: &str, addr: Ipv6Addr, _netmask: IpAddr) -> io::Result<()> {
    // Linux SIOCSIFADDR ioctl has limited IPv6 support; use `ip addr add` instead.
    let prefix = addr.to_string();
    let plen = match _netmask {
        IpAddr::V6(netmask) => {
            // Calculate prefix length from netmask
            let octets = netmask.octets();
            let mut plen = 0u8;
            for &octet in &octets {
                plen += octet.count_ones() as u8;
            }
            plen
        }
        IpAddr::V4(_) => 64,
    };
    let status = std::process::Command::new("ip")
        .args(["addr", "add", &format!("{}/{}", prefix, plen), "dev", ifname])
        .status()
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("`ip` command not found: {}", e)))?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::Other, format!("`ip addr add` failed with status {:?}", status)))
    }
}

#[allow(dead_code)]
#[allow(clippy::useless_conversion)]
fn get_device_netmask(ifname: &str) -> io::Result<IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFNETMASK.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => {
            let af = unsafe { ifreq.data.addr.af };
            if af as libc::c_int != libc::AF_INET {
                return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "Invalid address family".to_owned()));
            }
            let ip = unsafe { ifreq.data.addr.addr };
            Ok(IpAddr::V4(ip))
        }
        _ => Err(IoError::last_os_error()),
    }
}

#[allow(clippy::useless_conversion)]
fn set_device_netmask(ifname: &str, addr: Ipv4Addr) -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    ifreq.data.addr.af = libc::AF_INET as libc::c_int;
    ifreq.data.addr.addr = addr;
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFNETMASK.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => Ok(()),
        _ => Err(IoError::last_os_error()),
    }
}

#[allow(clippy::useless_conversion)]
fn set_device_enabled(ifname: &str, up: bool) -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS.try_into().unwrap(), &mut ifreq) } != 0 {
        return Err(IoError::last_os_error());
    }
    if up {
        unsafe { ifreq.data.value |= libc::IFF_UP | libc::IFF_RUNNING }
    } else {
        unsafe { ifreq.data.value &= !libc::IFF_UP }
    }
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => Ok(()),
        _ => Err(IoError::last_os_error()),
    }
}

fn get_default_device() -> io::Result<String> {
    let fd = BufReader::new(File::open("/proc/net/route")?);
    let mut best = None;
    for line in fd.lines() {
        let line = line?;
        let parts = line.split('\t').collect::<Vec<_>>();
        if parts[1] == "00000000" {
            best = Some(parts[0].to_string());
            break;
        }
        if parts[2] != "00000000" {
            best = Some(parts[0].to_string())
        }
    }
    if let Some(ifname) = best {
        Ok(ifname)
    } else {
        Err(io::Error::new(io::ErrorKind::NotFound, "No default interface found".to_string()))
    }
}

fn get_rp_filter(device: &str) -> io::Result<u8> {
    let mut fd = File::open(format!("/proc/sys/net/ipv4/conf/{}/rp_filter", device))?;
    let mut contents = String::with_capacity(10);
    fd.read_to_string(&mut contents)?;
    u8::from_str(contents.trim()).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid rp_filter value"))
}

fn set_rp_filter(device: &str, val: u8) -> io::Result<()> {
    let mut fd = File::create(format!("/proc/sys/net/ipv4/conf/{}/rp_filter", device))?;
    writeln!(fd, "{}", val)
}

}

#[cfg(unix)]
pub use unix_device::{TunTapDevice, MockDevice};

#[cfg(windows)]
mod windows_device {
    use super::*;
    use std::os::windows::io::{AsRawSocket, RawSocket};
    use std::time::{Duration, Instant};

    fn run_command_with_timeout(
        mut cmd: std::process::Command, timeout: Duration, label: &str,
    ) -> io::Result<std::process::Output> {
        use std::io::Read;
        cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn()?;
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut stdout = Vec::new();
                    let mut stderr = Vec::new();
                    if let Some(mut o) = child.stdout.take() {
                        let _ = o.read_to_end(&mut stdout);
                    }
                    if let Some(mut e) = child.stderr.take() {
                        let _ = e.read_to_end(&mut stderr);
                    }
                    return Ok(std::process::Output { status, stdout, stderr });
                }
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        warn!("Windows command timed out after {:?}: {}", timeout, label);
                        let _ = child.kill();
                        let _ = child.wait();
                        let mut stdout = Vec::new();
                        let mut stderr = Vec::new();
                        if let Some(mut o) = child.stdout.take() {
                            let _ = o.read_to_end(&mut stdout);
                        }
                        if let Some(mut e) = child.stderr.take() {
                            let _ = e.read_to_end(&mut stderr);
                        }
                        // On Windows, Command::status().code() can be None for abnormal/terminated processes.
                        // Use a synthetic exit status-like Output with code inferred as 1 in callers.
                        return Ok(std::process::Output {
                            status: status_from_code(1),
                            stdout,
                            stderr,
                        });
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(e),
            }
        }
    }

    #[cfg(windows)]
    fn status_from_code(code: i32) -> std::process::ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code as u32)
    }

    /// Minimal TUN-only device for Windows MVP using Wintun.
    pub struct WintunDevice {
        ifname: String,
        type_: Type,
        session: std::sync::Arc<wintun::Session>,
        ip: Option<IpAddr>,
        read_wait_event: windows_sys::Win32::Foundation::HANDLE,
    }

    impl WintunDevice {
        pub fn new(ifname: &str, type_: Type, _path: Option<&str>) -> io::Result<Self> {
            if type_ != Type::Tun {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "Only TUN is supported on Windows MVP"));
            }
            // Expand %d placeholder (used on Unix) to a concrete name on Windows.
            let ifname = if ifname.contains("%d") {
                ifname.replace("%d", "0")
            } else {
                ifname.to_string()
            };
            let wintun = unsafe { wintun::load() }
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to load wintun.dll: {}", e)))?;
            // Try to open existing adapter, otherwise create it. The "name" is the adapter name;
            // tunnel name can be the same.
            let adapter = match wintun::Adapter::open(&wintun, &ifname) {
                Ok(a) => a,
                Err(_) => wintun::Adapter::create(&wintun, &ifname, &ifname, None)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create wintun adapter: {}", e)))?,
            };
            let session = adapter.start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to start wintun session: {}", e)))?;
            let session = std::sync::Arc::new(session);
            let read_wait_event = session.get_read_wait_event()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to get wintun read wait event: {}", e)))?
                as windows_sys::Win32::Foundation::HANDLE;
            Ok(Self { ifname, type_, session, ip: None, read_wait_event })
        }

        pub fn set_mtu(&self, _value: Option<usize>) -> io::Result<()> { Ok(()) }
        pub fn configure(&mut self, addr: IpAddr, netmask: IpAddr) -> io::Result<()> {
            // Best-effort: configure via netsh; store IP for get_ip
            info!("Windows device configure start: ifname={} addr={} netmask={}", self.ifname, addr, netmask);
            match addr {
                IpAddr::V4(v4) => {
                    let mask = match netmask {
                        IpAddr::V4(m) => m.to_string(),
                        _ => "255.255.255.0".to_string(),
                    };
                    let prefix_len: u32 = match netmask {
                        IpAddr::V4(m) => m.octets().iter().map(|b| b.count_ones()).sum::<u32>(),
                        _ => 24,
                    };
                    // Bring interface up (best-effort)
                    let mut enable_cmd = std::process::Command::new("netsh");
                    enable_cmd.args(["interface", "set", "interface", &format!("name={}", self.ifname), "admin=enabled"]);
                    match run_command_with_timeout(enable_cmd, Duration::from_secs(8), "netsh interface set admin=enabled") {
                        Ok(out) => {
                            info!(
                                "Windows netsh enable interface status={:?} stdout='{}' stderr='{}'",
                                out.status.code(),
                                String::from_utf8_lossy(&out.stdout).trim(),
                                String::from_utf8_lossy(&out.stderr).trim()
                            );
                        }
                        Err(e) => warn!("Windows netsh enable interface failed: {}", e),
                    }

                    let mut configured = false;
                    let attempts: Vec<Vec<String>> = vec![
                        vec!["interface".into(), "ipv4".into(), "set".into(), "address".into(),
                             format!("name={}", self.ifname), "static".into(), v4.to_string(), mask.clone()],
                        vec!["interface".into(), "ipv4".into(), "set".into(), "address".into(),
                             self.ifname.clone(), "static".into(), v4.to_string(), mask.clone()],
                        vec!["interface".into(), "ipv4".into(), "add".into(), "address".into(),
                             format!("name={}", self.ifname), format!("addr={}", v4), format!("mask={}", mask)],
                        vec!["interface".into(), "ipv4".into(), "add".into(), "address".into(),
                             self.ifname.clone(), v4.to_string(), mask.clone()],
                        vec!["interface".into(), "ip".into(), "set".into(), "address".into(),
                             self.ifname.clone(), "static".into(), v4.to_string(), mask.clone()],
                    ];
                    for args in &attempts {
                        info!("Windows IPv4 config attempt: netsh {:?}", args);
                        let mut cmd = std::process::Command::new("netsh");
                        cmd.args(args.iter().map(|s| s.as_str()));
                        let label = format!("netsh {:?}", args);
                        match run_command_with_timeout(cmd, Duration::from_secs(10), &label) {
                            Ok(out) => {
                                let stdout = String::from_utf8_lossy(&out.stdout);
                                let stderr = String::from_utf8_lossy(&out.stderr);
                                info!(
                                    "Windows IPv4 netsh result status={:?} stdout='{}' stderr='{}' args={:?}",
                                    out.status.code(),
                                    stdout.trim(),
                                    stderr.trim(),
                                    args
                                );
                                if out.status.success() {
                                    configured = true;
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("Windows IPv4 netsh attempt failed ({:?}): {}", args, e);
                            }
                        }
                    }

                    if !configured {
                        // PowerShell fallback
                        let ps = format!(
                            "$ErrorActionPreference='Continue'; \
                             Remove-NetIPAddress -InterfaceAlias '{if}' -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue | Out-Null; \
                             New-NetIPAddress -InterfaceAlias '{if}' -IPAddress '{ip}' -PrefixLength {pfx} -PolicyStore ActiveStore -ErrorAction Stop | Out-Null; \
                             Start-Sleep -Milliseconds 200; \
                             $ok = Get-NetIPAddress -InterfaceAlias '{if}' -AddressFamily IPv4 -IPAddress '{ip}' -ErrorAction SilentlyContinue; \
                             if($ok){{ exit 0 }} else {{ exit 1 }}",
                            if = self.ifname.replace('\'', "''"),
                            ip = v4,
                            pfx = prefix_len
                        );
                        info!("Windows IPv4 config PowerShell fallback for {} on {}", v4, self.ifname);
                        let mut ps_cmd = std::process::Command::new("powershell");
                        ps_cmd.args(["-NoProfile", "-NonInteractive", "-Command", &ps]);
                        match run_command_with_timeout(ps_cmd, Duration::from_secs(20), "powershell ipv4 fallback") {
                            Ok(out) => {
                                let stdout = String::from_utf8_lossy(&out.stdout);
                                let stderr = String::from_utf8_lossy(&out.stderr);
                                info!(
                                    "Windows IPv4 PowerShell result status={:?} stdout='{}' stderr='{}'",
                                    out.status.code(),
                                    stdout.trim(),
                                    stderr.trim()
                                );
                                if out.status.success() {
                                    configured = true;
                                }
                            }
                            Err(e) => {
                                warn!("Windows IPv4 PowerShell fallback failed: {}", e);
                            }
                        }
                    }

                    // Post-check (best-effort visibility in logs)
                    let mut post_cmd = std::process::Command::new("netsh");
                    post_cmd.args(["interface", "ipv4", "show", "addresses", &format!("name={}", self.ifname)]);
                    match run_command_with_timeout(post_cmd, Duration::from_secs(8), "netsh show ipv4 addresses") {
                        Ok(out) => {
                            info!(
                                "Windows IPv4 post-check netsh status={:?} stdout='{}' stderr='{}'",
                                out.status.code(),
                                String::from_utf8_lossy(&out.stdout).trim(),
                                String::from_utf8_lossy(&out.stderr).trim()
                            );
                        }
                        Err(e) => {
                            warn!("Windows IPv4 post-check netsh failed: {}", e);
                        }
                    }

                    if !configured {
                        warn!("Failed to configure IPv4 {} on interface '{}'; tunnel data-plane may not work until address is set manually", v4, self.ifname);
                    }
                }
                IpAddr::V6(v6) => {
                    let prefix_len = match netmask {
                        IpAddr::V6(m) => m.octets().iter().map(|b| b.count_ones() as u8).sum::<u8>(),
                        _ => 64,
                    };
                    let attempts: Vec<Vec<String>> = vec![
                        vec!["interface".into(), "ipv6".into(), "add".into(), "address".into(),
                             self.ifname.clone(), format!("{}/{}", v6, prefix_len), "store=active".into()],
                        vec!["interface".into(), "ipv6".into(), "add".into(), "address".into(),
                             format!("interface={}", self.ifname), format!("address={}/{}", v6, prefix_len)],
                        vec!["interface".into(), "ipv6".into(), "set".into(), "address".into(),
                             format!("interface={}", self.ifname), format!("address={}/{}", v6, prefix_len)],
                    ];
                    let mut configured = false;
                    for args in &attempts {
                        info!("Windows IPv6 config attempt: netsh {:?}", args);
                        let mut cmd = std::process::Command::new("netsh");
                        cmd.args(args.iter().map(|s| s.as_str()));
                        let label = format!("netsh {:?}", args);
                        match run_command_with_timeout(cmd, Duration::from_secs(10), &label) {
                            Ok(out) => {
                                let stderr = String::from_utf8_lossy(&out.stderr);
                                let stdout = String::from_utf8_lossy(&out.stdout);
                                info!("Windows IPv6 netsh result status={:?} stdout='{}' stderr='{}' args={:?}", out.status.code(), stdout.trim(), stderr.trim(), args);
                                if out.status.success() {
                                    configured = true;
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("Windows IPv6 netsh attempt failed ({:?}): {}", args, e);
                            }
                        }
                    }
                    if !configured {
                        warn!("Failed to configure IPv6 {}/{} on interface '{}'; tunnel data-plane may not work until address is set manually", v6, prefix_len, self.ifname);
                    }
                }
            }
            info!("Windows device configure done for ifname={} addr={}", self.ifname, addr);
            self.ip = Some(addr);
            Ok(())
        }
        pub fn get_rp_filter(&self) -> io::Result<u8> { Ok(1) }
        pub fn fix_rp_filter(&self) -> io::Result<()> { Ok(()) }
        pub fn get_overhead(&self) -> usize { 40 + 8 + 16 + 16 + 1 }
    }

    impl Device for WintunDevice {
        fn get_type(&self) -> Type { self.type_ }
        fn ifname(&self) -> &str { &self.ifname }
        fn read(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
            use std::sync::atomic::{AtomicU64, Ordering};
            use std::time::Instant;
            static READ_OK: AtomicU64 = AtomicU64::new(0);
            static READ_NONE: AtomicU64 = AtomicU64::new(0);
            static READ_ERR: AtomicU64 = AtomicU64::new(0);
            static NONE_STREAK: AtomicU64 = AtomicU64::new(0);

            buffer.clear();
            let t0 = Instant::now();
            match self.session.try_receive() {
                Ok(Some(packet)) => {
                    let bytes = packet.bytes();
                    let len = bytes.len();
                    // HOT PATH FILTER: drop IPv6 link-local multicast (ff02::) noise.
                    // Windows constantly generates IPv6 multicast/SSDP/LLMNR packets on the
                    // TUN interface. If we let them through, the device stays readable forever
                    // and starves the socket in the single-threaded event loop.
                    if len >= 26 && bytes[0] >> 4 == 6 && bytes[24] == 0xff && bytes[25] == 0x02 {
                        let ok = READ_OK.fetch_add(1, Ordering::Relaxed) + 1;
                        let us = t0.elapsed().as_micros();
                        if ok % 100 == 1 {
                            debug!(
                                "[TUN_READ] dropped IPv6 multicast packet_len={} read_us={} ok={}",
                                len, us, ok
                            );
                        }
                        return Err(Error::Device("empty".to_string()));
                    }
                    buffer.set_length(len);
                    buffer.message_mut().copy_from_slice(bytes);
                    let ok = READ_OK.fetch_add(1, Ordering::Relaxed) + 1;
                    NONE_STREAK.store(0, Ordering::Relaxed);
                    let us = t0.elapsed().as_micros();
                    debug!(
                        "[TUN_READ] result=Ok packet_len={} read_us={} ok={} none={} err={} none_streak=0",
                        len,
                        us,
                        ok,
                        READ_NONE.load(Ordering::Relaxed),
                        READ_ERR.load(Ordering::Relaxed)
                    );
                    Ok(())
                }
                Ok(None) => {
                    // Debug mode: non-blocking. Do not wait 50ms inside read; rely on Wintun
                    // read-wait event re-triggering to avoid starving/blocking the main loop.
                    let none = READ_NONE.fetch_add(1, Ordering::Relaxed) + 1;
                    let streak = NONE_STREAK.fetch_add(1, Ordering::Relaxed) + 1;
                    let us = t0.elapsed().as_micros();
                    if none <= 20 || none % 200 == 0 || streak <= 5 || streak % 100 == 0 {
                        debug!(
                            "[TUN_READ] result=None(empty) read_us={} ok={} none={} err={} none_streak={} waited_ms=0",
                            us,
                            READ_OK.load(Ordering::Relaxed),
                            none,
                            READ_ERR.load(Ordering::Relaxed),
                            streak
                        );
                    }
                    Err(Error::Device("empty".to_string()))
                }
                Err(e) => {
                    let errc = READ_ERR.fetch_add(1, Ordering::Relaxed) + 1;
                    NONE_STREAK.store(0, Ordering::Relaxed);
                    let us = t0.elapsed().as_micros();
                    warn!(
                        "[TUN_READ] result=Err read_us={} ok={} none={} err={} err={}",
                        us,
                        READ_OK.load(Ordering::Relaxed),
                        READ_NONE.load(Ordering::Relaxed),
                        errc,
                        e
                    );
                    Err(Error::Device("empty".to_string()))
                }
            }
        }
        fn write(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
            use std::sync::atomic::{AtomicU64, Ordering};
            use std::time::Instant;
            static W_OK: AtomicU64 = AtomicU64::new(0);
            static W_ERR: AtomicU64 = AtomicU64::new(0);
            let data = buffer.message();
            let len = data.len();
            let icmp = if len >= 28 && (data[0] >> 4) == 4 {
                let ihl = ((data[0] & 0x0f) as usize) * 4;
                if len >= ihl + 8 && data.get(9) == Some(&1) {
                    let b = &data[ihl..];
                    Some((b[0], b[1], u16::from_be_bytes([b[4], b[5]]), u16::from_be_bytes([b[6], b[7]])))
                } else { None }
            } else { None };
            let t0 = Instant::now();
            match self.session.allocate_send_packet(len as u16) {
                Ok(mut packet) => {
                    let alloc_us = t0.elapsed().as_micros();
                    packet.bytes_mut().copy_from_slice(data);
                    self.session.send_packet(packet);
                    let ok = W_OK.fetch_add(1, Ordering::Relaxed) + 1;
                    let total_us = t0.elapsed().as_micros();
                    debug!("[TUN_WRITE] ok len={} alloc_us={} total_us={} ok_count={} err_count={} icmp={:?}", len, alloc_us, total_us, ok, W_ERR.load(Ordering::Relaxed), icmp);
                    Ok(())
                }
                Err(e) => {
                    let errc = W_ERR.fetch_add(1, Ordering::Relaxed) + 1;
                    let total_us = t0.elapsed().as_micros();
                    warn!("[TUN_WRITE] err len={} total_us={} ok_count={} err_count={} icmp={:?} err={:?}", len, total_us, W_OK.load(Ordering::Relaxed), errc, icmp, e);
                    Err(Error::Device("Wintun write error".to_string()))
                }
            }
        }
        fn get_ip(&self) -> Result<IpAddr, Error> {
            self.ip.ok_or(Error::Device("No IP configured".to_string()))
        }
        fn as_raw_socket(&self) -> RawSocket { self.read_wait_event as RawSocket }
    }

    impl AsRawSocket for WintunDevice {
        fn as_raw_socket(&self) -> RawSocket { self.read_wait_event as RawSocket }
    }
// WintunDevice contains a Win32 HANDLE (*mut c_void) which is not automatically Send,
// but a handle is safe to move between threads as long as it is used with proper
// synchronization. The Wintun session (Arc) is Send.
unsafe impl Send for WintunDevice {}

    // MockDevice for Windows
    pub struct MockDevice {
        inbound: std::collections::VecDeque<Vec<u8>>,
        outbound: std::collections::VecDeque<Vec<u8>>,
    }
    impl MockDevice {
        pub fn new() -> Self { Default::default() }
        pub fn put_inbound(&mut self, data: Vec<u8>) { self.inbound.push_back(data) }
        pub fn pop_outbound(&mut self) -> Option<Vec<u8>> { self.outbound.pop_front() }
        pub fn has_inbound(&self) -> bool { !self.inbound.is_empty() }
    }
    impl Default for MockDevice {
        fn default() -> Self { Self { outbound: std::collections::VecDeque::with_capacity(10), inbound: std::collections::VecDeque::with_capacity(10) } }
    }
    impl Device for MockDevice {
        fn get_type(&self) -> Type { Type::Tun }
        fn ifname(&self) -> &str { "mock0" }
        fn read(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
            if let Some(data) = self.inbound.pop_front() {
                buffer.clear();
                buffer.set_length(data.len());
                buffer.message_mut().copy_from_slice(&data);
                Ok(())
            } else { Err(Error::Device("empty".to_string())) }
        }
        fn write(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
            self.outbound.push_back(buffer.message().into());
            Ok(())
        }
        fn get_ip(&self) -> Result<IpAddr, Error> { Err(Error::Device("Dummy devices have no IP address".to_string())) }
        fn as_raw_socket(&self) -> RawSocket { 0 }
    }
    impl AsRawSocket for MockDevice {
        fn as_raw_socket(&self) -> RawSocket { 0 }
    }
}

#[cfg(windows)]
pub use windows_device::{WintunDevice as TunTapDevice, MockDevice};
