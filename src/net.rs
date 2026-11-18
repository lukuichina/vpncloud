// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    collections::{HashMap, VecDeque},
    io::{self, ErrorKind},
    net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket, FromRawSocket};

#[cfg(windows)]
use socket2::{Domain, Protocol, Socket as Socket2, Type};

#[cfg(windows)]
use std::os::windows::io::IntoRawSocket;

use super::util::{MockTimeSource, MsgBuffer, Time, TimeSource};
use crate::{config::DEFAULT_PORT, port_forwarding::PortForwarding};

pub fn mapped_addr(addr: SocketAddr) -> SocketAddr {
    // HOT PATH
    match addr {
        SocketAddr::V4(addr4) => SocketAddr::new(IpAddr::V6(addr4.ip().to_ipv6_mapped()), addr4.port()),
        _ => addr,
    }
}

pub fn get_ip() -> IpAddr {
    // Try to determine the outbound interface IP by connecting to a well-known
    // address.  Try IPv4 first, then IPv6, so the function works in both
    // dual-stack and IPv6-only environments.  If all attempts fail, fall back
    // to the unspecified address instead of panicking.
    for (bind_addr, target) in [("0.0.0.0:0", "8.8.8.8:0"), ("[::]:0", "[2001:4860:4860::8888]:0")] {
        if let Ok(s) = UdpSocket::bind(bind_addr) {
            if s.connect(target).is_ok() {
                if let Ok(addr) = s.local_addr() {
                    return addr.ip();
                }
            }
        }
    }
    // Fallback: return an unspecified address.  Callers should handle this
    // gracefully (e.g. by not advertising an external address).
    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
}

/// Try to detect the outbound IPv6 address of this host.
///
/// Returns None when no IPv6 connectivity is available.
pub fn get_ip_v6() -> Option<Ipv6Addr> {
    if let Ok(s) = UdpSocket::bind("[::]:0") {
        if s.connect("[2001:4860:4860::8888]:0").is_ok() {
            if let Ok(addr) = s.local_addr() {
                if let IpAddr::V6(ip6) = addr.ip() {
                    return Some(ip6);
                }
            }
        }
    }
    None
}

#[cfg(unix)]
pub trait Socket: AsRawFd + Sized {
    fn listen(addr: &str) -> Result<Self, io::Error>;
    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error>;
    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error>;
    fn address(&self) -> Result<SocketAddr, io::Error>;
    fn create_port_forwarding(&self) -> Option<PortForwarding>;
    /// Returns the number of packets waiting in the receive channel (0 for non-channel sockets).
    fn pending(&self) -> usize { 0 }
    /// Channel-mode inbound receiver for low-latency blocking waits in main loop.
    fn channel_net_rx(&self) -> Option<&crossbeam_channel::Receiver<crate::channel_io::NetPacket>> { None }
    /// Re-establish the underlying connection after a disconnection.
    /// Used by WebSocket proxy clients to reconnect without restarting the process.
    /// Default implementation does nothing (no-op for plain UDP sockets).
    fn reconnect(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
    /// Flush/drain the receive buffer to discard stale packets after reconnection.
    /// Default implementation drains kernel socket buffer via FIONREAD + recv_from loop.
    fn flush_receive_buffer(&mut self) -> Result<(), io::Error> {
        use std::os::unix::io::AsRawFd;
        let fd = self.as_raw_fd();
        // Drain kernel receive buffer
        let mut bytes: libc::c_int = 0;
        let ret = unsafe { libc::ioctl(fd, libc::FIONREAD, &mut bytes) };
        if ret == 0 && bytes > 0 {
            let mut buf = vec![0u8; bytes as usize];
            let mut drained = 0;
            while drained < bytes {
                match self.receive(&mut MsgBuffer::new(0)) {
                    Ok(_) => drained += 1,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
pub trait Socket: AsRawSocket + Sized {
    fn listen(addr: &str) -> Result<Self, io::Error>;
    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error>;
    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error>;
    fn address(&self) -> Result<SocketAddr, io::Error>;
    fn create_port_forwarding(&self) -> Option<PortForwarding>;
    /// Returns the number of packets waiting in the receive channel (0 for non-channel sockets).
    fn pending(&self) -> usize { 0 }
    /// Channel-mode inbound receiver for low-latency blocking waits in main loop.
    fn channel_net_rx(&self) -> Option<&crossbeam_channel::Receiver<crate::channel_io::NetPacket>> { None }
    /// Re-establish the underlying connection after a disconnection.
    /// Used by WebSocket proxy clients to reconnect without restarting the process.
    /// Default implementation does nothing (no-op for plain UDP sockets).
    fn reconnect(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
    /// Flush/drain the receive buffer to discard stale packets after reconnection.
    /// Default implementation drains kernel socket buffer via WSAIoctl + recv_from loop.
    fn flush_receive_buffer(&mut self) -> Result<(), io::Error> {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{WSAIoctl, FIONREAD, SOCKET_ERROR, SOCKET};
        let socket = self.as_raw_socket() as SOCKET;
        let mut bytes: u32 = 0;
        let mut bytes_returned: u32 = 0;
        let ret = unsafe {
            WSAIoctl(
                socket,
                FIONREAD as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes as *mut _ as *mut _,
                std::mem::size_of::<u32>() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
                None,
            )
        };
        if ret != SOCKET_ERROR && bytes > 0 {
            let mut drained = 0;
            while drained < bytes {
                match self.receive(&mut MsgBuffer::new(0)) {
                    Ok(_) => drained += 1,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }
}

pub fn parse_listen(addr: &str, default_port: u16) -> SocketAddr {
    if let Some(addr) = addr.strip_prefix("*:") {
        let port = try_fail!(addr.parse::<u16>(), "Invalid port: {}");
        // Prefer dual-stack-capable wildcard on all platforms; bind logic handles fallback.
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else if addr.contains(':') {
        try_fail!(addr.parse::<SocketAddr>(), "Invalid address: {}: {}", addr)
    } else if let Ok(port) = addr.parse::<u16>() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else {
        let ip = try_fail!(addr.parse::<IpAddr>(), "Invalid addr: {}");
        SocketAddr::new(ip, default_port)
    }
}

fn socket_bind_addr(addr: SocketAddr) -> SocketAddr {
    // Keep v4-mapped handling for explicit mapped addresses, but do not force
    // wildcard IPv6 down to IPv4 here; dual-stack/IPv6 support needs [::] binds.
    addr
}

pub(crate) fn socket_send_addr(addr: SocketAddr) -> SocketAddr {
    // Address-family normalization is handled in UdpSocket::send based on the
    // actual bound socket family (important for Windows dual-stack sockets).
    addr
}

impl Socket for UdpSocket {
    fn listen(addr: &str) -> Result<Self, io::Error> {
        let parsed = parse_listen(addr, DEFAULT_PORT);
        let bind_addr = socket_bind_addr(parsed);
        info!("Socket::listen: binding UDP socket to {} (from listen={})", bind_addr, addr);

        #[cfg(windows)]
        {
            // On Windows, use socket2 to create a dual-stack socket with IPV6_V6ONLY=0
            // so that a single [::] socket can handle both IPv6 and IPv4 (via v4-mapped).
            if let SocketAddr::V6(v6) = bind_addr {
                if v6.ip().is_unspecified() && v6.port() > 0 {
                    let port = v6.port();
                    match Socket2::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) {
                        Ok(sock2) => {
                            // Disable IPV6_V6ONLY to enable dual-stack (IPv4 via v4-mapped)
                            let _ = sock2.set_only_v6(false);
                            // Set non-blocking
                            let _ = sock2.set_nonblocking(true);
                            // Bind to [::]:port
                            let sockaddr = socket2::SockAddr::from(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port));
                            if sock2.bind(&sockaddr).is_ok() {
                                let raw = sock2.into_raw_socket();
                                // Convert to std::net::UdpSocket
                                let sock = unsafe { UdpSocket::from_raw_socket(raw) };
                                info!("Socket::listen: UDP socket bound to local_addr=[::]:{} nonblocking=true (dual-stack)", port);
                                return Ok(sock);
                            }
                            // If bind fails, fall through to fallback
                        }
                        Err(e) => {
                            warn!("Socket::listen: socket2 creation failed ({}), falling back to std bind", e);
                        }
                    }
                }
            }
        }

        // Standard bind (Unix, or Windows fallback / non-wildcard addresses)
        let sock = match UdpSocket::bind(bind_addr) {
            Ok(s) => s,
            Err(e) => {
                // Fallback for platforms/configs where [::] dual-stack bind is unavailable.
                if let SocketAddr::V6(v6) = bind_addr {
                    if v6.ip().is_unspecified() {
                        let v4 = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), v6.port());
                        warn!("Socket::listen: failed to bind {} ({}), falling back to {}", bind_addr, e, v4);
                        UdpSocket::bind(v4)?
                    } else {
                        return Err(e);
                    }
                } else {
                    return Err(e);
                }
            }
        };
        sock.set_nonblocking(true)?;
        match sock.local_addr() {
            Ok(local) => info!("Socket::listen: UDP socket bound to local_addr={} nonblocking=true", local),
            Err(e) => warn!("Socket::listen: bound but failed to get local_addr: {}", e),
        }
        Ok(sock)
    }

    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        buffer.clear();
        let (size, addr) = self.recv_from(buffer.buffer())?;
        buffer.set_length(size);
        let mapped = mapped_addr(addr);
        debug!("Socket.recv_from: {} bytes raw_src={} mapped_src={}", size, addr, mapped);
        Ok(mapped)
    }

    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        // Select sockaddr family compatible with the bound local socket.
        // - IPv6 socket ([::] / dual-stack): IPv4 peers must be sent as v4-mapped IPv6.
        // - IPv4 socket (fallback): v4-mapped IPv6 peers must be sent as IPv4.
        // Some Windows environments return WSAEFAULT(10014)/WSAEADDRNOTAVAIL(10049) on mismatch.
        let local_is_v6 = self.local_addr().map(|a| a.is_ipv6()).unwrap_or(addr.is_ipv6());
        let mut candidates: Vec<SocketAddr> = Vec::with_capacity(2);
        match (local_is_v6, addr) {
            (true, SocketAddr::V4(v4)) => {
                candidates.push(SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()));
                candidates.push(addr);
            }
            (true, SocketAddr::V6(v6)) => {
                candidates.push(addr);
                if let Some(v4) = v6.ip().to_ipv4_mapped() {
                    candidates.push(SocketAddr::new(IpAddr::V4(v4), v6.port()));
                }
            }
            (false, SocketAddr::V6(v6)) => {
                if let Some(v4) = v6.ip().to_ipv4_mapped() {
                    candidates.push(SocketAddr::new(IpAddr::V4(v4), v6.port()));
                }
                candidates.push(addr);
            }
            (false, SocketAddr::V4(_)) => {
                candidates.push(addr);
            }
        }

        let t0 = std::time::Instant::now();
        let mut last_err: Option<io::Error> = None;
        for (i, dst) in candidates.iter().copied().enumerate() {
            debug!(
                "Socket.send: {} bytes to dst={} (orig={}) local_v6={} attempt={}/{}",
                data.len(), dst, addr, local_is_v6, i + 1, candidates.len()
            );
            match self.send_to(data, dst) {
                Ok(n) => {
                    let us = t0.elapsed().as_micros();
                    debug!("[UDP_TX] sent {} bytes to {} (orig={}) send_us={}", n, dst, addr, us);
                    if us >= 5_000 {
                        warn!("[UDP_TX_SLOW] sent {} bytes to {} (orig={}) send_us={}", n, dst, addr, us);
                    }
                    return Ok(n);
                }
                Err(e) => {
                    let us = t0.elapsed().as_micros();
                    let retryable = matches!(e.raw_os_error(), Some(10014) | Some(10049) | Some(97) | Some(22));
                    warn!(
                        "[UDP_TX] failed to send {} bytes to {} (orig={}): {} send_us={} retryable={}",
                        data.len(), dst, addr, e, us, retryable
                    );
                    last_err = Some(e);
                    if !retryable || i + 1 == candidates.len() {
                        break;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "UDP send failed")))
    }

    fn address(&self) -> Result<SocketAddr, io::Error> {
        let mut addr = self.local_addr()?;
        addr.set_ip(get_ip());
        Ok(addr)
    }

    fn create_port_forwarding(&self) -> Option<PortForwarding> {
        let port = match self.address() {
            Ok(a) => a.port(),
            Err(e) => {
                log::warn!("create_port_forwarding: failed to get local address: {}", e);
                return None;
            }
        };
        log::info!("create_port_forwarding: starting UPnP discovery for port {}", port);
        let pfw = PortForwarding::new(port);
        log::info!("create_port_forwarding: finished UPnP discovery for port {} (success={})", port, pfw.is_some());
        pfw
    }

    fn pending(&self) -> usize {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = self.as_raw_fd();
            let mut bytes: libc::c_int = 0;
            // Use FIONREAD to get number of bytes pending in kernel receive buffer
            let ret = unsafe { libc::ioctl(fd, libc::FIONREAD, &mut bytes) };
            if ret == 0 && bytes > 0 {
                // Estimate packets: assume average packet size ~500 bytes
                return (bytes as usize).div_ceil(500).min(256);
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            use windows_sys::Win32::Networking::WinSock::{WSAIoctl, FIONREAD, SOCKET_ERROR, SOCKET};
            let socket = self.as_raw_socket() as SOCKET;
            let mut bytes: u32 = 0;
            let mut bytes_returned: u32 = 0;
            // Use WSAIoctl with FIONREAD to get bytes pending
            let ret = unsafe {
                WSAIoctl(
                    socket,
                    FIONREAD as u32,
                    std::ptr::null_mut(),
                    0,
                    &mut bytes as *mut _ as *mut _,
                    std::mem::size_of::<u32>() as u32,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                    None,
                )
            };
            if ret != SOCKET_ERROR && bytes > 0 {
                return (bytes as usize).div_ceil(500).min(256);
            }
        }
        0
    }
}

thread_local! {
    static MOCK_SOCKET_NAT: AtomicBool = AtomicBool::new(false);
}

pub struct MockSocket {
    nat: bool,
    nat_peers: HashMap<SocketAddr, Time>,
    address: SocketAddr,
    outbound: VecDeque<(SocketAddr, Vec<u8>)>,
    inbound: VecDeque<(SocketAddr, Vec<u8>)>,
}

impl MockSocket {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            nat: Self::get_nat(),
            nat_peers: HashMap::new(),
            address,
            outbound: VecDeque::with_capacity(10),
            inbound: VecDeque::with_capacity(10),
        }
    }

    pub fn set_nat(nat: bool) {
        MOCK_SOCKET_NAT.with(|t| t.store(nat, Ordering::SeqCst))
    }

    pub fn get_nat() -> bool {
        MOCK_SOCKET_NAT.with(|t| t.load(Ordering::SeqCst))
    }

    pub fn put_inbound(&mut self, from: SocketAddr, data: Vec<u8>) -> bool {
        if !self.nat {
            self.inbound.push_back((from, data));
            return true;
        }
        if let Some(timeout) = self.nat_peers.get(&from) {
            if *timeout >= MockTimeSource::now() {
                self.inbound.push_back((from, data));
                return true;
            }
        }
        warn!("Sender {:?} is filtered out by NAT", from);
        false
    }

    pub fn pop_outbound(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        self.outbound.pop_front()
    }
}

#[cfg(unix)]
impl AsRawFd for MockSocket {
    fn as_raw_fd(&self) -> RawFd {
        unimplemented!()
    }
}

#[cfg(windows)]
impl AsRawSocket for MockSocket {
    fn as_raw_socket(&self) -> RawSocket {
        unimplemented!()
    }
}

impl Socket for MockSocket {
    fn listen(addr: &str) -> Result<Self, io::Error> {
        Ok(Self::new(mapped_addr(parse_listen(addr, DEFAULT_PORT))))
    }

    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        if let Some((addr, data)) = self.inbound.pop_front() {
            buffer.clear();
            buffer.set_length(data.len());
            buffer.message_mut().copy_from_slice(&data);
            Ok(addr)
        } else {
            Err(io::Error::new(ErrorKind::Other, "nothing in queue"))
        }
    }

    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        self.outbound.push_back((addr, data.into()));
        if self.nat {
            self.nat_peers.insert(addr, MockTimeSource::now() + 300);
        }
        Ok(data.len())
    }

    fn address(&self) -> Result<SocketAddr, io::Error> {
        Ok(self.address)
    }

    fn create_port_forwarding(&self) -> Option<PortForwarding> {
        None
    }

    fn reconnect(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

#[cfg(feature = "bench")]
mod bench {
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
    use test::Bencher;

    #[bench]
    fn udp_send(b: &mut Bencher) {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let data = [0; 1400];
        let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1);
        b.iter(|| sock.send_to(&data, &addr).unwrap());
        b.bytes = 1400;
    }
}
