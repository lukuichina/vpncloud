// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Dual-thread + Channel I/O architecture.
//!
//! This module replaces the single-threaded mutex event loop (socket and TUN device
//! contending for the same `select()`/`epoll_wait()`) with three threads:
//!
//! 1. **Main thread** — runs `GenericCloud` core logic (crypto, routing, housekeep).
//! 2. **Net thread** — owns the real UDP socket, `select()`s on it, drains packets into
//!    a `crossbeam-channel` and sends outbound packets from another channel.
//! 3. **Device thread** — owns the real TUN/Wintun device, blocks on device readability,
//!    drains packets into a channel and writes outbound packets from another channel.
//!
//! `ChannelSocket` and `ChannelDevice` implement the `Socket`/`Device` traits by
//! forwarding I/O through channels, so `GenericCloud` needs almost no changes.

use super::{
    cloud::SPACE_BEFORE,
    config::Config,
    device::{Device, TunTapDevice, Type},
    error::Error,
    net::{Socket, NetPacket, PeerEndpoint, TransportId},
    util::{MsgBuffer, Time, TimeSource},
};
#[cfg(feature = "websocket")]
use crate::wsproxy::{read_addr, ProxyConnection};
use crossbeam_channel::{bounded, Receiver, Sender, Select, TryRecvError};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};

/// Capacity of the network and device channels. Large enough to absorb bursts
/// without dropping packets under load.
const CHANNEL_CAP: usize = 4096;

/// Poll interval for the net/device threads when nothing is ready (ms).
/// Lower values reduce latency but increase CPU usage. 5ms is a good tradeoff
/// on Windows with timeBeginPeriod(1) already set in main().
#[allow(dead_code)]
const THREAD_POLL_MS: u64 = 5;

/// Minimum/maximum adaptive wait in microseconds when idle (channel I/O threads).
const MIN_WAIT_US: u64 = 200;
const MAX_WAIT_US: u64 = 5000;

/// Wake handle to interrupt net thread wait when outbound packets are queued.
#[cfg(windows)]
#[derive(Clone)]
pub struct NetWake(std::sync::Arc<windows_sys::Win32::Foundation::HANDLE>);
#[cfg(windows)]
unsafe impl Send for NetWake {}
#[cfg(windows)]
unsafe impl Sync for NetWake {}
#[cfg(windows)]
impl NetWake {
    pub fn new() -> io::Result<Self> {
        use windows_sys::Win32::System::Threading::CreateEventW;
        let h = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        if h.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(std::sync::Arc::new(h)))
        }
    }
    #[inline]
    pub fn signal(&self) {
        use windows_sys::Win32::System::Threading::SetEvent;
        unsafe { SetEvent(*self.0) };
    }
    pub fn handle(&self) -> windows_sys::Win32::Foundation::HANDLE { *self.0 }
}
#[cfg(windows)]
impl Drop for NetWake {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        if std::sync::Arc::strong_count(&self.0) == 1 {
            unsafe { CloseHandle(*self.0) };
        }
    }
}
#[cfg(not(windows))]
#[derive(Clone, Default)]
pub struct NetWake;
#[cfg(not(windows))]
impl NetWake {
    pub fn new() -> io::Result<Self> { Ok(Self) }
    #[inline]
    pub fn signal(&self) {}
}

/// Wake handle to interrupt device thread wait when outbound (TUN write) packets are queued.
#[cfg(windows)]
#[derive(Clone)]
pub struct DevWake(std::sync::Arc<windows_sys::Win32::Foundation::HANDLE>);
#[cfg(windows)]
unsafe impl Send for DevWake {}
#[cfg(windows)]
unsafe impl Sync for DevWake {}
#[cfg(windows)]
impl DevWake {
    pub fn new() -> io::Result<Self> {
        use windows_sys::Win32::System::Threading::CreateEventW;
        let h = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        if h.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(std::sync::Arc::new(h)))
        }
    }
    #[inline]
    pub fn signal(&self) {
        use windows_sys::Win32::System::Threading::SetEvent;
        unsafe { SetEvent(*self.0) };
    }
    pub fn handle(&self) -> windows_sys::Win32::Foundation::HANDLE { *self.0 }
}
#[cfg(windows)]
impl Drop for DevWake {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        if std::sync::Arc::strong_count(&self.0) == 1 {
            unsafe { CloseHandle(*self.0) };
        }
    }
}
#[cfg(not(windows))]
#[derive(Clone, Default)]
pub struct DevWake;
#[cfg(not(windows))]
impl DevWake {
    pub fn new() -> io::Result<Self> { Ok(Self) }
    #[inline]
    pub fn signal(&self) {}
}

#[inline]
fn adaptive_idle_wait_us(idle_spins: u32, configured_ms: u64) -> u64 {
    let base = if configured_ms == 0 { MIN_WAIT_US } else { (configured_ms.max(1) * 1000).min(MAX_WAIT_US) };
    if configured_ms == 0 {
        // Low-latency mode: start at 200us, back off only after sustained idleness.
        if idle_spins < 32 { base } else { (base << (idle_spins.saturating_sub(32).min(4))).min(MAX_WAIT_US) }
    } else {
        // Honor configured poll timeout as the idle wait budget (e.g. --poll-timeout-ms 1).
        base.max(MIN_WAIT_US)
    }
}

/// ---------------- Channel-backed Socket ------------------

/// `Socket` implementation that forwards I/O to/from the net thread(s) through channels.
/// Each transport (UDP socket / WebSocket connection) runs in its own worker thread and
/// owns one outbound channel; all transports share one inbound channel whose packets
/// carry their `PeerEndpoint`. `GenericCloud` holds a single `ChannelSocket` and sends
/// to the correct worker via `send_endpoint(endpoint.transport)`.
pub struct ChannelSocket {
    net_rx: Receiver<NetPacket>,
    /// Per-transport outbound channel + wake handle.
    transports: HashMap<TransportId, (Sender<NetPacket>, NetWake)>,
    local_addr: SocketAddr,
}

impl ChannelSocket {
    pub fn new(
        net_rx: Receiver<NetPacket>,
        transports: HashMap<TransportId, (Sender<NetPacket>, NetWake)>,
        local_addr: SocketAddr,
    ) -> Self {
        Self { net_rx, transports, local_addr }
    }
}

impl Clone for ChannelSocket {
    fn clone(&self) -> Self {
        Self {
            net_rx: self.net_rx.clone(),
            transports: self.transports.clone(),
            local_addr: self.local_addr,
        }
    }
}

/// 选一个默认传输用于仅传 addr 的旧 `send`。
/// 当同时存在 UDP 和 WebSocket 时，优先 WebSocket：WebSocket 是通过代理
/// 连接远程 peer 的主要通路，UDP 仅用于本地 LAN。若只选 Udp(0)，则在
/// 混合模式（-l wss://... -l 0.0.0.0:2600）下 init 消息会错误地走 UDP，
/// 导致无法通过 WebSocket 隧道握手。
fn default_transport(transports: &HashMap<TransportId, (Sender<NetPacket>, NetWake)>) -> TransportId {
    transports
        .keys()
        .copied()
        .find(|t| matches!(t, TransportId::WebSocket(_)))
        .or_else(|| {
            transports
                .keys()
                .copied()
                .find(|t| matches!(t, TransportId::Udp(0)))
        })
        .or_else(|| transports.keys().next().copied())
        .unwrap_or(TransportId::Udp(0))
}

#[cfg(unix)]
impl AsRawFd for ChannelSocket {
    fn as_raw_fd(&self) -> RawFd {
        // Not used for epoll anymore; return a dummy.
        0
    }
}

#[cfg(windows)]
impl AsRawSocket for ChannelSocket {
    fn as_raw_socket(&self) -> RawSocket {
        // Not used for select anymore; return a dummy.
        0
    }
}

impl Socket for ChannelSocket {
    fn listen(_addr: &str) -> io::Result<Self> {
        // The real socket is already bound in the net thread(s); nothing to do here.
        Err(io::Error::new(
            io::ErrorKind::Other,
            "ChannelSocket::listen must not be called; use new()",
        ))
    }

    fn receive_endpoint(&mut self, buffer: &mut MsgBuffer) -> Result<PeerEndpoint, io::Error> {
        match self.net_rx.try_recv() {
            Ok(pkt) => {
                let len = pkt.data.len();
                buffer.clear();
                buffer.clone_from(&pkt.data);
                Ok(pkt.endpoint)
            }
            Err(TryRecvError::Empty) => Err(io::Error::new(io::ErrorKind::WouldBlock, "empty")),
            Err(TryRecvError::Disconnected) => {
                Err(io::Error::new(io::ErrorKind::ConnectionAborted, "net channel closed"))
            }
        }
    }

    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        self.receive_endpoint(buffer).map(|ep| ep.addr)
    }

    /// Send to a complete endpoint: route to the worker owning `endpoint.transport`.
    fn send_endpoint(&mut self, data: &[u8], endpoint: PeerEndpoint) -> Result<usize, io::Error> {
        let dst = v6_to_v4_if_mapped(endpoint.addr);
        let pkt = NetPacket {
            endpoint: PeerEndpoint { addr: dst, transport: endpoint.transport },
            data: data.to_vec(),
        };
        let (tx, wake) = self.transports.get(&endpoint.transport).cloned().expect("no transport channel");
        tx.send(pkt)
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, format!("net channel send failed: {e}")))?;
        wake.signal();
        Ok(data.len())
    }

    /// 仅按地址发送（旧路径）：使用默认传输。
    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        let ep = PeerEndpoint {
            addr: v6_to_v4_if_mapped(addr),
            transport: default_transport(&self.transports),
        };
        self.send_endpoint(data, ep)
    }

    fn transport_id(&self) -> TransportId {
        default_transport(&self.transports)
    }

    /// 优先返回 WebSocket 传输，用于 connect_sock，避免混合模式（-l wss://... -l 0.0.0.0:2600）
    /// 下 init 消息错误地走 UDP 导致无法通过 WebSocket 隧道握手。
    fn preferred_transport_id(&self) -> TransportId {
        self.transports
            .keys()
            .copied()
            .find(|t| matches!(t, TransportId::WebSocket(_)))
            .unwrap_or_else(|| self.transport_id())
    }

    fn address(&self) -> Result<SocketAddr, io::Error> {
        Ok(self.local_addr)
    }

    fn pending(&self) -> usize {
        self.net_rx.len()
    }

    fn create_port_forwarding(&self) -> Option<super::port_forwarding::PortForwarding> {
        // UPnP port forwarding is not available in the dual-thread mode; the real socket
        // lives in the net thread. Return None so callers degrade gracefully.
        warn!("create_port_forwarding: disabled in dual-thread channel mode");
        None
    }

    fn channel_net_rx(&self) -> Option<&crossbeam_channel::Receiver<NetPacket>> { Some(&self.net_rx) }

    fn flush_receive_buffer(&mut self) -> Result<(), io::Error> {
        // Drain the inbound channel queue to discard stale packets after reconnection
        while self.net_rx.try_recv().is_ok() {
            // Discard packet
        }
        Ok(())
    }
}

/// Windows 上 IPv4 socket 不能发送到 IPv6 地址（WSAEAFNOSUPPORT 10047）。
/// 把 ::ffff:a.b.c.d 转回 IPv4，让 Windows 的 IPv4 socket 可用。
fn v6_to_v4_if_mapped(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => {
            let ip = v6.ip();
            let segs = ip.segments();
            if segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0
                && segs[4] == 0 && segs[5] == 0xffff
            {
                let octets = [
                    (segs[6] >> 8) as u8,
                    (segs[6] & 0xff) as u8,
                    (segs[7] >> 8) as u8,
                    (segs[7] & 0xff) as u8,
                ];
                SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::from(octets)), v6.port())
            } else {
                addr
            }
        }
        _ => addr,
    }
}

/// ---------------- Channel-backed Device ------------------

/// `Device` implementation that forwards I/O to/from the device thread through channels.
/// The real `TunTapDevice`/`WintunDevice` lives in the device thread.
pub struct ChannelDevice {
    dev_rx: Receiver<Vec<u8>>,
    dev_tx: Sender<Vec<u8>>,
    ifname: String,
    type_: Type,
    ip: Option<IpAddr>,
    dev_wake: DevWake,
}

impl ChannelDevice {
    pub fn new(
        dev_rx: Receiver<Vec<u8>>,
        dev_tx: Sender<Vec<u8>>,
        ifname: String,
        type_: Type,
        ip: Option<IpAddr>,
        dev_wake: DevWake,
    ) -> Self {
        Self { dev_rx, dev_tx, ifname, type_, ip, dev_wake }
    }
}

#[cfg(unix)]
impl AsRawFd for ChannelDevice {
    fn as_raw_fd(&self) -> RawFd {
        0
    }
}

#[cfg(windows)]
impl AsRawSocket for ChannelDevice {
    fn as_raw_socket(&self) -> RawSocket {
        0
    }
}

impl Device for ChannelDevice {
    fn get_type(&self) -> Type {
        self.type_
    }

    fn ifname(&self) -> &str {
        &self.ifname
    }

    fn read(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        match self.dev_rx.try_recv() {
            Ok(data) => {
                let len = data.len();
                buffer.clear();
                buffer.clone_from(&data);
                debug!("[CHANNEL_DEV_READ] len={}", len);
                Ok(())
            }
            Err(TryRecvError::Empty) => Err(Error::Device("empty".to_string())),
            Err(TryRecvError::Disconnected) => Err(Error::DeviceIo(
                "device channel closed".to_string(),
                io::Error::new(io::ErrorKind::ConnectionAborted, "closed"),
            )),
        }
    }

    fn write(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        let data = buffer.message().to_vec();
        self.dev_tx.send(data).map_err(|e| {
            Error::DeviceIo(
                format!("device channel send failed: {e}"),
                io::Error::new(io::ErrorKind::ConnectionAborted, e),
            )
        })?;
        self.dev_wake.signal();
        Ok(())
    }

    fn get_ip(&self) -> Result<IpAddr, Error> {
        self.ip.ok_or(Error::Device("No IP configured".to_string()))
    }

    fn pending(&self) -> usize {
        self.dev_rx.len()
    }

    fn channel_dev_rx(&self) -> Option<&crossbeam_channel::Receiver<Vec<u8>>> { Some(&self.dev_rx) }

    #[cfg(unix)]
    fn as_raw_fd(&self) -> RawFd {
        0
    }

    #[cfg(windows)]
    fn as_raw_socket(&self) -> RawSocket {
        0
    }
}

/// ---------------- Platform-specific wait helpers ------------------

#[cfg(unix)]
mod net_wait {
    use super::*;
    use std::os::unix::io::AsRawFd;

    pub fn wait_socket_readable(socket: &UdpSocket, timeout_ms: u64) -> io::Result<bool> {
        let fd = socket.as_raw_fd();
        let mut rfds: libc::fd_set = unsafe { std::mem::zeroed() };
        unsafe { libc::FD_ZERO(&mut rfds) };
        unsafe { libc::FD_SET(fd, &mut rfds) };
        let mut tv = libc::timeval {
            tv_sec: (timeout_ms / 1000) as libc::c_long,
            tv_usec: ((timeout_ms % 1000) * 1000) as libc::c_long,
        };
        let r = unsafe {
            libc::select(fd + 1, &mut rfds, std::ptr::null_mut(), std::ptr::null_mut(), &mut tv)
        };
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(r > 0)
        }
    }
}

#[cfg(windows)]
mod net_wait {
    use super::*;
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::Networking::WinSock::{
        WSACreateEvent, WSACloseEvent, WSAEventSelect, WSAResetEvent,
        FD_READ, FD_CLOSE, SOCKET_ERROR, WSAEVENT, SOCKET,
    };
    use windows_sys::Win32::System::Threading::WaitForMultipleObjects;

    /// Wait for socket readability or outbound wake event.
    /// Unified path: WSAEventSelect + WaitForMultipleObjects so outbound NetWake can
    /// interrupt receive waits even for sub-ms/low-latency idle timeouts.
    pub fn wait_socket_readable_or_wake(socket: &UdpSocket, wake: &NetWake, timeout_us: u64) -> io::Result<bool> {
        unsafe {
            let ev: WSAEVENT = WSACreateEvent();
            if ev == 0 {
                return Err(io::Error::last_os_error());
            }
            let sock = socket.as_raw_socket() as SOCKET;
            if WSAEventSelect(sock, ev, (FD_READ | FD_CLOSE) as i32) == SOCKET_ERROR {
                let e = io::Error::last_os_error();
                WSACloseEvent(ev);
                return Err(e);
            }
            // WFMO timeout is millisecond-granular; events (socket readable/wake) preempt the wait.
            let timeout_ms = if timeout_us == 0 { 0 } else { ((timeout_us + 999) / 1000).max(1) as u32 };
            let handles = [ev as HANDLE, wake.handle()];
            let r = WaitForMultipleObjects(2, handles.as_ptr(), 0, timeout_ms);
            let _ = WSAEventSelect(sock, 0 as WSAEVENT, 0);
            let _ = WSAResetEvent(ev as HANDLE);
            WSACloseEvent(ev);
            if r == WAIT_OBJECT_0 {
                Ok(true)
            } else if r == WAIT_OBJECT_0 + 1 || r == WAIT_TIMEOUT {
                Ok(false)
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }
}

#[cfg(unix)]
mod dev_wait {
    use super::*;
    use std::os::unix::io::AsRawFd;

    pub fn wait_device_readable(device: &TunTapDevice, timeout_ms: u64) -> bool {
        let fd = AsRawFd::as_raw_fd(device);
        let mut rfds: libc::fd_set = unsafe { std::mem::zeroed() };
        unsafe { libc::FD_ZERO(&mut rfds) };
        unsafe { libc::FD_SET(fd, &mut rfds) };
        let mut tv = libc::timeval {
            tv_sec: (timeout_ms / 1000) as libc::c_long,
            tv_usec: ((timeout_ms % 1000) * 1000) as libc::c_long,
        };
        let r = unsafe {
            libc::select(fd + 1, &mut rfds, std::ptr::null_mut(), std::ptr::null_mut(), &mut tv)
        };
        if r < 0 {
            warn!("[DEV_THREAD] select() error: {}", io::Error::last_os_error());
            false
        } else {
            r > 0
        }
    }
}

#[cfg(windows)]
mod dev_wait {
    use super::*;
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT, HANDLE};
    use windows_sys::Win32::System::Threading::WaitForMultipleObjects;

    /// Wait for device read event OR outbound (TUN write) wake.
    /// Returns: 1 = readable, 2 = write wake, 0 = timeout/other.
    pub fn wait_device_readable_or_wake(device: &TunTapDevice, wake: &DevWake, timeout_ms: u64) -> u32 {
        let read_h = AsRawSocket::as_raw_socket(device) as HANDLE;
        let handles = [read_h, wake.handle()];
        let r = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, timeout_ms as u32) };
        if r == WAIT_OBJECT_0 { 1 }
        else if r == WAIT_OBJECT_0 + 1 { 2 }
        else if r == WAIT_TIMEOUT { 0 }
        else { 0 }
    }
}

#[cfg(unix)]
use net_wait::wait_socket_readable;
#[cfg(unix)]
use dev_wait::wait_device_readable;

/// ---------------- Net thread ------------------

/// Entry point for the network thread. Owns the real UDP socket.
///
/// - Waits for socket readability or outbound wake (Windows) / readability (Unix).
/// - Drains all pending datagrams and sends them to the main thread via `net_tx`.
/// - Receives outbound packets from `net_cmd_rx` and sends them via the real socket.
/// - Uses adaptive/hybrid idle waiting to reduce latency without busy-spinning logs/CPU.
pub fn net_thread(
    socket: UdpSocket,
    transport_id: TransportId,
    net_tx: Sender<NetPacket>,
    net_cmd_rx: Receiver<NetPacket>,
    stop: std::sync::Arc<AtomicBool>,
    poll_timeout_ms: u64,
    _net_wake: NetWake,
) {
    let _ = socket.set_nonblocking(true);
    let transport_index = match transport_id {
        TransportId::Udp(i) => i,
        TransportId::WebSocket(i) => i,
    };
    info!("[NET_THREAD] started, socket nonblocking=true, transport={transport_id:?}");

    let mut buf = [0u8; 65535];
    let mut idle_spins: u32 = 0;

    while !stop.load(Ordering::Relaxed) {
        let mut drained = false;

        // Drain outbound commands first (non-blocking). Immediate wake means low send latency.
        while let Ok(pkt) = net_cmd_rx.try_recv() {
            drained = true;
            match socket.send_to(&pkt.data, pkt.endpoint.addr) {
                Ok(n) => {
                    if n != pkt.data.len() {
                        warn!("[NET_THREAD] truncated send: wrote {n} of {} bytes to {}", pkt.data.len(), pkt.endpoint.addr);
                    }
                }
                Err(e) => {
                    #[cfg(windows)]
                    {
                        if let Some(code) = e.raw_os_error() {
                            if code == 10054 || code == 10061 || code == 10035 { continue; }
                        }
                    }
                    #[cfg(unix)]
                    {
                        use std::io::ErrorKind;
                        if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted { continue; }
                    }
                    warn!("[NET_THREAD] send error to {}: {}", pkt.endpoint.addr, e);
                }
            }
        }

        let wait_us = adaptive_idle_wait_us(idle_spins, poll_timeout_ms);

        #[cfg(windows)]
        let wait_res = net_wait::wait_socket_readable_or_wake(&socket, &_net_wake, wait_us);
        #[cfg(unix)]
        let wait_res = {
            let _ = &_net_wake;
            net_wait::wait_socket_readable(&socket, ((wait_us + 999) / 1000).max(1))
        };

        match wait_res {
            Ok(true) => {
                drained = true;
                loop {
                    match socket.recv_from(&mut buf) {
                        Ok((n, src)) => {
                            let data = buf[..n].to_vec();
                            if net_tx.send(NetPacket {
                                endpoint: PeerEndpoint::udp(src, transport_index),
                                data,
                            }).is_err() {
                                warn!("[NET_THREAD] main thread gone, shutting down");
                                return;
                            }
                        }
                        Err(e) => {
                            #[cfg(unix)]
                            {
                                use std::io::ErrorKind;
                                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted { break; }
                            }
                            #[cfg(windows)]
                            {
                                if let Some(code) = e.raw_os_error() {
                                    if code == 10035 || code == 10054 || code == 10061 { break; }
                                }
                            }
                            warn!("[NET_THREAD] recv_from error: {e}");
                            break;
                        }
                    }
                }
            }
            Ok(false) => {}
            Err(e) => {
                warn!("[NET_THREAD] wait error: {e}");
            }
        }

        // Re-drain outbound after wake/recv to flush promptly.
        while let Ok(pkt) = net_cmd_rx.try_recv() {
            drained = true;
            match socket.send_to(&pkt.data, pkt.endpoint.addr) {
                Ok(_) => {}
                Err(e) => {
                    #[cfg(windows)]
                    {
                        if let Some(code) = e.raw_os_error() {
                            if code == 10054 || code == 10061 || code == 10035 { continue; }
                        }
                    }
                    #[cfg(unix)]
                    {
                        use std::io::ErrorKind;
                        if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted { continue; }
                    }
                    warn!("[NET_THREAD] send error to {}: {}", pkt.endpoint.addr, e);
                }
            }
        }

        if drained {
            idle_spins = 0;
        } else {
            idle_spins = idle_spins.saturating_add(1);
            if wait_us == 0 {
                std::thread::yield_now();
            }
        }
    }

    info!("[NET_THREAD] stopped");
}

/// ---------------- Device thread ------------------

/// Entry point for the device thread. Owns the real TUN/Wintun device.
///
/// - Blocks on device readability (select() on Linux, WaitForSingleObject on Windows)
///   with a short timeout.
/// - Reads all available packets, filters IPv6 link-local multicast, sends them to the
///   main thread via `dev_tx`.
/// - Receives outbound packets from `dev_cmd_rx` and writes them to the real device.
pub fn device_thread(
    mut device: TunTapDevice,
    dev_tx: Sender<Vec<u8>>,
    dev_cmd_rx: Receiver<Vec<u8>>,
    stop: std::sync::Arc<AtomicBool>,
    poll_timeout_ms: u64,
    _dev_wake: DevWake,
) {
    info!("[DEV_THREAD] started, ifname={}", device.ifname());

    let mut buf = [0u8; 65535];

    let mut idle_spins: u32 = 0;
    while !stop.load(Ordering::Relaxed) {
        let mut drained = false;

        // Drain pending write commands first (non-blocking).
        while let Ok(data) = dev_cmd_rx.try_recv() {
            drained = true;
            let mut mb = MsgBuffer::new(SPACE_BEFORE);
            mb.clone_from(&data);
            if let Err(e) = device.write(&mut mb) {
                debug!("[DEV_THREAD] write error (will retry): {e}");
            }
        }

        let wait_us = adaptive_idle_wait_us(idle_spins, poll_timeout_ms);
        let wait_ms = ((wait_us + 999) / 1000).max(1);
        #[cfg(windows)]
        let dev_wait = dev_wait::wait_device_readable_or_wake(&device, &_dev_wake, wait_ms);
        #[cfg(not(windows))]
        let dev_wait = { let _ = &_dev_wake; if dev_wait::wait_device_readable(&device, wait_ms) { 1 } else { 0 } };
        if dev_wait == 1 {
            drained = true;
            loop {
                let mut mb = MsgBuffer::new(SPACE_BEFORE);
                match device.read(&mut mb) {
                    Ok(()) => {
                        let data = mb.message().to_vec();
                        if data.len() >= 26 && data[0] >> 4 == 6 && data[24] == 0xff && data[25] == 0x02 {
                            continue;
                        }
                        if dev_tx.send(data).is_err() {
                            warn!("[DEV_THREAD] main thread gone, shutting down");
                            return;
                        }
                    }
                    Err(Error::Device(ref msg)) if msg == "empty" => break,
                    Err(e) => {
                        warn!("[DEV_THREAD] read error: {e}");
                        break;
                    }
                }
            }
        } else if dev_wait == 2 {
            // Outbound write wake: handled by drain loops below.
            drained = true;
        }

        // Re-drain writes after read burst.
        while let Ok(data) = dev_cmd_rx.try_recv() {
            drained = true;
            let mut mb = MsgBuffer::new(SPACE_BEFORE);
            mb.clone_from(&data);
            if let Err(e) = device.write(&mut mb) {
                debug!("[DEV_THREAD] write error (will retry): {e}");
            }
        }

        if drained {
            idle_spins = 0;
        } else {
            idle_spins = idle_spins.saturating_add(1);
            if wait_us == 0 {
                std::thread::yield_now();
            }
        }
    }

    info!("[DEV_THREAD] stopped");
}

/// ---------------- Pair factory ------------------

/// Creates two channel pairs (net and device) and returns the handles plus the
/// thread stop flags. Callers must start `net_thread` and `device_thread`
/// themselves (or use `spawn_io_threads`).
pub fn io_channel_pairs() -> (
    Receiver<NetPacket>,
    Sender<NetPacket>,
    Receiver<NetPacket>, // net_cmd_rx (main thread sends to net thread)
    Sender<NetPacket>,   // net_cmd_tx
    Receiver<Vec<u8>>,
    Sender<Vec<u8>>,
    Receiver<Vec<u8>>, // dev_cmd_rx
    Sender<Vec<u8>>,   // dev_cmd_tx
) {
    let (net_tx, net_rx) = bounded::<NetPacket>(CHANNEL_CAP);
    let (net_cmd_tx, net_cmd_rx) = bounded::<NetPacket>(CHANNEL_CAP);
    let (dev_tx, dev_rx) = bounded::<Vec<u8>>(CHANNEL_CAP);
    let (dev_cmd_tx, dev_cmd_rx) = bounded::<Vec<u8>>(CHANNEL_CAP);
    (net_rx, net_tx, net_cmd_rx, net_cmd_tx, dev_rx, dev_tx, dev_cmd_rx, dev_cmd_tx)
}

/// Starts the net and device threads, returning stop flags that callers can set to shut them down.
/// `udp_sockets` is a list of (UDP socket, transport id) pairs; each gets its own net worker
/// but all share one inbound channel (packets carry their `PeerEndpoint`).
pub fn spawn_io_threads(
    udp_sockets: Vec<(UdpSocket, TransportId)>,
    device: TunTapDevice,
    ip: Option<IpAddr>,
    poll_timeout_ms: u64,
) -> (
    ChannelSocket,
    ChannelDevice,
    std::sync::Arc<AtomicBool>,
    std::sync::Arc<AtomicBool>,
    Sender<NetPacket>,
) {
    assert!(!udp_sockets.is_empty(), "at least one UDP socket is required");
    let (net_tx, net_rx) = bounded::<NetPacket>(CHANNEL_CAP);
    let (dev_tx, dev_rx) = bounded::<Vec<u8>>(CHANNEL_CAP);
    let (dev_cmd_tx, dev_cmd_rx) = bounded::<Vec<u8>>(CHANNEL_CAP);

    let mut transports = HashMap::new();
    let mut net_stop = std::sync::Arc::new(AtomicBool::new(false));
    let local_addr = None::<SocketAddr>;

    let mut first_local = None;
    for (idx, (socket, transport_id)) in udp_sockets.into_iter().enumerate() {
        let (net_cmd_tx, net_cmd_rx) = bounded::<NetPacket>(CHANNEL_CAP);
        let net_stop_c = net_stop.clone();
        let net_wake = NetWake::new().expect("failed to create net wake event");
        let net_wake_thread = net_wake.clone();
        let local = match socket.local_addr() {
            Ok(a) => match a {
                SocketAddr::V4(v4) => Some(SocketAddr::new(IpAddr::V4(*v4.ip()), v4.port())),
                SocketAddr::V6(v6) => Some(SocketAddr::new(IpAddr::V6(*v6.ip()), v6.port())),
            },
            Err(e) => {
                warn!("[SPAWN_IO_THREADS] failed to get socket local addr: {e}");
                None
            }
        };
        if first_local.is_none() { first_local = local; }
        let net_tx_c = net_tx.clone();
        thread::Builder::new()
            .name(format!("vpncloud-net-{}", idx))
            .spawn(move || net_thread(socket, transport_id, net_tx_c, net_cmd_rx, net_stop_c, poll_timeout_ms, net_wake_thread))
            .expect("failed to spawn net thread");
        transports.insert(transport_id, (net_cmd_tx, net_wake));
    }
    let local_addr = first_local.unwrap_or_else(|| {
        warn!("[SPAWN_IO_THREADS] failed to get any socket local addr");
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
    });

    let dev_stop = std::sync::Arc::new(AtomicBool::new(false));
    let dev_stop_c = dev_stop.clone();
    let dev_wake = DevWake::new().expect("failed to create dev wake event");
    let dev_wake_thread = dev_wake.clone();

    let dev_ifname = device.ifname().to_string();
    let dev_type = device.get_type();

    thread::Builder::new()
        .name("vpncloud-dev".into())
        .spawn(move || device_thread(device, dev_tx, dev_cmd_rx, dev_stop_c, poll_timeout_ms, dev_wake_thread))
        .expect("failed to spawn device thread");

    let channel_socket = ChannelSocket::new(net_rx, transports, local_addr);
    let channel_device = ChannelDevice::new(
        dev_rx,
        dev_cmd_tx,
        dev_ifname,
        dev_type,
        ip,
        dev_wake,
    );

    (channel_socket, channel_device, net_stop, dev_stop, net_tx)
}

/// Register an additional transport (e.g. WebSocket) on an existing ChannelSocket,
/// so `send_endpoint` can route packets to the correct worker thread.
impl ChannelSocket {
    pub fn register_transport(&mut self, transport_id: TransportId, tx: Sender<NetPacket>, wake: NetWake) {
        self.transports.insert(transport_id, (tx, wake));
    }
}

#[cfg(feature = "websocket")]
/// 可中断的退避等待：每 200ms 检查一次 stop 信号，避免线程卡死在长 sleep 里无法响应进程退出。
fn sleep_interruptible(duration_ms: u64, stop: &std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let mut elapsed = 0u64;
    let step: u64 = 200;
    while elapsed < duration_ms && !stop.load(std::sync::atomic::Ordering::Relaxed) {
        let remaining = duration_ms - elapsed;
        let sleep_ms = step.min(remaining);
        std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
        elapsed += sleep_ms;
    }
}

pub fn spawn_ws_thread(
    mut socket: ProxyConnection,
    transport_id: TransportId,
    net_tx: Sender<NetPacket>,
    net_cmd_rx: Receiver<NetPacket>,
    stop: std::sync::Arc<AtomicBool>,
    poll_timeout_ms: u64,
    _net_wake: NetWake,
) {
    let _ = poll_timeout_ms;
    info!("[WS_THREAD] started, transport={transport_id:?}");
    let mut stop = stop;
    let mut idle = 0u32;
    let mut reconnect_delay_ms: u64 = 2000;
    while !stop.load(Ordering::Relaxed) {
        // 处理主线程发来的发送请求；WS 重连期间直接丢弃旧包，避免阻塞通道
        let mut drained = false;
        while let Ok(pkt) = net_cmd_rx.try_recv() {
            drained = true;
            match socket.send(&pkt.data, pkt.endpoint.addr) {
                Ok(_) => {}
                Err(e) => {
                    warn!("[WS_THREAD] send error: {e}, attempting reconnect");
                    if let Err(re) = socket.reconnect() {
                        warn!("[WS_THREAD] reconnect failed: {re}, retrying in {}ms", reconnect_delay_ms);
                        sleep_interruptible(reconnect_delay_ms, &stop);
                        reconnect_delay_ms = (reconnect_delay_ms * 2).min(30000);
                    } else {
                        info!("[WS_THREAD] reconnect succeeded");
                        reconnect_delay_ms = 2000;
                        // 清空断线期间积压的旧包，防止僵尸包被发到新连接
                        while net_cmd_rx.try_recv().is_ok() {
                            // 丢弃断线期间残留的旧包
                        }
                    }
                    // 丢弃当前包，等上层 VPN 握手重试通过新 WS 流重新发送
                    continue;
                }
            }
        }
        match socket.read_message() {
            Ok(data) if !data.is_empty() => {
                drained = true;
                match read_addr(std::io::Cursor::new(&data)) {
                    Ok(addr) => {
                        let pkt = NetPacket {
                            endpoint: PeerEndpoint {
                                addr,
                                transport: transport_id,
                            },
                            data: data[18..].to_vec(),
                        };
                        if net_tx.send(pkt).is_err() {
                            warn!("[WS_THREAD] main thread gone, shutting down");
                            return;
                        }
                    }
                    Err(e) => warn!("[WS_THREAD] failed to parse address frame: {e}"),
                }
            }
            Ok(_) => {}
            Err(e) => {
                let is_wouldblock = e.kind() == std::io::ErrorKind::WouldBlock;
                if is_wouldblock {
                    idle = idle.saturating_add(1);
                    if idle > 32 {
                        std::thread::sleep(std::time::Duration::from_millis(poll_timeout_ms.max(1)));
                        idle = 0;
                    } else {
                        std::thread::yield_now();
                    }
                    continue;
                }
                warn!("[WS_THREAD] read error: {e}, attempting reconnect");
                if let Err(re) = socket.reconnect() {
                    warn!("[WS_THREAD] reconnect failed: {re}, retrying in {}ms", reconnect_delay_ms);
                    sleep_interruptible(reconnect_delay_ms, &stop);
                    reconnect_delay_ms = (reconnect_delay_ms * 2).min(30000);
                } else {
                    info!("[WS_THREAD] reconnect succeeded");
                    reconnect_delay_ms = 2000;
                    // 清空断线期间积压的旧包，防止僵尸包被发到新连接
                    while net_cmd_rx.try_recv().is_ok() {
                        // 丢弃断线期间残留的旧包
                    }
                }
                continue;
            }
        }
        if drained { idle = 0; }
    }
    info!("[WS_THREAD] stopped");
}
