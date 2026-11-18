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
    net::Socket,
    util::{MsgBuffer, Time, TimeSource},
};
use crossbeam_channel::{bounded, Receiver, Sender, Select, TryRecvError};
use std::{
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

/// A packet received from the network, destined for the main thread.
#[derive(Clone)]
pub struct NetPacket {
    pub addr: SocketAddr,
    pub data: Vec<u8>,
}

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

/// `Socket` implementation that forwards I/O to/from the net thread through channels.
/// The real `UdpSocket` lives in the net thread; this handle only sends/receives
/// `NetPacket`s via `crossbeam-channel`.
pub struct ChannelSocket {
    net_rx: Receiver<NetPacket>,
    net_tx: Sender<NetPacket>,
    local_addr: SocketAddr,
    net_wake: NetWake,
}

impl ChannelSocket {
    pub fn new(net_rx: Receiver<NetPacket>, net_tx: Sender<NetPacket>, local_addr: SocketAddr, net_wake: NetWake) -> Self {
        Self { net_rx, net_tx, local_addr, net_wake }
    }
}

impl Clone for ChannelSocket {
    fn clone(&self) -> Self {
        Self {
            net_rx: self.net_rx.clone(),
            net_tx: self.net_tx.clone(),
            local_addr: self.local_addr,
            net_wake: self.net_wake.clone(),
        }
    }
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
        // The real socket is already bound in the net thread; nothing to do here.
        Err(io::Error::new(
            io::ErrorKind::Other,
            "ChannelSocket::listen must not be called; use new()",
        ))
    }

    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        match self.net_rx.try_recv() {
            Ok(pkt) => {
                let len = pkt.data.len();
                buffer.clear();
                buffer.clone_from(&pkt.data);
                Ok(pkt.addr)
            }
            Err(TryRecvError::Empty) => Err(io::Error::new(io::ErrorKind::WouldBlock, "empty")),
            Err(TryRecvError::Disconnected) => {
                Err(io::Error::new(io::ErrorKind::ConnectionAborted, "net channel closed"))
            }
        }
    }

    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        // Windows 上 IPv4 socket 不能发送到 IPv6 地址（WSAEAFNOSUPPORT 10047）。
        // handle_net_message 会把 IPv4 地址通过 mapped_addr 转成 IPv6-mapped，
        // 这里在发送前把 ::ffff:a.b.c.d 转回 IPv4，让 Windows 的 IPv4 socket 可用。
        let dst = match addr {
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
        };
        let pkt = NetPacket {
            addr: dst,
            data: data.to_vec(),
        };
        self.net_tx.send(pkt).map_err(|e| {
            io::Error::new(io::ErrorKind::ConnectionAborted, format!("net channel send failed: {e}"))
        })?;
        self.net_wake.signal();
        Ok(data.len())
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
    net_tx: Sender<NetPacket>,
    net_cmd_rx: Receiver<NetPacket>,
    stop: std::sync::Arc<AtomicBool>,
    poll_timeout_ms: u64,
    _net_wake: NetWake,
) {
    let _ = socket.set_nonblocking(true);
    info!("[NET_THREAD] started, socket nonblocking=true");

    let mut buf = [0u8; 65535];
    let mut idle_spins: u32 = 0;

    while !stop.load(Ordering::Relaxed) {
        let mut drained = false;

        // Drain outbound commands first (non-blocking). Immediate wake means low send latency.
        while let Ok(pkt) = net_cmd_rx.try_recv() {
            drained = true;
            match socket.send_to(&pkt.data, pkt.addr) {
                Ok(n) => {
                    if n != pkt.data.len() {
                        warn!("[NET_THREAD] truncated send: wrote {n} of {} bytes to {}", pkt.data.len(), pkt.addr);
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
                    warn!("[NET_THREAD] send error to {}: {}", pkt.addr, e);
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
                            if net_tx.send(NetPacket { addr: src, data }).is_err() {
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
            match socket.send_to(&pkt.data, pkt.addr) {
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
                    warn!("[NET_THREAD] send error to {}: {}", pkt.addr, e);
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
pub fn spawn_io_threads(
    socket: UdpSocket,
    device: TunTapDevice,
    ip: Option<IpAddr>,
    poll_timeout_ms: u64,
) -> (
    ChannelSocket,
    ChannelDevice,
    std::sync::Arc<AtomicBool>,
    std::sync::Arc<AtomicBool>,
) {
    let (net_rx, net_tx, net_cmd_rx, net_cmd_tx, dev_rx, dev_tx, dev_cmd_rx, dev_cmd_tx) =
        io_channel_pairs();

    let local_addr = match socket.local_addr() {
        Ok(a) => match a {
            SocketAddr::V4(v4) => SocketAddr::new(IpAddr::V4(*v4.ip()), v4.port()),
            SocketAddr::V6(v6) => SocketAddr::new(IpAddr::V6(*v6.ip()), v6.port()),
        },
        Err(e) => {
            warn!("[SPAWN_IO_THREADS] failed to get socket local addr: {e}");
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        }
    };

    let net_stop = std::sync::Arc::new(AtomicBool::new(false));
    let dev_stop = std::sync::Arc::new(AtomicBool::new(false));

    let net_stop_c = net_stop.clone();
    let dev_stop_c = dev_stop.clone();
    let net_wake = NetWake::new().expect("failed to create net wake event");
    let net_wake_thread = net_wake.clone();
    let dev_wake = DevWake::new().expect("failed to create dev wake event");
    let dev_wake_thread = dev_wake.clone();

    // Save device metadata before moving ownership into the device thread.
    let dev_ifname = device.ifname().to_string();
    let dev_type = device.get_type();

    thread::Builder::new()
        .name("vpncloud-net".into())
        .spawn(move || net_thread(socket, net_tx, net_cmd_rx, net_stop_c, poll_timeout_ms, net_wake_thread))
        .expect("failed to spawn net thread");

    thread::Builder::new()
        .name("vpncloud-dev".into())
        .spawn(move || device_thread(device, dev_tx, dev_cmd_rx, dev_stop_c, poll_timeout_ms, dev_wake_thread))
        .expect("failed to spawn device thread");

    let channel_socket = ChannelSocket::new(net_rx, net_cmd_tx, local_addr, net_wake);
    let channel_device = ChannelDevice::new(
        dev_rx,
        dev_cmd_tx,
        dev_ifname,
        dev_type,
        ip,
        dev_wake,
    );

    (channel_socket, channel_device, net_stop, dev_stop)
}
