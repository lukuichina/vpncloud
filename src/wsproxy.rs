// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use crate::{
    crypto,
    error::Error,
    net::{get_ip, mapped_addr, parse_listen, Socket},
    poll::{WaitImpl, WaitResult},
    port_forwarding::PortForwarding,
    util::MsgBuffer,
};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use crossbeam_channel::Sender;
use std::{
    collections::VecDeque,
    error::Error as StdError,
    io::{self, Cursor, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream, UdpSocket},
    sync::Arc,
    thread::spawn,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{WSAEventSelect, WSACreateEvent, WSACloseEvent, FD_READ, SOCKET_ERROR, SOCKET, WSAEVENT};
#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;

#[cfg(all(target_arch = "x86_64", target_env = "gnu"))]
use socket2::{SockRef, TcpKeepalive};

use socket2::{Domain, Protocol, Socket as Socket2, Type};

#[cfg(target_env = "musl")]
use libc::{c_int, setsockopt, SOL_TCP, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT};
use tungstenite::{protocol::WebSocket, Message, accept, stream::{MaybeTlsStream, NoDelay}, Connector, client_tls_with_config, connect};
use url::Url;
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

/// A certificate verifier that accepts all certificates (for --insecure mode)
#[derive(Clone, Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

macro_rules! io_error {
    ($val:expr, $format:expr) => ( {
        $val.map_err(|err| io::Error::new(io::ErrorKind::Other, format!($format, err)))
    } );
    ($val:expr, $format:expr, $( $arg:expr ),+) => ( {
        $val.map_err(|err| io::Error::new(io::ErrorKind::Other, format!($format, $( $arg ),+, err)))
    } );
}

pub(crate) fn write_addr<W: Write>(addr: SocketAddr, mut out: W) -> Result<(), io::Error> {
    let addr = mapped_addr(addr);
    match mapped_addr(addr) {
        SocketAddr::V6(addr) => {
            out.write_all(&addr.ip().octets())?;
            out.write_u16::<NetworkEndian>(addr.port())?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

pub(crate) fn read_addr<R: Read>(mut r: R) -> Result<SocketAddr, io::Error> {
    let mut ip = [0u8; 16];
    r.read_exact(&mut ip)?;
    let port = r.read_u16::<NetworkEndian>()?;
    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0));
    Ok(addr)
}

#[cfg(all(target_arch = "x86_64", target_env = "gnu"))]
fn set_tcp_keepalive(stream: &TcpStream) -> Result<(), io::Error> {
    let sock_ref = SockRef::from(stream);
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    sock_ref.set_tcp_keepalive(&keepalive)?;
    Ok(())
}

#[cfg(target_env = "musl")]
fn set_tcp_keepalive(stream: &TcpStream) -> Result<(), io::Error> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let keepalive: c_int = 1;
    let keepidle: c_int = 30;
    let keepintvl: c_int = 10;
    let keepcnt: c_int = 3;
    
    unsafe {
        // Enable keepalive
        if setsockopt(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, &keepalive as *const _ as *const libc::c_void, std::mem::size_of::<c_int>() as libc::socklen_t) != 0 {
            return Err(io::Error::last_os_error());
        }
        // Set keepalive parameters
        if setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &keepidle as *const _ as *const libc::c_void, std::mem::size_of::<c_int>() as libc::socklen_t) != 0 {
            return Err(io::Error::last_os_error());
        }
        if setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &keepintvl as *const _ as *const libc::c_void, std::mem::size_of::<c_int>() as libc::socklen_t) != 0 {
            return Err(io::Error::last_os_error());
        }
        if setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &keepcnt as *const _ as *const libc::c_void, std::mem::size_of::<c_int>() as libc::socklen_t) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(any(all(target_arch = "x86_64", target_env = "gnu"), target_env = "musl")))]
fn set_tcp_keepalive(_stream: &TcpStream) -> Result<(), io::Error> {
    // TCP keepalive only available on x86_64-gnu and musl targets
    Ok(())
}

fn serve_proxy_connection(stream: TcpStream, net_tx: Option<Sender<crate::net::NetPacket>>) -> Result<(), io::Error> {
    let peer = stream.peer_addr()?;
    info!("WS client {} connected, net_tx is_some={}", peer, net_tx.is_some());
    stream.set_nodelay(true)?;
    set_tcp_keepalive(&stream)?;
    let mut websocket = io_error!(accept(stream), "Failed to initialize websocket with {}: {}", peer)?;
    // Create dual-stack UDP socket (IPv6 with IPV6_V6ONLY=false for IPv4-mapped support)
    // This matches original v0.0.5 design: each connection gets its own ephemeral port
    let udpsocket: UdpSocket = {
        let sock = Socket2::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        #[cfg(target_os = "windows")]
        sock.set_only_v6(false)?;  // Allow IPv4-mapped addresses on Windows
        sock.bind(&"[::]:0".parse::<SocketAddr>().unwrap().into())?;
        sock.into()
    };
    let mut msg = Vec::with_capacity(18);
    let mut addr = udpsocket.local_addr()?;
    info!("Listening on {} for peer {}", addr, peer);
    addr.set_ip(get_ip());
    write_addr(addr, &mut msg)?;
    io_error!(websocket.send(Message::Binary(msg)), "Failed to write to ws connection: {}")?;

    #[cfg(windows)]
    {
        use windows_sys::Win32::Networking::WinSock::{
            WSAEventSelect, WSACreateEvent, WSACloseEvent, WSAEnumNetworkEvents, WSANETWORKEVENTS,
            FD_READ, FD_CLOSE, FD_READ_BIT, FD_CLOSE_BIT, SOCKET_ERROR, SOCKET, WSAEVENT,
        };
        use windows_sys::Win32::System::Threading::WaitForMultipleObjects;
        use windows_sys::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
        use std::os::windows::io::AsRawSocket;

        let ws_socket = websocket.get_ref().as_raw_socket() as SOCKET;
        let udp_socket = udpsocket.as_raw_socket() as SOCKET;

        let ws_event: WSAEVENT = unsafe { WSACreateEvent() };
        if ws_event == 0 {
            return Err(io::Error::last_os_error());
        }
        let udp_event: WSAEVENT = unsafe { WSACreateEvent() };
        if udp_event == 0 {
            unsafe { WSACloseEvent(ws_event) };
            return Err(io::Error::last_os_error());
        }

        if unsafe { WSAEventSelect(ws_socket, ws_event, (FD_READ | FD_CLOSE) as i32) } == SOCKET_ERROR {
            let e = io::Error::last_os_error();
            unsafe {
                WSACloseEvent(ws_event);
                WSACloseEvent(udp_event);
            }
            return Err(e);
        }
        if unsafe { WSAEventSelect(udp_socket, udp_event, FD_READ as i32) } == SOCKET_ERROR {
            let e = io::Error::last_os_error();
            unsafe {
                let _ = WSAEventSelect(ws_socket, 0 as WSAEVENT, 0);
                WSACloseEvent(ws_event);
                WSACloseEvent(udp_event);
            }
            return Err(e);
        }

        info!(
            "Proxy wait: ws_socket={:?}, udp_socket={:?}, ws_event={:?}, udp_event={:?}, peer={}",
            ws_socket, udp_socket, ws_event, udp_event, peer
        );

        let mut buffer = [0u8; 65535];
        let mut ws_closed = false;
        let timeout_ms: u32 = 300_000;
        loop {
            let handles = [ws_event as HANDLE, udp_event as HANDLE];
            let r = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, timeout_ms) };

            if r == WAIT_OBJECT_0 {
                // WebSocket (TCP) socket event
                unsafe {
                    let mut events: WSANETWORKEVENTS = std::mem::zeroed();
                    if WSAEnumNetworkEvents(ws_socket, ws_event, &mut events) == SOCKET_ERROR {
                        let e = io::Error::last_os_error();
                        let _ = WSAEventSelect(ws_socket, 0 as WSAEVENT, 0);
                        let _ = WSAEventSelect(udp_socket, 0 as WSAEVENT, 0);
                        WSACloseEvent(ws_event);
                        WSACloseEvent(udp_event);
                        return Err(e);
                    }
                    let net = events.lNetworkEvents as i32;
                    if (net & FD_READ as i32) != 0 && events.iErrorCode[FD_READ_BIT as usize] != 0 {
                        let e = io::Error::from_raw_os_error(events.iErrorCode[FD_READ_BIT as usize]);
                        let _ = WSAEventSelect(ws_socket, 0 as WSAEVENT, 0);
                        let _ = WSAEventSelect(udp_socket, 0 as WSAEVENT, 0);
                        WSACloseEvent(ws_event);
                        WSACloseEvent(udp_event);
                        return Err(e);
                    }
                    if (net & FD_CLOSE as i32) != 0 {
                        ws_closed = true;
                    }
                }

                // Drain websocket messages while available
                loop {
                    let msg = match websocket.read() {
                        Ok(m) => m,
                        Err(e) => {
                            if let Some(source) = e.source() {
                                if let Some(io_err) = source.downcast_ref::<io::Error>() {
                                    if io_err.kind() == io::ErrorKind::WouldBlock {
                                        break;
                                    }
                                }
                            }
                            // Treat close/other errors as termination
                            debug!("WebSocket read ended for {}: {}", peer, e);
                            ws_closed = true;
                            break;
                        }
                    };
                    match msg {
                        Message::Binary(data) => {
                            info!("Proxy: received binary msg, len={}", data.len());
                            if data.len() >= 18 {
                                let _dst = match read_addr(Cursor::new(&data)) {
                                    Ok(d) => {
                                        info!("Proxy: read_addr dst={}", d);
                                        d
                                    }
                                    Err(e) => {
                                        error!("Proxy: read_addr failed: {}", e);
                                        continue;
                                    }
                                };
                                // Inject packet directly into net thread via channel instead of UDP forwarding.
                                // This avoids Windows same-process UDP loopback issues.
                                // Use the proxy's ephemeral UDP address as the source endpoint.
                                if let Some(ref tx) = net_tx {
                                    if let Ok(local_addr) = udpsocket.local_addr() {
                                        let endpoint = crate::net::PeerEndpoint::udp(local_addr, 0);
                                        let pkt = crate::net::NetPacket {
                                            endpoint,
                                            data: data[18..].to_vec(),
                                        };
                                        if let Err(e) = tx.send(pkt) {
                                            error!("Proxy: failed to inject packet: {}", e);
                                        } else {
                                            info!("Proxy: injected {} bytes to net thread", data.len() - 18);
                                        }
                                    } else {
                                        error!("Proxy: failed to get local UDP address");
                                    }
                                } else {
                                    // Fallback to UDP forwarding if no channel available
                                    #[cfg(target_os = "windows")]
                                    if let IpAddr::V6(ipv6) = _dst.ip() {
                                        if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                                            let _dst = SocketAddr::new(IpAddr::V4(ipv4), _dst.port());
                                        }
                                    }
                                    // Use the wsproxy's own UDP socket (udpsocket) to forward packets
                                    // to the destination address read from the WebSocket message.
                                    // This is the same as v0.2.1 design: each wsproxy connection has
                                    // its own ephemeral UDP socket for forwarding to remote peers.
                                    match udpsocket.send_to(&data[18..], _dst) {
                                        Ok(n) => info!("Proxy: forwarded {} bytes to {} via wsproxy UDP socket", n, _dst),
                                        Err(e) => error!("Proxy: failed to forward to {} via wsproxy UDP socket: {}", _dst, e),
                                    }
                                    continue;
                                    #[cfg(not(target_os = "windows"))]
                                    if let IpAddr::V6(ipv6) = _dst.ip() {
                                        if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                                            let _dst = SocketAddr::new(IpAddr::V4(ipv4), _dst.port());
                                        }
                                    }
                                    if let Err(e) = udpsocket.send_to(&data[18..], _dst) {
                                        error!("Proxy: failed to forward to {}: {}", _dst, e);
                                    }
                                }
                            }
                        }
                        Message::Ping(data) => {
                            if let Err(e) = websocket.send(Message::Pong(data)) {
                                error!("Failed to send pong to {}: {}", peer, e);
                                ws_closed = true;
                                break;
                            }
                        }
                        Message::Close(_) => {
                            ws_closed = true;
                            break;
                        }
                        _ => {}
                    }
                }
                if ws_closed {
                    unsafe {
                        let _ = WSAEventSelect(ws_socket, 0 as WSAEVENT, 0);
                        let _ = WSAEventSelect(udp_socket, 0 as WSAEVENT, 0);
                        WSACloseEvent(ws_event);
                        WSACloseEvent(udp_event);
                    }
                    return Ok(());
                }
            } else if r == WAIT_OBJECT_0 + 1 {
                // UDP socket event - must call WSAEnumNetworkEvents to reset event
                unsafe {
                    let mut events: WSANETWORKEVENTS = std::mem::zeroed();
                    if WSAEnumNetworkEvents(udp_socket, udp_event, &mut events) == SOCKET_ERROR {
                        let e = io::Error::last_os_error();
                        let _ = WSAEventSelect(ws_socket, 0 as WSAEVENT, 0);
                        let _ = WSAEventSelect(udp_socket, 0 as WSAEVENT, 0);
                        WSACloseEvent(ws_event);
                        WSACloseEvent(udp_event);
                        return Err(e);
                    }
                }
                // Drain all available UDP packets
                loop {
                    match udpsocket.recv_from(&mut buffer) {
                        Ok((size, src_addr)) => {
                            let send_addr = if let IpAddr::V6(ipv6) = src_addr.ip() {
                                if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                                    SocketAddr::new(IpAddr::V4(ipv4), src_addr.port())
                                } else {
                                    src_addr
                                }
                            } else {
                                src_addr
                            };
                            let mut data = Vec::with_capacity(18 + size);
                            write_addr(send_addr, &mut data)?;
                            data.write_all(&buffer[..size])?;
                            if let Err(e) = websocket.send(Message::Binary(data)) {
                                error!("Failed to write to {}: {}", peer, e);
                                unsafe {
                                    let _ = WSAEventSelect(ws_socket, 0 as WSAEVENT, 0);
                                    let _ = WSAEventSelect(udp_socket, 0 as WSAEVENT, 0);
                                    WSACloseEvent(ws_event);
                                    WSACloseEvent(udp_event);
                                }
                                return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            error!("Proxy UDP recv error for {}: {}", peer, e);
                            break;
                        }
                    }
                }
            } else if r == WAIT_TIMEOUT {
                if let Err(e) = websocket.send(Message::Ping(vec![])) {
                    error!("Failed to send ping to {}: {}", peer, e);
                    unsafe {
                        let _ = WSAEventSelect(ws_socket, 0 as WSAEVENT, 0);
                        let _ = WSAEventSelect(udp_socket, 0 as WSAEVENT, 0);
                        WSACloseEvent(ws_event);
                        WSACloseEvent(udp_event);
                    }
                    return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
                }
            } else if r == WAIT_FAILED {
                let e = io::Error::last_os_error();
                unsafe {
                    let _ = WSAEventSelect(ws_socket, 0 as WSAEVENT, 0);
                    let _ = WSAEventSelect(udp_socket, 0 as WSAEVENT, 0);
                    WSACloseEvent(ws_event);
                    WSACloseEvent(udp_event);
                }
                return Err(e);
            } else {
                let e = io::Error::new(
                    io::ErrorKind::Other,
                    format!("WaitForMultipleObjects returned {}", r),
                );
                unsafe {
                    let _ = WSAEventSelect(ws_socket, 0 as WSAEVENT, 0);
                    let _ = WSAEventSelect(udp_socket, 0 as WSAEVENT, 0);
                    WSACloseEvent(ws_event);
                    WSACloseEvent(udp_event);
                }
                return Err(e);
            }
        }
    }
    
    #[cfg(not(windows))]
    {
        use std::os::unix::io::{AsRawFd, RawFd};

        let websocketfd: RawFd = websocket.get_ref().as_raw_fd();
        let udpfd: RawFd = udpsocket.as_raw_fd();
        let poll = WaitImpl::new(websocketfd, udpfd, 300 * 1000)?;
        info!("Proxy epoll: ws_fd={}, udp_fd={}, peer={}", websocketfd, udpfd, peer);
        let mut buffer = [0; 65535];
        for evt in poll {
            debug!("Proxy epoll event: {:?}", evt);
            match evt {
                WaitResult::Socket => {
                    let msg = io_error!(websocket.read(), "Failed to read message on websocket {}: {}", peer)?;
                    match msg {
                        Message::Binary(data) => {
                            let _dst = read_addr(Cursor::new(&data))?;
                            // Inject packet directly into net thread via channel instead of UDP forwarding.
                            if let Some(ref tx) = net_tx {
                                if let Ok(local_addr) = udpsocket.local_addr() {
                                    let endpoint = crate::net::PeerEndpoint::udp(local_addr, 0);
                                    let pkt = crate::net::NetPacket {
                                        endpoint,
                                        data: data[18..].to_vec(),
                                    };
                                    if let Err(e) = tx.send(pkt) {
                                        error!("Proxy: failed to inject packet: {}", e);
                                    } else {
                                        info!("Proxy: injected {} bytes to net thread", data.len() - 18);
                                    }
                                } else {
                                    error!("Proxy: failed to get local UDP address");
                                }
                            } else {
                                // Fallback to UDP forwarding if no channel available
                                // Convert IPv6-mapped IPv4 to pure IPv4 for IPv4 socket
                                if let IpAddr::V6(ipv6) = _dst.ip() {
                                    if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                                        let _dst = SocketAddr::new(IpAddr::V4(ipv4), _dst.port());
                                    }
                                }
                                match udpsocket.send_to(&data[18..], _dst) {
                                    Ok(_) => {}
                                    Err(e) => error!("Proxy: failed to forward to {}: {}", _dst, e),
                                }
                            }
                        }
                        Message::Ping(data) => {
                            if let Err(e) = websocket.send(Message::Pong(data)) {
                                error!("Failed to send pong to {}: {}", peer, e);
                                return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
                            }
                        }
                        Message::Close(_) => return Ok(()),
                        _ => {}
                    }
                }
                WaitResult::Device => {
                    let (size, src_addr) = udpsocket.recv_from(&mut buffer)?;
                    // Convert IPv4-mapped IPv6 address back to pure IPv4 for compatibility
                    // with peers listening on pure IPv4/IPv6 sockets (e.g., Linux RUN_WS mode)
                    let send_addr = if let IpAddr::V6(ipv6) = src_addr.ip() {
                        if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                            SocketAddr::new(IpAddr::V4(ipv4), src_addr.port())
                        } else {
                            src_addr
                        }
                    } else {
                        src_addr
                    };
                    // Forward response back to client with actual source address
                    let mut data = Vec::with_capacity(18 + size);
                    write_addr(send_addr, &mut data)?;
                    data.write_all(&buffer[..size])?;
                    io_error!(websocket.send(Message::Binary(data)), "Failed to write to {}: {}", peer)?;
                }
                WaitResult::Timeout => {
                    io_error!(websocket.send(Message::Ping(vec![])), "Failed to send ping: {}")?;
                }
                WaitResult::Error(err) => return Err(err),
            }
        }
        Ok(())
    }
}

pub fn run_proxy(listen: &str, net_tx: Option<Sender<crate::net::NetPacket>>) -> Result<(), io::Error> {
    info!("run_proxy called, net_tx is_some={}", net_tx.is_some());
    use std::net::{TcpListener, TcpStream, SocketAddr, IpAddr, Ipv4Addr};
    use std::thread;
    
    let thread_id = std::thread::current().id();
    info!("WebSocket proxy: thread {:?} starting", thread_id);
    
    let addr = parse_listen(listen, 8080);
    info!("WebSocket proxy: attempting to bind to {}", addr);
    
    let port = addr.port();
    let ipv4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    
    let listener = TcpListener::bind(ipv4_addr)?;
    let local_addr = listener.local_addr()?;
    info!("WebSocket proxy: successfully bound, listening on ws://{}", local_addr);
    info!("WebSocket proxy: listener local_addr = {:?}", local_addr);
    
    // Test: try to connect to 127.0.0.1:port to verify the listener is working
    let test_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), local_addr.port());
    match std::net::TcpStream::connect(test_addr) {
        Ok(_) => info!("WebSocket proxy: SELF-CONNECT TEST PASSED (to {})", test_addr),
        Err(e) => error!("WebSocket proxy: SELF-CONNECT TEST FAILED (to {}): {}", test_addr, e),
    }
    
    info!("WebSocket proxy: entering accept loop");
    
    let incoming = listener.incoming();
    info!("WebSocket proxy: got incoming iterator");
    info!("WebSocket proxy: waiting for connections... (thread {:?})", thread_id);
    
    let mut count = 0;
    for stream in incoming {
        count += 1;
        info!("WebSocket proxy: accept loop iteration {} (thread {:?})", count, thread_id);
        match stream {
            Ok(stream) => {
                let peer = stream.peer_addr().unwrap_or(local_addr);
                info!("WebSocket proxy: accepted connection from {}", peer);
                let net_tx_c = net_tx.clone();
                thread::spawn(move || {
                    if let Err(err) = serve_proxy_connection(stream, net_tx_c) {
                        error!("Error on connection {}: {}", peer, err);
                    }
                });
            }
            Err(e) => {
                error!("WebSocket proxy: accept error: {}", e);
            }
        }
    }
    
    Ok(())
}

pub struct ProxyConnection {
    url: String,               // WebSocket URL (ws:// or wss://)
    sni: Option<String>,       // Optional SNI override for TLS
    addr: SocketAddr,          // WebSocket proxy assigned UDP address (local address)
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    insecure: bool,
    /// Internal buffer for received WebSocket frames.
    /// Allows draining multiple frames per event loop iteration.
    rx_buffer: VecDeque<(Vec<u8>, SocketAddr)>,
}

impl ProxyConnection {
    /// Connect to a wss:// URL, optionally skipping TLS certificate verification
    pub fn connect(url: &str, sni: Option<&str>, insecure: bool) -> Result<Self, io::Error> {
        let parsed_url = io_error!(Url::parse(url), "Invalid URL {}: {}", url)?;
        let host_str = parsed_url.host_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, format!("No host in URL {}", url))
        })?;
        let port = parsed_url.port_or_known_default().unwrap_or(443);
        let addr = if host_str.contains(':') {
            format!("[{}]:{}", host_str, port)
        } else {
            format!("{}:{}", host_str, port)
        };

        // When --sni is given, override the URL host so that TLS SNI and HTTP Host header
        // use the sni value while the underlying TCP connection stays at the original IP.
        let effective_url = if let Some(sni_val) = sni {
            let mut modified = parsed_url.clone();
            modified.set_host(Some(sni_val)).map_err(|_| {
                io::Error::new(io::ErrorKind::Other, format!("Invalid SNI host {}", sni_val))
            })?;
            modified
        } else {
            parsed_url
        };

        let mut socket = if insecure && effective_url.scheme() == "wss" {
            let config = Arc::new(
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                    .with_no_client_auth(),
            );
            let tcp_stream = TcpStream::connect(&addr)?;
            set_tcp_keepalive(&tcp_stream)?;
            let connector = Connector::Rustls(config);
            let (ws, _) = client_tls_with_config(
                effective_url.as_str(),
                tcp_stream,
                None,
                Some(connector),
            ).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS error: {}", e)))?;
            ws
        } else {
            let (socket, _) = io_error!(
                tungstenite::connect(effective_url),
                "Failed to connect to URL {}: {}", url
            )?;
            socket
        };
        // Set TCP keepalive on the underlying stream
        if let MaybeTlsStream::Plain(ref mut stream) = socket.get_mut() {
            set_tcp_keepalive(stream)?;
        } else if let MaybeTlsStream::Rustls(ref mut stream) = socket.get_mut() {
            set_tcp_keepalive(stream.get_mut())?;
        }
        socket.get_mut().set_nodelay(true)?;
        // Set underlying TcpStream to non-blocking
        if let MaybeTlsStream::Plain(ref mut stream) = socket.get_mut() {
            stream.set_nonblocking(true)?;
        } else if let MaybeTlsStream::Rustls(ref mut stream) = socket.get_mut() {
            stream.get_mut().set_nonblocking(true)?;
        }
        let addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let mut con = ProxyConnection {
            url: url.to_string(),
            sni: sni.map(|s| s.to_string()),
            addr,
            socket,
            insecure,
            rx_buffer: VecDeque::new(),
        };
        // Read initial address message in non-blocking mode with retry (don't toggle blocking)
        let addr_data = con.read_address_message()?;
        con.addr = read_addr(Cursor::new(&addr_data))?;
        Ok(con)
    }

    pub fn read_message(&mut self) -> Result<Vec<u8>, io::Error> {
        loop {
            match self.socket.read() {
                Ok(Message::Binary(data)) => {
                    if data.is_empty() {
                        // Empty binary frame, keep reading
                        continue;
                    }
                    return Ok(data);
                }
                Ok(Message::Ping(data)) => {
                    // Respond to ping with pong to keep connection alive
                    if let Err(e) = self.socket.send(Message::Pong(data)) {
                        return Err(io::Error::new(io::ErrorKind::Other, format!("Failed to send pong: {}", e)));
                    }
                    // Continue reading for binary data
                    continue;
                }
                Ok(Message::Close(_)) => {
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "WebSocket connection closed"));
                }
                Ok(_) => continue, // Ignore other non-binary messages (Pong, etc.)
                Err(e) => {
                    // Check if it's a WouldBlock error from underlying socket
                    // tungstenite::Error has source() that returns the underlying IO error
                    if let Some(source) = e.source() {
                        if let Some(io_err) = source.downcast_ref::<io::Error>() {
                            if io_err.kind() == io::ErrorKind::WouldBlock {
                                // Return empty vec to signal no data available
                                return Ok(Vec::new());
                            }
                        }
                    }
                    return Err(io::Error::new(io::ErrorKind::Other, format!("Failed to read from ws proxy: {}", e)));
                }
            }
        }
    }

    /// Read messages until a valid address message (>=18 bytes) is received.
    /// Used during connection establishment to get the server's UDP address.
    /// Works in non-blocking mode with retry on WouldBlock.
    fn read_address_message(&mut self) -> Result<Vec<u8>, io::Error> {
        loop {
            let data = self.read_message()?;
            if data.is_empty() {
                // WouldBlock - wait and retry in non-blocking mode
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            if data.len() >= 18 {
                return Ok(data);
            }
            // Too short to be an address message, ignore and continue
        }
    }

    /// Reconnect to the WebSocket proxy after a disconnection.
    /// Re-establishes the WebSocket connection, re-reads the server-assigned UDP
    /// address, and updates the internal state. On success the connection is
    /// ready for the event loop to resume.
    pub fn reconnect(&mut self) -> Result<(), io::Error> {
        info!("ProxyConnection::reconnect: reconnecting to {}", self.url);
        let parsed_url = io_error!(Url::parse(&self.url), "Invalid URL {}: {}", self.url)?;
        let host_str = parsed_url.host_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, format!("No host in URL {}", self.url))
        })?;
        let port = parsed_url.port_or_known_default().unwrap_or(443);
        let addr = if host_str.contains(':') {
            format!("[{}]:{}", host_str, port)
        } else {
            format!("{}:{}", host_str, port)
        };

        let effective_url = if let Some(ref sni_val) = self.sni {
            let mut modified = parsed_url.clone();
            modified.set_host(Some(sni_val)).map_err(|_| {
                io::Error::new(io::ErrorKind::Other, format!("Invalid SNI host {}", sni_val))
            })?;
            modified
        } else {
            parsed_url
        };

        let mut socket = if self.insecure && effective_url.scheme() == "wss" {
            let config = Arc::new(
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                    .with_no_client_auth(),
            );
            let tcp_stream = TcpStream::connect(&addr)?;
            set_tcp_keepalive(&tcp_stream)?;
            let connector = Connector::Rustls(config);
            let (ws, _) = client_tls_with_config(
                effective_url.as_str(),
                tcp_stream,
                None,
                Some(connector),
            ).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS error: {}", e)))?;
            ws
        } else {
            let (socket, _) = io_error!(
                tungstenite::connect(effective_url),
                "Failed to connect to URL {}: {}", self.url
            )?;
            socket
        };
        // Set TCP keepalive on the underlying stream
        if let MaybeTlsStream::Plain(ref mut stream) = socket.get_mut() {
            set_tcp_keepalive(stream)?;
        } else if let MaybeTlsStream::Rustls(ref mut stream) = socket.get_mut() {
            set_tcp_keepalive(stream.get_mut())?;
        }
        socket.get_mut().set_nodelay(true)?;
        // Set underlying TcpStream to non-blocking
        if let MaybeTlsStream::Plain(ref mut stream) = socket.get_mut() {
            stream.set_nonblocking(true)?;
        } else if let MaybeTlsStream::Rustls(ref mut stream) = socket.get_mut() {
            stream.get_mut().set_nonblocking(true)?;
        }
        self.socket = socket;
        self.rx_buffer.clear();
        // Re-read the server-assigned UDP address
        let addr_data = self.read_address_message()?;
        self.addr = read_addr(Cursor::new(&addr_data))?;
        info!("ProxyConnection::reconnect: reconnected, UDP address={}", self.addr);
        Ok(())
    }
}

#[cfg(unix)]
impl AsRawFd for ProxyConnection {
    fn as_raw_fd(&self) -> RawFd {
        match self.socket.get_ref() {
            MaybeTlsStream::Plain(stream) => stream.as_raw_fd(),
            MaybeTlsStream::Rustls(stream) => stream.get_ref().as_raw_fd(),
            _ => panic!("unsupported TLS stream type"),
        }
    }
}

#[cfg(windows)]
impl AsRawSocket for ProxyConnection {
    fn as_raw_socket(&self) -> RawSocket {
        match self.socket.get_ref() {
            MaybeTlsStream::Plain(stream) => stream.as_raw_socket(),
            MaybeTlsStream::Rustls(stream) => stream.get_ref().as_raw_socket(),
            _ => panic!("unsupported TLS stream type"),
        }
    }
}

impl Socket for ProxyConnection {
    fn listen(url: &str) -> Result<Self, io::Error> {
        let parsed_url = io_error!(Url::parse(url), "Invalid URL {}: {}", url)?;
        let (mut socket, _) = io_error!(tungstenite::connect(parsed_url), "Failed to connect to URL {}: {}", url)?;
        socket.get_mut().set_nodelay(true)?;
        // Set underlying TcpStream to non-blocking
        if let MaybeTlsStream::Plain(ref mut stream) = socket.get_mut() {
            stream.set_nonblocking(true)?;
        } else if let MaybeTlsStream::Rustls(ref mut stream) = socket.get_mut() {
            stream.get_mut().set_nonblocking(true)?;
        }
        let addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let mut con = ProxyConnection {
            url: url.to_string(),
            sni: None,
            addr,
            socket,
            insecure: false,
            rx_buffer: VecDeque::new(),
        };
        // Read initial address message in non-blocking mode with retry (don't toggle blocking)
        let addr_data = con.read_address_message()?;
        con.addr = read_addr(Cursor::new(&addr_data))?;
        Ok(con)
    }

    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        // First, try to return a buffered frame
        if let Some((data, addr)) = self.rx_buffer.pop_front() {
            buffer.clear();
            buffer.clone_from(&data[18..]);
            return Ok(addr);
        }

        // Buffer empty: drain all available frames from tungstenite
        loop {
            let data = self.read_message()?;
            if data.is_empty() {
                // WouldBlock - no more data available
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "No data available"));
            }
            let addr = read_addr(Cursor::new(&data))?;
            // Push to buffer, return the first one
            if self.rx_buffer.is_empty() {
                buffer.clear();
                buffer.clone_from(&data[18..]);
                return Ok(addr);
            } else {
                self.rx_buffer.push_back((data, addr));
            }
        }
    }

    /// Returns the number of buffered WebSocket frames waiting to be processed.
    /// This allows the event loop to know there's more data without waiting for the next FD_READ.
    fn pending(&self) -> usize {
        self.rx_buffer.len()
    }

    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        // Use the provided peer address (original vpncloud design)
        let mut msg = Vec::with_capacity(data.len() + 18);
        write_addr(addr, &mut msg)?;
        msg.write_all(data)?;
        io_error!(self.socket.send(Message::Binary(msg)), "Failed to write to ws proxy: {}")?;
        Ok(data.len())
    }

    fn address(&self) -> Result<SocketAddr, io::Error> {
        Ok(self.addr)
    }

    fn create_port_forwarding(&self) -> Option<PortForwarding> {
        None
    }

    fn reconnect(&mut self) -> Result<(), io::Error> {
        self.reconnect()
    }
}
