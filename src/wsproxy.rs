// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::{
    net::{get_ip, mapped_addr, parse_listen, Socket},
    poll::{WaitImpl, WaitResult},
    port_forwarding::PortForwarding,
    util::MsgBuffer,
};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::{
    io::{self, Cursor, Read, Write},
    net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream, UdpSocket},
    os::unix::io::{AsRawFd, RawFd},
    sync::Arc,
    thread::spawn,
};
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

fn write_addr<W: Write>(addr: SocketAddr, mut out: W) -> Result<(), io::Error> {
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

fn read_addr<R: Read>(mut r: R) -> Result<SocketAddr, io::Error> {
    let mut ip = [0u8; 16];
    r.read_exact(&mut ip)?;
    let port = r.read_u16::<NetworkEndian>()?;
    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0));
    Ok(addr)
}

fn serve_proxy_connection(stream: TcpStream) -> Result<(), io::Error> {
    let peer = stream.peer_addr()?;
    info!("WS client {} connected", peer);
    stream.set_nodelay(true)?;
    let mut websocket = io_error!(accept(stream), "Failed to initialize websocket with {}: {}", peer)?;
    let udpsocket = UdpSocket::bind("[::]:0")?;
    let mut msg = Vec::with_capacity(18);
    let mut addr = udpsocket.local_addr()?;
    info!("Listening on {} for peer {}", addr, peer);
    addr.set_ip(get_ip());
    write_addr(addr, &mut msg)?;
    io_error!(websocket.send(Message::Binary(msg)), "Failed to write to ws connection: {}")?;
    let websocketfd = websocket.get_ref().as_raw_fd();
    let poll = WaitImpl::new(websocketfd, udpsocket.as_raw_fd(), 60 * 1000)?;
    let mut buffer = [0; 65535];
    for evt in poll {
        match evt {
            WaitResult::Socket => {
                let msg = io_error!(websocket.read(), "Failed to read message on websocket {}: {}", peer)?;
                match msg {
                    Message::Binary(data) => {
                        let dst = read_addr(Cursor::new(&data))?;
                        udpsocket.send_to(&data[18..], dst)?;
                    }
                    Message::Close(_) => return Ok(()),
                    _ => {}
                }
            }
            WaitResult::Device => {
                let (size, addr) = udpsocket.recv_from(&mut buffer)?;
                let mut data = Vec::with_capacity(18 + size);
                write_addr(addr, &mut data)?;
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

pub fn run_proxy(listen: &str) -> Result<(), io::Error> {
    let addr = parse_listen(listen, 8080);
    let server = TcpListener::bind(addr)?;
    info!("Listening on ws://{}", server.local_addr()?);
    for stream in server.incoming() {
        let stream = stream?;
        let peer = stream.peer_addr()?;
        spawn(move || {
            if let Err(err) = serve_proxy_connection(stream) {
                error!("Error on connection {}: {}", peer, err);
            }
        });
    }
    Ok(())
}

pub struct ProxyConnection {
    addr: SocketAddr,
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    insecure: bool,
}

impl ProxyConnection {
    /// Connect to a wss:// URL, optionally skipping TLS certificate verification
    pub fn connect(url: &str, insecure: bool) -> Result<Self, io::Error> {
        let parsed_url = io_error!(Url::parse(url), "Invalid URL {}: {}", url)?;
        let mut socket = if insecure && parsed_url.scheme() == "wss" {
            let config = Arc::new(
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                    .with_no_client_auth(),
            );
            let domain = parsed_url.domain().ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, format!("No domain in URL {}", url))
            })?;
            let port = parsed_url.port_or_known_default().unwrap_or(443);
            let addr = format!("{}:{}", domain, port);
            let tcp_stream = TcpStream::connect(&addr)?;
            let connector = Connector::Rustls(config);
            let (ws, _) = client_tls_with_config(
                parsed_url.as_str(),
                tcp_stream,
                None,
                Some(connector),
            ).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS error: {}", e)))?;
            ws
        } else {
            let (socket, _) = io_error!(
                tungstenite::connect(parsed_url),
                "Failed to connect to URL {}: {}", url
            )?;
            socket
        };
        socket.get_mut().set_nodelay(true)?;
        let addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let mut con = ProxyConnection { addr, socket, insecure: false };
        let addr_data = con.read_message()?;
        con.addr = read_addr(Cursor::new(&addr_data))?;
        Ok(con)
    }

    fn read_message(&mut self) -> Result<Vec<u8>, io::Error> {
        loop {
            if let Message::Binary(data) = io_error!(self.socket.read(), "Failed to read from ws proxy: {}")? {
                return Ok(data);
            }
        }
    }
}

impl AsRawFd for ProxyConnection {
    fn as_raw_fd(&self) -> RawFd {
        match self.socket.get_ref() {
            MaybeTlsStream::Plain(stream) => stream.as_raw_fd(),
            MaybeTlsStream::Rustls(stream) => stream.get_ref().as_raw_fd(),
            _ => panic!("unsupported TLS stream type"),
        }
    }
}

impl Socket for ProxyConnection {
    fn listen(url: &str) -> Result<Self, io::Error> {
        let parsed_url = io_error!(Url::parse(url), "Invalid URL {}: {}", url)?;
        let (mut socket, _) = io_error!(tungstenite::connect(parsed_url), "Failed to connect to URL {}: {}", url)?;
        socket.get_mut().set_nodelay(true)?;
        let addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let mut con = ProxyConnection { addr, socket, insecure: false };
        let addr_data = con.read_message()?;
        con.addr = read_addr(Cursor::new(&addr_data))?;
        Ok(con)
    }

    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        buffer.clear();
        let data = self.read_message()?;
        let addr = read_addr(Cursor::new(&data))?;
        buffer.clone_from(&data[18..]);
        Ok(addr)
    }

    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
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
}
