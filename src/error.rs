// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use thiserror::Error;

use std::io;

/// Returns true when an I/O error means the destination is definitively
/// unreachable (no route / host down / address not available), as opposed to a
/// transient condition. Used to decide whether to give up on a direct peer
/// endpoint and fall back to relaying through another peer.
pub fn io_unreachable(err: &io::Error) -> bool {
    match err.raw_os_error() {
        Some(101) | Some(113) | Some(99) => true, // Linux ENETUNREACH / EHOSTUNREACH / EADDRNOTAVAIL
        Some(10051) | Some(10065) | Some(10049) => true, // Windows WSAENETUNREACH / WSAEHOSTUNREACH / WSAEADDRNOTAVAIL
        _ => matches!(
            err.kind(),
            io::ErrorKind::AddrNotAvailable | io::ErrorKind::NotConnected
        ),
    }
}

#[derive(Error, Debug)]
pub enum Error {
    /// Crypto init error, this is recoverable
    #[error("Crypto initialization error: {0}")]
    CryptoInit(&'static str),

    /// Crypto init error, this is fatal and the init needs to be aborted
    #[error("Fatal crypto initialization error: {0}")]
    CryptoInitFatal(&'static str),

    /// Crypto error with this one message, no permanent error
    #[error("Crypto error: {0}")]
    Crypto(&'static str),

    #[error("Invalid crypto state: {0}")]
    InvalidCryptoState(&'static str),

    #[error("Invalid config: {0}")]
    InvalidConfig(&'static str),

    #[error("Socket error: {0}")]
    Socket(&'static str),

    #[error("Socket error: {0} ({1})")]
    SocketIo(&'static str, #[source] io::Error),

    /// Underlying socket/transport closed (e.g., WebSocket proxy disconnected)
    #[error("Socket closed: {0}")]
    SocketClosed(&'static str),

    #[error("Device error: {0}")]
    Device(String),

    #[error("Device error: {0} ({1})")]
    DeviceIo(String, #[source] io::Error),

    #[error("File error: {0}")]
    FileIo(&'static str, #[source] io::Error),

    #[error("Message error: {0}")]
    Message(&'static str),

    #[error("Beacon error: {0} ({1})")]
    BeaconIo(&'static str, #[source] io::Error),

    #[error("Parse error: {0}")]
    Parse(&'static str),

    #[error("Name can not be resolved: {0}")]
    NameUnresolvable(String),
}

impl Error {
    /// True if this error is a definitive "destination unreachable" socket error.
    pub fn is_unreachable(&self) -> bool {
        match self {
            Error::SocketIo(_, e) => io_unreachable(e),
            _ => false,
        }
    }
}
