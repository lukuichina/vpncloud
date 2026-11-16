// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

#[cfg(any(target_os = "linux", target_os = "android"))]
mod epoll;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use self::epoll::EpollWait as WaitImpl;

#[cfg(windows)]
mod windows_wait;

#[cfg(windows)]
pub use self::windows_wait::WindowsWait as WaitImpl;

use std::io;

#[derive(Debug)]
pub enum WaitResult {
    Timeout,
    Socket,
    Device,
    Error(io::Error),
}
