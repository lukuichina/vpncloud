// VpnCloud - Peer-to-Peer VPN (Windows single-thread fast path)
// Event-driven wait using WSAEventSelect + WaitForMultipleObjects on
// [socket_read_event, wintun_read_event] to avoid select/poll quantization
// and cross-handle polling overhead.

use std::{io, os::windows::io::RawSocket};

use windows_sys::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::Networking::WinSock::{
    WSAEventSelect, WSACreateEvent, WSACloseEvent, WSAEnumNetworkEvents, WSANETWORKEVENTS,
    FD_READ, FD_CLOSE, FD_READ_BIT, FD_CLOSE_BIT, SOCKET_ERROR, WSAEVENT, SOCKET,
};
use windows_sys::Win32::System::Threading::WaitForMultipleObjects;

use super::WaitResult;

pub struct WindowsWait {
    socket: SOCKET,
    socket_event: WSAEVENT,
    device_event: HANDLE,
    timeout_ms: u32,
    closed: bool,
}

impl WindowsWait {
    pub fn new(socket: RawSocket, device_event: RawSocket, timeout_ms: u32) -> io::Result<Self> {
        unsafe {
            let sock = socket as SOCKET;
            let ev: WSAEVENT = WSACreateEvent();
            if ev == 0 {
                return Err(io::Error::last_os_error());
            }
            let result = WSAEventSelect(sock, ev, (FD_READ | FD_CLOSE) as i32);
            info!("WindowsWait::new: socket={:?}, WSAEventSelect result={}", sock, result);
            if result == SOCKET_ERROR {
                let e = io::Error::last_os_error();
                WSACloseEvent(ev);
                return Err(e);
            }
            Ok(Self {
                socket: sock,
                socket_event: ev,
                device_event: device_event as HANDLE,
                timeout_ms,
                closed: false,
            })
        }
    }

    pub fn testing(socket: RawSocket, device_event: RawSocket, timeout_ms: u32) -> io::Result<Self> {
        Self::new(socket, device_event, timeout_ms)
    }
}

impl Drop for WindowsWait {
    fn drop(&mut self) {
        unsafe {
            let _ = WSAEventSelect(self.socket, 0 as WSAEVENT, 0);
            WSACloseEvent(self.socket_event);
        }
    }
}

impl Iterator for WindowsWait {
    type Item = WaitResult;

    fn next(&mut self) -> Option<Self::Item> {
        if self.closed {
            return Some(WaitResult::Error(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "socket closed",
            )));
        }
        let handles = [self.socket_event as HANDLE, self.device_event];
        let r = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, self.timeout_ms) };
        if r == WAIT_OBJECT_0 {
            let mut treat_as_readable = false;
            unsafe {
                let mut events: WSANETWORKEVENTS = std::mem::zeroed();
                let rc = WSAEnumNetworkEvents(self.socket, self.socket_event, &mut events);
                if rc == SOCKET_ERROR {
                    return Some(WaitResult::Error(io::Error::last_os_error()));
                }
                let net = events.lNetworkEvents as i32;

                // FD_READ: report socket readiness; caller must drain to WOULDBLOCK.
                if (net & FD_READ as i32) != 0 {
                    if events.iErrorCode[FD_READ_BIT as usize] == 0 {
                        treat_as_readable = true;
                    } else {
                        return Some(WaitResult::Error(io::Error::from_raw_os_error(
                            events.iErrorCode[FD_READ_BIT as usize],
                        )));
                    }
                }

                // FD_CLOSE: mark closed but still allow one drain pass if FD_READ also fired.
                if (net & FD_CLOSE as i32) != 0 {
                    let close_err = events.iErrorCode[FD_CLOSE_BIT as usize];
                    if close_err != 0 && close_err != 10053 /* WSAECONNABORTED */ && close_err != 10054 /* WSAECONNRESET */ {
                        // Surface unexpected close errors, but only if no readable data remains.
                        if !treat_as_readable {
                            return Some(WaitResult::Error(io::Error::from_raw_os_error(close_err)));
                        }
                    }
                    self.closed = true;
                    // Even on graceful close there may be buffered data; ensure caller drains.
                    treat_as_readable = true;
                }
            }
            if treat_as_readable || self.closed {
                Some(WaitResult::Socket)
            } else {
                // Spurious wake without actionable FD_READ/FD_CLOSE; continue waiting.
                self.next()
            }
        } else if r == WAIT_OBJECT_0 + 1 {
            Some(WaitResult::Device)
        } else if r == WAIT_TIMEOUT {
            Some(WaitResult::Timeout)
        } else if r == WAIT_FAILED {
            Some(WaitResult::Error(io::Error::last_os_error()))
        } else {
            Some(WaitResult::Error(io::Error::new(
                io::ErrorKind::Other,
                format!("WaitForMultipleObjects returned {}", r),
            )))
        }
    }
}
