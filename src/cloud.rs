// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    cmp::{max, min},
    collections::HashMap,
    fmt,
    fs::{self, File},
    hash::BuildHasherDefault,
    io::{self, Cursor, Seek, SeekFrom, Write},
    marker::PhantomData,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::Path,
    str::FromStr,
    thread,
    time::Duration as StdDuration,
};

use fnv::FnvHasher;
use rand::{random, seq::SliceRandom, thread_rng};
use smallvec::{smallvec, SmallVec};

use crate::{
    beacon::BeaconSerializer,
    config::{Config, DEFAULT_PEER_TIMEOUT, DEFAULT_PORT},
    crypto::{is_init_message, Crypto, MessageResult, PeerCrypto},
    device::{Device, Type},
    error::Error,
    messages::{
        AddrList, NodeInfo, PeerInfo, MESSAGE_TYPE_CLOSE, MESSAGE_TYPE_DATA, MESSAGE_TYPE_KEEPALIVE,
        MESSAGE_TYPE_NODE_INFO,
    },
    net::{mapped_addr, parse_listen, Socket},
    payload::Protocol,
    poll::{WaitImpl, WaitResult},
    port_forwarding::PortForwarding,
    table::ClaimTable,
    traffic::TrafficStats,
    types::{Address, Mode, NodeId, Range, RangeList},
    util::{addr_nice, bytes_to_hex, resolve, CtrlC, Duration, MsgBuffer, StatsdMsg, Time, TimeSource},
};

pub type Hash = BuildHasherDefault<FnvHasher>;

// Cap on reconnect back-off. Keep this small so a transiently-unreachable peer
// (underlay blip, NAT path change, restarted process) is retried quickly rather
// than waiting up to an hour. Liveness resets the back-off immediately on any
// received peer packet, so a modest cap costs nothing while connected.
const MAX_RECONNECT_INTERVAL: u16 = 30;
/// How long (seconds) an endpoint that proved unreachable is skipped before we
/// are willing to dial it again. Prevents a gossip-learned direct peer whose
/// addresses we cannot route from being re-dialed on every peer-list update.
const BAD_ADDR_TTL: u16 = 120;
/// Consecutive send failures to a peer's send_addr before we try another candidate.
const PEER_SEND_FAIL_LIMIT: u8 = 3;
/// Minimum dwell time / anti-flap cooldown (seconds) after switching a peer's
/// send_addr. A newly selected endpoint is kept at least this long before a
/// health-based switch is allowed, so it cannot flip straight back.
const PEER_SWITCH_COOLDOWN: u16 = 10;
/// A candidate endpoint is considered "healthy" (recently usable) if we received
/// a packet from it within this many seconds.
const PEER_ACTIVE_WINDOW: u16 = 15;

#[inline]
fn dbg_icmp(payload: &[u8]) -> Option<(u8, u8, u16, u16)> {
    // IPv4 ICMP echo: type,code,identifier,sequence
    if payload.len() >= 28 && (payload[0] >> 4) == 4 {
        let ihl = ((payload[0] & 0x0f) as usize) * 4;
        if payload.len() >= ihl + 8 && payload.get(9) == Some(&1) {
            let b = &payload[ihl..];
            return Some((b[0], b[1], u16::from_be_bytes([b[4], b[5]]), u16::from_be_bytes([b[6], b[7]])));
        }
    }
    None
}

const RESOLVE_INTERVAL: Time = 300;
pub const STATS_INTERVAL: Time = 60;
const OWN_ADDRESS_RESET_INTERVAL: Time = 300;
pub const SPACE_BEFORE: usize = 100;

struct PeerData {
    addrs: AddrList,
    #[allow(dead_code)] //TODO: export in status
    last_seen: Time,
    /// Current best endpoint to send replies to. Updated on every valid packet
    /// received from this peer's NodeId (WireGuard-style roaming).
    last_seen_addr: SocketAddr,
    timeout: Time,
    peer_timeout: u16,
    node_id: NodeId,
    crypto: PeerCrypto<NodeInfo>,
    /// Endpoint we currently send this peer's traffic to. Sticky: only changed
    /// when it stops being healthy (no recent rx) or after send failures, and
    /// subject to a cooldown, to avoid ping-ponging between candidates.
    send_addr: SocketAddr,
    /// Consecutive send failures to `send_addr`.
    send_fail: u8,
    /// Per-candidate last time we successfully received a packet from it.
    rx_seen: HashMap<SocketAddr, Time, Hash>,
    /// Earliest time we may re-select `send_addr` (anti-flap cooldown).
    switch_after: Time,
}

#[derive(Clone)]
pub struct ReconnectEntry {
    address: Option<(String, Time)>,
    resolved: AddrList,
    tries: u16,
    timeout: u16,
    next: Time,
    final_timeout: Option<Time>,
}

pub struct GenericCloud<D: Device, P: Protocol, S: Socket, TS: TimeSource> {
    node_id: NodeId,
    config: Config,
    learning: bool,
    broadcast: bool,
    peers: HashMap<NodeId, PeerData, Hash>,
    /// Reverse index: endpoint -> NodeId, for fast receive-side dispatch.
    /// Several endpoints may map to one NodeId (multi-homed peers). The
    /// authoritative current reply endpoint is `PeerData::last_seen_addr`.
    addr_index: HashMap<SocketAddr, NodeId, Hash>,
    /// Temporarily-blacklisted endpoints that a send proved unreachable
    /// (no route / host down). Cleared after BAD_ADDR_TTL so gossip-learned
    /// direct peers are not re-dialed into a black hole every peer-list update.
    /// This is PER-ADDRESS (not a global direct-peer switch).
    bad_addrs: HashMap<SocketAddr, Time, Hash>,
    reconnect_peers: SmallVec<[ReconnectEntry; 3]>,
    own_addresses: AddrList,
    /// This node's own tunnel addresses (config ip/ipv6) — used to classify an
    /// incoming payload as "deliver locally" vs "userspace relay to another peer".
    local_addrs: SmallVec<[Address; 2]>,
    pending_inits: HashMap<SocketAddr, PeerCrypto<NodeInfo>, Hash>,
    table: ClaimTable<TS>,
    socket: S,
    device: D,
    claims: RangeList,
    crypto: Crypto,
    next_peers: Time,
    /// Next time to send an explicit KEEPALIVE to all peers. Without this an
    /// idle peer receives nothing from us; the liveness check (3×update_freq)
    /// would then drop a perfectly healthy peer and reset its crypto state.
    next_keepalive: Time,
    peer_timeout_publish: u16,
    update_freq: u16,
    stats_file: Option<File>,
    statsd_server: Option<String>,
    next_housekeep: Time,
    next_stats_out: Time,
    next_beacon: Time,
    next_own_address_reset: Time,
    port_forwarding: Option<PortForwarding>,
    traffic: TrafficStats,
    beacon_serializer: BeaconSerializer<TS>,
    _dummy_p: PhantomData<P>,
    _dummy_ts: PhantomData<TS>,
}

impl<D: Device, P: Protocol, S: Socket, TS: TimeSource> GenericCloud<D, P, S, TS> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &Config, socket: S, device: D, port_forwarding: Option<PortForwarding>, stats_file: Option<File>,
    ) -> Self {
        info!("GenericCloud::new: start");
        if let Ok(local) = socket.address() {
            info!("GenericCloud::new: socket local/address={}", local);
        } else {
            warn!("GenericCloud::new: failed to query socket address");
        }
        let (learning, broadcast) = match config.mode {
            Mode::Normal => match config.device_type {
                Type::Tap => (true, true),
                Type::Tun => (false, false),
            },
            Mode::Router => (false, false),
            Mode::Switch => (true, true),
            Mode::Hub => (false, true),
        };
        let mut claims = SmallVec::with_capacity(config.claims.len());
        for s in &config.claims {
            claims.push(try_fail!(Range::from_str(s), "Invalid subnet format: {} ({})", s));
        }
        if device.get_type() == Type::Tun && config.auto_claim {
            // Always claim primary configured address if present.
            if let Some(ref ip_str) = config.ip {
                if let Ok((ip, _)) = crate::parse_ip_netmask(ip_str) {
                    let prefix_len = match ip { IpAddr::V4(_) => 32, IpAddr::V6(_) => 128 };
                    let range = Range { base: Address::from_ip(ip), prefix_len };
                    if !claims.iter().any(|c| *c == range) {
                        info!("Auto-claiming {} due to configured interface address", range);
                        claims.push(range);
                    }
                }
            }
            // Also claim additional IPv6 address in dual-stack setups.
            if let Some(ref ipv6_str) = config.ipv6 {
                if config.ip.as_ref().map(|s| s != ipv6_str).unwrap_or(true) {
                    if let Ok((ip, _)) = crate::parse_ip_netmask(ipv6_str) {
                        let prefix_len = match ip { IpAddr::V4(_) => 32, IpAddr::V6(_) => 128 };
                        let range = Range { base: Address::from_ip(ip), prefix_len };
                        if !claims.iter().any(|c| *c == range) {
                            info!("Auto-claiming {} due to configured IPv6 interface address", range);
                            claims.push(range);
                        }
                    }
                }
            }
            // Fallback to device-reported address if nothing configured.
            if claims.is_empty() {
                match device.get_ip() {
                    Ok(ip) => {
                        let prefix_len = match ip { IpAddr::V4(_) => 32, IpAddr::V6(_) => 128 };
                        let range = Range { base: Address::from_ip(ip), prefix_len };
                        info!("Auto-claiming {} due to interface address", range);
                        claims.push(range);
                    }
                    Err(Error::DeviceIo(_, e)) if e.kind() == io::ErrorKind::AddrNotAvailable => {
                        info!("No address set on interface.")
                    }
                    Err(e) => error!("{}", e),
                }
            }
        }
        // Local tunnel addresses (this node's own IPs).
        let mut local_addrs: SmallVec<[Address; 2]> = SmallVec::new();
        for s in [config.ip.as_ref(), config.ipv6.as_ref()].into_iter().flatten() {
            if let Ok((ip, _)) = crate::parse_ip_netmask(s) {
                let a = Address::from_ip(ip);
                if !local_addrs.contains(&a) {
                    local_addrs.push(a);
                }
            }
        }
        let now = TS::now();
        let update_freq = config.get_keepalive() as u16;
        let crypto = Crypto::new(&config.crypto).unwrap();
        let node_id = crypto.node_id;
        let beacon_key = config.beacon_password.as_ref().map(|s| s.as_bytes()).unwrap_or(&[]);
        let mut res = GenericCloud {
            node_id,
            peers: HashMap::default(),
            addr_index: HashMap::default(),
            bad_addrs: HashMap::default(),
            claims,
            learning,
            broadcast,
            pending_inits: HashMap::default(),
            reconnect_peers: SmallVec::new(),
            own_addresses: SmallVec::new(),
            local_addrs,
            peer_timeout_publish: config.peer_timeout as u16,
            table: ClaimTable::new(config.switch_timeout as Duration, config.peer_timeout as Duration),
            socket,
            device,
            next_peers: now,
            next_keepalive: now,
            update_freq,
            stats_file,
            statsd_server: config.statsd_server.clone(),
            next_housekeep: now,
            next_stats_out: now + STATS_INTERVAL,
            next_beacon: now,
            next_own_address_reset: now + OWN_ADDRESS_RESET_INTERVAL,
            port_forwarding,
            traffic: TrafficStats::default(),
            beacon_serializer: BeaconSerializer::new(beacon_key),
            crypto,
            config: config.clone(),
            _dummy_p: PhantomData,
            _dummy_ts: PhantomData,
        };
        res.initialize();
        res
    }

    #[inline]
    pub fn ifname(&self) -> &str {
        self.device.ifname()
    }

    /// Check if an IP packet's destination is multicast or broadcast.
    /// Returns Some(true) if multicast/broadcast (should drop), Some(false) if unicast, None if unable to parse.
    fn is_multicast_or_broadcast(payload: &[u8]) -> Option<bool> {
        if payload.is_empty() {
            return None;
        }
        let version = payload[0] >> 4;
        match version {
            4 => {
                // IPv4: need at least 20 bytes for header, dst at offset 16
                if payload.len() < 20 {
                    return None;
                }
                let dst = &payload[16..20];
                // 224.0.0.0/4 (multicast) or 255.255.255.255 (broadcast)
                if dst[0] >= 224 || (dst[0] == 255 && dst[1] == 255 && dst[2] == 255 && dst[3] == 255) {
                    return Some(true);
                }
                Some(false)
            }
            6 => {
                // IPv6: need at least 40 bytes for header, dst at offset 24
                if payload.len() < 40 {
                    return None;
                }
                let dst = &payload[24..40];
                // ff00::/8 (multicast)
                if dst[0] == 0xff {
                    return Some(true);
                }
                Some(false)
            }
            _ => None,
        }
    }

    /// Sends the message to all peers
    ///
    /// # Errors
    /// Returns an `Error::SocketError` when the underlying system call fails or only part of the
    /// message could be sent (can this even happen?).
    /// Some messages could have been sent.
    #[inline]
    fn broadcast_msg(&mut self, type_: u8, msg: &mut MsgBuffer) -> Result<(), Error> {
        debug!("Broadcasting message type {}, {:?} bytes to {} peers", type_, msg.len(), self.peers.len());
        let mut msg_data = MsgBuffer::new(100);
        let mut bad: SmallVec<[SocketAddr; 4]> = SmallVec::new();
        for peer in self.peers.values_mut() {
            let addr = peer.last_seen_addr;
            msg_data.set_start(msg.get_start());
            msg_data.set_length(msg.len());
            msg_data.message_mut().clone_from_slice(msg.message());
            peer.crypto.send_message(type_, &mut msg_data)?;
            self.traffic.count_out_traffic(addr, msg_data.len());
            match self.socket.send(msg_data.message(), addr) {
                Ok(written) if written == msg_data.len() => {}
                Ok(written) => warn!(
                    "[BROADCAST] truncated send {}/{} bytes to {}",
                    written,
                    msg_data.len(),
                    addr_nice(addr)
                ),
                Err(e) => {
                    // Do NOT abort the whole broadcast because one peer endpoint is
                    // unreachable; keep updating the remaining peers (e.g. keepalive
                    // / peer-list must still reach the healthy uplink).
                    warn!(
                        "[BROADCAST] send to {} failed: {} (continuing with other peers)",
                        addr_nice(addr),
                        e
                    );
                    if crate::error::io_unreachable(&e) {
                        bad.push(addr);
                    }
                }
            }
        }
        for a in bad {
            self.mark_addr_bad(a);
        }
        Ok(())
    }

    #[inline]
    fn send_to(&mut self, addr: SocketAddr, msg: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        let addr_m = crate::net::mapped_addr(addr);
        let local = self.socket.address().ok();
        debug!("Sending msg with {} bytes to {} (mapped={}) local={:?}", msg.len(), addr, addr_m, local);
        self.traffic.count_out_traffic(addr_m, msg.len());
        match self.socket.send(msg.message(), addr_m) {
            Ok(written) if written == msg.len() => {
                debug!("UDP TX ok: {} bytes to {} local={:?}", written, addr_m, local);
                Ok(())
            }
            Ok(written) => {
                error!("UDP TX truncated: wrote {} of {} bytes to {} local={:?}", written, msg.len(), addr_m, local);
                Err(Error::Socket("Sent out truncated packet"))
            }
            Err(e) => {
                error!("UDP TX failed to {} local={:?}: {}", addr_m, local, e);
                Err(Error::SocketIo("IOError when sending", e))
            }
        }
    }

    #[inline]
    fn send_msg(&mut self, peer_id: NodeId, type_: u8, msg: &mut MsgBuffer) -> Result<(), Error> {
        // Encrypt once. Ciphertext is transport-address independent, so the same
        // buffer can be retried on a different candidate address.
        let primary = match self.peers.get_mut(&peer_id) {
            Some(peer) => {
                peer.crypto.send_message(type_, msg)?;
                peer.send_addr
            }
            None => return Err(Error::Message("Sending to node that is not a peer")),
        };
        debug!(
            "Sending msg with {} bytes to node {} @ {}",
            msg.len(),
            bytes_to_hex(&peer_id),
            addr_nice(primary)
        );
        match self.send_to(primary, msg) {
            Ok(()) => {
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    if peer.send_addr == primary {
                        peer.send_fail = 0;
                    }
                }
                Ok(())
            }
            Err(e) => {
                let next = self.note_send_failure(peer_id, primary, &e);
                if let Some(alt) = next {
                    debug!(
                        "send_msg: candidate {} failed ({}); retrying via alternate {} for node {}",
                        addr_nice(primary),
                        e,
                        addr_nice(alt),
                        bytes_to_hex(&peer_id)
                    );
                    self.send_to(alt, msg)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Record a send failure to `addr` for `peer_id`. Blacklists a definitively
    /// unreachable endpoint (per-address, not global) and, when the current
    /// send_addr is failing, selects a new candidate (subject to cooldown).
    /// Returns Some(alternate) if a different candidate should be tried now.
    fn note_send_failure(&mut self, peer_id: NodeId, addr: SocketAddr, e: &Error) -> Option<SocketAddr> {
        if e.is_unreachable() {
            self.mark_addr_bad(addr);
        }
        let (is_current, cooldown_ok) = match self.peers.get_mut(&peer_id) {
            Some(peer) => {
                if peer.send_addr == addr {
                    peer.send_fail = peer.send_fail.saturating_add(1);
                }
                let fail = peer.send_fail;
                (peer.send_addr == addr, TS::now() >= peer.switch_after && (fail >= PEER_SEND_FAIL_LIMIT || e.is_unreachable()))
            }
            None => return None,
        };
        if !is_current || !cooldown_ok {
            return None;
        }
        self.pick_next_addr(peer_id, addr)
    }

    /// Pick a new send_addr for a peer. Only candidates we have RECENTLY RECEIVED
    /// FROM (proven reachable in both directions) and that are not blacklisted are
    /// eligible. If none qualify, return None — the caller must NOT blind-fire at
    /// unverified/known-bad addresses; it should fall back to relay/probe instead.
    /// Sets the dwell/cooldown and returns the chosen address.
    fn pick_next_addr(&mut self, peer_id: NodeId, exclude: SocketAddr) -> Option<SocketAddr> {
        let now = TS::now();
        let window = PEER_ACTIVE_WINDOW as Time;
        let mut ranked: SmallVec<[(Time, SocketAddr); 8]> = SmallVec::new();
        {
            let peer = self.peers.get(&peer_id)?;
            let mut consider = |a: SocketAddr, t: Option<Time>| {
                if a == exclude || self.addr_is_bad(&a) {
                    return;
                }
                if let Some(tt) = t {
                    if now.saturating_sub(tt) <= window {
                        ranked.push((tt, a));
                    }
                }
            };
            for a in &peer.addrs {
                consider(*a, peer.rx_seen.get(a).copied());
            }
            for (a, t) in &peer.rx_seen {
                if !peer.addrs.contains(a) {
                    consider(*a, Some(*t));
                }
            }
        }
        // Most recently-heard first.
        ranked.sort_by(|a, b| b.0.cmp(&a.0));
        let chosen = ranked.first().map(|(_, a)| *a);
        if let Some(addr) = chosen {
            if let Some(peer) = self.peers.get_mut(&peer_id) {
                peer.send_addr = addr;
                peer.send_fail = 0;
                peer.switch_after = now + PEER_SWITCH_COOLDOWN as Time;
            }
            info!(
                "Peer node {} switching send_addr: {} -> {} (recently-heard only)",
                bytes_to_hex(&peer_id),
                addr_nice(exclude),
                addr_nice(addr)
            );
            Some(addr)
        } else {
            None
        }
    }

    /// Periodic per-peer endpoint maintenance: if the current send_addr has not
    /// been heard from for a while but another candidate has (and cooldown
    /// permits), switch to it. Keeps endpoints sticky otherwise (anti-flap).
    fn maintain_peer_endpoints(&mut self) {
        let now = TS::now();
        let window = PEER_ACTIVE_WINDOW as Time;
        let ids: SmallVec<[NodeId; 8]> = self.peers.keys().copied().collect();
        for pid in ids {
            let (cur_send, cooldown_ok, healthy, alt) = {
                let peer = match self.peers.get(&pid) {
                    Some(p) => p,
                    None => continue,
                };
                let cur_healthy = peer
                    .rx_seen
                    .get(&peer.send_addr)
                    .map(|t| now.saturating_sub(*t) <= window)
                    .unwrap_or(false)
                    && !self.addr_is_bad(&peer.send_addr);
                let mut best: Option<(Time, SocketAddr)> = None;
                for (a, t) in &peer.rx_seen {
                    if *a == peer.send_addr || self.addr_is_bad(a) {
                        continue;
                    }
                    if now.saturating_sub(*t) > window {
                        continue;
                    }
                    if best.map(|(bt, _)| *t > bt).unwrap_or(true) {
                        best = Some((*t, *a));
                    }
                }
                (peer.send_addr, now >= peer.switch_after, cur_healthy, best.map(|(_, a)| a))
            };
            if healthy || !cooldown_ok {
                continue;
            }
            if let Some(alt) = alt {
                if let Some(peer) = self.peers.get_mut(&pid) {
                    peer.send_addr = alt;
                    peer.send_fail = 0;
                    peer.switch_after = now + PEER_SWITCH_COOLDOWN as Time;
                }
                info!(
                    "Peer node {} send_addr {} unhealthy; switching to recently-heard {}",
                    bytes_to_hex(&pid),
                    addr_nice(cur_send),
                    addr_nice(alt)
                );
            }
        }
    }

    /// Record that we received a valid packet from `peer_id` at `src`.
    #[allow(dead_code)]
    fn record_rx(&mut self, peer_id: NodeId, src: SocketAddr) {
        let now = TS::now();
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            peer.rx_seen.insert(src, now);
            if peer.send_addr == src {
                peer.send_fail = 0;
            }
        }
    }

    pub fn reset_own_addresses(&mut self) -> io::Result<()> {
        self.own_addresses.clear();
        let socket_addr = self.socket.address().map(mapped_addr)?;
        // 1) Specified advertise addresses
        for addr in &self.config.advertise_addresses {
            self.own_addresses.push(parse_listen(addr, socket_addr.port()));
        }
        // 2) No explicit advertise addresses (bare mode): advertise the source IP
        //    the kernel actually uses toward each peer, instead of a single
        //    get_ip() value. On multi-homed hosts (LAN + netbird wt0 + public v6)
        //    get_ip() may pick an address no peer can reach, which makes peers try
        //    us at that address and causes routing/key churn. We probe the route
        //    toward each configured/known peer with a connected UDP socket (no
        //    packets sent) and advertise the resulting source IP. Loopback and
        //    unspecified addresses are filtered out.
        if self.config.advertise_addresses.is_empty() {
            let port = socket_addr.port();
            let mut candidates: SmallVec<[SocketAddr; 6]> = SmallVec::new();
            let mut add_ip = |cands: &mut SmallVec<[SocketAddr; 6]>, ip: std::net::IpAddr| {
                if ip.is_unspecified() || ip.is_loopback() {
                    return;
                }
                let sa = SocketAddr::new(ip, port);
                if !cands.contains(&sa) {
                    cands.push(sa);
                }
            };
            // (a) Per-peer source IP via kernel route lookup.
            let peer_targets: SmallVec<[SocketAddr; 8]> = self
                .config
                .peers
                .iter()
                .filter_map(|p| p.parse::<SocketAddr>().ok())
                .chain(self.peers.values().map(|p| p.last_seen_addr))
                .collect();
            for dst in peer_targets {
                if let Some(ip) = crate::net::local_ip_for(dst) {
                    add_ip(&mut candidates, ip);
                }
            }
            // (b) Fallback: generic outbound IP (may be unreachable for some peers).
            add_ip(&mut candidates, socket_addr.ip());
            if candidates.is_empty() {
                candidates.push(socket_addr);
            }
            self.own_addresses.extend(candidates);
        }
        // 3) Addresses from port forwarding
        if let Some(ref pfw) = self.port_forwarding {
            self.own_addresses.push(pfw.get_internal_ip().into());
            self.own_addresses.push(pfw.get_external_ip().into());
        }
        // 4) (--advertise_auto only) Actively enumerate unicast addresses of local
        //    ACTIVE network cards (IPv4 + IPv6) so peers can reach us on every real
        //    interface (LAN, netbird/wt0, public v6). We deliberately filter out:
        //      - loopback / unspecified / link-local (not routable to peers),
        //      - our own virtual tunnel interface (vpncloud0) to avoid advertising
        //        the tunnel IPs back to peers (self-loop).
        if self.config.advertise_auto {
            let ifname = self.device.ifname().to_owned();
            let port = socket_addr.port();
            let mut nic: SmallVec<[SocketAddr; 8]> = SmallVec::new();
            for iface in netdev::get_interfaces() {
                if iface.is_loopback() {
                    continue;
                }
                if !iface.is_up() {
                    continue;
                }
                if iface.name == ifname {
                    continue;
                }
                for net in &iface.ipv4 {
                    let ip = net.addr();
                    if ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() {
                        continue;
                    }
                    let sa = SocketAddr::new(std::net::IpAddr::V4(ip), port);
                    if !nic.contains(&sa) {
                        nic.push(sa);
                    }
                }
                for net in &iface.ipv6 {
                    let ip = net.addr();
                    if ip.is_loopback() || ip.is_unspecified() || ip.is_unicast_link_local() {
                        continue;
                    }
                    let sa = SocketAddr::new(std::net::IpAddr::V6(ip), port);
                    if !nic.contains(&sa) {
                        nic.push(sa);
                    }
                }
            }
            for sa in nic {
                if !self.own_addresses.contains(&sa) {
                    self.own_addresses.push(sa);
                }
            }
        }
        debug!("Own addresses: {:?}", self.own_addresses);
        // TODO: detect address changes and call event
        Ok(())
    }

    /// Manually set own addresses (for WebSocket mode where socket address is the proxy's address)
    pub fn set_own_addresses(&mut self, addrs: Vec<SocketAddr>) {
        self.own_addresses.clear();
        self.own_addresses.extend(addrs);
        debug!("Own addresses manually set: {:?}", self.own_addresses);
    }

    /// Get the socket's local address (for WebSocket reconnect to update own_addresses)
    pub fn socket_address(&self) -> io::Result<SocketAddr> {
        self.socket.address()
    }

    /// Returns the number of peers
    #[allow(dead_code)]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Adds a peer to the reconnect list
    ///
    /// This method adds a peer to the list of nodes to reconnect to. A periodic task will try to
    /// connect to the peer if it is not already connected.
    pub fn add_reconnect_peer(&mut self, add: String) {
        let now = TS::now();
        let resolved = match resolve(&add as &str) {
            Ok(addrs) => addrs,
            Err(err) => {
                warn!("Failed to resolve {}: {:?}", add, err);
                smallvec![]
            }
        };
        self.reconnect_peers.push(ReconnectEntry {
            address: Some((add, now)),
            tries: 0,
            timeout: 1,
            resolved,
            next: now,
            final_timeout: None,
        })
    }

    /// Connects to a node given by its address
    ///
    /// This method connects to node by sending a `Message::Init` to it. If `addr` is a name that
    /// resolves to multiple addresses, one message is sent to each of them.
    /// If the node is already a connected peer or the address is blacklisted, no message is sent.
    ///
    /// # Errors
    /// This method returns `Error::NameError` if the address is a name that fails to resolve.
    pub fn connect<Addr: ToSocketAddrs + fmt::Debug + Clone>(&mut self, addr: Addr) -> Result<(), Error> {
        let resolved = resolve(&addr)?;
        info!("Connect target {:?} resolved to {:?}", addr, resolved);
        let addrs = resolved.into_iter().map(mapped_addr).collect::<SmallVec<[SocketAddr; 3]>>();
        info!("Connect target {:?} mapped addrs={:?}", addr, addrs);
        let send_addrs = addrs
            .into_iter()
            .filter(|a| {
                let skip = self.own_addresses.contains(a)
                    || self.addr_index.contains_key(a)
                    || self.pending_inits.contains_key(a)
                    || self.addr_is_bad(a);
                if skip {
                    info!(
                        "Connect target {:?}: addr {} already known/own/pending/blacklisted, skipping",
                        addr,
                        addr_nice(*a)
                    );
                }
                !skip
            })
            .collect::<SmallVec<[SocketAddr; 3]>>();
        if send_addrs.is_empty() {
            return Ok(());
        }
        self.config.call_hook(
            "peer_connecting",
            vec![("PEER", format!("{:?}", addr_nice(send_addrs[0]))), ("IFNAME", self.device.ifname().to_owned())],
            true,
        );
        // Send a message to each resolved, reachable address
        for a in send_addrs {
            info!("Connect target {:?}: initiating handshake to {}", addr, addr_nice(a));
            // Ignore error this time
            self.connect_sock(a).ok();
        }
        Ok(())
    }

    fn create_node_info(&self) -> NodeInfo {
        let mut peers = smallvec![];
        for peer in self.peers.values() {
            peers.push(PeerInfo { node_id: Some(peer.node_id), addrs: peer.addrs.clone() })
        }
        if peers.len() > 20 {
            let mut rng = rand::thread_rng();
            peers.partial_shuffle(&mut rng, 20);
            peers.truncate(20);
        }
        NodeInfo {
            node_id: self.node_id,
            peers,
            claims: self.claims.clone(),
            peer_timeout: Some(self.peer_timeout_publish),
            addrs: self.own_addresses.clone(),
        }
    }

    fn connect_sock(&mut self, addr: SocketAddr) -> Result<(), Error> {
        let addr = mapped_addr(addr);
        if self.addr_index.contains_key(&addr)
            || self.own_addresses.contains(&addr)
            || self.pending_inits.contains_key(&addr)
        {
            debug!("connect_sock: {} already connected/own/pending, skipping", addr_nice(addr));
            return Ok(());
        }
        let local = self.socket.address().ok();
        info!("connect_sock: initiating to {} local={:?}", addr_nice(addr), local);
        let payload = self.create_node_info();
        let mut peer_crypto = self.crypto.peer_instance(payload);
        let mut msg = MsgBuffer::new(SPACE_BEFORE);
        peer_crypto.initialize(&mut msg)?;
        info!("connect_sock: sending init ({} bytes) to {} local={:?}", msg.len(), addr_nice(addr), local);
        // Send FIRST; only register the pending handshake if the init actually
        // left the socket. Otherwise a failed send would leave a stuck pending
        // entry that blocks further connect_sock() retries (the "already
        // pending, skipping" branch) until it times out.
        self.send_to(addr, &mut msg)?;
        self.pending_inits.insert(addr, peer_crypto);
        Ok(())
    }

    fn crypto_housekeep(&mut self) -> Result<(), Error> {
        let mut msg = MsgBuffer::new(SPACE_BEFORE);
        let mut del_pending: SmallVec<[SocketAddr; 4]> = smallvec![];
        let mut del_peers: SmallVec<[NodeId; 4]> = smallvec![];
        for addr in self.pending_inits.keys().copied().collect::<SmallVec<[SocketAddr; 4]>>() {
            msg.clear();
            match self.pending_inits.get_mut(&addr).unwrap().every_second(&mut msg) {
                Err(_) => del_pending.push(addr),
                Ok(MessageResult::None) => (),
                Ok(MessageResult::Reply) => self.send_to(addr, &mut msg)?,
                Ok(_) => unreachable!(),
            }
        }
        for peer_id in self.peers.keys().copied().collect::<SmallVec<[NodeId; 16]>>() {
            msg.clear();
            let reply_addr = {
                let peer = self.peers.get_mut(&peer_id).unwrap();
                match peer.crypto.every_second(&mut msg) {
                    Err(_) => {
                        del_peers.push(peer_id);
                        None
                    }
                    Ok(MessageResult::None) => None,
                    Ok(MessageResult::Reply) => Some(peer.last_seen_addr),
                    Ok(_) => unreachable!(),
                }
            };
            if let Some(addr) = reply_addr {
                self.send_to(addr, &mut msg)?;
            }
        }
        for addr in del_pending {
            self.pending_inits.remove(&addr);
        }
        for peer_id in del_peers {
            self.remove_peer_by_id(peer_id, true)?;
        }
        Ok(())
    }

    /// Reset exponential back-off for any reconnect target that owns `addr`.
    /// Called on process start (fresh state) and whenever a packet is received
    /// from a peer address, so reachability immediately drives retries fast.
    fn reset_reconnect_backoff(&mut self, addr: SocketAddr) {
        let now = TS::now();
        for entry in &mut self.reconnect_peers {
            if entry.resolved.contains(&addr) {
                entry.tries = 0;
                entry.timeout = 1;
                entry.next = now + 1;
            }
        }
    }

    /// Mark `addr` as temporarily unreachable so connect()/gossip-dial skips it.
    fn mark_addr_bad(&mut self, addr: SocketAddr) {
        let until = TS::now() + BAD_ADDR_TTL as Time;
        self.bad_addrs.insert(mapped_addr(addr), until);
    }

    /// True if `addr` is currently blacklisted as unreachable.
    fn addr_is_bad(&self, addr: &SocketAddr) -> bool {
        match self.bad_addrs.get(&mapped_addr(*addr)) {
            Some(&until) => until > TS::now(),
            None => false,
        }
    }

    /// True if `addr` belongs to a statically-configured peer (reconnect target).
    /// Those are never dropped as "unreachable direct peers" because they are the
    /// uplink we must keep trying to reach.
    fn is_configured_addr(&self, addr: &SocketAddr) -> bool {
        let a = mapped_addr(*addr);
        self.reconnect_peers.iter().any(|e| e.resolved.contains(&a))
    }

    /// Drop a direct (gossip) peer that proved unreachable: blacklist all of its
    /// endpoints, remove its claims and reverse-index entries. Traffic for its
    /// address space then falls back to relaying through the remaining peer(s).
    fn drop_peer_for_relay(&mut self, peer_id: NodeId) {
        if let Some(peer) = self.peers.remove(&peer_id) {
            let addrs: SmallVec<[SocketAddr; 4]> = peer.addrs.iter().copied().collect();
            for a in addrs {
                self.mark_addr_bad(a);
            }
            self.mark_addr_bad(peer.last_seen_addr);
        }
        self.addr_index.retain(|_, v| *v != peer_id);
        self.table.remove_claims(peer_id);
    }

    /// Send `data` without a known claim/route: relay via the remaining peer(s).
    /// Mirrors the no-destination branch of handle_interface_data.
    fn route_without_claim(&mut self, data: &mut MsgBuffer) -> Result<(), Error> {
        if self.broadcast {
            self.broadcast_msg(MESSAGE_TYPE_DATA, data)
        } else if self.peers.len() == 1 {
            if let Some((fb_id, fb_addr)) = self.peers.values().next().map(|p| (p.node_id, p.last_seen_addr)) {
                debug!(
                    "Relay fallback: sole peer node {} @ {}",
                    bytes_to_hex(&fb_id),
                    addr_nice(fb_addr)
                );
                self.send_msg(fb_id, MESSAGE_TYPE_DATA, data)
            } else {
                self.traffic.count_dropped_payload(data.len());
                Ok(())
            }
        } else if !self.peers.is_empty() {
            debug!("Relay fallback: flooding to {} peers", self.peers.len());
            self.broadcast_msg(MESSAGE_TYPE_DATA, data)
        } else {
            self.traffic.count_dropped_payload(data.len());
            Ok(())
        }
    }

    fn reconnect_to_peers(&mut self) -> Result<(), Error> {
        let now = TS::now();
        // Connect to those reconnect_peers that are due
        for entry in self.reconnect_peers.clone() {
            if entry.next > now {
                continue;
            }
            self.connect(&entry.resolved as &[SocketAddr])?;
        }
        for entry in &mut self.reconnect_peers {
            // Schedule for next second if node is connected
            for addr in &entry.resolved {
                if self.addr_index.contains_key(addr) {
                    entry.tries = 0;
                    entry.timeout = 1;
                    entry.next = now + 1;
                    continue;
                }
            }
            // Resolve entries anew
            if let Some((ref address, ref mut next_resolve)) = entry.address {
                if *next_resolve <= now {
                    match resolve(address as &str) {
                        Ok(addrs) => entry.resolved = addrs,
                        Err(_) => match resolve(&format!("{}:{}", address, DEFAULT_PORT)) {
                            Ok(addrs) => entry.resolved = addrs,
                            Err(err) => warn!("Failed to resolve {}: {}", address, err),
                        },
                    }
                    *next_resolve = now + RESOLVE_INTERVAL;
                }
            }
            // Ignore if next attempt is already in the future
            if entry.next > now {
                continue;
            }
            // Exponential back-off: every 10 tries, the interval doubles
            entry.tries += 1;
            if entry.tries > 10 {
                entry.tries = 0;
                entry.timeout *= 2;
            }
            // Maximum interval is capped (see MAX_RECONNECT_INTERVAL) so
            // unreachable peers are retried promptly.
            if entry.timeout > MAX_RECONNECT_INTERVAL {
                entry.timeout = MAX_RECONNECT_INTERVAL;
            }
            // Schedule next connection attempt
            entry.next = now + Time::from(entry.timeout);
        }
        self.reconnect_peers.retain(|e| e.final_timeout.unwrap_or(now) >= now);
        Ok(())
    }

    fn housekeep(&mut self) -> Result<(), Error> {
        let now = TS::now();
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        let mut del: SmallVec<[NodeId; 3]> = SmallVec::new();
        // Liveness probe: if we have received NO packet from a peer for several
        // keepalive intervals, treat it as dead and reconnect. This detects a
        // silently-restarted peer (which lost all state) far sooner than the long
        // peer_timeout, instead of holding a zombie peer for up to peer_timeout.
        let liveness_timeout: Time = (self.update_freq as Time).saturating_mul(3).max(15);
        for (peer_id, data) in &self.peers {
            let stale = now.saturating_sub(data.last_seen) > liveness_timeout;
            if data.timeout < now || stale {
                if stale && data.timeout >= now {
                    info!(
                        "Peer node {} liveness expired (no packet for >{}s); dropping to force reconnect",
                        bytes_to_hex(peer_id),
                        liveness_timeout
                    );
                }
                del.push(*peer_id);
            }
        }
        for peer_id in del {
            info!("Forgot peer node {} due to timeout", bytes_to_hex(&peer_id));
            self.remove_peer_by_id(peer_id, true)?; // remove + try to reconnect
        }
        self.table.housekeep();
        // Expire unreachable-address blacklist entries.
        self.bad_addrs.retain(|_, until| *until > now);
        // Keep peer endpoints sticky but fail over to a recently-heard candidate
        // when the current one goes quiet (anti-flap cooldown inside).
        self.maintain_peer_endpoints();
        self.crypto_housekeep()?;
        // Periodically extend the port-forwarding
        if let Some(ref mut pfw) = self.port_forwarding {
            pfw.check_extend();
        }
        let now = TS::now();
        // Send an explicit KEEPALIVE to all peers at the keepalive interval so
        // idle links stay fresh and the liveness check (3×update_freq) never
        // expires a healthy peer (which would reset its crypto state).
        if self.next_keepalive <= now && !self.peers.is_empty() {
            let mut ka = MsgBuffer::new(SPACE_BEFORE);
            self.broadcast_msg(MESSAGE_TYPE_KEEPALIVE, &mut ka)?;
            self.next_keepalive = now + Time::from(self.update_freq.max(1) as i64);
        }
        // Periodically send peer list to peers
        if self.next_peers <= now {
            debug!("Send peer list to all peers");
            let info = self.create_node_info();
            info.encode(&mut buffer);
            self.broadcast_msg(MESSAGE_TYPE_NODE_INFO, &mut buffer)?;
            // Reschedule for next update
            let min_peer_timeout = self.peers.iter().map(|p| p.1.peer_timeout).min().unwrap_or(DEFAULT_PEER_TIMEOUT);
            let interval = min(self.update_freq, max(min_peer_timeout / 2 - 60, 1));
            self.next_peers = now + Time::from(interval);
        }
        self.reconnect_to_peers()?;
        if self.next_stats_out < now {
            // Write out the statistics
            self.write_out_stats().map_err(|err| Error::FileIo("Failed to write stats file", err))?;
            self.send_stats_to_statsd()?;
            self.next_stats_out = now + STATS_INTERVAL;
            self.traffic.period(Some(5));
        }
        if let Some(peers) = self.beacon_serializer.get_cmd_results() {
            debug!("Loaded beacon with peers: {:?}", peers);
            for peer in peers {
                self.connect_sock(peer)?;
            }
        }
        if self.next_beacon < now {
            self.store_beacon()?;
            self.load_beacon()?;
            self.next_beacon = now + Time::from(self.config.beacon_interval);
        }
        // Periodically reset own peers
        if self.next_own_address_reset <= now {
            self.reset_own_addresses().map_err(|err| Error::SocketIo("Failed to get own addresses", err))?;
            self.next_own_address_reset = now + OWN_ADDRESS_RESET_INTERVAL;
        }
        Ok(())
    }

    /// Stores the beacon
    fn store_beacon(&mut self) -> Result<(), Error> {
        if let Some(ref path) = self.config.beacon_store {
            let peers: SmallVec<[SocketAddr; 3]> =
                self.own_addresses.choose_multiple(&mut thread_rng(), 3).cloned().collect();
            if let Some(path) = path.strip_prefix('|') {
                self.beacon_serializer
                    .write_to_cmd(&peers, path)
                    .map_err(|e| Error::BeaconIo("Failed to call beacon command", e))?;
            } else {
                self.beacon_serializer
                    .write_to_file(&peers, path)
                    .map_err(|e| Error::BeaconIo("Failed to write beacon to file", e))?;
            }
        }
        Ok(())
    }

    /// Loads the beacon
    fn load_beacon(&mut self) -> Result<(), Error> {
        let peers;
        if let Some(ref path) = self.config.beacon_load {
            if let Some(path) = path.strip_prefix('|') {
                self.beacon_serializer
                    .read_from_cmd(path, Some(50))
                    .map_err(|e| Error::BeaconIo("Failed to call beacon command", e))?;
                return Ok(());
            } else {
                peers = self
                    .beacon_serializer
                    .read_from_file(path, Some(50))
                    .map_err(|e| Error::BeaconIo("Failed to read beacon from file", e))?;
            }
        } else {
            return Ok(());
        }
        debug!("Loaded beacon with peers: {:?}", peers);
        for peer in peers {
            self.connect_sock(peer)?;
        }
        Ok(())
    }

    /// Writes out the statistics to a file
    fn write_out_stats(&mut self) -> Result<(), io::Error> {
        if let Some(ref mut f) = self.stats_file {
            debug!("Writing out stats");
            f.seek(SeekFrom::Start(0))?;
            f.set_len(0)?;
            writeln!(f, "peers:")?;
            let now = TS::now();
            for data in self.peers.values() {
                writeln!(
                    f,
                    "  - \"node:{}\": {{ addr: \"{}\", ttl_secs: {}, crypto: {} }}",
                    bytes_to_hex(&data.node_id),
                    addr_nice(data.last_seen_addr),
                    data.timeout - now,
                    data.crypto.algorithm_name()
                )?;
            }
            writeln!(f)?;
            self.table.write_out(f)?;
            writeln!(f)?;
            self.traffic.write_out(f)?;
            writeln!(f)?;
        }
        Ok(())
    }

    /// Sends the statistics to a statsd endpoint
    fn send_stats_to_statsd(&mut self) -> Result<(), Error> {
        if let Some(ref endpoint) = self.statsd_server {
            let peer_traffic = self.traffic.total_peer_traffic();
            let payload_traffic = self.traffic.total_payload_traffic();
            let dropped = &self.traffic.dropped;
            let prefix = self.config.statsd_prefix.as_ref().map(|s| s as &str).unwrap_or("vpncloud");
            let msg = StatsdMsg::new()
                .with_ns(prefix, |msg| {
                    msg.add("peer_count", self.peers.len(), "g");
                    msg.add("table_cache_entries", self.table.cache_len(), "g");
                    msg.add("table_claims", self.table.claim_len(), "g");
                    msg.with_ns("traffic", |msg| {
                        msg.with_ns("protocol", |msg| {
                            msg.with_ns("inbound", |msg| {
                                msg.add("bytes", peer_traffic.in_bytes, "c");
                                msg.add("packets", peer_traffic.in_packets, "c");
                            });
                            msg.with_ns("outbound", |msg| {
                                msg.add("bytes", peer_traffic.out_bytes, "c");
                                msg.add("packets", peer_traffic.out_packets, "c");
                            });
                        });
                        msg.with_ns("payload", |msg| {
                            msg.with_ns("inbound", |msg| {
                                msg.add("bytes", payload_traffic.in_bytes, "c");
                                msg.add("packets", payload_traffic.in_packets, "c");
                            });
                            msg.with_ns("outbound", |msg| {
                                msg.add("bytes", payload_traffic.out_bytes, "c");
                                msg.add("packets", payload_traffic.out_packets, "c");
                            });
                        });
                    });
                    msg.with_ns("invalid_protocol_traffic", |msg| {
                        msg.add("bytes", dropped.in_bytes, "c");
                        msg.add("packets", dropped.in_packets, "c");
                    });
                    msg.with_ns("dropped_payload", |msg| {
                        msg.add("bytes", dropped.out_bytes, "c");
                        msg.add("packets", dropped.out_packets, "c");
                    });
                })
                .build();
            let msg_data = msg.as_bytes();
            let addrs = resolve(endpoint)?;
            if let Some(addr) = addrs.first() {
                match self.socket.send(msg_data, *addr) {
                    Ok(written) if written == msg_data.len() => Ok(()),
                    Ok(_) => Err(Error::Socket("Sent out truncated packet")),
                    Err(e) => Err(Error::SocketIo("IOError when sending", e)),
                }?
            } else {
                error!("Failed to resolve statsd server {}", endpoint);
            }
        }
        Ok(())
    }

    pub fn handle_interface_data(&mut self, data: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        let t0 = std::time::Instant::now();
        // HOT PATH FILTER: drop multicast/broadcast noise at the interface layer.
        // Windows/Linux constantly generate multicast/broadcast on TUN (mDNS, SSDP, LLMNR, IGMP, etc.).
        // Dropping them here avoids expensive route lookup + crypto + send for traffic
        // that will never reach a VPN peer and would flood fallback peers.
        if let Some(is_mcast_bcast) = Self::is_multicast_or_broadcast(data.message()) {
            if is_mcast_bcast {
                self.traffic.count_dropped_payload(data.len());
                return Ok(());
            }
        }
        let (src, dst) = P::parse(data.message())?;
        let icmp = dbg_icmp(data.message());
        let src_s = src.to_string();
        let dst_s = dst.to_string();
        if src_s.starts_with("10.99.0.") || dst_s.starts_with("10.99.0.") || icmp.is_some() {
            debug!("[TUN_RX_PATH] t0 src={}, dst={}, len={}, icmp={:?}", src, dst, data.len(), icmp);
        }
        debug!("Read data from interface: src: {}, dst: {}, {} bytes", src, dst, data.len());
        self.traffic.count_out_payload(dst, src, data.len());
        match self.table.lookup(dst) {
            Some(peer_id) => {
                // HOT PATH
                let endpoint = self.peers.get(&peer_id).map(|p| p.send_addr);
                debug!("Found destination for {} => node {}", dst, bytes_to_hex(&peer_id));
                let t_lookup = t0.elapsed().as_micros();
                // Plaintext copy so we can re-route via relay if the direct peer's
                // endpoint turns out to be unreachable (no route / host down).
                let mut fallback = data.clone();
                match self.send_msg(peer_id, MESSAGE_TYPE_DATA, data) {
                    Ok(()) => {}
                    Err(e)
                        if e.is_unreachable()
                            && self.peers.len() > 1
                            && endpoint.map(|a| !self.is_configured_addr(&a)).unwrap_or(true) =>
                    {
                        // This "direct" peer (learned via gossip) cannot be reached
                        // from here. Drop it and relay the packet through the
                        // remaining peer(s) instead of black-holing into a dead route.
                        warn!(
                            "Direct send to peer node {} @ {:?} unreachable ({}); dropping direct peer and relaying via remaining peers",
                            bytes_to_hex(&peer_id),
                            endpoint.map(addr_nice),
                            e
                        );
                        self.drop_peer_for_relay(peer_id);
                        self.route_without_claim(&mut fallback)?;
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                }
                let total_us = t0.elapsed().as_micros();
                if src_s.starts_with("10.99.0.") || dst_s.starts_with("10.99.0.") || icmp.is_some() {
                    debug!(
                        "[TUN_RX_PATH_DONE] src={}, dst={}, peer={:?}, len_out={}, icmp={:?}, lookup_us={}, send_path_us={}, total_us={}",
                        src, dst, endpoint.map(addr_nice), data.len(), icmp, t_lookup, total_us.saturating_sub(t_lookup), total_us
                    );
                }
                if !self.peers.contains_key(&peer_id) {
                    // COLD PATH
                    // If the peer is not actually connected, remove the entry in the table and try
                    // to reconnect.
                    warn!("Destination for {} not found in peers: node {}", dst, bytes_to_hex(&peer_id));
                    self.table.remove_claims(peer_id);
                    if let Some(a) = endpoint {
                        self.connect_sock(a)?;
                    }
                }
            }
            None => {
                // COLD PATH
                if self.broadcast {
                    debug!("No destination for {} found, broadcasting", dst);
                    self.broadcast_msg(MESSAGE_TYPE_DATA, data)?;
                } else if self.peers.len() == 1 {
                    // Single peer (typical client/star): deliver to it.
                    if let Some((fb_id, fb_addr)) =
                        self.peers.values().next().map(|p| (p.node_id, p.last_seen_addr))
                    {
                        debug!(
                            "No destination for {} found, using sole peer node {} @ {}",
                            dst,
                            bytes_to_hex(&fb_id),
                            addr_nice(fb_addr)
                        );
                        self.send_msg(fb_id, MESSAGE_TYPE_DATA, data)?;
                    } else {
                        self.traffic.count_dropped_payload(data.len());
                    }
                } else if !self.peers.is_empty() {
                    // Phase 2: no claim/route match (bare mode) and multiple peers ->
                    // bounded flood to all peers so the destination's owner receives it.
                    // Wire loop prevention is split horizon (receivers never forward
                    // back to the source peer) + TTL/hop-limit decrement; non-owner
                    // peers that cannot route it simply drop it.
                    debug!("No destination for {} found, flooding to {} peers", dst, self.peers.len());
                    self.broadcast_msg(MESSAGE_TYPE_DATA, data)?;
                } else {
                    debug!("No destination for {} found, dropping", dst);
                    self.traffic.count_dropped_payload(data.len());
                }
            }
        }
        Ok(())
    }

    /// Deterministic tie-break for simultaneous-open handshakes.
    ///
    /// Returns `true` if the freshly negotiated handshake should replace the
    /// existing ready one for `peer_id`. Rule:
    ///  * different roles (one initiator, one responder) => the canonical
    ///    handshake is the one where the pair member with the smaller NodeId is
    ///    the initiator. Both peers evaluate this independently and converge on
    ///    the same handshake.
    ///  * same role (e.g. responder re-handshake after reconnect) => replace
    ///    with the fresh handshake.
    ///  * unknown role (pre-handshake / legacy) => keep the existing handshake,
    ///    never blindly clobber a working crypto.
    fn prefer_new_handshake(self_id: &NodeId, peer_id: &NodeId, existing: Option<bool>, new: Option<bool>) -> bool {
        match (existing, new) {
            (Some(e), Some(n)) => {
                if e == n {
                    true
                } else {
                    let canonical_self_is_initiator = self_id < peer_id;
                    n == canonical_self_is_initiator
                }
            }
            _ => false,
        }
    }

    fn add_new_peer(&mut self, addr: SocketAddr, info: NodeInfo) -> Result<bool, Error> {
        // Peer identity is the NodeId (public-key fingerprint), NOT the SocketAddr.
        // A single NodeId may be reached through many endpoints over time
        // (NAT/SNAT/multi-homed/mobile). `last_seen_addr` is the current reply
        // endpoint; claims and crypto live on the NodeId and therefore survive
        // address changes with no migration step.
        let node_id = info.node_id;
        // Reject handshakes that resolve to an all-zero NodeId. A real NodeId is a
        // public-key fingerprint and is never all-zero; a zero id means the handshake
        // payload was mis-derived (e.g. a simultaneous-open/one-sided race) and
        // installing it would create a bogus peer that keeps blasting undecryptable
        // traffic at the other side. Clean up any stale such entry and drop it.
        if node_id.iter().all(|b| *b == 0) {
            warn!("Ignoring peer handshake with empty/zero NodeId @ {}", addr_nice(addr));
            if let Some(stale) = self.peers.remove(&node_id) {
                info!("Dropped stale zero-NodeId peer @ {} (node {})", addr_nice(stale.last_seen_addr), bytes_to_hex(&node_id));
            }
            self.addr_index.retain(|_, v| *v != node_id);
            self.pending_inits.remove(&addr);
            self.traffic.count_invalid_protocol(0);
            return Ok(false);
        }
        // When SNAT is not allowed, the packet source may be an intermediate NAT
        // address; prefer the node's advertised address as the reply endpoint.
        let endpoint = if self.config.allow_snat {
            addr
        } else {
            info.addrs.first().copied().unwrap_or(addr)
        };

        // True if the peer's active crypto is the handshake that produced the
        // current `data` buffer (caller uses this to decide whether to reply).
        let mut installed_new = false;

        if self.peers.contains_key(&node_id) {
            // Same node, (possibly) new endpoint or refreshed handshake.
            let mut crypto_replaced = false;
            let self_id = self.node_id;
            {
                let peer = self.peers.get_mut(&node_id).unwrap();
                if !peer.addrs.contains(&endpoint) {
                    peer.addrs.push(endpoint);
                }
                if !peer.addrs.contains(&addr) {
                    peer.addrs.push(addr);
                }
                for new_addr in &info.addrs {
                    if !peer.addrs.contains(new_addr) {
                        peer.addrs.push(*new_addr);
                    }
                }
                peer.last_seen_addr = endpoint;
                peer.last_seen = TS::now();
                peer.timeout = TS::now() + self.config.peer_timeout as Time;
                // Replace crypto with the freshly negotiated state, if ready.
                // Deterministic simultaneous-open tie-break: never blindly
                // clobber an existing ready handshake. When two handshakes race
                // (both sides initiated), keep the canonical one so both sides
                // converge on the same key instead of desyncing.
                if let Some(init) = self.pending_inits.remove(&addr) {
                    if init.is_ready() {
                        let replace = if peer.crypto.is_ready() {
                            Self::prefer_new_handshake(&self_id, &node_id, peer.crypto.is_initiator(), init.is_initiator())
                        } else {
                            true
                        };
                        if replace {
                            peer.crypto = init;
                            crypto_replaced = true;
                            installed_new = true;
                            info!(
                                "Replaced crypto for node {} (tie-break: new handshake selected)",
                                bytes_to_hex(&node_id)
                            );
                        } else {
                            info!(
                                "Kept existing ready crypto for node {} (tie-break: dropped competing handshake)",
                                bytes_to_hex(&node_id)
                            );
                        }
                    }
                } else {
                    // Reply was produced by the already-installed peer crypto.
                    installed_new = true;
                }
            }
            self.addr_index.insert(endpoint, node_id);
            self.addr_index.insert(addr, node_id);
            info!(
                "Peer node {} endpoint -> {} (crypto_replaced={})",
                bytes_to_hex(&node_id),
                addr_nice(endpoint),
                crypto_replaced
            );
            self.update_peer_info(addr, Some(info))?;
        } else if let Some(init) = self.pending_inits.remove(&addr) {
            info!("Added peer node {} @ {}", bytes_to_hex(&node_id), addr_nice(endpoint));
            installed_new = true;
            self.config.call_hook(
                "peer_connected",
                vec![
                    ("PEER", format!("{:?}", addr_nice(endpoint))),
                    ("IFNAME", self.device.ifname().to_owned()),
                    ("CLAIMS", info.claims.iter().map(|r| format!("{:?}", r)).collect::<Vec<String>>().join(" ")),
                    ("NODE_ID", bytes_to_hex(&node_id)),
                ],
                true,
            );
            let mut addrs = info.addrs.clone();
            if !addrs.contains(&endpoint) {
                addrs.push(endpoint);
            }
            if !addrs.contains(&addr) {
                addrs.push(addr);
            }
            self.peers.insert(
                node_id,
                PeerData {
                    addrs,
                    crypto: init,
                    node_id,
                    peer_timeout: info.peer_timeout.unwrap_or(DEFAULT_PEER_TIMEOUT),
                    last_seen: TS::now(),
                    last_seen_addr: endpoint,
                    timeout: TS::now() + self.config.peer_timeout as Time,
                    send_addr: endpoint,
                    send_fail: 0,
                    rx_seen: {
                        let mut m: HashMap<SocketAddr, Time, Hash> = HashMap::default();
                        m.insert(endpoint, TS::now());
                        m.insert(addr, TS::now());
                        m
                    },
                    switch_after: 0,
                },
            );
            self.addr_index.insert(endpoint, node_id);
            self.addr_index.insert(addr, node_id);
            self.update_peer_info(addr, Some(info))?;
        } else {
            error!("No init for new peer node {} @ {}", bytes_to_hex(&node_id), addr_nice(addr));
        }
        Ok(installed_new)
    }

    fn remove_peer(&mut self, addr: SocketAddr) {
        // Explicit CLOSE: resolve endpoint -> NodeId, drop the peer, never reconnect.
        if let Some(peer_id) = self.resolve_peer_id(addr) {
            let _ = self.remove_peer_by_id(peer_id, false);
        }
    }

    /// Remove a peer by NodeId, cleaning up the reverse address index and claims.
    /// When `reconnect` is true, immediately try to reconnect to its last endpoint.
    fn remove_peer_by_id(&mut self, peer_id: NodeId, reconnect: bool) -> Result<(), Error> {
        let last_addr = self.peers.get(&peer_id).map(|p| p.last_seen_addr);
        if let Some(peer) = self.peers.remove(&peer_id) {
            info!("Closing connection to node {} @ {}", bytes_to_hex(&peer_id), addr_nice(peer.last_seen_addr));
            self.table.remove_claims(peer_id);
            self.addr_index.retain(|_, v| *v != peer_id);
            self.config.call_hook(
                "peer_disconnected",
                vec![
                    ("PEER", format!("{:?}", addr_nice(peer.last_seen_addr))),
                    ("IFNAME", self.device.ifname().to_owned()),
                    ("NODE_ID", bytes_to_hex(&peer.node_id)),
                ],
                true,
            );
            if reconnect {
                if let Some(a) = last_addr {
                    self.connect_sock(a)?;
                }
            }
        }
        Ok(())
    }

    fn connect_to_peers(&mut self, peers: &[PeerInfo]) -> Result<(), Error> {
        'outer: for peer in peers {
            for addr in &peer.addrs {
                if self.addr_index.contains_key(addr) {
                    continue 'outer;
                }
            }
            if let Some(node_id) = peer.node_id {
                if self.node_id == node_id {
                    // Check addresses and add addresses that we don't know to own addresses
                    for addr in &peer.addrs {
                        if !self.own_addresses.contains(addr) {
                            self.own_addresses.push(*addr)
                        }
                    }
                    continue 'outer;
                }
                for p in self.peers.values() {
                    if p.node_id == node_id {
                        continue 'outer;
                    }
                }
            }
            for addr in &peer.addrs {
                match self.connect_sock(*addr) {
                    Ok(()) => {}
                    Err(e) if e.is_unreachable() => {
                        // Per-address disable (NOT global): blacklist just this
                        // unreachable endpoint and continue trying the peer's
                        // other candidate addresses.
                        warn!(
                            "Gossip direct peer addr {} unreachable ({}); blacklisting this address only",
                            addr_nice(*addr),
                            e
                        );
                        self.mark_addr_bad(*addr);
                    }
                    Err(_) => {}
                }
            }
        }
        Ok(())
    }

    fn resolve_peer_id(&self, addr: SocketAddr) -> Option<NodeId> {
        if let Some(id) = self.addr_index.get(&addr) {
            return Some(*id);
        }
        debug!("[RESOLVE_PEER] addr={:?} not found directly, trying conversions", addr);
        // 尝试 IPv6 映射的 IPv4 <-> 纯 IPv4 地址转换（mapped_addr 可能导致地址族不一致）
        match addr {
            SocketAddr::V6(a) => {
                if let Some(ip4) = a.ip().to_ipv4() {
                    let alt = SocketAddr::V4(std::net::SocketAddrV4::new(ip4, a.port()));
                    if let Some(id) = self.addr_index.get(&alt) {
                        return Some(*id);
                    }
                }
            }
            SocketAddr::V4(a) => {
                let alt = SocketAddr::new(IpAddr::V6(a.ip().to_ipv6_mapped()), a.port());
                if let Some(id) = self.addr_index.get(&alt) {
                    return Some(*id);
                }
            }
        }
        debug!("[RESOLVE_PEER] no match found");
        None
    }

    fn update_peer_info(&mut self, addr: SocketAddr, info: Option<NodeInfo>) -> Result<(), Error> {
        let peer_id = match self.resolve_peer_id(addr) {
            Some(id) => id,
            None => {
                error!("Received peer update from non peer {}", addr_nice(addr));
                return Ok(());
            }
        };
        if !self.peers.contains_key(&peer_id) {
            return Ok(());
        }
        // Reply endpoint: the observed source unless SNAT is disallowed, in which
        // case prefer the peer's advertised address.
        let endpoint = if self.config.allow_snat {
            addr
        } else {
            info.as_ref().and_then(|i| i.addrs.first().copied()).unwrap_or(addr)
        };
        {
            let peer = self.peers.get_mut(&peer_id).unwrap();
            peer.last_seen = TS::now();
            peer.timeout = TS::now() + self.config.peer_timeout as Time;
            peer.last_seen_addr = endpoint;
            if let Some(info) = &info {
                // Update peer addresses, always keep the seen endpoint.
                peer.addrs.clear();
                peer.addrs.push(endpoint);
                for a in &info.addrs {
                    if !peer.addrs.contains(a) {
                        peer.addrs.push(*a);
                    }
                }
            } else if !peer.addrs.contains(&endpoint) {
                peer.addrs.push(endpoint);
            }
            // Keep the sticky send_addr in the candidate set.
            if !peer.addrs.contains(&peer.send_addr) {
                peer.addrs.push(peer.send_addr);
            }
            // Record source/endpoint as recently-reachable candidates (health).
            peer.rx_seen.insert(addr, TS::now());
            peer.rx_seen.insert(endpoint, TS::now());
            if peer.send_addr == addr || peer.send_addr == endpoint {
                peer.send_fail = 0;
            }
            if peer.rx_seen.len() > 16 {
                if let Some(old) = peer.rx_seen.iter().min_by_key(|(_, t)| **t).map(|(a, _)| *a) {
                    peer.rx_seen.remove(&old);
                }
            }
        }
        self.addr_index.insert(endpoint, peer_id);
        self.addr_index.insert(addr, peer_id);
        if let Some(info) = info {
            debug!("Adding claims of node {}: {:?}", bytes_to_hex(&peer_id), info.claims);
            self.table.set_claims(peer_id, info.claims);
            debug!("Received {} peers from node {}: {:?}", info.peers.len(), bytes_to_hex(&peer_id), info.peers);
            // Force-star option: when --no-direct-peers is set, do not dial
            // gossiped peers. Unreachable gossip addresses are handled per-address
            // via bad_addrs elsewhere (not by disabling direct peers globally).
            if !self.config.no_direct_peers {
                self.connect_to_peers(&info.peers)?;
            }
        }
        Ok(())
    }

    /// Decrement the IPv4 TTL / IPv6 hop limit in place, recomputing the IPv4
    /// header checksum (mandatory). Returns false when the packet cannot be
    /// forwarded (malformed header, or TTL/hop-limit would reach 0).
    fn decrement_ttl(pkt: &mut [u8]) -> bool {
        if pkt.is_empty() {
            return false;
        }
        match pkt[0] >> 4 {
            4 => {
                if pkt.len() < 20 {
                    return false;
                }
                let ihl = ((pkt[0] & 0x0f) as usize) * 4;
                if ihl < 20 || pkt.len() < ihl {
                    return false;
                }
                if pkt[8] <= 1 {
                    return false;
                }
                pkt[8] -= 1;
                // Recompute header checksum over the modified header with the
                // checksum field zeroed out.
                pkt[10] = 0;
                pkt[11] = 0;
                let mut sum: u32 = 0;
                let mut i = 0;
                while i + 1 < ihl {
                    sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
                    i += 2;
                }
                if i < ihl {
                    sum += (pkt[i] as u32) << 8;
                }
                while (sum >> 16) != 0 {
                    sum = (sum & 0xffff) + (sum >> 16);
                }
                let cksum = !(sum as u16);
                pkt[10..12].copy_from_slice(&cksum.to_be_bytes());
                true
            }
            6 => {
                if pkt.len() < 40 || pkt[7] <= 1 {
                    return false;
                }
                pkt[7] -= 1;
                true
            }
            _ => false,
        }
    }

    fn handle_payload_from(&mut self, peer_addr: SocketAddr, data: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        let peer_id = self.addr_index.get(&peer_addr).copied();
        let t0 = std::time::Instant::now();
        let (src, dst) = P::parse(data.message())?;
        let len = data.len();
        let icmp = dbg_icmp(data.message());
        debug!("[TUN_WRITE_PATH] start: {} bytes, inner src={}, dst={}, peer={}, icmp={:?}", len, src, dst, addr_nice(peer_addr), icmp);
        self.traffic.count_in_payload(src, dst, len);
        let t_parse = t0.elapsed().as_micros();

        // --- Phase 1: userspace relay (removes the kernel ip_forward dependency) ---
        // If dst is not one of our own tunnel addresses and we have a route to it,
        // forward the packet straight to the next peer instead of pushing it back
        // through the TUN device (which would rely on the kernel routing it out
        // again via ip_forward, fragile across v4/v6 and container resets).
        // Loop prevention uses ONLY split horizon + TTL decrement (no wire change).
        if !self.local_addrs.contains(&dst) {
            if let Some(next_id) = self.table.lookup(dst) {
                if self.peers.contains_key(&next_id) {
                    if Some(next_id) == peer_id {
                        // Split horizon: never send a packet back to where it came from.
                        debug!("Split horizon: dropping payload from {} destined {}", addr_nice(peer_addr), dst);
                        self.traffic.count_dropped_payload(len);
                        return Ok(());
                    }
                    if !Self::decrement_ttl(data.message_mut()) {
                        debug!("Relayed payload for {} reached TTL/hop-limit, dropping", dst);
                        self.traffic.count_dropped_payload(len);
                        return Ok(());
                    }
                    if let Some(id) = peer_id {
                        if self.learning {
                            self.table.cache(src, id);
                        }
                    }
                    debug!(
                        "[RELAY] {} bytes from peer {:?} -> node {} (inner dst={})",
                        len, addr_nice(peer_addr), bytes_to_hex(&next_id), dst
                    );
                    self.send_msg(next_id, MESSAGE_TYPE_DATA, data)?;
                    return Ok(());
                }
                // Route exists but the peer is gone: fall through and let the
                // local device (kernel) handle/drop it.
            }
        }

        // --- Local delivery (dst is us, or no usable route) ---
        match self.device.write(data) {
            Ok(()) => {
                let total_us = t0.elapsed().as_micros();
                debug!(
                    "[TUN_WRITE_PATH_DONE] ok: {} bytes, inner src={}, dst={}, peer={}, icmp={:?}, parse_us={}, write_us={}, total_us={}",
                    len, src, dst, addr_nice(peer_addr), icmp, t_parse, total_us.saturating_sub(t_parse), total_us
                );
                if let Some(id) = peer_id {
                    if self.learning {
                        self.table.cache(src, id);
                    }
                    // Refresh claim timeout so routes stay alive while traffic flows,
                    // even without periodic NodeInfo re-exchange.
                    self.table.refresh_claims_timeout(id);
                }
                Ok(())
            }
            Err(e) => {
                let total_us = t0.elapsed().as_micros();
                error!(
                    "[TUN_WRITE_PATH] failed: {} bytes, inner src={}, dst={}, peer={}, icmp={:?}, total_us={}, err={}",
                    len, src, dst, addr_nice(peer_addr), icmp, total_us, e
                );
                Err(e)
            }
        }
    }

    fn handle_message(
        &mut self, src: SocketAddr, msg_result: MessageResult<NodeInfo>, data: &mut MsgBuffer,
    ) -> Result<(), Error> {
        // HOT PATH
        match msg_result {
            MessageResult::Message(type_) => {
                // HOT PATH
                debug!("Decrypted/app message from {}: type={}", addr_nice(src), type_);
                match type_ {
                    MESSAGE_TYPE_DATA => {
                        // HOT PATH
                        self.handle_payload_from(src, data)?
                    }
                    MESSAGE_TYPE_NODE_INFO => {
                        // COLD PATH
                        let info = match NodeInfo::decode(Cursor::new(data.message())) {
                            Ok(val) => val,
                            Err(err) => {
                                self.traffic.count_invalid_protocol(data.len());
                                return Err(err);
                            }
                        };
                        self.update_peer_info(src, Some(info))?
                    }
                    MESSAGE_TYPE_KEEPALIVE => {
                        // COLD PATH
                        self.update_peer_info(src, None)?
                    }
                    MESSAGE_TYPE_CLOSE => {
                        // COLD PATH
                        self.remove_peer(src)
                    }
                    _ => {
                        // COLD PATH
                        self.traffic.count_invalid_protocol(data.len());
                        return Err(Error::Message("Unknown message type"));
                    }
                }
            }
            MessageResult::Initialized(info) => {
                // COLD PATH
                self.add_new_peer(src, info)?;
            }
            MessageResult::InitializedWithReply(info) => {
                // COLD PATH
                // Only send the completion reply if this handshake is the one
                // now installed on the peer; the simultaneous-open tie-break may
                // have dropped a competing handshake, in which case replying with
                // its buffer would just confuse the other side.
                if self.add_new_peer(src, info)? {
                    self.send_to(src, data)?
                }
            }
            MessageResult::Reply => {
                // COLD PATH
                self.send_to(src, data)?
            }
            MessageResult::None => {
                // COLD PATH
            }
        }
        Ok(())
    }

    pub fn handle_net_message(&mut self, src: SocketAddr, data: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        let src = mapped_addr(src);
        let mut effective_src = src;
        debug!("Received {} bytes from {}", data.len(), src);

        // Defensive: reject packets too short for any valid message (init or encrypted)
        // Init messages need at least 1 byte (type); encrypted messages need EXTRA_LEN + TAG_LEN
        const MIN_ENCRYPTED_LEN: usize = 9 + 16; // EXTRA_LEN + TAG_LEN
        if data.is_empty() || (!is_init_message(data.message()) && data.len() < MIN_ENCRYPTED_LEN) {
            debug!(
                "Dropping short packet from {}: len={}, min_encrypted={}, is_init={}",
                src,
                data.len(),
                MIN_ENCRYPTED_LEN,
                is_init_message(data.message())
            );
            self.traffic.count_invalid_protocol(data.len());
            return Err(Error::Message("Packet too short"));
        }

        let msg_result = if let Some(init) = self.pending_inits.get_mut(&src) {
            // COLD PATH
            debug!("Dispatch: using pending init state for {}", addr_nice(src));
            init.handle_message(data)
        } else if is_init_message(data.message()) {
            // COLD PATH
            debug!("Dispatch: init message from {}", addr_nice(src));
            let mut result = None;
            let mut ignore_duplicate_init = false;
            if let Some(pid) = self.resolve_peer_id(src) {
                if let Some(peer) = self.peers.get_mut(&pid) {
                    effective_src = src;
                    if peer.crypto.has_init() {
                        debug!("Dispatch: existing peer node {} has crypto init, reusing it", bytes_to_hex(&pid));
                        result = Some(peer.crypto.handle_message(data))
                    } else if peer.crypto.is_ready() {
                        // A peer we already consider "ready" is sending a fresh init.
                        // This normally means it restarted / lost its crypto state while
                        // we kept a stale ready entry (e.g. our peer_timeout is much
                        // longer than the remote's). Previously we ignored such inits,
                        // which deadlocked reconnection: the remote re-handshakes forever
                        // while we keep reusing the stale key. Re-key instead: leave
                        // result=None and ignore_duplicate_init=false so the code below
                        // creates a fresh pending init (responder), and add_new_peer()
                        // installs the newly negotiated crypto for this NodeId.
                        debug!(
                            "Dispatch: ready peer node {} sent a new init; re-keying via a fresh handshake",
                            bytes_to_hex(&pid)
                        );
                    } else {
                        debug!("Dispatch: existing peer node {} has no crypto init and not ready", bytes_to_hex(&pid));
                    }
                }
            }
            // During handshake/init window, always try SNAT/NAT address change handling.
            // For init messages (handshake), use heuristic: if any pending init exists,
            // assume it's the same peer (WebSocket proxy / NAT case).
            // For non-init messages, use crypto state matching.
            let is_init = is_init_message(data.message());
            if result.is_none() && !ignore_duplicate_init && (is_init || !self.config.allow_snat) {
                let mut matched_addr: Option<SocketAddr> = None;
                if is_init {
                    // Heuristic: any pending init = WebSocket proxy / NAT (single peer case)
                    if !self.pending_inits.is_empty() {
                        if let Some((addr, _)) = self.pending_inits.iter().next() {
                            debug!(
                                "SNAT/NAT heuristic match (any pending init): {} -> {}",
                                addr_nice(*addr),
                                addr_nice(src)
                            );
                            matched_addr = Some(*addr);
                        }
                    }
                } else {
                    // For non-init messages, use crypto state matching (original logic)
                    for (addr, init) in self.pending_inits.iter_mut() {
                        if data.len() < MIN_ENCRYPTED_LEN {
                            continue;
                        }
                        let mut test = data.clone();
                        if init.handle_message(&mut test).is_ok() {
                            matched_addr = Some(*addr);
                            break;
                        }
                    }
                }
                if let Some(matched_addr) = matched_addr {
                    if matched_addr != src {
                        debug!(
                            "SNAT/NAT handshake rebind for pending init: {} -> {}",
                            addr_nice(matched_addr),
                            addr_nice(src)
                        );
                        if let Some(init) = self.pending_inits.remove(&matched_addr) {
                            self.pending_inits.insert(src, init);
                        }
                    }
                    effective_src = src;
                    // Process the message on the rebound init and send reply if needed
                    if let Some(init) = self.pending_inits.get_mut(&src) {
                        if let Ok(res) = init.handle_message(data) {
                            self.handle_message(src, res, data)?;
                        }
                    }
                    return Ok(());
                }
                // Existing peer still in init/handshake state: reply to observed src
                // during the init window. Collect the match first so the borrow on
                // self.peers ends before we rebind the endpoint / call handle_message.
                let mut init_match: Option<(NodeId, MessageResult<NodeInfo>, MsgBuffer)> = None;
                for (peer_id, peer) in self.peers.iter_mut() {
                    if peer.crypto.has_init() {
                        // Skip short packets that can't possibly decrypt
                        if data.len() < MIN_ENCRYPTED_LEN && !is_init {
                            continue;
                        }
                        let mut test = data.clone();
                        if let Ok(msg_result) = peer.crypto.handle_message(&mut test) {
                            init_match = Some((*peer_id, msg_result, test));
                            break;
                        }
                    }
                }
                if let Some((pid, msg_result, mut test)) = init_match {
                    if let Some(peer) = self.peers.get_mut(&pid) {
                        if peer.last_seen_addr != src {
                            debug!(
                                "SNAT/NAT handshake endpoint for peer node {} observed at {}",
                                bytes_to_hex(&pid),
                                addr_nice(src)
                            );
                            peer.last_seen_addr = src;
                            if !peer.addrs.contains(&src) {
                                peer.addrs.push(src);
                            }
                            peer.last_seen = TS::now();
                            peer.timeout = TS::now() + self.config.peer_timeout as Time;
                        }
                    }
                    self.addr_index.insert(src, pid);
                    effective_src = src;
                    self.handle_message(src, msg_result, &mut test)?;
                    return Ok(());
                }
            }
            if ignore_duplicate_init {
                return Ok(());
            }
            if let Some(result) = result {
                result
            } else {
                debug!("Dispatch: creating new pending init for {}", addr_nice(src));
                // Skip short packets that can't possibly be valid init messages
                if data.is_empty() {
                    debug!("Dropping empty packet from {}", src);
                    self.traffic.count_invalid_protocol(0);
                    return Err(Error::Message("Empty packet"));
                }
                let mut init = self.crypto.peer_instance(self.create_node_info());
                let msg_result = init.handle_message(data);
                match msg_result {
                    Ok(res) => {
                        self.config.call_hook(
                            "peer_connecting",
                            vec![
                                ("PEER", format!("{:?}", addr_nice(src))),
                                ("IFNAME", self.device.ifname().to_owned()),
                            ],
                            true,
                        );
                        self.pending_inits.insert(src, init);
                        debug!("Dispatch: inserted pending init for {}", addr_nice(src));
                        Ok(res)
                    }
                    Err(err) => {
                        debug!("Dispatch: new pending init failed for {}: {}", addr_nice(src), err);
                        self.traffic.count_invalid_protocol(data.len());
                        return Err(err);
                    }
                }
            }
        } else if let Some(pid) = self.resolve_peer_id(src) {
            // HOT PATH: packet from a known endpoint of a known node.
            let pt = self.config.peer_timeout as Time;
            let peer = self.peers.get_mut(&pid).unwrap();
            let ready = peer.crypto.is_ready();
            if !ready {
                debug!("Peer node {} exists but crypto not ready yet; processing message as existing peer", bytes_to_hex(&pid));
            } else {
                debug!("Dispatch: existing ready peer node {} handling non-init message", bytes_to_hex(&pid));
            }
            let result = peer.crypto.handle_message(data);
            // Refresh liveness and record the source as a healthy candidate.
            if result.is_ok() {
                peer.last_seen = TS::now();
                peer.timeout = TS::now() + pt;
                peer.rx_seen.insert(src, TS::now());
                if peer.send_addr == src {
                    peer.send_fail = 0;
                }
            }
            result
        } else {
            // COLD PATH - SNAT/NAT/多地址：未知源包尝试用已知 peer/pending 的 crypto 解密，
            // 匹配成功则认为是同一 peer 的地址变化（多网卡 LAN/netbird/公网），重关联后处理。
            // 这样即使收到的源地址与 peer key 不一致（NAT/多宿主），也不会被当作 unknown peer 丢弃。
            // 对每个 peer/pending_init 先用 data.clone() 试解密，成功后用解密后的数据处理，
            // 避免 handle_message 两次推进 crypto 状态导致握手/解密失败。
            let mut matched_peer: Option<(NodeId, MessageResult<NodeInfo>, MsgBuffer)> = None;
            for (peer_id, peer) in self.peers.iter_mut() {
                let mut test = data.clone();
                if let Ok(msg_result) = peer.crypto.handle_message(&mut test) {
                    matched_peer = Some((*peer_id, msg_result, test));
                    break;
                }
            }
            if let Some((pid, msg_result, mut decrypted_data)) = matched_peer {
                // Roaming: this known node (identified by NodeId via decrypt) is now
                // speaking from a different endpoint. Rebind its reply endpoint.
                info!(
                    "SNAT/NAT address change: node {} now at {}",
                    bytes_to_hex(&pid),
                    addr_nice(src)
                );
                if let Some(peer) = self.peers.get_mut(&pid) {
                    peer.last_seen_addr = src;
                    if !peer.addrs.contains(&src) {
                        peer.addrs.push(src);
                    }
                    peer.last_seen = TS::now();
                    peer.timeout = TS::now() + self.config.peer_timeout as Time;
                }
                self.addr_index.insert(src, pid);
                self.handle_message(src, msg_result, &mut decrypted_data)?;
                Ok(MessageResult::None)
            } else {
                // Try pending handshakes (handshake continuation from a new address).
                let mut matched_pending: Option<(SocketAddr, MessageResult<NodeInfo>, MsgBuffer)> = None;
                for (addr, init) in self.pending_inits.iter_mut() {
                    let mut test = data.clone();
                    if let Ok(msg_result) = init.handle_message(&mut test) {
                        matched_pending = Some((*addr, msg_result, test));
                        break;
                    }
                }
                if let Some((old_addr, msg_result, mut decrypted_data)) = matched_pending {
                    if old_addr != src {
                        debug!(
                            "SNAT/NAT address change for pending init: {} -> {}",
                            addr_nice(old_addr),
                            addr_nice(src)
                        );
                        if let Some(init) = self.pending_inits.remove(&old_addr) {
                            self.pending_inits.insert(src, init);
                        }
                    }
                    self.handle_message(src, msg_result, &mut decrypted_data)?;
                    Ok(MessageResult::None)
                } else {
                    // COLD PATH
                    // Self-heal: we forgot this peer (e.g. peer_timeout expired during an
                    // underlay blip) but it is still sending traffic to us. Instead of
                    // blackholing the link forever, re-initiate the handshake. connect_sock
                    // is idempotent (skips when already connected/own/pending).
                    info!(
                        "Received non-init message from unknown peer {}; re-initiating handshake",
                        addr_nice(src)
                    );
                    self.traffic.count_invalid_protocol(data.len());
                    self.connect_sock(src)?;
                    return Ok(());
                }
            }
        };
        // Any packet arriving from an address that belongs to a configured
        // reconnect target proves reachability: reset its back-off immediately
        // so a later drop retries from interval 1s instead of a long interval.
        self.reset_reconnect_backoff(src);
        // HOT PATH
        match msg_result {
            Ok(val) => {
                // HOT PATH
                self.handle_message(effective_src, val, data)
            }
            Err(err) => {
                // COLD PATH
                self.traffic.count_invalid_protocol(data.len());
                Err(err)
            }
        }
    }

    fn initialize(&mut self) {
        if let Err(err) = self.reset_own_addresses() {
            error!("Failed to obtain local addresses: {}", err)
        }
    }

    fn handle_socket_event(&mut self, buffer: &mut MsgBuffer, first: Option<crate::channel_io::NetPacket>) -> Result<bool, Error> {
        // HOT PATH
        // On Windows, yield after processing a batch of socket events to avoid
        // monopolizing the thread when the socket is very busy. Without this,
        // the event loop can spin indefinitely on socket events and starve the
        // device thread (Wintun) or the housekeep timer.
        #[cfg(windows)]
        const MAX_SOCKET_DRAIN: u64 = 512;
        #[cfg(not(windows))]
        const MAX_SOCKET_DRAIN: u64 = 4096;

        let socket_pending = self.socket.pending();
        if socket_pending > 100 {
            warn!("[CLOUD] socket channel backlog={} packets (bufferbloat risk)", socket_pending);
        }
        let t_ev = std::time::Instant::now();
        let mut drained_packets: u64 = 0;
        let mut drained_bytes: usize = 0;
        let mut first_pkt = first;

        loop {
            let src = if let Some(pkt) = first_pkt.take() {
                buffer.clear();
                buffer.clone_from(&pkt.data);
                pkt.addr
            } else {
                match self.socket.receive(buffer) {
                    Ok(src) => src,
                    Err(e) => {
                    #[cfg(windows)]
                    {
                        use std::io::ErrorKind;
                        if e.kind() == ErrorKind::WouldBlock {
                            // WSAEWOULDBLOCK / channel empty - no more data, drain done
                            return Ok(drained_packets > 0);
                        }
                        // On Windows UDP sockets, recvfrom may report prior ICMP errors (e.g. port
                        // unreachable) as WSAECONNRESET(10054)/WSAECONNREFUSED(10061). Treat as
                        // transient/non-fatal so we keep processing future packets.
                        if let Some(code) = e.raw_os_error() {
                            if code == 10054 || code == 10061 {
                                warn!("Transient UDP recv error (os error {}), likely ICMP unreachable/refused for a previous send; continuing: {}", code, e);
                                return Ok(drained_packets > 0);
                            }
                            if code == 10035 {
                                // WSAEWOULDBLOCK - no more data, drain done
                                return Ok(drained_packets > 0);
                            }
                        }
                    }
                    #[cfg(unix)]
                    {
                        use std::io::ErrorKind;
                        if e.kind() == ErrorKind::WouldBlock {
                            // EAGAIN/EWOULDBLOCK - no more data, drain done
                            return Ok(drained_packets > 0);
                        }
                    }
                    // Check if this is a WebSocket connection closed error
                    // (e.g., "Trying to work with closed connection" or "Connection reset")
                    let err_str = e.to_string();
                    if err_str.contains("Trying to work with closed connection")
                        || err_str.contains("Connection reset")
                        || err_str.contains("Connection closed")
                        || err_str.contains("WebSocket connection closed")
                        || err_str.contains("Connection aborted")
                    {
                        info!("WebSocket connection closed detected: {}, signaling reconnect", err_str);
                        return Err(Error::SocketClosed("WebSocket connection closed"));
                    }
                    error!("Failed to read from network socket: {}", e);
                    // On Windows, yield to the OS scheduler after an unexpected socket
                    // error to avoid a tight retry loop that starves the device thread.
                    #[cfg(windows)]
                    std::thread::yield_now();
                    #[cfg(not(windows))]
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    return Ok(drained_packets > 0);
                }
            }
            };

            drained_packets += 1;
            drained_bytes += buffer.len();

            self.traffic.count_in_traffic(src, buffer.len());
            let raw = src;
            let src = crate::net::mapped_addr(src);
            let len = buffer.len();
            debug!("UDP RX raw: {} bytes from {} (mapped={})", len, raw, src);
            if len == 0 {
                debug!("UDP RX empty datagram from {}, ignoring", src);
                continue;
            }
            let t_before_handle = t_ev.elapsed().as_micros();
            match self.handle_net_message(src, buffer) {
                Err(e @ Error::CryptoInitFatal(_)) => {
                    // COLD PATH
                    debug!("Fatal crypto init error from {}: {}", src, e);
                    info!("Closing pending connection to {} due to error in crypto init", addr_nice(src));
                    self.pending_inits.remove(&src);
                    self.config.call_hook(
                        "peer_disconnected",
                        vec![("PEER", format!("{:?}", addr_nice(src))), ("IFNAME", self.device.ifname().to_owned())],
                        true,
                    );
                    debug!("[SOCKET_EVT] src={} len={} recv_us={} total_us={} result=crypto_init_fatal", src, len, t_before_handle, t_ev.elapsed().as_micros());
                }
                Err(e @ Error::CryptoInit(_)) => {
                    // COLD PATH
                    debug!("Recoverable init error from {}: {}", src, e);
                    info!("Ignoring invalid init message from peer {}", addr_nice(src));
                    debug!("[SOCKET_EVT] src={} len={} recv_us={} total_us={} result=crypto_init", src, len, t_before_handle, t_ev.elapsed().as_micros());
                }
                Err(e @ Error::Crypto(_)) => {
                    // COLD PATH
                    error!("Crypto error from {}: {}", src, e);
                    debug!("[SOCKET_EVT] src={} len={} recv_us={} total_us={} result=crypto_err", src, len, t_before_handle, t_ev.elapsed().as_micros());
                }
                Err(e) => {
                    // COLD PATH
                    error!("handle_net_message error from {}: {}", src, e);
                    debug!("[SOCKET_EVT] src={} len={} recv_us={} total_us={} result=err", src, len, t_before_handle, t_ev.elapsed().as_micros());
                }
                Ok(_) => {
                    let total_us = t_ev.elapsed().as_micros();
                    let handle_us = total_us.saturating_sub(t_before_handle);
                    debug!("[SOCKET_EVT] src={} len={} recv_us={} handle_us={} total_us={} result=ok", src, len, t_before_handle, handle_us, total_us);
                    if handle_us >= 10_000 || total_us >= 15_000 {
                        warn!(
                            "[SOCKET_EVT_SLOW] src={} len={} recv_us={} handle_us={} total_us={}",
                            src, len, t_before_handle, handle_us, total_us
                        );
                    }
                }
            }

            // Safety bound: avoid monopolizing the single-threaded loop when socket is very busy.
            // Reduced from 100ms to 5ms for lower latency (VPN real-time traffic sensitivity)
            #[cfg(windows)]
            const MAX_DRAIN_PACKETS: u64 = 512;
            #[cfg(not(windows))]
            const MAX_DRAIN_PACKETS: u64 = 2048;
            if drained_packets >= MAX_DRAIN_PACKETS || t_ev.elapsed().as_micros() >= 5_000 {
                // Rate-limit this warning: only log once per 100 occurrences
                static BREAK_EARLY_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
                let count = BREAK_EARLY_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if count % 100 == 0 {
                    warn!(
                        "[SOCKET_EVT_DRAIN] break early (count={}) drained_packets={} drained_bytes={} total_us={}",
                        count, drained_packets, drained_bytes, t_ev.elapsed().as_micros()
                    );
                }
                return Ok(true);
            }
        }
        Ok(drained_packets > 0)
    }

    fn handle_device_event(&mut self, buffer: &mut MsgBuffer, first: Option<Vec<u8>>) -> bool {
        // HOT PATH
        let device_pending = self.device.pending();
        if device_pending > 100 {
            warn!("[CLOUD] device channel backlog={} packets (bufferbloat risk)", device_pending);
        }
        let t_evt = std::time::Instant::now();
        let mut drained_packets: u64 = 0;
        let mut drained_bytes: usize = 0;
        let mut first_data = first;

        loop {
            let t_read = std::time::Instant::now();
            let (read_result, read_us) = if let Some(data) = first_data.take() {
                buffer.clear();
                buffer.clone_from(&data);
                (Ok(()), 0u128)
            } else {
                let rr = self.device.read(buffer);
                let rus = t_read.elapsed().as_micros();
                if rus > 10_000 {
                    warn!("[DEVICE_READ_SLOW] read_us={}", rus);
                }
                (rr, rus)
            };

            match read_result {
                Ok(_) => {
                    let len = buffer.len();
                    debug!("[TUN_READ] len={} read_us={}", len, read_us);
                    let t_handle = std::time::Instant::now();
                    if let Err(e) = self.handle_interface_data(buffer) {
                        error!("{}", e);
                    }
                    let handle_us = t_handle.elapsed().as_micros();
                    drained_packets += 1;
                    drained_bytes += len;

                    let total_us = t_evt.elapsed().as_micros();
                    // Reduced logging: sample every 1000 packets, or log slow packets (>10ms)
                    if drained_packets == 1 || drained_packets % 1000 == 0 || handle_us >= 10_000 {
                        debug!(
                            "[DEVICE_EVT_DRAIN] seq={} len={} read_us={} handle_us={} total_us={} drained_packets={} drained_bytes={}",
                            drained_packets, len, read_us, handle_us, total_us, drained_packets, drained_bytes
                        );
                    }

                    // Safety bound: avoid monopolizing the main loop when TUN is very busy.
                    const MAX_DRAIN_PACKETS: u64 = 2048;
                    // Reduced from 100ms to 5ms for lower latency (VPN real-time traffic sensitivity)
                    if drained_packets >= MAX_DRAIN_PACKETS || total_us >= 5_000 {
                        // Rate-limit this warning: only log once per 100 occurrences
                        static BREAK_EARLY_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
                        let count = BREAK_EARLY_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if count % 100 == 0 {
                            warn!(
                                "[DEVICE_EVT_DRAIN] break early (count={}) drained_packets={} drained_bytes={} total_us={}",
                                count, drained_packets, drained_bytes, total_us
                            );
                        }
                        return true;
                    }
                }
                Err(Error::Device(ref msg)) if msg == "empty" => {
                    return drained_packets > 0;
                }
                Err(e) => {
                    let total_us = t_evt.elapsed().as_micros();
                    error!("Failed to read from device: {}", e);
                    debug!(
                        "[DEVICE_EVT] result=err drained_packets={} drained_bytes={} total_us={}",
                        drained_packets, drained_bytes, total_us
                    );
                    return drained_packets > 0;
                }
            }
        }
    }

    /// The main method of the node
    ///
    /// This method runs the dual-thread main loop:
    /// - The net thread owns the real UDP socket and drains packets into a channel.
    /// - The device thread owns the real TUN/Wintun device and drains packets into a channel.
    /// - This main thread drains both channels, runs crypto/routing/housekeep,
    ///   and sends outbound packets back through the channels.
    ///
    /// This replaces the old single-threaded mutex event loop where socket and device
    /// contended for the same select()/epoll_wait(), which caused socket starvation
    /// on Windows when the TUN device was continuously readable (IPv6 multicast etc.).
    pub fn run(&mut self) {
        info!("Cloud::run: starting, ifname={}", self.device.ifname());
        let ctrlc = CtrlC::new();
        let poll_timeout_ms = self.config.poll_timeout_ms;
        info!("Cloud::run: poll wait timeout = {} ms", poll_timeout_ms);
        info!("Cloud::run: entering channel-based dual-thread main loop");
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        let mut event_count: u64 = 0;
        let mut last_event_ts = TS::now();
        self.config.call_hook("vpn_started", vec![("IFNAME", self.device.ifname())], true);
        loop {
            // HOT PATH
            event_count += 1;
            let now_ts = TS::now();
            let since_last_ms = (now_ts - last_event_ts) as i64;
            // When poll_timeout_ms==0 the loop can spin very fast; avoid periodic count-based
            // debug logs that flood logs. Keep early samples and gap-based diagnostics.
            let periodic = if poll_timeout_ms == 0 { event_count % 200000 == 0 } else { event_count % 200 == 0 };
            if event_count <= 50 || periodic || since_last_ms >= 50 {
                debug!("Cloud::run: event #{} since_last_ms={}", event_count, since_last_ms);
            }
            if since_last_ms >= 500 {
                warn!("Cloud::run: long gap between loop iterations event #{} since_last_ms={}", event_count, since_last_ms);
            }
            last_event_ts = now_ts;

            // Drain all available network/device packets.
            let socket_drained = match self.handle_socket_event(&mut buffer, None) {
                Ok(d) => d,
                Err(e) => {
                    error!("Cloud::run: socket event error: {}", e);
                    false
                }
            };
            let device_drained = self.handle_device_event(&mut buffer, None);

            if !socket_drained && !device_drained {
                // Zero-consumption idle wait: block on channel events and process the received item
                // immediately (do not drop it), then drain remaining packets.
                let now = TS::now();
                if self.next_housekeep <= now {
                    if ctrlc.was_pressed() { break; }
                    if let Err(e) = self.housekeep() { error!("{}", e) }
                    self.next_housekeep = TS::now() + 1;
                    continue;
                }
                let until_housekeep_ms = ((self.next_housekeep - now) as u64).saturating_mul(1000).max(1);
                let idle_ms = if poll_timeout_ms == 0 { 1 } else { poll_timeout_ms as u64 };
                let wait_ms = idle_ms.min(until_housekeep_ms).min(200);
                if let (Some(nrx), Some(drx)) = (self.socket.channel_net_rx(), self.device.channel_dev_rx()) {
                    crossbeam_channel::select! {
                        recv(nrx) -> msg => {
                            if let Ok(pkt) = msg {
                                if let Err(e) = self.handle_socket_event(&mut buffer, Some(pkt)) {
                                    error!("Cloud::run: socket event error: {}", e);
                                }
                                self.handle_device_event(&mut buffer, None);
                            }
                        },
                        recv(drx) -> msg => {
                            if let Ok(data) = msg {
                                self.handle_device_event(&mut buffer, Some(data));
                                if let Err(e) = self.handle_socket_event(&mut buffer, None) {
                                    error!("Cloud::run: socket event error: {}", e);
                                }
                            }
                        },
                        default(std::time::Duration::from_millis(wait_ms)) => {},
                    }
                } else {
                    thread::sleep(StdDuration::from_millis(wait_ms));
                }
                // loop again to honor housekeep/ctrlc and continue draining
                if self.next_housekeep < TS::now() {
                    if ctrlc.was_pressed() { break; }
                    if let Err(e) = self.housekeep() { error!("{}", e) }
                    self.next_housekeep = TS::now() + 1;
                }
                continue;
            }

            if self.next_housekeep < TS::now() {
                // COLD PATH
                if ctrlc.was_pressed() {
                    break;
                }
                if let Err(e) = self.housekeep() {
                    error!("{}", e)
                }
                self.next_housekeep = TS::now() + 1
            }
        }
        info!("Shutting down...");
        self.config.call_hook("vpn_shutdown", vec![("IFNAME", self.device.ifname())], true);
        buffer.clear();
        self.broadcast_msg(MESSAGE_TYPE_CLOSE, &mut buffer).ok();
        if let Some(ref path) = self.config.beacon_store {
            let path = Path::new(path);
            if path.exists() {
                info!("Removing beacon file");
                if let Err(e) = fs::remove_file(path) {
                    error!("Failed to remove beacon file: {}", e)
                }
            }
        }
    }

    /// Single-threaded event loop using WaitImpl (epoll/WSAEvent+WFMO).
    /// Used as the native fast path (direct nonblocking UDP socket + TUN/Wintun)
    /// and as the fallback path for websocket-proxy connections.
    ///
    /// Returns `true` if the event loop exited normally (Ctrl-C or clean shutdown),
    /// `false` if the underlying socket died unexpectedly (e.g. WebSocket proxy
    /// disconnected). Callers can use this to trigger a reconnect.
    pub fn run_legacy(&mut self) -> bool {
        info!("Cloud::run_legacy: starting single-thread event loop, ifname={}", self.device.ifname());
        let ctrlc = CtrlC::new();
        let poll_timeout_ms = self.config.poll_timeout_ms;
        info!("Cloud::run_legacy: wait timeout = {} ms", poll_timeout_ms);

        #[cfg(unix)]
        let waiter = {
            let socket_fd = self.socket.as_raw_fd();
            let device_fd = self.device.as_raw_fd();
            info!("Cloud::run_legacy: socket_fd={}, device_fd={}", socket_fd, device_fd);
            try_fail!(
                WaitImpl::new(socket_fd, device_fd, poll_timeout_ms),
                "Failed to setup poll: {}"
            )
        };
        #[cfg(windows)]
        let waiter = {
            let sock = self.socket.as_raw_socket();
            let dev = self.device.as_raw_socket();
            info!("Cloud::run_legacy: socket={:?}, device={:?}", sock, dev);
            try_fail!(
                WaitImpl::new(sock, dev, poll_timeout_ms),
                "Failed to setup poll: {}"
            )
        };

        info!("Cloud::run_legacy: poll/waiter initialized, entering main loop");
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        let mut poll_error = false;
        let mut event_count: u64 = 0;
        let mut last_event_ts = TS::now();
        self.config.call_hook("vpn_started", vec![("IFNAME", self.device.ifname())], true);
        let mut waiter_iter = waiter;
        
        // Fair scheduling: limit consecutive events of same type to prevent starvation
        const MAX_CONSECUTIVE_SOCKET_EVENTS: u32 = 10;
        const MAX_CONSECUTIVE_DEVICE_EVENTS: u32 = 10;
        let mut consecutive_socket = 0u32;
        let mut consecutive_device = 0u32;

        loop {
            // HOT PATH: get next event (may block)
            let evt = match waiter_iter.next() {
                Some(e) => e,
                None => {
                    // Waiter exhausted: underlying socket/fd closed (e.g. WebSocket proxy
                    // disconnected). Signal caller to reconnect rather than exiting.
                    info!("Cloud::run_legacy: waiter exhausted (socket closed), returning for reconnect");
                    return false;
                }
            };
            event_count += 1;
            let now_ts = TS::now();
            let since_last_ms = (now_ts - last_event_ts) as i64;
            if event_count <= 50 || event_count % 200 == 0 || since_last_ms >= 50 {
                debug!("Cloud::run_legacy: event #{} {:?} since_last_ms={}", event_count, evt, since_last_ms);
            }
            if since_last_ms >= 500 {
                warn!("Cloud::run_legacy: long gap between loop iterations event #{} {:?} since_last_ms={}", event_count, evt, since_last_ms);
            }
            last_event_ts = now_ts;

            // Fair scheduling: process events with limits to prevent starvation
            let mut current_evt = Some(evt);
            while let Some(e) = current_evt.take() {
                // Under continuous traffic the inner loop would never yield, starving
                // housekeep() (keepalive / node_info / reconnect / liveness). Break out
                // as soon as a housekeep tick is due so the outer loop can service it.
                if self.next_housekeep < TS::now() {
                    break;
                }
                match e {
                    WaitResult::Error(err) => {
                        // COLD PATH
                        // On WebSocket proxy mode, a poll error means the underlying
                        // TCP/WebSocket connection died. Return to caller for reconnect
                        // instead of exiting the process.
                        error!("Cloud::run_legacy: poll/socket error: {} (returning for reconnect)", err);
                        return false;
                    }
                    WaitResult::Timeout => {
                        // No fd ready: yield back to the outer loop so periodic
                        // housekeep() actually runs instead of spinning here.
                        break;
                    }
                    WaitResult::Socket => {
                        // Fair scheduling: if we've processed too many socket events consecutively,
                        // force a device check by breaking the inner loop (will poll again)
                        if consecutive_socket >= MAX_CONSECUTIVE_SOCKET_EVENTS {
                            consecutive_socket = 0;
                            // Don't process this socket event now, let next poll pick it up
                            current_evt = Some(WaitResult::Socket);
                            break;
                        }
                        match self.handle_socket_event(&mut buffer, None) {
                            Ok(_) => {
                                consecutive_socket += 1;
                                consecutive_device = 0;
                                // After handling socket, check if more socket data is immediately available
                                // by peeking the socket channel without blocking.
                                if self.socket.pending() > 0 {
                                    continue; // process next socket event in this inner loop
                                }
                            }
                            Err(Error::SocketClosed(_)) => {
                                // WebSocket connection closed - signal caller to reconnect
                                info!("Cloud::run_legacy: WebSocket connection closed, returning for reconnect");
                                return false;
                            }
                            Err(e) => {
                                // Other errors - log and continue
                                error!("Cloud::run_legacy: socket event error: {}", e);
                            }
                        }
                    }
                    WaitResult::Device => {
                        // Fair scheduling: if we've processed too many device events consecutively,
                        // force a socket check by breaking the inner loop
                        if consecutive_device >= MAX_CONSECUTIVE_DEVICE_EVENTS {
                            consecutive_device = 0;
                            current_evt = Some(WaitResult::Device);
                            break;
                        }
                        self.handle_device_event(&mut buffer, None);
                        consecutive_device += 1;
                        consecutive_socket = 0;
                        // After device, check if socket has pending events before next poll
                        if self.socket.pending() > 0 {
                            continue; // process socket event next
                        }
                    }
                }
                // Get next event from waiter (may block) for inner loop
                current_evt = waiter_iter.next();
            }

            // Periodic housekeep: reconnect peers, crypto housekeep, beacon, stats, etc.
            // Runs every second (matching v0.0.5 behaviour) so that reconnect logic
            // is active even in the single-threaded run_legacy path.
            if self.next_housekeep < TS::now() {
                // COLD PATH
                poll_error = false;
                if ctrlc.was_pressed() {
                    info!("Cloud::run_legacy: Ctrl-C pressed, shutting down");
                    return true;
                }
                if let Err(e) = self.housekeep() {
                    error!("{}", e)
                }
                self.next_housekeep = TS::now() + 1
            }
        }
    }

    /// Re-establish the underlying transport connection after a disconnection.
    /// Calls the Socket trait's reconnect() method (no-op for plain UDP sockets,
    /// WebSocket reconnect for ProxyConnection), then clears stale peer state
    /// and flushes receive buffers so the next housekeep()/connect() cycle
    /// re-establishes the connection with a clean slate.
    pub fn socket_reconnect(&mut self) -> Result<(), Error> {
        info!("GenericCloud::socket_reconnect: reconnecting underlying socket");
        self.socket.reconnect().map_err(|e| Error::SocketIo("socket reconnect", e))?;
        // Flush receive buffer to discard stale packets accumulated during disconnection
        if let Err(e) = self.socket.flush_receive_buffer() {
            warn!("GenericCloud::socket_reconnect: failed to flush receive buffer: {}", e);
        }
        // Clear all peers and pending inits so the next housekeep()/connect() cycle
        // re-establishes the connection with the freshly connected proxy.
        self.peers.clear();
        self.addr_index.clear();
        self.pending_inits.clear();
        self.table.clear();
        Ok(())
    }
}

#[cfg(test)]
use super::device::MockDevice;
#[cfg(test)]
use super::net::MockSocket;
#[cfg(test)]
use super::util::MockTimeSource;

#[cfg(test)]
impl<P: Protocol> GenericCloud<MockDevice, P, MockSocket, MockTimeSource> {
    pub fn socket(&mut self) -> &mut MockSocket {
        &mut self.socket
    }

    pub fn device(&mut self) -> &mut MockDevice {
        &mut self.device
    }

    pub fn trigger_socket_event(&mut self) {
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        self.handle_socket_event(&mut buffer, None);
    }

    pub fn trigger_device_event(&mut self) {
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        self.handle_device_event(&mut buffer, None);
    }

    pub fn trigger_housekeep(&mut self) {
        assert!(self.housekeep().is_ok())
    }

    pub fn is_connected(&self, addr: &SocketAddr) -> bool {
        self.addr_index.contains_key(addr)
    }

    pub fn own_addresses(&self) -> &[SocketAddr] {
        &self.own_addresses
    }

    pub fn get_num(&self) -> usize {
        self.socket.address().unwrap().port() as usize
    }
}
