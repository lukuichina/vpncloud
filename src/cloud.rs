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

const MAX_RECONNECT_INTERVAL: u16 = 3600;

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
    timeout: Time,
    peer_timeout: u16,
    node_id: NodeId,
    crypto: PeerCrypto<NodeInfo>,
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
    peers: HashMap<SocketAddr, PeerData, Hash>,
    reconnect_peers: SmallVec<[ReconnectEntry; 3]>,
    own_addresses: AddrList,
    pending_inits: HashMap<SocketAddr, PeerCrypto<NodeInfo>, Hash>,
    table: ClaimTable<TS>,
    socket: S,
    device: D,
    claims: RangeList,
    crypto: Crypto,
    next_peers: Time,
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
        let now = TS::now();
        let update_freq = config.get_keepalive() as u16;
        let crypto = Crypto::new(&config.crypto).unwrap();
        let node_id = crypto.node_id;
        let beacon_key = config.beacon_password.as_ref().map(|s| s.as_bytes()).unwrap_or(&[]);
        let mut res = GenericCloud {
            node_id,
            peers: HashMap::default(),
            claims,
            learning,
            broadcast,
            pending_inits: HashMap::default(),
            reconnect_peers: SmallVec::new(),
            own_addresses: SmallVec::new(),
            peer_timeout_publish: config.peer_timeout as u16,
            table: ClaimTable::new(config.switch_timeout as Duration, config.peer_timeout as Duration),
            socket,
            device,
            next_peers: now,
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
        for (addr, peer) in &mut self.peers {
            msg_data.set_start(msg.get_start());
            msg_data.set_length(msg.len());
            msg_data.message_mut().clone_from_slice(msg.message());
            peer.crypto.send_message(type_, &mut msg_data)?;
            self.traffic.count_out_traffic(*addr, msg_data.len());
            match self.socket.send(msg_data.message(), *addr) {
                Ok(written) if written == msg_data.len() => Ok(()),
                Ok(_) => Err(Error::Socket("Sent out truncated packet")),
                Err(e) => Err(Error::SocketIo("IOError when sending", e)),
            }?
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
    fn send_msg(&mut self, addr: SocketAddr, type_: u8, msg: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        debug!("Sending msg with {} bytes to {}", msg.len(), addr);
        let peer = match self.peers.get_mut(&addr) {
            Some(peer) => peer,
            None => return Err(Error::Message("Sending to node that is not a peer")),
        };
        peer.crypto.send_message(type_, msg)?;
        self.send_to(addr, msg)
    }

    pub fn reset_own_addresses(&mut self) -> io::Result<()> {
        self.own_addresses.clear();
        let socket_addr = self.socket.address().map(mapped_addr)?;
        // 1) Specified advertise addresses
        for addr in &self.config.advertise_addresses {
            self.own_addresses.push(parse_listen(addr, socket_addr.port()));
        }
        // 2) Address of UDP socket
        self.own_addresses.push(socket_addr);
        // 3) Addresses from port forwarding
        if let Some(ref pfw) = self.port_forwarding {
            self.own_addresses.push(pfw.get_internal_ip().into());
            self.own_addresses.push(pfw.get_external_ip().into());
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
        for a in &addrs {
            if self.own_addresses.contains(a)
                || self.peers.contains_key(a)
                || self.pending_inits.contains_key(a)
            {
                info!("Connect target {:?}: addr {} already known/own/pending, skipping", addr, addr_nice(*a));
                return Ok(());
            }
        }
        if !addrs.is_empty() {
            self.config.call_hook(
                "peer_connecting",
                vec![("PEER", format!("{:?}", addr_nice(addrs[0]))), ("IFNAME", self.device.ifname().to_owned())],
                true,
            );
        }
        // Send a message to each resolved address
        for a in addrs {
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
        if self.peers.contains_key(&addr)
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
        self.pending_inits.insert(addr, peer_crypto);
        info!("connect_sock: sending init ({} bytes) to {} local={:?}", msg.len(), addr_nice(addr), local);
        self.send_to(addr, &mut msg)
    }

    fn crypto_housekeep(&mut self) -> Result<(), Error> {
        let mut msg = MsgBuffer::new(SPACE_BEFORE);
        let mut del: SmallVec<[SocketAddr; 4]> = smallvec![];
        for addr in self.pending_inits.keys().copied().collect::<SmallVec<[SocketAddr; 4]>>() {
            msg.clear();
            match self.pending_inits.get_mut(&addr).unwrap().every_second(&mut msg) {
                Err(_) => del.push(addr),
                Ok(MessageResult::None) => (),
                Ok(MessageResult::Reply) => self.send_to(addr, &mut msg)?,
                Ok(_) => unreachable!(),
            }
        }
        for addr in self.peers.keys().copied().collect::<SmallVec<[SocketAddr; 16]>>() {
            msg.clear();
            match self.peers.get_mut(&addr).unwrap().crypto.every_second(&mut msg) {
                Err(_) => del.push(addr),
                Ok(MessageResult::None) => (),
                Ok(MessageResult::Reply) => self.send_to(addr, &mut msg)?,
                Ok(_) => unreachable!(),
            }
        }
        for addr in del {
            self.pending_inits.remove(&addr);
            if self.peers.remove(&addr).is_some() {
                self.connect_sock(addr)?;
            }
        }
        Ok(())
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
                if self.peers.contains_key(addr) {
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
            // Maximum interval is one hour
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
        let mut del: SmallVec<[SocketAddr; 3]> = SmallVec::new();
        for (&addr, data) in &self.peers {
            if data.timeout < now {
                del.push(addr);
            }
        }
        for addr in del {
            info!("Forgot peer {} due to timeout", addr_nice(addr));
            self.peers.remove(&addr);
            self.table.remove_claims(addr);
            self.connect_sock(addr)?; // Try to reconnect
        }
        self.table.housekeep();
        self.crypto_housekeep()?;
        // Periodically extend the port-forwarding
        if let Some(ref mut pfw) = self.port_forwarding {
            pfw.check_extend();
        }
        let now = TS::now();
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
            for (addr, data) in &self.peers {
                writeln!(
                    f,
                    "  - \"{}\": {{ ttl_secs: {}, crypto: {} }}",
                    addr_nice(*addr),
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
        // HOT PATH FILTER: drop IPv6 link-local multicast (ff02::) noise at the
        // interface layer as a second line of defense (device.rs does the same).
        // Windows constantly generates IPv6 multicast/SSDP/LLMNR packets on the TUN
        // interface. Dropping them here avoids expensive route lookup + crypto + send
        // for noise traffic that will never reach a peer.
        if data.len() >= 26 && data.message()[0] >> 4 == 6 && data.message()[24] == 0xff && data.message()[25] == 0x02 {
            self.traffic.count_dropped_payload(data.len());
            return Ok(());
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
            Some(addr) => {
                // HOT PATH
                debug!("Found destination for {} => {}", dst, addr);
                let t_lookup = t0.elapsed().as_micros();
                self.send_msg(addr, MESSAGE_TYPE_DATA, data)?;
                let total_us = t0.elapsed().as_micros();
                if src_s.starts_with("10.99.0.") || dst_s.starts_with("10.99.0.") || icmp.is_some() {
                    debug!(
                        "[TUN_RX_PATH_DONE] src={}, dst={}, peer={}, len_out={}, icmp={:?}, lookup_us={}, send_path_us={}, total_us={}",
                        src, dst, addr_nice(addr), data.len(), icmp, t_lookup, total_us.saturating_sub(t_lookup), total_us
                    );
                }
                if !self.peers.contains_key(&addr) {
                    // COLD PATH
                    // If the peer is not actually connected, remove the entry in the table and try
                    // to reconnect.
                    warn!("Destination for {} not found in peers: {}", dst, addr_nice(addr));
                    self.table.remove_claims(addr);
                    self.connect_sock(addr)?;
                }
            }
            None => {
                // COLD PATH
                if self.broadcast {
                    debug!("No destination for {} found, broadcasting", dst);
                    self.broadcast_msg(MESSAGE_TYPE_DATA, data)?;
                } else if let Some((fallback_addr, _)) = self.peers.iter().next() {
                    // Fallback: use the existing peer when route claims have expired,
                    // preventing traffic drop after peer_timeout without re-handshake.
                    warn!("No destination for {} found, using fallback peer {}", dst, addr_nice(*fallback_addr));
                    self.send_msg(*fallback_addr, MESSAGE_TYPE_DATA, data)?;
                } else {
                    debug!("No destination for {} found, dropping", dst);
                    self.traffic.count_dropped_payload(data.len());
                }
            }
        }
        Ok(())
    }

    fn add_new_peer(&mut self, addr: SocketAddr, info: NodeInfo) -> Result<(), Error> {
        // 检查是否已有相同 node_id 的 peer（NAT/SNAT 导致地址变化时）
        let existing_addr: Option<SocketAddr> = self
            .peers
            .iter()
            .find(|(_, p)| p.node_id == info.node_id)
            .map(|(a, _)| *a);

        // 在 allow_snat=false 模式下，addr 可能是 SNAT/NAT 地址（消息源地址被中间设备改写），
        // 不能直接作为 peer key，否则 routing table 中的 claims 会指向错误地址，导致数据包发送失败。
        // 应使用 info.addrs 中的节点宣称地址（真实监听地址）作为 peer key。
        let peer_addr = if self.config.allow_snat {
            addr
        } else {
            info.addrs.first().copied().unwrap_or(addr)
        };

        if let Some(existing_addr) = existing_addr {
            // 同一节点，地址已变（SNAT/NAT/重连/WS-proxy新端口）
            // 必须将 peer 条目从旧地址移动到新地址，并替换 crypto
            // 否则 routing table 仍指向旧地址，导致重连后数据发往错误地址
            let mut crypto_replaced = false;
            let mut new_peer_data: Option<PeerData> = None;
            
            if let Some(mut peer) = self.peers.remove(&existing_addr) {
                // 合并地址列表
                if !peer.addrs.contains(&addr) {
                    peer.addrs.push(addr);
                }
                for new_addr in &info.addrs {
                    if !peer.addrs.contains(new_addr) {
                        peer.addrs.push(*new_addr);
                    }
                }
                peer.last_seen = TS::now();
                peer.timeout = TS::now() + self.config.peer_timeout as Time;
                
                // 关键：替换 crypto 为新握手产生的状态
                if let Some(init) = self.pending_inits.remove(&addr) {
                    if init.is_ready() {
                        peer.crypto = init;
                        crypto_replaced = true;
                        info!("Replaced crypto for peer {} due to address change/reconnect", addr_nice(existing_addr));
                    }
                }
                
                new_peer_data = Some(peer);
            }
            
            // 关键：移除旧地址的 claims，防止 routing table 仍指向旧地址
            self.table.remove_claims(existing_addr);
            
            // 以新地址作为 key 重新插入
            if let Some(peer_data) = new_peer_data {
                self.peers.insert(peer_addr, peer_data);
            }
            
            info!(
                "Moved peer {} -> {} due to address change, crypto_replaced={}",
                addr_nice(existing_addr),
                addr_nice(peer_addr),
                crypto_replaced
            );
            
            // 使用新地址更新 routing table
            self.update_peer_info(peer_addr, Some(info))?;
        } else {
            info!("Added peer {}", addr_nice(peer_addr));
            self.config.call_hook(
                "peer_connected",
                vec![
                    ("PEER", format!("{:?}", addr_nice(peer_addr))),
                    ("IFNAME", self.device.ifname().to_owned()),
                    ("CLAIMS", info.claims.iter().map(|r| format!("{:?}", r)).collect::<Vec<String>>().join(" ")),
                    ("NODE_ID", bytes_to_hex(&info.node_id)),
                ],
                true,
            );
            if let Some(init) = self.pending_inits.remove(&addr) {
                self.peers.insert(
                    peer_addr,
                    PeerData {
                        addrs: info.addrs.clone(),
                        crypto: init,
                        node_id: info.node_id,
                        peer_timeout: info.peer_timeout.unwrap_or(DEFAULT_PEER_TIMEOUT),
                        last_seen: TS::now(),
                        timeout: TS::now() + self.config.peer_timeout as Time,
                    },
                );
                self.update_peer_info(peer_addr, Some(info))?;
            } else {
                error!("No init for new peer {}", addr_nice(addr));
            }
        }
        Ok(())
    }

    fn remove_peer(&mut self, addr: SocketAddr) {
        let lookup_addr = if self.config.allow_snat {
            addr
        } else {
            match self.resolve_peer_addr(addr) {
                Some(a) => a,
                None => return,
            }
        };
        if let Some(peer) = self.peers.remove(&lookup_addr) {
            info!("Closing connection to {}", addr_nice(lookup_addr));
            self.table.remove_claims(lookup_addr);
            self.config.call_hook(
                "peer_disconnected",
                vec![
                    ("PEER", format!("{:?}", addr)),
                    ("IFNAME", self.device.ifname().to_owned()),
                    ("NODE_ID", bytes_to_hex(&peer.node_id)),
                ],
                true,
            );
        }
    }

    fn connect_to_peers(&mut self, peers: &[PeerInfo]) -> Result<(), Error> {
        'outer: for peer in peers {
            for addr in &peer.addrs {
                if self.peers.contains_key(addr) {
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
            self.connect(&peer.addrs as &[SocketAddr])?;
        }
        Ok(())
    }

    fn resolve_peer_addr(&self, addr: SocketAddr) -> Option<SocketAddr> {
        if self.peers.contains_key(&addr) {
            return Some(addr);
        }
        debug!("[RESOLVE_PEER] addr={:?} not found directly, trying conversions", addr);
        // 尝试 IPv6 映射的 IPv4 <-> 纯 IPv4 地址转换（mapped_addr 可能导致地址族不一致）
        match addr {
            SocketAddr::V6(a) => {
                if let Some(ip4) = a.ip().to_ipv4() {
                    let alt = SocketAddr::V4(std::net::SocketAddrV4::new(ip4, a.port()));
                    debug!("[RESOLVE_PEER] trying IPv4 alt={:?}, found={}", alt, self.peers.contains_key(&alt));
                    if self.peers.contains_key(&alt) {
                        return Some(alt);
                    }
                }
            }
            SocketAddr::V4(a) => {
                let alt = SocketAddr::new(IpAddr::V6(a.ip().to_ipv6_mapped()), a.port());
                debug!("[RESOLVE_PEER] trying IPv6 alt={:?}, found={}", alt, self.peers.contains_key(&alt));
                if self.peers.contains_key(&alt) {
                    return Some(alt);
                }
            }
        }
        debug!("[RESOLVE_PEER] no match found");
        None
    }

    fn update_peer_info(&mut self, addr: SocketAddr, info: Option<NodeInfo>) -> Result<(), Error> {
        let lookup_addr = if self.config.allow_snat {
            addr
        } else {
            match self.resolve_peer_addr(addr) {
                Some(a) => a,
                None => {
                    error!("Received peer update from non peer {}", addr_nice(addr));
                    return Ok(());
                }
            }
        };
        if let Some(peer) = self.peers.get_mut(&lookup_addr) {
            peer.last_seen = TS::now();
            peer.timeout = TS::now() + self.config.peer_timeout as Time;
            if let Some(info) = &info {
                // Update peer addresses, always add seen address
                peer.addrs.clear();
                peer.addrs.push(addr);
                for addr in &info.addrs {
                    if !peer.addrs.contains(addr) {
                        peer.addrs.push(*addr);
                    }
                }
            }
        }
        if let Some(info) = info {
            debug!("Adding claims of peer {}: {:?}", addr_nice(lookup_addr), info.claims);
            self.table.set_claims(lookup_addr, info.claims);
            debug!("Received {} peers from {}: {:?}", info.peers.len(), addr_nice(lookup_addr), info.peers);
            self.connect_to_peers(&info.peers)?;
        }
        Ok(())
    }

    fn handle_payload_from(&mut self, peer: SocketAddr, data: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        let t0 = std::time::Instant::now();
        let (src, dst) = P::parse(data.message())?;
        let len = data.len();
        let icmp = dbg_icmp(data.message());
        debug!("[TUN_WRITE_PATH] start: {} bytes, inner src={}, dst={}, peer={}, icmp={:?}", len, src, dst, addr_nice(peer), icmp);
        self.traffic.count_in_payload(src, dst, len);
        let t_parse = t0.elapsed().as_micros();
        match self.device.write(data) {
            Ok(()) => {
                let total_us = t0.elapsed().as_micros();
                debug!(
                    "[TUN_WRITE_PATH_DONE] ok: {} bytes, inner src={}, dst={}, peer={}, icmp={:?}, parse_us={}, write_us={}, total_us={}",
                    len, src, dst, addr_nice(peer), icmp, t_parse, total_us.saturating_sub(t_parse), total_us
                );
                if self.learning {
                    self.table.cache(src, peer);
                }
                // Refresh claim timeout so routes stay alive while traffic flows,
                // even without periodic NodeInfo re-exchange.
                self.table.refresh_claims_timeout(peer);
                Ok(())
            }
            Err(e) => {
                let total_us = t0.elapsed().as_micros();
                error!(
                    "[TUN_WRITE_PATH] failed: {} bytes, inner src={}, dst={}, peer={}, icmp={:?}, total_us={}, err={}",
                    len, src, dst, addr_nice(peer), icmp, total_us, e
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
                self.add_new_peer(src, info)?
            }
            MessageResult::InitializedWithReply(info) => {
                // COLD PATH
                self.add_new_peer(src, info)?;
                self.send_to(src, data)?
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
            if let Some(peer) = self.peers.get_mut(&src) {
                effective_src = src;
                if peer.crypto.has_init() {
                    debug!("Dispatch: existing peer {} has crypto init, reusing it", addr_nice(src));
                    result = Some(peer.crypto.handle_message(data))
                } else if peer.crypto.is_ready() {
                    debug!("Dispatch: existing ready peer {} has no init state; ignoring duplicate/late init message", addr_nice(src));
                    ignore_duplicate_init = true;
                } else {
                    debug!("Dispatch: existing peer {} has no crypto init and not ready", addr_nice(src));
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
                // Existing peer still in init/handshake state: reply to observed src during init window.
                for (addr, peer) in self.peers.iter_mut() {
                    if peer.crypto.has_init() {
                        // Skip short packets that can't possibly decrypt
                        if data.len() < MIN_ENCRYPTED_LEN && !is_init {
                            continue;
                        }
                        let mut test = data.clone();
                        if let Ok(msg_result) = peer.crypto.handle_message(&mut test) {
                            if *addr != src {
                                debug!(
                                    "SNAT/NAT handshake endpoint for peer init: {} observed at {}",
                                    addr_nice(*addr),
                                    addr_nice(src)
                                );
                                if !peer.addrs.contains(&src) {
                                    peer.addrs.push(src);
                                }
                                peer.last_seen = TS::now();
                                peer.timeout = TS::now() + self.config.peer_timeout as Time;
                            }
                            effective_src = src;
                            self.handle_message(src, msg_result, &mut test)?;
                            return Ok(());
                        }
                    }
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
        } else if let Some(peer) = if self.config.allow_snat {
            self.peers.get_mut(&src)
        } else {
            self.resolve_peer_addr(src).and_then(|a| self.peers.get_mut(&a))
        } {
            // HOT PATH
            let ready = peer.crypto.is_ready();
            if !ready {
                debug!("Peer {} exists but crypto not ready yet; processing message as existing peer", addr_nice(src));
            } else {
                debug!("Dispatch: existing ready peer {} handling non-init message", addr_nice(src));
            }
            peer.crypto.handle_message(data)
        } else if !self.config.allow_snat {
            // COLD PATH - SNAT/NAT 地址变化：尝试用已知 peer 的 crypto 解密。
            // 对每个 peer/pending_init 先用 data.clone() 试解密，成功后用解密后的数据处理，
            // 避免 handle_message 两次推进 crypto 状态导致握手/解密失败。
            // 不提前从 pending_inits 移除 init，由 add_new_peer 在握手完成后统一移除。
            let mut matched: Option<(SocketAddr, MessageResult<NodeInfo>, MsgBuffer, bool)> = None;
            for (addr, peer) in self.peers.iter_mut() {
                let mut test = data.clone();
                if let Ok(msg_result) = peer.crypto.handle_message(&mut test) {
                    matched = Some((*addr, msg_result, test, false));
                    break;
                }
            }
            if matched.is_none() {
                for (addr, init) in self.pending_inits.iter_mut() {
                    let mut test = data.clone();
                    if let Ok(msg_result) = init.handle_message(&mut test) {
                        matched = Some((*addr, msg_result, test, true));
                        break;
                    }
                }
            }

            if let Some((matched_addr, msg_result, mut decrypted_data, is_pending)) = matched {
                info!(
                    "SNAT/NAT address change: peer {} now at {}",
                    addr_nice(matched_addr),
                    addr_nice(src)
                );
                if is_pending {
                    // pending_inits 中的条目：不在此处移除，由 add_new_peer 在握手完成时移除
                    // 仅更新 last_seen（pending_inits 无 last_seen 字段，跳过）
                } else if let Some(peer) = self.peers.get_mut(&matched_addr) {
                    if !peer.addrs.contains(&src) {
                        peer.addrs.push(src);
                    }
                    peer.last_seen = TS::now();
                    peer.timeout = TS::now() + self.config.peer_timeout as Time;
                }
                self.handle_message(matched_addr, msg_result, &mut decrypted_data)?;
                Ok(MessageResult::None)
            } else {
                // COLD PATH
                info!("Ignoring non-init message from unknown peer {}", addr_nice(src));
                self.traffic.count_invalid_protocol(data.len());
                return Ok(());
            }
        } else {
            // COLD PATH - allow_snat is true, ignore unknown peer
            info!("Ignoring non-init message from unknown peer {}", addr_nice(src));
            self.traffic.count_invalid_protocol(data.len());
            return Ok(());
        };
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
            const MAX_DRAIN_PACKETS: u64 = 1024;
            if drained_packets >= MAX_DRAIN_PACKETS || t_ev.elapsed().as_micros() >= 50_000 {
                warn!(
                    "[SOCKET_EVT_DRAIN] break early drained_packets={} drained_bytes={} total_us={}",
                    drained_packets, drained_bytes, t_ev.elapsed().as_micros()
                );
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
                    if drained_packets == 1 || drained_packets % 32 == 0 || total_us >= 10_000 {
                        debug!(
                            "[DEVICE_EVT_DRAIN] seq={} len={} read_us={} handle_us={} total_us={} drained_packets={} drained_bytes={}",
                            drained_packets, len, read_us, handle_us, total_us, drained_packets, drained_bytes
                        );
                    }

                    // Safety bound: avoid monopolizing the main loop when TUN is very busy.
                    const MAX_DRAIN_PACKETS: u64 = 1024;
                    if drained_packets >= MAX_DRAIN_PACKETS || total_us >= 50_000 {
                        warn!(
                            "[DEVICE_EVT_DRAIN] break early drained_packets={} drained_bytes={} total_us={}",
                            drained_packets, drained_bytes, total_us
                        );
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

            // Priority: process all ready Socket events before Device events.
            // This ensures crypto handshakes, keepalives, and ACKs are not delayed by TUN drain.
            let mut current_evt = Some(evt);
            while let Some(e) = current_evt.take() {
                match e {
                    WaitResult::Error(err) => {
                        // COLD PATH
                        // On WebSocket proxy mode, a poll error means the underlying
                        // TCP/WebSocket connection died. Return to caller for reconnect
                        // instead of exiting the process.
                        error!("Cloud::run_legacy: poll/socket error: {} (returning for reconnect)", err);
                        return false;
                    }
                    WaitResult::Timeout => {}
                    WaitResult::Socket => {
                        match self.handle_socket_event(&mut buffer, None) {
                            Ok(_) => {
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
                        self.handle_device_event(&mut buffer, None);
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
        self.peers.contains_key(addr)
    }

    pub fn own_addresses(&self) -> &[SocketAddr] {
        &self.own_addresses
    }

    pub fn get_num(&self) -> usize {
        self.socket.address().unwrap().port() as usize
    }
}
