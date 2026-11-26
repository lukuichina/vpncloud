VpnCloud - Peer-to-Peer VPN
---------------------------
![Checks](https://github.com/dswd/vpncloud/workflows/Checks/badge.svg?branch=master)
![Security audit](https://github.com/dswd/vpncloud/workflows/Security%20audit/badge.svg?branch=master)

**VpnCloud** is a high performance peer-to-peer mesh VPN over UDP supporting strong encryption, NAT traversal and a simple configuration. It establishes a fully-meshed self-healing VPN network in a peer-to-peer manner with strong end-to-end encryption based on elliptic curve keys and AES-256. VpnCloud creates a virtual network interface on the host and forwards all received data via UDP to the destination. It can work on TUN devices (IP based) and TAP devices (Ethernet based).

```sh
$> vpncloud -c REMOTE_HOST:PORT -p 'mypassword' --ip 10.0.0.1/24
```

or as config file:

```yaml
crypto:
  password: mysecret
ip: 10.0.0.1
peers:
  - REMOTE_HOST:PORT
```

For more information, please see the [Website](https://vpncloud.ddswd.de) or the [Discussions group](https://github.com/dswd/vpncloud/discussions).


### Project Status
This project is still [under development](CHANGELOG.md) but has reached a
somewhat stable state. VpnCloud features the following functionality:

* Automatic peer-to-peer meshing, no central servers
* Automatic reconnecting when connections are lost
* Connecting hundreds of nodes with the VPN
* High throughput and low additional latency (see [performance page](https://vpncloud.ddswd.de/features/performance))
* Creating virtual network interfaces based on Ethernet (TAP) and IP (TUN)
* Strong end-to-end encryption using Curve25519 key pairs and AES methods
* Support for different forwarding/routing behaviors (Hub, Switch, Router)
* NAT and firewall traversal using hole punching
* Automatic port forwarding via UPnP
* Websocket proxy mode for restrictive environments (`--ws-proxy`)
* IPv6 support (dual-stack UDP, IPv6 TUN addresses, IPv6 route auto-configuration)
* Support for tunneled VLans (TAP devices)
* Support for publishing [beacons](https://vpncloud.ddswd.de/docs/beacons) to help nodes find each others
* Support for statsd monitoring
* Low memory footprint
* Single binary, no dependencies, no kernel module

### `--ws-proxy` behavior

When `--ws-proxy` is given, an embedded WebSocket proxy runs in the same
process alongside the VPN UDP listener. The proxy is started in both regular
(UDP) mode and WebSocket (WSS) mode, so it can be used as a relay even when
the node itself connects to an upstream peer via `wss://`:

* `--ws-proxy 127.0.0.1:8080` — proxy listens on `127.0.0.1:8080`
* `--ws-proxy :8080` or `--ws-proxy 8080` — IP part may be omitted,
  defaults to `0.0.0.0` (listens on all interfaces)
* `--listen` may be omitted when `--ws-proxy` is given; the UDP listener
  automatically uses the same port as the proxy target

Example:

```sh
$> vpncloud --ws-proxy :8080 --password mysecret --ip 10.0.0.1/24
# UDP listens on 0.0.0.0:8080, WS proxy listens on 0.0.0.0:8080
```

### WebSocket Reconnection

When running in WebSocket proxy mode (`--ws-proxy`), vpnCloud automatically
reconnects if the WebSocket connection is lost (network blip, proxy restart,
etc.). The underlying TCP/WebSocket connection is re-established and the peer
connection is re-initiated via the standard handshake — no manual restart
required. Reconnection uses a 5-second retry interval to avoid hammering a
downstream proxy.

### `--sni` (custom TLS SNI / HTTP Host header for wss://)

When connecting to a `wss://` URL whose target is an IP address, the TLS SNI
and HTTP `Host` header are normally derived from that IP. Use `--sni <host>`
to override both with a custom hostname:

```sh
$> vpncloud --ip fd03::3 -l wss://100.101.102.61:8788 -c 100.101.102.61:8788 -p 123 --sni vnetc.swings.one --insecure
# TCP connects to 100.101.102.61:8788, but TLS SNI and HTTP Host header
# use "vnetc.swings.one"
```

This is useful when the network path inspects SNI or when the remote endpoint
expects a specific `Host` header. Combine with `--insecure` when the remote
certificate does not match the SNI hostname.

### `--insecure` (skip TLS certificate verification for wss://)

When connecting to a `wss://` URL, vpnCloud normally verifies the remote
server's TLS certificate. If the certificate is not yet valid, self-signed,
or otherwise untrusted, the connection fails with `invalid peer certificate`.
Use `--insecure` to skip certificate verification:

```sh
$> vpncloud --ip fd03::3 -l wss://vnetc.swings.one:443 -c 127.0.0.1:8788 -p 123 --insecure
```

⚠️ **Warning**: `--insecure` disables server certificate validation and makes
the connection vulnerable to man-in-the-middle attacks. Only use it for
testing or when you trust the remote endpoint. Not recommended for production.

### IPv6 Support

VpnCloud supports IPv6 for both the underlay transport and the virtual TUN interface.

**IPv6 TUN address:**
```sh
$> vpncloud --ip fd03::3/64 -p mysecret
```
The `--ip` parameter accepts IPv6 addresses with CIDR notation (e.g. `fd03::3/64`). If the prefix length is omitted, `/64` is used by default for IPv6.

**`--ipv6 <addr>` (manual IPv6 address):**
When `--ip` is not given, `--ipv6 <addr>` specifies the IPv6 address for the TUN interface directly. It is equivalent to `--ip <addr>` but only accepts IPv6 addresses:

```sh
$> vpncloud --ipv6 fd03::3 -p mysecret   # configured as fd03::3/64
```

This is useful when you want to run an IPv6-only node without specifying `--ip`. Like `--ip`, the prefix length defaults to `/64` when omitted, so the system route `fd03::/64 dev vpncloud0` is added automatically and direct peer ping works without any additional `--claim`.

Example:

```sh
$> vpncloud --ipv6 fd03::3 -p mysecret --peer REMOTE_HOST:PORT
```

**Auto-claim:**
When an IP address is configured on the TUN device, vpnCloud automatically claims that exact address (`/128` for IPv6, `/32` for IPv4) so that direct peer-to-peer communication works without any additional `--claim`. For example:

```sh
$> vpncloud --ip fd03::3/64 -p mysecret   # auto-claims fd03::3/128
$> vpncloud --ip 10.0.0.1/24 -p mysecret  # auto-claims 10.0.0.1/32
```

**Automatic underlay routing:**
To route an entire subnet through the TUN device, explicitly claim it:

```sh
$> vpncloud --ip fd03::3/64 -p mysecret --claim fd03::/64
```
vpnCloud automatically adds `ip route add fd03::/64 dev vpncloud0` for IPv6 claims.

**IPv6 listening:**
The UDP listener binds to an IPv6 dual-stack socket by default (`[::]:PORT`), accepting both IPv4 and IPv6 connections. WebSocket proxy addresses also support IPv6.

**Example: IPv6-only node (no --claim needed for direct IP ping)**
```sh
$> vpncloud --ip fd03::3/64 -p mysecret --peer REMOTE_HOST:PORT
```

**Example: IPv4 node (existing behavior unchanged)**
```sh
$> vpncloud --ip 10.0.0.1/24 -p mysecret --peer REMOTE_HOST:PORT
```

For dual-stack operation (both IPv4 and IPv6 on the same TUN device), configure the second address via the `--ifup` script or config file, since `--ip` accepts a single address.

**Dual-stack with `--ip` and `--ipv6`:**
When both `--ip` and `--ipv6` are given, vpnCloud configures both an IPv4 and an IPv6 address on the TUN device. Both addresses are auto-claimed (`/32` for IPv4, `/128` for IPv6) so direct peer communication works without additional `--claim`:

```sh
$> vpncloud --ip 10.0.0.1/24 --ipv6 fd03::3 -p mysecret --peer REMOTE_HOST:PORT
```

The `--advertise-addresses` option can be used to publish additional addresses to peers (e.g. for multi-homed nodes):

```sh
$> vpncloud --ip 10.0.0.1/24 --ipv6 fd03::3 --advertise-addresses 10.0.0.1,fd03::3 -p mysecret
```

**Automatic address discovery with `--advertise_auto` (default: off):**
Instead of listing addresses manually, `--advertise_auto` makes vpnCloud enumerate the
unicast IPv4/IPv6 addresses of all local *active* network cards and advertise them:

```sh
$> vpncloud --ip 10.0.0.1/24 --ipv6 fd03::3 --advertise_auto -p mysecret --peer REMOTE_HOST:PORT
```

The enumeration deliberately skips:
- loopback (`127.0.0.0/8`, `::1`), unspecified (`0.0.0.0`, `::`) and link-local
  (`169.254.0.0/16`, `fe80::/10`) addresses, which are not routable to peers;
- the vpnCloud virtual interface itself (`vpncloud0`), so the tunnel addresses
  (e.g. `10.0.0.1`, `fd03::3`) are never advertised back to peers (no self-loop).

This is useful on multi-homed nodes (LAN + a mesh/VPN interface + public IPv6):
peers learn every reachable address without hand-maintaining `--advertise-addresses`.
It is disabled by default; the previous behaviour (`--advertise-addresses` or the
kernel route lookup toward each peer) is unchanged.


### Authentication: `--password` vs `--private-key`/`--public-key`

vpnCloud supports two authentication methods:

**`--password <password>` (shared secret):**
A simple pre-shared password. Both sides must use the same password. The password is fed through PBKDF2 to derive the Curve25519 key pair, so **the same password always produces the same key pair on every node**. This works for small setups, but all nodes with the same password share the same public key, which limits peer differentiation and access control.

```sh
$> vpncloud --ip 10.0.0.1/24 -p mysecret --peer REMOTE_HOST:PORT
```

**`--private-key` / `--public-key` / `--trusted-key` (explicit keys):**
Generate a unique key pair per node with `vpncloud genkey`, then distribute public keys via `--trusted-key`. This is the recommended method for production use, as each node has a unique identity and you can explicitly choose which peers to trust.

```sh
# Generate a key pair
$> vpncloud genkey
Private key: HoFrm2jbJHp7RDwKvA9LUyNbPbJXP7TAQjvvNWKqX6x
Public key: tTzcYNnZtTvk5kFluKr1shsodAE3sRmXgIIoHr73bGV

# Run with explicit keys
$> vpncloud --ip fd03::3/64 \
  --private-key HoFrm2jbJHp7RDwKvA9LUyNbPbJXP7TAQjvvNWKqX6x \
  --public-key tTzcYNnZtTvk5kFluKr1shsodAE3sRmXgIIoHr73bGV \
  --trusted-key <peer-public-key> \
  -l [::]:2600
```

### Installing

#### Compiling from source
Prerequisites: Git, [Cargo](https://www.rust-lang.org/install.html), asciidoctor

The checked-out code can be compiled with ``cargo build`` or ``cargo build --release`` (release version). The binary could then be found in `target/release/vpncloud`.

The tests can be run via ``cargo test``.


#### Cross-Compiling & packaging
Use the provided scripts in the repository root:

* `./build-static.sh <target>` — cross-build a stripped static binary for one
  target into `build-linux-<target>/` (or `build-windows-<target>/`).
  Supported targets include `x86_64-unknown-linux-musl`,
  `aarch64-unknown-linux-gnu`, `armv7-unknown-linux-gnueabihf`,
  `mipsel-unknown-linux-musl` (nightly + build-std), etc.
* `./gz.sh` — package all binaries from `build-linux-*/` into `gz/*.tar.gz`.

Examples:

```sh
$> ./build-static.sh x86_64-unknown-linux-musl
$> ./build-static.sh aarch64-unknown-linux-gnu
$> ./build-static.sh armv7-unknown-linux-gnueabihf
$> ./build-static.sh mipsel-unknown-linux-musl
$> ./gz.sh
```


### Contributions welcome
There are several areas in which still some work has to be done and where
contributions are very welcome:

* **Linux packages**: VpnCloud is stable enough to be packaged for Linux
  distributions. Maintainers who want to package VpnCloud are very welcome.
* **Help with other platforms**: If you are a Rust developer with experience
  on Windows or MacOS your help on porting VpnCloud to those platforms is very
  welcome.
* **Security review**: The security has been implemented with strong security
  primitives but it would be great if a cryptography expert could verify the
  system.
* **Feedback on use cases**: Some feedback on how VpnCloud is being used and
  maybe some tutorials covering common use cases would be nice.


### Semantic Versioning
This project uses [semantic versioning](http://semver.org).

---

## Windows Support (MVP)

VpnCloud now has experimental Windows support via Wintun. The Windows build
uses a separate device implementation (`WintunDevice`) and a Windows-specific
poll/wait mechanism (`WindowsWait` based on `WSAEventSelect` + `WFMO`).

### Building on Windows

```sh
cargo build --release --no-default-features --features nat,websocket
```

Prerequisites:
- [Wintun](https://wintun.net/) driver installed
- Rust toolchain for `x86_64-pc-windows-gnu`
- `wintun` and `windows-sys` crates (declared under `[target.'cfg(windows)'.dependencies]`)

### Running on Windows

```sh
vpncloud.exe --ip 10.0.0.1/24 --password mysecret --peer REMOTE_HOST:PORT
```

Note: `--daemonize`, `--user`, `--group`, and Unix-only privilege dropping are not
supported on Windows. Use task scheduling or a service wrapper instead.

### Known Limitations

- TUN only (IP layer); TAP (Ethernet) is not supported on Windows
- Wintun 0.5.1 does not support overlapped I/O, so the device thread still uses
  event-driven polling (not IOCP)
- `--ws-proxy` on Windows uses the legacy single-threaded event loop
---

## `--poll-timeout-ms` (event loop wait timeout)

Controls how long the event loop waits for socket/device activity when idle.
Lower values reduce latency but increase CPU usage; higher values reduce CPU
but add latency. Default: `50` ms.

```sh
$> vpncloud --poll-timeout-ms 5 --ip 10.0.0.1/24 -p mysecret
```

## `--mtu` (TUN/TAP interface MTU)

Sets the MTU for the virtual TUN/TAP interface. When omitted, the MTU is derived
automatically from the default route MTU minus crypto/encapsulation overhead.

On **Windows**, a fixed MTU of `1380` is used by default. This accounts for the
additional overhead introduced by WebSocket framing and cloudflared (HTTP/2 /
QUIC) encapsulation, which can push the outer packet size beyond the physical
NIC MTU (typically 1500) and trigger IP fragmentation. Fragmentation in turn
causes packet loss and increased latency.

```sh
# Explicit MTU (recommended for Windows + cloudflared)
$> vpncloud --mtu 1380 --ip 10.0.0.1/24 -p mysecret

# Auto-derive from default route (Linux default)
$> vpncloud --ip 10.0.0.1/24 -p mysecret
```

## `--advertise_auto` (automatic local address discovery)

When enabled (`false` by default), vpnCloud actively enumerates the unicast
IPv4/IPv6 addresses of every **active** local network card and advertises them to
peers — no need to maintain `--advertise-addresses` by hand on multi-homed hosts
(LAN + a mesh/VPN interface + public IPv6).

```sh
$> vpncloud --ip 10.0.0.1/24 --ipv6 fd03::3 --advertise_auto -p mysecret --peer REMOTE_HOST:PORT
```

Filtered out automatically (never advertised):

- loopback (`127.0.0.0/8`, `::1`) and unspecified (`0.0.0.0`, `::`) addresses;
- link-local addresses (`169.254.0.0/16`, `fe80::/10`), not routable to peers;
- interfaces that are down (`is_up() == false`);
- **the vpnCloud virtual interface itself (`vpncloud0`)** — the tunnel addresses
  (e.g. `10.0.0.1`, `fd03::3`) are never advertised back to peers (no self-loop).

When the flag is off, behaviour is unchanged (explicit `--advertise-addresses`
or the kernel route lookup toward each peer).

## `--allow-snat` (SNAT/NAT address change handling)

When enabled (default), vpnCloud tolerates source NAT/NAT address rewriting
between peers. When set to `false`, vpnCloud uses a stricter peer matching
algorithm that prefers the peer's claimed listening address over the observed
transport source address, which is more robust in certain NAT scenarios.

```sh
$> vpncloud --allow-snat=false --ip 10.0.0.1/24 -p mysecret
```