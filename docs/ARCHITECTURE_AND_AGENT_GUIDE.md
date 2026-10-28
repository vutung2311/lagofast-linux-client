# LagoFast VPN Linux Client: Architecture, Diagnostic & Agent Guide

> **Notice to Future AI Agents & Maintainers:**  
> Read this document in full before modifying the codebase, routing logic, or NetworkManager integration. This file documents the reverse-engineered internal architecture of LagoFast/Qiyou, the Linux networking design, known pitfalls, resolved edge cases, and testing methodologies.

---

## Table of Contents
1. [System Architecture Overview](#1-system-architecture-overview)
2. [Component Details](#2-component-details)
   - [A. D-Bus NetworkManager Plugin (`nm-lagofast-service`)](#a-d-bus-networkmanager-plugin-nm-lagofast-service)
   - [B. Core REST API Client (`pkg/api/client.go`)](#b-core-rest-api-client-pkgapiclientgo)
   - [C. Native Proxy Engine (`native/libQyProxy.so`)](#c-native-proxy-engine-nativelibqyproxyso)
   - [D. Socket Interposer (`pkg/bind/bind.c` -> `liblagofast_bind.so`)](#d-socket-interposer-pkgbindbindc---liblagofast_bindso)
3. [Routing Architecture & Loop Prevention](#3-routing-architecture--loop-prevention)
   - [The `/32` Host Route Rule](#the-32-host-route-rule)
   - [Subnet Exclusion Logic](#subnet-exclusion-logic)
   - [Route Table Hygiene](#route-table-hygiene)
4. [Smart Connect-Time Node Selection Algorithm](#4-smart-connect-time-node-selection-algorithm)
   - [Motivation & Problem Solved](#motivation--problem-solved)
   - [Multi-Probe Stability Formula](#multi-probe-stability-formula)
   - [Relay Topologies: Direct vs Two-Node Backhaul](#relay-topologies-direct-vs-two-node-backhaul)
5. [Wine / Proton Gaming Pitfalls & Edge Cases](#5-wine--proton-gaming-pitfalls--edge-cases)
   - [Interface Detachment & Path MTU Collapse (The `mss: 48` Bug)](#interface-detachment--path-mtu-collapse-the-mss-48-bug)
   - [TCP Congestion Control & Buffer Bloat](#tcp-congestion-control--buffer-bloat)
   - [Longest Prefix Match (LPM) Hijacking](#longest-prefix-match-lpm-hijacking)
6. [Packaging, Build & Deployment](#6-packaging-build--deployment)
7. [Standard Diagnostic & Verification Commands](#7-standard-diagnostic--verification-commands)

---

## 1. System Architecture Overview

```mermaid
flowchart TD
    User["User / Desktop UI / nmcli"] -->|Activate Connection| NM["NetworkManager Daemon"]
    NM -->|D-Bus: org.freedesktop.NetworkManager.lagofast| Daemon["nm-lagofast-service (Go)"]

    Daemon -->|REST API (AES-ECB Auth)| API["cbs.lagofast.com\n(Auth, Routes, Nodes)"]
    Daemon -->|Multi-Probe Benchmark| Probes["PingNode UDP Probes\n(All Candidate Relay IPs)"]
    Daemon -->|Kernel Route Bypass| Bypass["Add /32 Host Routes via wlan0/eth0\n(Prevents Relay Loops)"]

    Daemon -->|Initialize FFI / Cgo| Native["native/libQyProxy.so\n(Proprietary Tunnel Core)"]
    Native -->|TUN Read/Write| Tun["Linux TUN Interface: lagofast0\n(MTU 1400, Peer 10.10.10.1)"]

    Tun -->|Split-Tunnel CIDRs| KernelRoutes["Kernel Routing Table\n(Game Server Subnets)"]

    Game["Proton / Wine Game (e.g. wwm.exe)"] -->|Optional Interceptor| BindSO["liblagofast_bind.so (LD_PRELOAD)"]
    BindSO -->|Force BBR, TCP_NODELAY, 4MB Buffers| KernelRoutes
    KernelRoutes -->|Tunneled Traffic| Tun
    KernelRoutes -->|Relay & Public Traffic| Direct["wlan0 / Default Gateway"]
```

---

## 2. Component Details

### A. D-Bus NetworkManager Plugin (`nm-lagofast-service`)
- **Location:** [`cmd/nm-lagofast-service/`](file:///home/tung/Git/lagofast_vpn/cmd/nm-lagofast-service), [`pkg/nm/service.go`](file:///home/tung/Git/lagofast_vpn/pkg/nm/service.go)
- **Role:** Implements the `org.freedesktop.NetworkManager.VPN.Plugin` D-Bus specification.
- **Workflow:**
  1. Authenticates using existing saved sessions or connection credentials.
  2. If `node_ip` is omitted or set to `"auto"`, runs the multi-probe benchmark across all nodes in the target `zone_id`.
  3. Proactively creates `/32` bypass routes via the default gateway for all candidate nodes in the zone.
  4. Queries the LagoFast REST API for acceleration credentials (`acct_detail_all`) and dynamic game routing subnets (`client_start_line`).
  5. Dynamically filters out any CIDR that contains the selected relay node IP to eliminate routing loops.
  6. Configures the TUN interface (`lagofast0`) with IP `10.10.10.2/24` and gateway `10.10.10.1`.
  7. Initializes the `libQyProxy.so` tunnel engine passing the TUN file descriptor.
  8. Emits `Ip4Config` D-Bus signals so NetworkManager populates kernel routes.

### B. Core REST API Client (`pkg/api/client.go`)
- **Location:** [`pkg/api/client.go`](file:///home/tung/Git/lagofast_vpn/pkg/api/client.go)
- **Authentication:** HMAC and custom MD5 signature algorithms with device GUID simulation.
- **Password Decryption:** Reverse-engineered AES-128-ECB decryption of acceleration passwords returned by `acct_detail_all`.
- **Dynamic Subnet Resolution:** Resolves game routing subnets dynamically per game ID and zone ID. Never hardcode game CIDRs!

### C. Native Proxy Engine (`native/libQyProxy.so`)
- **Location:** `native/libQyProxy.so`
- **Origin:** Extracted and reverse-engineered from the proprietary LagoFast Android and macOS clients.
- **Interface:** C-ABI dynamic loading via `dlopen`/`dlsym`. Handled in [`pkg/tunnel/cgo.go`](file:///home/tung/Git/lagofast_vpn/pkg/tunnel).
- **MTU:** Fixed to **1400** to account for encapsulation overhead over standard 1500-byte WAN MTU without IP packet fragmentation.

### D. Socket Interposer (`pkg/bind/bind.c` -> `liblagofast_bind.so`)
- **Location:** [`pkg/bind/bind.c`](file:///home/tung/Git/lagofast_vpn/pkg/bind/bind.c)
- **Role:** An `LD_PRELOAD` interposer that optimizes socket settings for game binaries running under Wine/Proton.
- **Key Behaviors:**
  - **Selective Binding:** Binds game combat sockets and state sync sockets to `lagofast0`.
  - **Preserves Local & DNS Traffic:** Excludes `127.0.0.1`, `::1`, and UDP port 53 (DNS) to prevent local networking breakdowns.
  - **Includes State Sync Ports (80 & 443):** State synchronization on game subnets (`8.208.0.0/12`, `47.84.0.0/16`, etc.) is bound to `lagofast0` rather than bypassed.
  - **Socket Buffer Expansion:** Automatically enlarges UDP buffers to `SO_RCVBUF = 4MB` and `SO_SNDBUF = 2MB`.
  - **Congestion Control Enforcement:** Intercepts `setsockopt` calls requesting suboptimal congestion control (such as DCTCP falling back to Reno) and forces `TCP_CONGESTION = "bbr"`. Enables `TCP_NODELAY` and `TCP_QUICKACK`.

---

## 3. Routing Architecture & Loop Prevention

### The `/32` Host Route Rule
**Problem:** The game acceleration service receives routing CIDRs covering wide IP ranges (e.g. `150.109.0.0/16`). If the relay node itself resides within one of these CIDRs (e.g. `Singapore-P1738` at `150.109.94.71`), sending traffic destined for `150.109.94.71` into `lagofast0` causes the tunnel to encapsulate packets to itself, producing an immediate, total routing freeze.

**Remedy in Code:**
1. **Dynamic Subnet Exclusion:**
   [`pkg/nm/service.go`](file:///home/tung/Git/lagofast_vpn/pkg/nm/service.go) parses all CIDRs returned by the API and removes any subnet whose IP network contains `s.activeNode.NodeIP`.
2. **Explicit `/32` Bypass Routes:**
   Before establishing the tunnel, the service determines the default gateway interface (e.g. `wlan0`) and installs explicit `/32` host routes for **all candidate nodes** in the active zone via the physical gateway. Even if routing rules change, physical transit to the relay nodes can never accidentally route into `lagofast0`.

### Route Table Hygiene
Never add static diagnostic routes (e.g. `ip route add 47.84.156.0/24 via 192.168.88.1`) without removing them. Linux uses Longest Prefix Match (LPM); a `/24` route on `wlan0` will take precedence over a `/16` route on `lagofast0`, splitting game traffic and breaking multiplayer synchronization.

The package installer script [`packaging/arch/lagofast-vpn.install`](file:///home/tung/Git/lagofast_vpn/packaging/arch/lagofast-vpn.install) automatically purges known leftover diagnostic routes.

---

## 4. Smart Connect-Time Node Selection Algorithm

### Motivation & Problem Solved
Early implementations used a single UDP ping probe or required manual node pinning in the NetworkManager profile (`node_ip=...`). A single ping probe was susceptible to transient Wi-Fi drops and could not distinguish between direct low-latency subsea routes and multi-hop transit backhauls.

### Multi-Probe Stability Formula
Implemented in `pkg/api/client.go` (`benchmarkNodes`):
1. **Probe Configuration:**
   - 6 sequential probes per node.
   - Spacing: 80 ms between probes.
   - Timeout: 500 ms per probe.
   - Concurrency: Up to 15 worker goroutines simultaneously.
2. **Metrics Measured:**
   - Minimum RTT ($RTT_{\min}$)
   - Average RTT ($RTT_{\text{avg}}$)
   - Maximum RTT ($RTT_{\max}$)
   - Mean absolute jitter: $Jitter = \frac{1}{N} \sum |RTT_i - RTT_{\text{avg}}|$
   - Packet loss rate: $LossRate = \frac{FailedProbes}{TotalProbes}$
3. **Scoring Function:**
   $$\text{Score} = RTT_{\text{avg}} \text{ (ms)} + 2.5 \times Jitter \text{ (ms)} + (LossRate \times 150)$$
   - Jitter is penalized $2.5\times$ to avoid routes prone to micro-stutter.
   - Nodes with $>40\%$ packet loss are disqualified.
   - The node with the minimum score is selected.
4. **Speed:** The entire benchmark finishes in **~2.8 seconds**.

### Relay Topologies: Direct vs Two-Node Backhaul
- **Direct Singapore Nodes:** (e.g. `Singapore-P1738` `150.109.94.71`, `Singapore-P1739` `43.153.212.197`).
  - Ping from Vietnam: **~31–34 ms**.
  - Route: Direct subsea cable (APG / AAE-1). Best for twitch/competitive gaming.
- **Two-Node Dedicated Backhaul Lines:** (e.g. `HongKong-Singapore-P1754` `101.32.23.5`).
  - Ping from Vietnam: **~45–46 ms**.
  - Route: Jumps through Hong Kong, then dedicated IPLC cross-border line to Singapore. Higher latency, but near-zero jitter (0.5 ms).
- **Domestic Vietnam Nodes:** LagoFast does not operate in-country relay nodes in Vietnam due to domestic telecom licensing / Decree 53.

---

## 5. Wine / Proton Gaming Pitfalls & Edge Cases

### Interface Detachment & Path MTU Collapse (The `mss: 48` Bug)
> [!CAUTION]
> **DO NOT restart or cycle the VPN connection while the game process is running.**

**Phenomenon:**
If a Wine/Proton game (`wwm.exe`) is running on tunnel interface `lagofast0` (interface index `95`), and the VPN is cycled:
1. Interface index `95` is destroyed and index `96` is created.
2. Existing game sockets held open in Wine/wineserver become detached from the valid interface.
3. The Linux kernel Path MTU Discovery collapses the PMTU for detached sockets down to **68 bytes** (the IPv4 theoretical minimum), yielding **`mss: 48 bytes`**.
4. The socket's `Send-Q` backs up (e.g. `Send-Q: 8224`), TCP window collapses (`backoff: 6`), and all server communication stalls.

**Rule:**
Always ensure `lagofast0` is up and active **before** starting the game process.

### TCP Congestion Control & Buffer Bloat
Wine games often negotiate `dctcp` (Data Center TCP). When connecting across the public internet without an end-to-end ECN path, the Linux kernel degrades `dctcp` into `dctcp-reno`. On minor transit spikes, Reno halves the congestion window (`cwnd: 10`), causing `rcv_rtt` to skyrocket to ~184ms.

**Remedy:**
`liblagofast_bind.so` enforces **BBR** (`TCP_CONGESTION = "bbr"`), which bases its congestion window on actual bottleneck bandwidth and round-trip propagation time rather than packet jitter.

### Longest Prefix Match (LPM) Hijacking
Game combat servers often use specific subnets like `47.84.156.0/24`. If any manual route on `wlan0` matches `/24`, the kernel will send combat packets unencrypted over the physical interface, while game authentication/sync on `47.84.0.0/16` routes through `lagofast0`. This produces a split-brain state where the game connects but actions do not register.

---

## 6. Packaging, Build & Deployment

### Build Commands
```bash
# Build Go binaries and native shared libraries
make build

# Package for Arch Linux / CachyOS (makepkg)
make package
```

### Installation
Always use `pkexec` when running root commands on Linux:
```bash
pkexec pacman -U /home/tung/Git/lagofast_vpn/packaging/arch/lagofast-vpn-1.0.0-1-x86_64.pkg.tar.zst --overwrite "*" --noconfirm
```

### NetworkManager Profile Configuration
To use automatic multi-probe node selection:
```bash
# Set game and zone, leaving node_ip blank or 'auto'
nmcli connection modify LagoFast-WWM vpn.data "game_id=54758,zone_id=45983"

# Connect
nmcli connection up LagoFast-WWM
```

To pin a specific node if ever required:
```bash
nmcli connection modify LagoFast-WWM vpn.data "game_id=54758,zone_id=45983,node_ip=150.109.94.71"
```

---

## 7. Standard Diagnostic & Verification Commands

### 1. Verify Active Tunnel & Routes
```bash
# Check interface status and MTU
ip addr show dev lagofast0

# Verify game subnet routes point to 10.10.10.1
ip route show dev lagofast0 | head -n 15

# Verify relay node bypasses tunnel via physical interface
ip route get 150.109.94.71
```

### 2. Inspect Connection Logs
```bash
# Check node benchmark scoring and selection
journalctl -u NetworkManager --since "2 minutes ago" --no-pager | grep -iE "NM-LagoFast|Selected optimal node"
```

### 3. Check Live Game Sockets
```bash
# Check running game sockets, MSS, PMTU, and Congestion Control
ss -tni 'dst 47.84.0.0/16 or dst 8.208.0.0/12'
ss -u -a '( dport = :4000 or sport = :4000 )'
```

### 4. Known Game Identifiers (Reference)
- **Where Winds Meet (WWM)**:
  - Game ID: `54758`
  - Singapore Zone ID: `45983`
  - Combat Server Subnets: `47.84.0.0/16`, `47.76.0.0/15`, `8.208.0.0/12`
  - Combat UDP Port: `4000`
  - Fast Direct Nodes: `150.109.94.71` (P1738), `43.153.212.197` (P1739)
