# LagoFast VPN Linux Client & NetworkManager Plugin

A native Linux client and NetworkManager VPN plugin for **LagoFast / Qiyou Game Booster**, enabling low-latency gaming routing on desktop Linux, SteamOS (Steam Deck), and gaming distributions (Bazzite, Nobara, Arch, Fedora, Ubuntu).

---

## Architecture Overview

```
                               ┌─────────────────────────────┐
                               │   NetworkManager / nmcli    │
                               └──────────────┬──────────────┘
                                              │ (D-Bus)
                                              ▼
┌───────────────────────┐      ┌─────────────────────────────┐
│     lagofast CLI      │      │     nm-lagofast-service     │
│ (Login / Games / Tun) │      │ (NM VPN Plugin D-Bus Server)│
└───────────┬───────────┘      └──────────────┬──────────────┘
            │                                 │
            └────────────────┬────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────┐
│                    Go Core Controller                      │
│                                                            │
│  ┌───────────────────────┐      ┌───────────────────────┐  │
│  │     pkg/api Client    │      │    pkg/tunnel (TUN)   │  │
│  │   (LagoFast REST API) │      │   (/dev/net/tun 1400) │  │
│  └───────────┬───────────┘      └───────────┬───────────┘  │
└──────────────┼──────────────────────────────┼──────────────┘
               │                              │
               ▼                              ▼
     cbs.lagofast.com               lagofast0 (Linux Kernel)
 (Auth, Game Catalog, Nodes)         (Split-tunnel Game IP CIDRs)
```

---

## Features

- **NetworkManager VPN Plugin (`nm-lagofast-service`)**:
  - Implements the standard `org.freedesktop.NetworkManager.VPN.Plugin` D-Bus interface.
  - Can be activated, monitored, and disconnected using `nmcli` or standard desktop environment network applets.
- **Standalone CLI (`lagofast`)**:
  - `lagofast login`: Authenticate credentials with the LagoFast cloud.
  - `lagofast games`: Search and browse live game IDs.
  - `lagofast nodes`: Query low-latency relay nodes for any game.
  - `lagofast connect`: Spin up a dedicated game acceleration tunnel.
- **Anti-Cheat Safe**:
  - Operates purely at the network layer (`/dev/net/tun`) without injecting into game processes or using `LD_PRELOAD`.
  - Fully compatible with Easy Anti-Cheat (EAC), BattlEye, and VAC under Proton/Wine.

---

## Building & Installation

### 1. Build Binaries
```bash
make build
```
Binaries will be placed in `./bin/`:
- `bin/lagofast`: Standalone CLI utility
- `bin/nm-lagofast-service`: NetworkManager D-Bus VPN service daemon

### 2. Install NetworkManager Plugin
To register the plugin with NetworkManager and D-Bus:
```bash
./scripts/install-nm-plugin.sh
```
*(Uses `pkexec` to authenticate root privileges securely).*

This installs:
- `/usr/local/bin/nm-lagofast-service`
- `/usr/local/bin/lagofast`
- `/etc/NetworkManager/VPN/nm-lagofast-service.name`
- `/etc/dbus-1/system.d/org.freedesktop.NetworkManager.lagofast.conf`

---

## Usage

### NetworkManager (`nmcli`)

Add a LagoFast VPN connection:
```bash
nmcli connection add \
  type vpn \
  vpn-type lagofast \
  con-name "LagoFast-Warzone" \
  vpn.data "username=your_email@example.com,password=your_password,game_id=13975"
```

Activate the connection:
```bash
nmcli connection up "LagoFast-Warzone"
```

Deactivate:
```bash
nmcli connection down "LagoFast-Warzone"
```

---

### Standalone CLI

#### 1. Search Games
```bash
./bin/lagofast games -q "duty"
```
Example Output:
```
GAME ID    NAME                           PACKAGE
----------------------------------------------------------------------
13958      Call of Duty®: Mobile          com.activision.callofduty.shooter
13975      Call of Duty Warzone Mobile    com.activision.callofduty.warzone
39700      Easy Lobby - CoD Series        com.activision.callofduty.warzone
```

#### 2. Query Relay Nodes
```bash
./bin/lagofast nodes -g 13958
```

#### 3. Login & Connect
```bash
./bin/lagofast login -u "your_email@example.com" -p "your_password"
sudo ./bin/lagofast connect -g 13958
```

---

## Project Structure

```
├── cmd/
│   ├── lagofast/              # Standalone CLI entrypoint
│   └── nm-lagofast-service/   # NetworkManager D-Bus service binary
├── pkg/
│   ├── api/                   # LagoFast / Qiyou REST API client
│   ├── model/                 # Data structures & VpnConfigModel
│   ├── nm/                    # NetworkManager D-Bus plugin implementation
│   └── tunnel/                # Linux TUN interface controller
├── config/
│   ├── nm-lagofast-service.name
│   └── org.freedesktop.NetworkManager.lagofast.conf
└── scripts/
    └── install-nm-plugin.sh
```
