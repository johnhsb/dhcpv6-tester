# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DHCPv6 Client Simulator - A Python-based tool for simulating DHCPv6 clients with real-time terminal dashboard for testing DHCPv6 servers.

## Running the Simulator

**Requirements**: Root/sudo privileges (for raw socket access)

```bash
# Install dependencies
pip install -r requirements.txt

# Basic usage (single client with dashboard)
sudo python3 dhcpv6_simulator.py --interface eth0

# Multiple clients with all features
sudo python3 dhcpv6_simulator.py --interface eth0 --clients 10 --prefix-delegation --renew --duration 180

# Disable dashboard (log mode only)
sudo python3 dhcpv6_simulator.py --interface eth0 --no-dashboard

# Debug mode
sudo python3 dhcpv6_simulator.py --interface eth0 --verbose --no-dashboard
```

**Key CLI Options**:
- `--interface, -i`: Network interface (required)
- `--clients, -c`: Number of simultaneous clients (default: 1)
- `--prefix-delegation, -p`: Enable DHCPv6-PD
- `--duration, -d`: Run duration in seconds (default: 60)
- `--renew`: Enable T1/T2 renewal timers
- `--no-dashboard`: Disable real-time UI
- `--verbose, -v`: Debug logging

## Architecture

### Layer 1: Packet Building (`dhcpv6_packet.py`)
- **DHCPv6Packet** class handles packet construction using Scapy
- Generates DUID (DUID-LLT format), random MAC addresses, transaction IDs
- Builds DHCPv6 messages: SOLICIT, REQUEST, RENEW, REBIND
- Parses ADVERTISE/REPLY messages extracting addresses, prefixes, server DUID
- Supports both IA_NA (address allocation) and IA_PD (prefix delegation)

### Layer 2: Client State Machine (`dhcpv6_client.py`)
- **DHCPv6Client** implements RFC 8415 state machine
- States: INIT → SELECTING → REQUESTING → BOUND → RENEWING/REBINDING
- Each client runs in its own thread with packet sniffing (via scapy.sniff)
- Handles T1 (renew) and T2 (rebind) timers using threading.Timer
- Uses netifaces to auto-detect link-local IPv6 source addresses
- Thread-safe state management for concurrent clients

**State Flow**:
1. SOLICIT → wait for ADVERTISE (SELECTING)
2. REQUEST → wait for REPLY (REQUESTING)
3. BOUND → schedule T1 timer (50% of lifetime) → RENEWING
4. If RENEW fails → T2 timer (80% of lifetime) → REBINDING

### Layer 3: Multi-Client Orchestration (`dhcpv6_simulator.py`)
- **DHCPv6Simulator** manages multiple DHCPv6Client instances
- Uses asyncio event loop with ThreadPoolExecutor for concurrent client startup
- Staggers client initialization (0.5s delay between starts)
- Integrates with dashboard or traditional logging based on `--no-dashboard` flag
- Handles graceful shutdown on SIGINT/SIGTERM

**Threading Model**:
- Main: asyncio event loop
- Per-client: dedicated thread for packet sniffing
- Dashboard: separate thread for Rich Live display (if enabled)

### Layer 4: Real-time Dashboard (`dashboard.py`)
- **DHCPv6Dashboard** generates Rich layouts with 3 sections:
  - Header: Interface, elapsed/remaining time
  - Main (split): Client table + Statistics panel
  - Footer: Recent events, keyboard hints
- **DashboardRunner** wraps Rich's Live() context manager
- Updates at 0.5s intervals (configurable)
- Color-coded states with emoji icons (⚪ INIT, 🔍 SELECTING, ✅ BOUND, etc.)
- Shows success rate percentage based on BOUND clients

## State Management

Clients maintain internal state accessible via `get_status()`:
- `client_id`: String identifier
- `state`: Current DHCPv6 state
- `addresses`: List of assigned IPv6 addresses with lifetimes
- `prefixes`: List of delegated prefixes with prefix length
- `server_duid`: Server identifier (hex bytes)

Dashboard polls this state every refresh cycle.

## DHCPv6 Protocol Implementation

**Standard 4-message exchange**:
```
Client → SOLICIT → Server
Client ← ADVERTISE ← Server
Client → REQUEST → Server
Client ← REPLY ← Server (BOUND state)
```

**Renewal process** (if `--renew` enabled):
```
T1 timer expires → RENEW (unicast to server)
T2 timer expires → REBIND (multicast, any server)
```

**Multicast address**: `ff02::1:2` (All_DHCP_Relay_Agents_and_Servers)
**Ports**: Client 546, Server 547

## Testing DHCPv6 Servers

This tool is designed for:
- Load testing (100+ concurrent clients)
- Prefix delegation verification
- Renewal/rebind behavior testing
- Server response time monitoring via dashboard

Requires actual DHCPv6 server on network (e.g., ISC Kea, dnsmasq, Windows DHCP).

## Common Modifications

**Adding new DHCPv6 message types**:
1. Add constants in `dhcpv6_packet.py`
2. Add `build_*()` method in DHCPv6Packet class
3. Add state in DHCPv6Client (e.g., STATE_RELEASING)
4. Add handler in `_handle_packet()` and send method

**Customizing dashboard**:
- Modify `_generate_*()` methods in DHCPv6Dashboard
- STATE_COLORS dict controls icons and colors
- Layout structure in `generate_layout()`

**Adjusting timers**:
- T1/T2 calculation in `_handle_reply()`: Currently 50%/80% of valid_lifetime
- Client startup stagger: `asyncio.sleep(0.5)` in simulator.start()
