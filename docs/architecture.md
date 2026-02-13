# netxfw Architecture Design

## Overview
`netxfw` is a high-performance, programmable firewall built on **eBPF (Extended Berkeley Packet Filter)** and **XDP (eXpress Data Path)**. It operates at the earliest possible point in the Linux networking stack (the driver hook), allowing it to drop or redirect packets with minimal CPU overhead before they reach the kernel's networking stack (`sk_buff` allocation).

## Core Components

### 1. Data Plane (eBPF/XDP)
The data plane is written in C and compiled into BPF bytecode. It runs directly in the kernel.
*   **Location**: `bpf/`
*   **Key Features**:
    *   **Unified LPM Trie**: Uses a single 128-bit Longest Prefix Match (LPM) Trie for both IPv4 and IPv6 traffic. IPv4 addresses are handled as IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`).
    *   **Lockless Design**: Uses per-CPU arrays and hash maps for statistics to minimize locking contention.
    *   **XDP Actions**: Supports `XDP_DROP` (Block), `XDP_PASS` (Allow), and `XDP_TX` (Bounce - planned).

### 2. Control Plane (Go Agent)
The control plane is written in Go and runs in user space. It manages the lifecycle of the BPF programs and interacts with BPF maps.
*   **Location**: `cmd/netxfw`, `internal/`
*   **Responsibilities**:
    *   **Loading/Unloading**: Uses `cilium/ebpf` library to load XDP programs and pin maps to `/sys/fs/bpf/netxfw`.
    *   **Map Management**: CRUD operations on BPF maps (adding/removing rules).
    *   **Persistence**: Syncs in-memory BPF map state to `/etc/netxfw/rules.deny.txt` and `config.yaml`.
    *   **CLI**: Provides a user-friendly command-line interface (`netxfw rule add`, `netxfw system top`).

## Unified Dual-Stack Architecture
To simplify maintenance and reduce memory footprint, `netxfw` uses a unified map strategy:
*   **Map**: `lock_list` (LPM Trie)
*   **Key**: `struct lpm_key` (128-bit IPv6 address + Prefix Length)
*   **IPv4 Handling**:
    *   User Input: `192.0.2.1`
    *   Internal Conversion: `::ffff:192.0.2.1`
    *   Storage: Stored in the 128-bit trie.
    *   Lookup: Incoming IPv4 packets are constructed into an IPv4-mapped IPv6 key before lookup.

## Directory Structure
*   `bpf/`: eBPF source code (`.c`) and headers.
*   `cmd/netxfw/`: Main entry point for the Go binary.
*   `internal/core/`: Business logic for rule management.
*   `internal/xdp/`: Low-level BPF interaction (loading, map wrappers).
*   `rules/`: Default configuration files.
*   `test/`: Integration and unit tests.

## Data Flow
1.  **Packet Arrival**: NIC receives packet -> XDP Driver Hook.
2.  **Parsing**: `filter.bpf.c` parses Ethernet -> IP (v4/v6) -> L4 headers.
3.  **Lookup**:
    *   Checks `whitelist` (Allow).
    *   Checks `lock_list` (Deny).
    *   Checks `ip_port_rules` (Fine-grained).
4.  **Decision**:
    *   If Match Deny -> `XDP_DROP` + Increment Drop Counter.
    *   If No Match -> `XDP_PASS` (Proceed to kernel stack).

## Persistence Model
*   **Runtime**: `/sys/fs/bpf/netxfw/*` (Pinned BPF Maps).
*   **Storage**: `/etc/netxfw/rules.deny.txt` (Plain text list) & `config.yaml`.
*   **Sync**: `netxfw system sync` commands handle bidirectional synchronization between Runtime and Storage.
