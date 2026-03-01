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
    *   **Load/Unload**: Loads XDP programs using `cilium/ebpf` and pins Maps to `/sys/fs/bpf/netxfw_v2`.
    *   **Map Management**: CRUD operations on BPF Maps (add/remove rules).
    *   **Persistence**: Syncs in-memory BPF Map state to `rules.deny.txt` and `config.yaml`.
    *   **CLI**: User-friendly command-line interface (`netxfw rule add`, `netxfw system top`).

## Unified Dual-Stack Architecture
To simplify maintenance and reduce memory usage, `netxfw` uses a unified Map strategy:
*   **Map**: `lock_list` (LPM Trie)
*   **Key**: `struct lpm_key` (128-bit IPv6 address + prefix length)
*   **IPv4 Handling**:
    *   User input: `192.0.2.1`
    *   Internal conversion: `::ffff:192.0.2.1`
    *   Storage: Stored in the 128-bit Trie.
    *   Lookup: Incoming IPv4 packets are constructed as IPv4-mapped IPv6 Keys before lookup.

## Directory Structure
*   `bpf/`: eBPF source code (`.c`) and headers.
*   `cmd/netxfw/`: Main entry point for the Go binary.
*   `internal/core/`: Business logic for rule management.
*   `internal/xdp/`: Low-level BPF interaction (loading, Map wrappers).
*   `rules/`: Default configuration files.
*   `test/`: Integration and unit tests.

## Data Flow
1.  **Packet Arrival**: NIC receives packet -> XDP driver hook.
2.  **Parsing**: `filter.bpf.c` parses Ethernet -> IP (v4/v6) -> L4 headers.
3.  **Lookup**:
    *   Check `whitelist` (Allow).
    *   Check `lock_list` (Block).
    *   Check `ip_port_rules` (Fine-grained).
4.  **Decision**:
    *   If Match Deny -> `XDP_DROP` + Increment drop counter.
    *   If No Match -> `XDP_PASS` (Continue to kernel stack).

## Persistence Model
*   **Runtime**: `/sys/fs/bpf/netxfw_v2/*` (Pinned BPF Maps).
*   **Storage**: `rules.deny.txt` (Plain text list) & `config.yaml`.
*   **Sync**: `netxfw system sync` command handles bidirectional sync between runtime state and storage.
