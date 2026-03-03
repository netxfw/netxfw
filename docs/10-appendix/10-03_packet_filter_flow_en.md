# netxfw BPF Program Packet Filter Flow Detailed Explanation

## Overall Architecture

netxfw uses eBPF/XDP technology to achieve high-performance packet filtering. The XDP program runs at the earliest stage of the network stack, making filtering decisions before kernel processing, thus achieving the lowest latency and highest throughput.

## Configuration Management System

### Configuration Caching Mechanism
- **Global Cache Variables**: Use `cached_*` variables to store configuration values
- **Version Control**: Implement configuration hot update through `cached_version` and `CONFIG_CONFIG_VERSION`
- **Sampled Update**: Refresh configuration every `CONFIG_REFRESH_INTERVAL` (default 1000) packets

### Configuration Items
- `cached_default_deny`: Default deny policy switch
- `cached_allow_return`: Return traffic allow switch
- `cached_allow_icmp`: ICMP traffic allow switch
- `cached_ct_enabled`: Connection tracking function switch
- `cached_bogon_filter`: Bogon (private/reserved) address filtering switch
- `cached_strict_tcp`: Strict TCP flag check switch
- `cached_ratelimit_enabled`: Rate limiting function switch
- `cached_auto_block`: Automatic blocking function switch
- `cached_auto_block_expiry`: Automatic blocking expiration time

## Packet Processing Flow

### 1. Main Entry Function (`xdp_firewall`)
- **Sampled Configuration Refresh**: Update configuration cache every certain number of packets to reduce overhead
- **Plugin System Support**: Support plugin chain calls through jump table (`jmp_table`)
- **Protocol Distribution**: Distribute to corresponding processing functions (IPv4/IPv6) based on Ethernet protocol field

### 2. IPv4 Packet Processing Flow (`handle_ipv4`)

#### Phase 0: Basic Checks and Anti-spoofing
1. **Sanity Check and Bogon Filtering**
   - If Bogon filtering is enabled (`cached_bogon_filter`)
   - Check if source IP is private/reserved address
   - If yes, drop directly (`XDP_DROP`)

2. **Fragment Check**
   - If fragment filtering is enabled (`cached_drop_frags`)
   - Check IP fragment flags
   - If fragmented packet, drop directly

3. **Protocol Parsing**
   - Parse TCP/UDP headers to get port information
   - Extract TCP flags for subsequent checks

4. **Anti-spoofing Check**
   - Check if source IP is multicast or broadcast address
   - If yes, drop directly

#### Phase 1: Whitelist Check
- **IP+Port Whitelist**: Check if source IP and destination port are in whitelist
- **Action Execution**: Pass directly (`XDP_PASS`) if matched

#### Phase 2: Blacklist Check (Static and Dynamic)
- **Static Blacklist**: Check if source IP is in `lock_list` in LPM format
- **Dynamic Blacklist**: Check if source IP is in LRU Hash format `dyn_lock_list`
- **Priority**: Dynamic blacklist has higher priority than static blacklist
- **Counter Update**: Update match count
- **Action Execution**: Drop directly if matched

#### Phase 2.5: Rate Limiting and SYN Flood Protection
- **Conditional Trigger**: If rate limiting is enabled (`cached_ratelimit_enabled`)
- **SYN Check**: Special rate limiting for SYN packets
- **Action Execution**: Drop if exceeded

#### Phase 3: Connection Tracking
- **Conditional Trigger**: If connection tracking is enabled (`cached_ct_enabled`)
- **Reverse Lookup**: Check if it's return traffic of established connection
- **Timeout Check**: Verify if connection active time is within threshold (`cached_ct_timeout`)
- **Action Execution**: Pass if yes, continue to subsequent checks if no

#### Phase 4: IP+Port Rule Check
- **Exact Match**: Check source IP + destination port combination rules
- **Action Types**: Allow (1), Deny (2) or Continue (0)
- **Action Execution**: Decide based on rule action

#### Phase 5: ICMP Filtering
- **Conditional Trigger**: If protocol is ICMP and ICMP is allowed (`cached_allow_icmp`)
- **Rate Limiting**: Check ICMP rate limiting (`cached_icmp_rate`, `cached_icmp_burst`)
- **Action Execution**: Pass if within limits, drop otherwise

#### Phase 6: Return Traffic Handling
- **Conditional Trigger**: If return traffic allow is enabled (`cached_allow_return`) and connection tracking is disabled
- **Judgment Logic**: TCP ACK packet or high-numbered UDP port (>= 32768)
- **Action Execution**: Pass if conditions met

#### Phase 7: Default Deny/Port Whitelist
- **Conditional Trigger**: If default deny is enabled (`cached_default_deny`)
- **Global Port Whitelist**: Check if destination port is in global allowed list (`allowed_ports`)
- **Action Execution**: Pass if in whitelist, drop otherwise

### 3. IPv6 Packet Processing Flow (`handle_ipv6`)

IPv6 processing flow is basically the same as IPv4, with main differences:

1. **Protocol Headers**: Use IPv6 header structure (`ipv6hdr`) and next header field (`nexthdr`)
2. **Address Format**: Use 128-bit IPv6 address structure
3. **ICMPv6**: Support ICMPv6 protocol
4. **Mapping Tables**: Use IPv6 specific mapping tables (e.g., `conntrack_map6`, `dyn_lock_list6`, etc.)

## Dynamic Blacklist System

### Dynamic Blacklist Features
- **Data Structure**: Use LRU Hash table (`dyn_lock_list` / `dyn_lock_list6`)
- **Capacity Limit**: LRU mechanism ensures least recently used entries are automatically cleared
- **Automatic Blocking**: Support automatic blocking based on traffic patterns
- **Expiration Time**: Support automatic expiration based on `cached_auto_block_expiry`

### Static vs Dynamic Blacklist
- **Static Blacklist (`lock_list`)**:
  - Use LPM Trie structure
  - Support CIDR subnet matching
  - Suitable for long-term blocking rules
- **Dynamic Blacklist (`dyn_lock_list`)**:
  - Use LRU Hash structure
  - Only support single IP matching
  - Suitable for temporary blocking and automatic blocking
  - Higher priority than static blacklist

### User Space Management
- **CLI Command**: `./netxfw display lock` command displays both static and dynamic blacklists
- **Identification**: Dynamic blacklist entries are marked with "(auto)" suffix for distinction
- **Synchronization**: Synchronize data between kernel and user space through BPF mapping tables

## Performance Optimization Strategies

### 1. Sampled Configuration Refresh
- **Reduce Overhead**: Don't read configuration for every packet
- **Balance Update Frequency**: Update configuration every 1000 packets
- **Maintain Real-time**: Balance between performance and configuration update

### 2. Early Filtering Strategy
- **Priority Sorting**: Sort filtering steps by threat level and check cost
- **Fast Path**: Most common legitimate traffic takes shortest path
- **Early Drop**: Malicious traffic is identified and dropped in early stages

### 3. Memory Access Optimization
- **Cache Locality**: Related data structures are closely arranged in memory
- **Minimize Lookup**: Use efficient data structures (LPM trie, hash map)
- **Batch Operations**: Use atomic operations where appropriate

## Security Features

### 1. Multi-layer Defense
- **Protocol Level**: TCP/UDP compliance checks
- **Network Level**: IP spoofing protection, Bogon filtering
- **Application Level**: IP+port rules, rate limiting

### 2. Adaptive Protection
- **Dynamic Configuration**: Support runtime configuration adjustment
- **Self-learning**: Understand normal communication patterns through connection tracking
- **Automation**: Support automatic blocking of abnormal traffic

## Scalability Design

### 1. Plugin Architecture
- **Modular**: Decompose functions into independent modules
- **Plugin System**: Support function expansion through jump table
- **Hot Loading**: Support function addition/removal at runtime

### 2. Configuration-driven
- **Strategy Variable**: Behavior completely determined by configuration
- **Remote Management**: Support remote configuration update
- **Version Control**: Configuration changes are traceable

## Data Flow Diagram

```
Packet Arrival → Protocol Recognition → [IPv4] → Sanity Check → Anti-spoofing → Whitelist → Dynamic Blacklist → Static Blacklist → Rate Limiting → Connection Tracking → IP+Port Rules → ICMP → Return Traffic → Default Policy → Decision (XDP_PASS/DROP)

                     ↓
                  [IPv6] → (Same as above, adapted for IPv6 format)
```

## Summary

netxfw's filtering flow adopts a multi-layer, multi-stage security strategy, forming a complete security protection system from basic protocol compliance checks to advanced application layer rule matching. Through carefully designed processing order and efficient BPF code, it achieves high-performance packet filtering capability. The configuration management system ensures runtime flexibility, while performance optimization strategies guarantee stable operation under high load. The dynamic blacklist system provides automated threat response capability, forming a complete access control system combined with static blacklist.