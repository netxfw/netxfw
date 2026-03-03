# Performance Tuning Guide

This document provides detailed guidance for optimizing netxfw performance across different scenarios.

## Table of Contents

1. [Performance Benchmarks](#performance-benchmarks)
2. [Hardware Optimization](#hardware-optimization)
3. [Kernel Parameter Tuning](#kernel-parameter-tuning)
4. [BPF Map Optimization](#bpf-map-optimization)
5. [CPU Optimization](#cpu-optimization)
6. [Memory Optimization](#memory-optimization)
7. [Network Optimization](#network-optimization)
8. [Monitoring and Diagnostics](#monitoring-and-diagnostics)

---

## Performance Benchmarks

### Expected Performance Metrics

| Scenario | Packet Rate (PPS) | Latency | CPU Usage |
|----------|-------------------|---------|-----------|
| Empty rules | 10M+ | <1μs | <5% |
| 1000 rules | 8M+ | <2μs | <10% |
| 10000 rules | 5M+ | <5μs | <20% |
| Conntrack (100K) | 3M+ | <10μs | <30% |

### Performance Testing Tools

```bash
# Generate test traffic with pktgen
sudo modprobe pktgen
echo "add_device eth0" > /proc/net/pktgen/pgctrl

# Use XDP statistics tool
sudo xdp-stat -d eth0 -i 1

# Analyze with perf
sudo perf stat -e cycles,instructions,cache-misses -p $(pgrep netxfw)
```

---

## Hardware Optimization

### NIC Selection

| Feature | Recommended NIC | Performance Impact |
|---------|-----------------|-------------------|
| XDP Support | Intel X520/X540/X710 | High |
| Multi-queue | Mellanox ConnectX-5 | High |
| Hardware Offload | XDP offload capable NICs | Very High |

### CPU Configuration

```bash
# View CPU topology
lscpu

# View NUMA nodes
numactl --hardware

# Bind NIC interrupts to specific CPUs
sudo /sbin/irqbalance --oneshot
```

### Memory Configuration

```bash
# View huge pages
cat /proc/meminfo | grep Huge

# Configure huge pages (recommended)
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Configure in boot parameters
# GRUB_CMDLINE_LINUX="default_hugepagesz=2M hugepagesz=2M hugepages=1024"
```

---

## Kernel Parameter Tuning

### Network Parameters

```bash
# Increase network buffers
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
sudo sysctl -w net.core.rmem_default=33554432
sudo sysctl -w net.core.wmem_default=33554432

# Increase backlog queue
sudo sysctl -w net.core.netdev_max_backlog=30000

# Enable RPS (Receive Packet Steering)
sudo sysctl -w net.core.rps_sock_flow_entries=32768

# TCP parameter optimization
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"
sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 134217728"
```

### BPF Related Parameters

```bash
# Increase BPF JIT limit
sudo sysctl -w net.core.bpf_jit_limit=1000000000

# Enable BPF statistics
sudo sysctl -w kernel.bpf_stats_enabled=1

# Increase lockable memory
sudo sysctl -w vm.max_map_count=262144
```

### Persistent Configuration

```bash
# Write to /etc/sysctl.d/99-netxfw.conf
cat << 'EOF' | sudo tee /etc/sysctl.d/99-netxfw.conf
# Network buffer optimization
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.core.netdev_max_backlog = 30000

# BPF optimization
net.core.bpf_jit_limit = 1000000000
kernel.bpf_stats_enabled = 1

# Memory
vm.max_map_count = 262144
EOF

sudo sysctl -p /etc/sysctl.d/99-netxfw.conf
```

---

## BPF Map Optimization

### Map Type Selection

| Map Type | Use Case | Performance Characteristics |
|----------|----------|----------------------------|
| LPM_TRIE | IP/CIDR lookup | O(log n) lookup |
| LRU_HASH | Dynamic blacklist | Auto eviction |
| PERCPU_HASH | Statistics counting | Lock-free concurrent |
| ARRAY | Fixed index | O(1) lookup |

### Map Size Configuration

```yaml
# /etc/netxfw/config.yaml
capacity:
  # Conntrack - adjust based on concurrent connections
  conntrack: 100000

  # Static blacklist - adjust based on blocked IP count
  lock_list: 50000

  # Dynamic blacklist - LRU auto eviction
  dyn_lock_list: 100000

  # Whitelist - usually small
  whitelist: 1000

  # IP+Port rules
  ip_port_rules: 10000

  # Rate limit rules
  rate_limits: 1000
```

### Memory Calculation

```bash
# Calculate Map memory usage
# LPM_TRIE: ~100 bytes per entry
# LRU_HASH: ~80 bytes per entry

# Example calculation
# conntrack: 100,000 × 80B = 8 MB
# lock_list: 50,000 × 100B = 5 MB
# dyn_lock_list: 100,000 × 80B = 8 MB
# Total: ~21 MB
```

---

## CPU Optimization

### CPU Affinity

```bash
# Bind NIC queues to specific CPUs
for i in /sys/class/net/eth0/queues/rx-*/rps_cpus; do
    echo f > "$i"
done

# Bind netxfw process to specific CPUs
sudo taskset -pc 0-3 $(pgrep netxfw)
```

### Interrupt Balancing

```bash
# View NIC interrupts
cat /proc/interrupts | grep eth0

# Configure SMP affinity
# Distribute interrupts across different CPUs
for irq in $(grep eth0 /proc/interrupts | cut -d: -f1); do
    echo $((1 << (irq % 4))) > /proc/irq/$irq/smp_affinity
done
```

### RPS/RFS Configuration

```bash
# Enable RPS
for i in /sys/class/net/eth0/queues/rx-*/rps_cpus; do
    echo f > "$i"
done

# Configure RFS
echo 32768 > /sys/class/net/eth0/queues/rx-0/rps_flow_cnt

# Enable RFS
sysctl -w net.core.rps_sock_flow_entries=32768
```

---

## Memory Optimization

### Memory Allocation Optimization

```yaml
# Memory optimization in configuration
capacity:
  # Avoid over-allocation
  conntrack: 50000
  lock_list: 20000
  dyn_lock_list: 50000

# Conntrack timeout
conntrack:
  timeout: 300  # Shorten timeout to release memory
```

### Huge Page Usage

```bash
# Configure huge pages
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Check huge page usage
cat /proc/meminfo | grep HugePages

# Enable huge pages in netxfw (if supported)
# Requires kernel support for BPF_MAP_TYPE_PACKED
```

### Memory Monitoring

```bash
# Monitor memory usage
watch -n 1 'ps aux | grep netxfw'

# View BPF Map memory
sudo bpftool map show | grep -E "name|bytes"

# View memory details
cat /proc/$(pgrep netxfw)/status | grep -E "VmRSS|VmSize"
```

---

## Network Optimization

### XDP Mode Selection

| Mode | Performance | Feature Limitations | Recommended Scenario |
|------|-------------|---------------------|---------------------|
| Native (driver mode) | Highest | Some features limited | High performance |
| Generic (skb mode) | Medium | No limitations | Compatibility first |
| Offload (hardware) | Very High | Features limited | Specific NICs |

```bash
# Specify XDP mode
sudo netxfw start --xdp-mode native  # or generic, offload
```

### Batch Processing

```yaml
# Enable AF_XDP batch processing (requires hardware support)
af_xdp:
  enabled: true
  batch_size: 64
  fill_size: 2048
  comp_size: 2048
```

### GRO/LRO Configuration

```bash
# Enable GRO (Generic Receive Offload)
sudo ethtool -K eth0 gro on

# Enable LRO (Large Receive Offload)
sudo ethtool -K eth0 lro on

# View current configuration
sudo ethtool -k eth0 | grep -E "gro|lro"
```

---

## Monitoring and Diagnostics

### Performance Monitoring

```bash
# Real-time performance monitoring
sudo netxfw status -v

# View processing rate
watch -n 1 'sudo netxfw status | grep pps'

# View drop statistics
sudo bpftool map dump name stats_global_map
```

### Performance Analysis Tools

```bash
# Analyze CPU hotspots with perf
sudo perf record -g -p $(pgrep netxfw) -- sleep 10
sudo perf report

# Generate flame graph
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > flame.svg

# Analyze with bpftrace
sudo bpftrace -e 'profile:hz:99 /pid == '$(pgrep netxfw)'/ { @[ustack] = count(); }'
```

### Performance Metrics

```bash
# View key metrics
sudo netxfw status -v | grep -E "PPS|BPS|CPU|Memory"

# View latency distribution
sudo bpftrace -e 'kprobe:xdp_generic_pass { @start[tid] = nsecs; } kretprobe:xdp_generic_pass /@start[tid]/ { @latency = hist(nsecs - @start[tid]); delete(@start[tid]); }'
```

---

## Scenario Optimization Recommendations

### High Traffic Scenario (10Gbps+)

```yaml
capacity:
  conntrack: 500000
  lock_list: 100000
  dyn_lock_list: 200000

conntrack:
  timeout: 180

# Enable XDP native mode
xdp_mode: native

# Enable hardware offload (if supported)
offload: true
```

### Low Latency Scenario

```yaml
# Reduce rule count
capacity:
  lock_list: 5000
  whitelist: 100

# Shorten timeout
conntrack:
  timeout: 60

# Disable unnecessary features
features:
  rate_limit: false
  log_engine: false
```

### High Concurrency Scenario

```yaml
capacity:
  conntrack: 1000000
  dyn_lock_list: 500000

conntrack:
  timeout: 300

# Increase worker threads
workers: 4
```

### Low Memory Scenario (512MB)

```yaml
capacity:
  conntrack: 20000
  lock_list: 5000
  dyn_lock_list: 10000
  whitelist: 30
  ip_port_rules: 50

conntrack:
  timeout: 120

# Disable non-essential features
features:
  rate_limit: false
  top_stats: false
```

---

## Performance Tuning Checklist

- [ ] Kernel version >= 5.10
- [ ] BPF JIT enabled
- [ ] Appropriate Map sizes configured
- [ ] RPS/RFS enabled
- [ ] Interrupt balancing configured
- [ ] Network buffers optimized
- [ ] Correct XDP mode selected
- [ ] CPU/Memory usage monitored
- [ ] Expired data cleaned regularly
- [ ] Stress test validation
