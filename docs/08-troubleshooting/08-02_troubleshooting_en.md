# Troubleshooting Guide

This document provides diagnosis and solutions for common netxfw issues.

## Table of Contents

1. [Common Errors and Solutions](#common-errors-and-solutions)
2. [Log Analysis](#log-analysis)
3. [Performance Issue Diagnosis](#performance-issue-diagnosis)
4. [BPF Map Issues](#bpf-map-issues)
5. [Network Connection Issues](#network-connection-issues)
6. [Daemon Issues](#daemon-issues)

---

## Common Errors and Solutions

### 1. Permission Denied Error

**Error Message**:
```
Error: permission denied
Error: failed to pin BPF map: operation not permitted
```

**Cause**: XDP programs require root privileges or `CAP_BPF`, `CAP_NET_ADMIN` capabilities.

**Solutions**:
```bash
# Run with sudo
sudo netxfw start

# Or grant necessary capabilities
sudo setcap cap_bpf,cap_net_admin,cap_sys_admin+ep /usr/bin/netxfw
```

### 2. BPF Program Load Failure

**Error Message**:
```
Error: failed to load BPF program: invalid argument
Error: BPF program load failed
```

**Possible Causes and Solutions**:

| Cause | Solution |
|-------|----------|
| Kernel version too low | Upgrade to Linux 5.10+ |
| BTF not supported | Enable `CONFIG_DEBUG_INFO_BTF` |
| Insufficient memory | Check and free memory |
| Map size limit exceeded | Reduce Map capacity configuration |

**Check Kernel Support**:
```bash
# Check kernel version
uname -r

# Check BTF support
ls /sys/kernel/btf/vmlinux

# Check XDP support
bpftool feature | grep xdp
```

### 3. Interface Binding Failure

**Error Message**:
```
Error: failed to attach XDP program: no such device
Error: interface eth0 not found
```

**Solutions**:
```bash
# List available interfaces
ip link show

# Check interface status
ip link show eth0

# Ensure interface is UP
sudo ip link set eth0 up
```

### 4. Map Operation Failure

**Error Message**:
```
Error: map not found
Error: key does not exist
Error: map update failed
```

**Diagnostic Steps**:
```bash
# List all BPF Maps
sudo bpftool map list

# View Map details
sudo bpftool map show name whitelist

# View Map contents
sudo bpftool map dump name whitelist
```

### 5. Configuration File Error

**Error Message**:
```
Error: invalid configuration
Error: yaml: unmarshal errors
```

**Solutions**:
```bash
# Validate configuration file syntax
python3 -c "import yaml; yaml.safe_load(open('/etc/netxfw/config.yaml'))"

# Or use netxfw validation
sudo netxfw validate --config /etc/netxfw/config.yaml
```

---

## Log Analysis

### Log Locations

| Log Type | Location |
|----------|----------|
| Daemon Log | `/var/log/netxfw/daemon.log` |
| Audit Log | `/var/log/netxfw/audit.log` |
| Error Log | `/var/log/netxfw/error.log` |

### Log Levels

```yaml
# Set log level in configuration
log:
  level: info  # debug, info, warn, error
  output: /var/log/netxfw/daemon.log
```

### Common Log Analysis Commands

```bash
# View recent errors
sudo tail -100 /var/log/netxfw/error.log

# Real-time log monitoring
sudo tail -f /var/log/netxfw/daemon.log

# Search for specific errors
sudo grep -i "error\|failed" /var/log/netxfw/*.log

# Count error types
sudo grep -c "error" /var/log/netxfw/daemon.log
```

### Log Level Description

| Level | Description | Use Case |
|-------|-------------|----------|
| DEBUG | Detailed debug info | Development |
| INFO | Normal operation info | Production |
| WARN | Warning info | Needs attention |
| ERROR | Error info | Needs handling |

---

## Performance Issue Diagnosis

### High CPU Usage

**Diagnostic Steps**:
```bash
# View CPU usage
top -p $(pgrep netxfw)

# Analyze with perf
sudo perf top -p $(pgrep netxfw)

# Generate CPU flame graph
sudo perf record -g -p $(pgrep netxfw) -- sleep 30
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > cpu.svg
```

**Common Causes and Solutions**:

| Cause | Solution |
|-------|----------|
| High traffic volume | Enable hardware offload |
| Frequent Map operations | Use per-CPU Map |
| Too many rules | Optimize rules, use CIDR merge |
| Too many connections | Increase conntrack Map or reduce timeout |

### High Memory Usage

**Diagnostic Steps**:
```bash
# View memory usage
ps aux | grep netxfw

# View BPF Map memory
sudo bpftool map show | grep -E "name|bytes"

# View detailed memory mapping
pmap -x $(pgrep netxfw)
```

**Memory Optimization Suggestions**:
```yaml
# Adjust Map sizes
capacity:
  lock_list: 100000      # Static blacklist
  dyn_lock_list: 50000   # Dynamic blacklist
  conntrack: 50000       # Connection tracking

# Reduce timeout
conntrack:
  timeout: 300           # Connection timeout (seconds)
```

### High Packet Processing Latency

**Diagnostic Steps**:
```bash
# View XDP processing stats
sudo netxfw status -v

# View drop statistics
sudo bpftool map dump name stats_global_map

# Use XDP statistics tool
sudo xdp-stat -d eth0
```

---

## BPF Map Issues

### Map is Full

**Error Message**:
```
Error: map is full
Error: failed to update map: no space left
```

**Solutions**:
```bash
# View current Map usage
sudo netxfw status -v

# Clear dynamic blacklist
sudo netxfw dynamic clear

# Adjust Map size
# Edit /etc/netxfw/config.yaml
capacity:
  dyn_lock_list: 200000
```

### Map Data Inconsistency

**Diagnostic Steps**:
```bash
# Export Map data
sudo bpftool map dump name whitelist > whitelist_backup.txt

# Verify data consistency
sudo netxfw rule list --verify

# Rebuild Map (use with caution)
sudo netxfw stop
sudo rm -rf /sys/fs/bpf/netxfw/*
sudo netxfw start
```

### Map Persistence Issues

**Problem**: Rules lost after restart

**Solutions**:
```yaml
# Ensure persistence files are configured
persistence:
  enabled: true
  lock_list_file: /etc/netxfw/lock_list.txt
  whitelist_file: /etc/netxfw/whitelist.txt
```

```bash
# Manually save rules
sudo netxfw rule export /etc/netxfw/rules.yaml

# Auto-load on startup
sudo netxfw start --load-rules /etc/netxfw/rules.yaml
```

---

## Network Connection Issues

### Cannot Connect to Server

**Diagnostic Steps**:
```bash
# Check if blocked
sudo netxfw deny list
sudo netxfw allow list

# View connection tracking
sudo netxfw conntrack list | grep <IP>

# Check port rules
sudo netxfw rule list

# View real-time drops
sudo netxfw status -v | grep "drop"
```

**Common Causes**:

| Cause | Check Command | Solution |
|-------|---------------|----------|
| IP blocked | `netxfw deny list` | `netxfw deny del <IP>` |
| Default deny policy | `netxfw status` | Add whitelist or allow rule |
| Port blocked | `netxfw rule list` | `netxfw allow port <PORT>` |
| Rate limited | `netxfw limit list` | Adjust or remove limit |

### SSH Connection Blocked

**Emergency Recovery**:
```bash
# Method 1: Via console
sudo netxfw allow add <your-ip>

# Method 2: Direct BPF Map operation
sudo bpftool map update name whitelist key <IP> value 1

# Method 3: Stop firewall
sudo netxfw stop

# Method 4: Remove BPF program
sudo ip link set dev eth0 xdp off
```

### Connection Tracking Issues

**Problem**: Connections cannot be established or disconnect

**Diagnostic Steps**:
```bash
# View connection tracking count
sudo netxfw conntrack count

# View connections for specific IP
sudo netxfw conntrack list | grep <IP>

# Clear expired connections
sudo netxfw conntrack flush --expired
```

---

## Daemon Issues

### Daemon Won't Start

**Diagnostic Steps**:
```bash
# Check process status
sudo systemctl status netxfw

# View startup logs
sudo journalctl -u netxfw -n 100

# Check PID file
ls -la /var/run/netxfw.pid

# Check port usage
sudo netstat -tlnp | grep 11811
```

**Common Problems**:

| Problem | Solution |
|---------|----------|
| PID file exists | `sudo rm /var/run/netxfw.pid` |
| Port in use | `sudo lsof -i :11811` then kill |
| Configuration error | `sudo netxfw validate` |
| Permission issue | `sudo chown -R root:root /etc/netxfw` |

### Daemon Crashes

**Diagnostic Steps**:
```bash
# View core dump
sudo coredumpctl list netxfw
sudo coredumpctl info <ID>

# View system logs
sudo dmesg | grep -i netxfw

# Check memory limits
cat /proc/$(pgrep netxfw)/limits | grep memory
```

### Daemon Not Responding

**Diagnostic Steps**:
```bash
# Check process status
sudo kill -0 $(cat /var/run/netxfw.pid) && echo "Running" || echo "Not running"

# Check goroutine stack
sudo kill -USR1 $(cat /var/run/netxfw.pid)

# View stack output
cat /var/log/netxfw/stack.log
```

---

## Debug Mode

### Enable Debug Mode

```bash
# Enable debug on startup
sudo netxfw start --debug

# Or in configuration file
log:
  level: debug
```

### Debug with bpftool

```bash
# List all BPF programs
sudo bpftool prog list

# View XDP program details
sudo bpftool prog show xdp

# Trace BPF program execution
sudo bpftool prog tracelog

# View BPF helper functions
sudo bpftool feature | grep helper
```

### Debug with bpftrace

```bash
# Trace XDP program entry
sudo bpftrace -e 'kprobe:xdp_generic_pass { @[comm] = count(); }'

# Trace packet drops
sudo bpftrace -e 'kprobe:xdp_drop { @[comm] = count(); }'
```

---

## Contact Support

If the above methods don't resolve your issue:

1. Collect diagnostic information:
```bash
# Collect system info
sudo netxfw debug --collect-info > debug_info.tar.gz
```

2. Submit an Issue: https://github.com/netxfw/netxfw/issues

3. Include the following information:
   - System version (`uname -a`)
   - netxfw version (`netxfw version`)
   - Error logs (`/var/log/netxfw/error.log`)
   - Configuration file (`/etc/netxfw/config.yaml`)
   - Steps to reproduce
