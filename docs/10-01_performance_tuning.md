# 性能调优指南 (Performance Tuning Guide)

本文档提供 netxfw 性能优化的详细指南，帮助您在不同场景下获得最佳性能。

## 目录

1. [性能基准](#性能基准)
2. [硬件优化](#硬件优化)
3. [内核参数调优](#内核参数调优)
4. [BPF Map 优化](#bpf-map-优化)
5. [CPU 优化](#cpu-优化)
6. [内存优化](#内存优化)
7. [网络优化](#网络优化)
8. [监控与诊断](#监控与诊断)

---

## 性能基准

### 预期性能指标

| 场景 | 包率 (PPS) | 延迟 | CPU 使用率 |
|------|-----------|------|-----------|
| 空规则 | 10M+ | <1μs | <5% |
| 1000 条规则 | 8M+ | <2μs | <10% |
| 10000 条规则 | 5M+ | <5μs | <20% |
| 连接跟踪 (100K) | 3M+ | <10μs | <30% |

### 性能测试工具

```bash
# 使用 pktgen 生成测试流量
sudo modprobe pktgen
echo "add_device eth0" > /proc/net/pktgen/pgctrl

# 使用 XDP 统计工具
sudo xdp-stat -d eth0 -i 1

# 使用 perf 分析
sudo perf stat -e cycles,instructions,cache-misses -p $(pgrep netxfw)
```

---

## 硬件优化

### 网卡选择

| 特性 | 推荐网卡 | 性能影响 |
|------|----------|----------|
| XDP 支持 | Intel X520/X540/X710 | 高 |
| 多队列 | Mellanox ConnectX-5 | 高 |
| 硬件卸载 | 支持 XDP offload 的网卡 | 极高 |

### CPU 配置

```bash
# 查看 CPU 拓扑
lscpu

# 查看 NUMA 节点
numactl --hardware

# 绑定网卡中断到特定 CPU
sudo /sbin/irqbalance --oneshot
```

### 内存配置

```bash
# 查看大页内存
cat /proc/meminfo | grep Huge

# 配置大页内存 (推荐)
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# 在启动参数中配置
# GRUB_CMDLINE_LINUX="default_hugepagesz=2M hugepagesz=2M hugepages=1024"
```

---

## 内核参数调优

### 网络参数

```bash
# 增加网络缓冲区
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
sudo sysctl -w net.core.rmem_default=33554432
sudo sysctl -w net.core.wmem_default=33554432

# 增加 backlog 队列
sudo sysctl -w net.core.netdev_max_backlog=30000

# 启用 RPS (Receive Packet Steering)
sudo sysctl -w net.core.rps_sock_flow_entries=32768

# TCP 参数优化
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"
sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 134217728"
```

### BPF 相关参数

```bash
# 增加 BPF JIT 限制
sudo sysctl -w net.core.bpf_jit_limit=1000000000

# 启用 BPF 统计
sudo sysctl -w kernel.bpf_stats_enabled=1

# 增加可锁定内存
sudo sysctl -w vm.max_map_count=262144
```

### 持久化配置

```bash
# 写入 /etc/sysctl.d/99-netxfw.conf
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

## BPF Map 优化

### Map 类型选择

| Map 类型 | 适用场景 | 性能特点 |
|----------|----------|----------|
| LPM_TRIE | IP/CIDR 查找 | O(log n) 查找 |
| LRU_HASH | 动态黑名单 | 自动淘汰 |
| PERCPU_HASH | 统计计数 | 无锁并发 |
| ARRAY | 固定索引 | O(1) 查找 |

### Map 大小配置

```yaml
# /etc/netxfw/config.yaml
capacity:
  # 连接跟踪 - 根据并发连接数调整
  conntrack: 100000

  # 静态黑名单 - 根据封禁 IP 数量调整
  lock_list: 50000

  # 动态黑名单 - LRU 自动淘汰
  dyn_lock_list: 100000

  # 白名单 - 通常较小
  whitelist: 1000

  # IP+端口规则
  ip_port_rules: 10000

  # 速率限制规则
  rate_limits: 1000
```

### 内存计算

```bash
# 计算 Map 内存占用
# LPM_TRIE: 每条目约 100 字节
# LRU_HASH: 每条目约 80 字节

# 示例计算
# conntrack: 100,000 × 80B = 8 MB
# lock_list: 50,000 × 100B = 5 MB
# dyn_lock_list: 100,000 × 80B = 8 MB
# 总计约: 21 MB
```

---

## CPU 优化

### CPU 亲和性

```bash
# 绑定网卡队列到特定 CPU
for i in /sys/class/net/eth0/queues/rx-*/rps_cpus; do
    echo f > "$i"
done

# 绑定 netxfw 进程到特定 CPU
sudo taskset -pc 0-3 $(pgrep netxfw)
```

### 中断均衡

```bash
# 查看网卡中断
cat /proc/interrupts | grep eth0

# 配置 SMP 亲和性
# 将中断分散到不同 CPU
for irq in $(grep eth0 /proc/interrupts | cut -d: -f1); do
    echo $((1 << (irq % 4))) > /proc/irq/$irq/smp_affinity
done
```

### RPS/RFS 配置

```bash
# 启用 RPS
for i in /sys/class/net/eth0/queues/rx-*/rps_cpus; do
    echo f > "$i"
done

# 配置 RFS
echo 32768 > /sys/class/net/eth0/queues/rx-0/rps_flow_cnt

# 启用 RFS
sysctl -w net.core.rps_sock_flow_entries=32768
```

---

## 内存优化

### 内存分配优化

```yaml
# 配置文件中的内存优化
capacity:
  # 避免过度分配
  conntrack: 50000
  lock_list: 20000
  dyn_lock_list: 50000

# 连接跟踪超时
conntrack:
  timeout: 300  # 缩短超时释放内存
```

### 大页内存使用

```bash
# 配置大页内存
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# 检查大页内存使用
cat /proc/meminfo | grep HugePages

# 在 netxfw 中启用大页内存（如果支持）
# 需要内核支持 BPF_MAP_TYPE_PACKED
```

### 内存监控

```bash
# 监控内存使用
watch -n 1 'ps aux | grep netxfw'

# 查看 BPF Map 内存
sudo bpftool map show | grep -E "name|bytes"

# 查看内存详情
cat /proc/$(pgrep netxfw)/status | grep -E "VmRSS|VmSize"
```

---

## 网络优化

### XDP 模式选择

| 模式 | 性能 | 功能限制 | 推荐场景 |
|------|------|----------|----------|
| Native (驱动模式) | 最高 | 部分功能受限 | 高性能场景 |
| Generic (通用模式) | 中等 | 无限制 | 兼容性优先 |
| Offload (硬件卸载) | 极高 | 功能受限 | 特定网卡 |

```bash
# 指定 XDP 模式
sudo netxfw start --xdp-mode native  # 或 generic, offload
```

### 批量处理

```yaml
# 启用 AF_XDP 批量处理（需要硬件支持）
af_xdp:
  enabled: true
  batch_size: 64
  fill_size: 2048
  comp_size: 2048
```

### GRO/LRO 配置

```bash
# 启用 GRO (Generic Receive Offload)
sudo ethtool -K eth0 gro on

# 启用 LRO (Large Receive Offload)
sudo ethtool -K eth0 lro on

# 查看当前配置
sudo ethtool -k eth0 | grep -E "gro|lro"
```

---

## 监控与诊断

### 性能监控

```bash
# 实时性能监控
sudo netxfw status -v

# 查看处理速率
watch -n 1 'sudo netxfw status | grep pps'

# 查看丢包统计
sudo bpftool map dump name stats_global_map
```

### 性能分析工具

```bash
# 使用 perf 分析 CPU 热点
sudo perf record -g -p $(pgrep netxfw) -- sleep 10
sudo perf report

# 生成火焰图
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > flame.svg

# 使用 bpftrace 分析
sudo bpftrace -e 'profile:hz:99 /pid == '$(pgrep netxfw)'/ { @[ustack] = count(); }'
```

### 性能指标

```bash
# 查看关键指标
sudo netxfw status -v | grep -E "PPS|BPS|CPU|Memory"

# 查看延迟分布
sudo bpftrace -e 'kprobe:xdp_generic_pass { @start[tid] = nsecs; } kretprobe:xdp_generic_pass /@start[tid]/ { @latency = hist(nsecs - @start[tid]); delete(@start[tid]); }'
```

---

## 场景优化建议

### 高流量场景 (10Gbps+)

```yaml
capacity:
  conntrack: 500000
  lock_list: 100000
  dyn_lock_list: 200000

conntrack:
  timeout: 180

# 启用 XDP native 模式
xdp_mode: native

# 启用硬件卸载（如果支持）
offload: true
```

### 低延迟场景

```yaml
# 减少规则数量
capacity:
  lock_list: 5000
  whitelist: 100

# 缩短超时
conntrack:
  timeout: 60

# 禁用不必要的功能
features:
  rate_limit: false
  log_engine: false
```

### 高并发场景

```yaml
capacity:
  conntrack: 1000000
  dyn_lock_list: 500000

conntrack:
  timeout: 300

# 增加工作线程
workers: 4
```

### 低内存场景 (512MB)

```yaml
capacity:
  conntrack: 20000
  lock_list: 5000
  dyn_lock_list: 10000
  whitelist: 30
  ip_port_rules: 50

conntrack:
  timeout: 120

# 禁用非必要功能
features:
  rate_limit: false
  top_stats: false
```

---

## 性能调优检查清单

- [ ] 内核版本 >= 5.10
- [ ] 启用 BPF JIT
- [ ] 配置合适的 Map 大小
- [ ] 启用 RPS/RFS
- [ ] 配置中断均衡
- [ ] 优化网络缓冲区
- [ ] 选择正确的 XDP 模式
- [ ] 监控 CPU/内存使用
- [ ] 定期清理过期数据
- [ ] 压力测试验证
