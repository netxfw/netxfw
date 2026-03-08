# Performance Monitoring

## Overview

NetXFW provides comprehensive performance monitoring system, including Map operation latency, cache hit rate, real-time traffic statistics and other key metrics. Through these metrics, operators can deeply understand system performance bottlenecks and optimize accordingly.

## Monitoring Metrics

### Map Operation Latency

| Metric | Description |
|--------|-------------|
| `total_operations` | Total operation count |
| `total_errors` | Total error count |
| `avg_latency_ns` | Average latency (ns) |
| `min_latency_ns` | Minimum latency (ns) |
| `max_latency_ns` | Maximum latency (ns) |

### Cache Hit Rate

| Cache | Description |
|-------|-------------|
| `global_stats` | Global statistics cache |
| `drop_details` | Drop details cache |
| `pass_details` | Pass details cache |
| `map_counts` | Map counts cache |

### Traffic Statistics

| Metric | Description |
|--------|-------------|
| `pps` | Packets per second |
| `bps` | Bytes per second |
| `drops_per_second` | Drops per second |
| `peak_pps` | Peak PPS |
| `peak_bps` | Peak BPS |

## API Interface

### Get Performance Statistics

```bash
GET /api/perf
```

### Get Latency Details

```bash
GET /api/perf/latency
```

### Get Cache Statistics

```bash
GET /api/perf/cache
```

### Get Traffic Statistics

```bash
GET /api/perf/traffic
```

### Reset Statistics

```bash
POST /api/perf/reset
```

## CLI Commands

### View Performance Overview

```bash
sudo netxfw perf
```

### Continuous Monitoring

```bash
sudo netxfw perf watch --interval 1s
```

## Prometheus Metrics

```
netxfw_map_latency_avg_ns{operation="read"} 25000
netxfw_cache_hit_rate{cache="global_stats"} 0.95
netxfw_traffic_pps 125000
netxfw_traffic_bps 1.875e+08
```

## Performance Optimization

| Latency | Status | Action |
|---------|--------|--------|
| < 10 µs | Excellent | None |
| 10-50 µs | Good | Normal |
| 50-100 µs | Fair | Check Map size |
| > 100 µs | Poor | Optimize config |

| Hit Rate | Status | Action |
|----------|--------|--------|
| > 95% | Excellent | None |
| 90-95% | Good | Normal |
| 80-90% | Fair | Increase cache |
| < 80% | Poor | Check patterns |
