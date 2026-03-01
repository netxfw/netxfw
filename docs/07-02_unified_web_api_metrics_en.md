# NetXFW - Unified Web, API and Metrics Service

NetXFW provides a unified service that integrates Web interface, API interface, and metrics monitoring into a single service.

## Architecture Overview

### Unified Service Design
- **Web UI**: Provides intuitive web interface, accessible via root path `/`
- **API Interface**: Provides RESTful API interface, accessible via `/api/*` path
- **Metrics Monitoring**: Provides Prometheus metrics, accessible via `/metrics` path

### Route Structure
```
GET    /                    -> Web UI
GET    /api/stats          -> Statistics
GET    /api/rules          -> Rule Management
GET    /api/config         -> Configuration Management
GET    /api/sync           -> Sync Operations
GET    /api/conntrack      -> Connection Tracking
GET    /metrics            -> Prometheus Metrics
```

### Configuration Options

In `config.yaml`, you can control service behavior with the following configuration:

```yaml
web:
  enabled: true
  port: 11811
  token: "auto-generated"  # Auto-generated or manually specified

metrics:
  enabled: true           # Enable metrics collection
  server_enabled: false   # If false, provide metrics on web server
  port: 11812             # Independent metrics server port
```

When `metrics.server_enabled` is `false`, metrics are provided on the web server's `/metrics` path.
When `metrics.server_enabled` is `true`, metrics are provided on an independent server.

## Features

### Web Interface
- Real-time network traffic monitoring
- Configuration management interface
- Rule management interface
- System status overview

### API Interface
- Statistics query
- Dynamic rule management
- Configuration updates
- System control

### Metrics Monitoring
- XDP drop/pass statistics
- Locked IP count
- Connection tracking entries
- Various rule count statistics

## Deployment Modes

### Single Service Mode (Recommended)
- Web, API, and Metrics run on the same port
- Access through different paths
- Simplified deployment and management

### Separated Service Mode
- Web and API run on one port
- Metrics run on an independent port
- Suitable for scenarios requiring independent monitoring service

## Metrics Reference

### XDP Metrics
| Metric Name | Type | Description |
|-------------|------|-------------|
| `netxfw_packets_total` | Counter | Total packets processed |
| `netxfw_packets_passed` | Counter | Packets passed |
| `netxfw_packets_dropped` | Counter | Packets dropped |
| `netxfw_drop_blacklist` | Counter | Dropped by blacklist |
| `netxfw_drop_rate_limit` | Counter | Dropped by rate limit |
| `netxfw_pass_whitelist` | Counter | Passed by whitelist |

### Map Metrics
| Metric Name | Type | Description |
|-------------|------|-------------|
| `netxfw_blacklist_count` | Gauge | Blacklist entry count |
| `netxfw_whitelist_count` | Gauge | Whitelist entry count |
| `netxfw_conntrack_count` | Gauge | Connection tracking count |
| `netxfw_rule_count` | Gauge | IP+Port rule count |

### System Metrics
| Metric Name | Type | Description |
|-------------|------|-------------|
| `netxfw_uptime_seconds` | Gauge | Service uptime |
| `netxfw_config_version` | Gauge | Configuration version |

## Prometheus Integration

### Prometheus Configuration

Add the following to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'netxfw'
    static_configs:
      - targets: ['localhost:11811']
    metrics_path: '/metrics'
```

### Grafana Dashboard

NetXFW provides a pre-built Grafana dashboard for visualizing metrics:

1. Import dashboard from `contrib/grafana-dashboard.json`
2. Configure Prometheus data source
3. View real-time firewall statistics

## Security Considerations

### Token Authentication
- Web UI and API require token authentication
- Token can be auto-generated or manually specified
- Rotate tokens periodically for security

### TLS Support
For production deployment, enable TLS:

```yaml
web:
  enabled: true
  port: 11811
  tls:
    enabled: true
    cert_file: /path/to/cert.pem
    key_file: /path/to/key.pem
```

## Related Documentation

- [API Reference](./api/04-05_api_reference_en.md)
- [Configuration Management](./07-01_config_management_unification_en.md)
- [Performance Benchmarks](./performance/06-02_benchmarks_en.md)
