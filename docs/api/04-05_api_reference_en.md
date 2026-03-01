# NetXFW API Reference

## Overview

NetXFW provides a complete RESTful API for managing and controlling firewall rules. The API service runs at `http://localhost:11811` by default.

## Authentication

Most API endpoints require authentication. Use Bearer Token for authentication:

```
Authorization: Bearer <token>
```

## API Endpoints

### Health Check

#### Health Check (Kubernetes Style)
```
GET /healthz
```
**Response Example**:
```json
{
  "status": "ok"
}
```

#### Detailed Health Status
```
GET /health
```
**Response Example**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": "24h"
}
```

#### BPF Map Health Check
```
GET /health/maps
GET /health/map?name=<map_name>
```

### Version Information

#### Get Version
```
GET /version
```
**Response Example**:
```json
{
  "version": "1.0.0",
  "commit": "abc123",
  "build_date": "2024-01-01"
}
```

### Statistics

#### Get Statistics
```
GET /api/stats
```
**Response Example**:
```json
{
  "packets": {
    "total": 1234567,
    "passed": 1234000,
    "dropped": 567
  },
  "drop_reasons": {
    "blacklist": 300,
    "rate_limit": 150,
    "port_blocked": 117
  },
  "maps": {
    "blacklist_count": 1234,
    "whitelist_count": 56,
    "conntrack_count": 1500
  }
}
```

### Rule Management

#### Get All Rules
```
GET /api/rules
```
**Response Example**:
```json
{
  "rules": [
    {
      "ip": "192.168.1.100",
      "port": 80,
      "action": "allow"
    }
  ]
}
```

#### Add Rule
```
POST /api/rules
```
**Request Body**:
```json
{
  "ip": "192.168.1.100",
  "port": 80,
  "action": "allow"
}
```

#### Delete Rule
```
DELETE /api/rules
```
**Request Body**:
```json
{
  "ip": "192.168.1.100",
  "port": 80
}
```

### Configuration Management

#### Get Configuration
```
GET /api/config
```

#### Update Configuration
```
PUT /api/config
```
**Request Body**:
```json
{
  "base": {
    "default_deny": true
  }
}
```

### Sync Operations

#### Sync Status
```
GET /api/sync
```

#### Sync to BPF Map
```
POST /api/sync
```
**Request Body**:
```json
{
  "action": "to_map"
}
```

### Connection Tracking

#### Get Connection Tracking Table
```
GET /api/conntrack
```
**Query Parameters**:
- `limit`: Maximum number of entries (default: 100)
- `offset`: Pagination offset
- `protocol`: Protocol filter (tcp/udp/icmp)

**Response Example**:
```json
{
  "connections": [
    {
      "src_ip": "192.168.1.100",
      "dst_ip": "8.8.8.8",
      "src_port": 12345,
      "dst_port": 53,
      "protocol": "udp",
      "last_seen": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 1500
}
```

### Performance Monitoring

#### Get Performance Statistics
```
GET /api/perf
```

#### Get Latency Statistics
```
GET /api/perf/latency
```

#### Get Cache Statistics
```
GET /api/perf/cache
```

#### Get Traffic Statistics
```
GET /api/perf/traffic
```

#### Reset Performance Statistics
```
POST /api/perf/reset
```

### Metrics API (v1)

#### Get All Metrics
```
GET /api/v1/metrics
```

#### Get Traffic Metrics
```
GET /api/v1/metrics/traffic
```

#### Get Connection Tracking Health
```
GET /api/v1/metrics/conntrack
```

#### Get Map Usage
```
GET /api/v1/metrics/maps
```

#### Get Rate Limit Statistics
```
GET /api/v1/metrics/ratelimit
```

#### Get Protocol Statistics
```
GET /api/v1/metrics/protocols
```

### Prometheus Metrics

#### Get Prometheus Format Metrics
```
GET /metrics
```

## Error Handling

The API uses standard HTTP status codes:

| Status Code | Description |
|-------------|-------------|
| `200 OK` | Request successful |
| `201 Created` | Resource created |
| `400 Bad Request` | Invalid request format |
| `401 Unauthorized` | Unauthorized |
| `404 Not Found` | Resource not found |
| `500 Internal Server Error` | Internal server error |

**Error Response Format**:
```json
{
  "error": "Invalid IP address format",
  "code": "INVALID_IP"
}
```

## Examples

### Add Rule with curl
```bash
curl -X POST http://localhost:11811/api/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "ip": "192.168.1.100",
    "port": 80,
    "action": "allow"
  }'
```

### Get Statistics with curl
```bash
curl -X GET http://localhost:11811/api/stats \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Get Connection Tracking with curl
```bash
curl -X GET "http://localhost:11811/api/conntrack?limit=50&protocol=tcp" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Health Check with curl
```bash
curl -X GET http://localhost:11811/healthz
```

## Debug Endpoints

When `enable_pprof: true` is set in the configuration, the following endpoints are available:

```
GET /debug/pprof/         # pprof index
GET /debug/pprof/cmdline  # Command line
GET /debug/pprof/profile  # CPU profile
GET /debug/pprof/symbol   # Symbol table
GET /debug/pprof/trace    # Execution trace
```

## Related Documentation

- [CLI Manual](./cli/03-02_cli_en.md) - Command line operations
- [Config Management](./07-01_config_management_unification_en.md) - Configuration reference
- [Architecture Overview](./02-02_architecture_en.md) - System architecture
