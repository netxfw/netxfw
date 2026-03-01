# Log Engine Documentation

The Log Engine is a high-performance log analysis and defense subsystem built into NetXFW. It uses Zero-Copy technology to directly process byte streams, supporting everything from simple keyword matching to complex logical expression analysis, capable of real-time threat intelligence extraction from logs and automatic execution of defense actions (such as IP blocking).

## 1. Core Features

*   **High Performance**: Uses `Byte Mode` by default, directly operates on memory bytes, no string conversion overhead.
*   **Dual Syntax**: Supports simple YAML semantic configuration (Cloudflare style) and advanced expressions (Expr language).
*   **Frequency Control**: Built-in sliding window counter, supports time-window-based rate limiting (e.g., 5 errors in 60 seconds).
*   **Context Awareness**: Supports rule isolation based on log file path (`path`).
*   **Field Extraction**: Supports KV extraction (`key=value`), JSON field extraction, delimiter extraction.

## 2. Enable Configuration

Configure the `log_engine` section in `config.yaml`:

```yaml
log_engine:
  enabled: true       # Enable engine
  workers: 4          # Concurrent processing goroutines
  files:              # Log files to monitor
    - "/var/log/nginx/access.log"
    - "/var/log/auth.log"
    - "/var/log/syslog"
  rules: []           # Rule list (see below)
```

## 3. Rule Writing Guide

Log Engine supports two rule writing methods, which can be mixed based on complexity.

### 3.1 Method 1: Semantic Configuration (Recommended)

Suitable for quickly configuring common matching logic. Uses intuitive fields similar to Cloudflare WAF.

**Field Description:**

| Field | Alias | Description | Logic |
| :--- | :--- | :--- | :--- |
| `contains` | `and`, `is`, `keywords` | Must contain **all** specified content | AND (&&) |
| `any_contains` | `or` | Must contain **any** specified content | OR (\|\|) |
| `not_contains` | `not` | Must **not contain** any specified content | NOT (!) |
| `regex` | - | Must match regex pattern | AND |
| `path` | - | Only effective when matching this file path | Filter |

**Frequency Control Fields:**

| Field | Description | Default |
| :--- | :--- | :--- |
| `threshold` | Trigger threshold (count) | 0 (single match triggers immediately) |
| `interval` | Count time window (seconds) | 60 |

**Example 1: SSH Brute Force Defense**
*Rule: In `auth.log`, if contains "Failed password" and doesn't contain "invalid user", appears 5 times within 60 seconds, then block.*

```yaml
- id: "ssh_bruteforce"
  path: "/var/log/auth.log"
  action: "dynblack"
  is: 
    - "Failed password"
  not:
    - "invalid user"  # Exclude specific false positives
  threshold: 5
  interval: 60
```

**Example 2: Block Specific User-Agent**
*Rule: Block requests containing "Go-http-client" or "python-requests".*

```yaml
- id: "block_scrapers"
  path: "*.log"
  action: "dynblack"
  or:
    - "Go-http-client"
    - "python-requests"
    - "curl/"
```

### 3.2 Method 2: Advanced Expressions

For complex logic, use Expr expression language:

**Example: Complex SQL Injection Detection**
```yaml
- id: "sqli_advanced"
  path: "/var/log/nginx/access.log"
  action: "dynblack"
  expr: |
    contains(line, "SELECT") && 
    (contains(line, "UNION") || contains(line, "DROP")) &&
    !contains(line, "internal-monitor")
  threshold: 3
  interval: 60
```

## 4. Action Types

| Action Value | String Form | Description | Duration |
| :--- | :--- | :--- | :--- |
| `0` | `log` | Only log alert | N/A |
| `1` | `dynblack` | Add to dynamic blacklist | Auto-expire (configurable) |
| `1` | `dynblack:1h` | Add to dynamic blacklist with duration | Specified duration (e.g., 10m, 1h, 30s) |
| `2` | `blacklist` / `lock` / `deny` | Add to static blacklist | Permanent |

> **Note**: Actions support both numeric form (`0`/`1`/`2`) and string form, both are equivalent.

## 5. Field Extraction

### 5.1 KV Extraction
Extract `key=value` pairs from logs:

```yaml
- id: "extract_kv"
  path: "/var/log/app.log"
  extract:
    type: "kv"
    fields:
      - "ip"
      - "status"
      - "user"
```

### 5.2 JSON Extraction
Extract fields from JSON logs:

```yaml
- id: "extract_json"
  path: "/var/log/json.log"
  extract:
    type: "json"
    fields:
      - "remote_addr"
      - "request.method"
      - "response.status"
```

### 5.3 Delimiter Extraction
Extract fields by delimiter:

```yaml
- id: "extract_csv"
  path: "/var/log/csv.log"
  extract:
    type: "delimiter"
    delimiter: ","
    fields:
      - { name: "ip", index: 0 }
      - { name: "status", index: 2 }
```

## 6. Performance Tuning

### 6.1 Worker Count
Adjust worker count based on log volume:
- Low volume (< 1000 lines/sec): 2 workers
- Medium volume (1000-10000 lines/sec): 4 workers
- High volume (> 10000 lines/sec): 8 workers

### 6.2 Buffer Size
```yaml
log_engine:
  buffer_size: 4096  # Read buffer size (bytes)
```

### 6.3 Batch Processing
```yaml
log_engine:
  batch_size: 100    # Process in batches
  batch_timeout: "1s" # Batch timeout
```

## 7. Monitoring

### 7.1 Metrics
Log Engine exposes Prometheus metrics:
- `netxfw_log_lines_processed_total`
- `netxfw_log_rules_triggered_total`
- `netxfw_log_blocks_total`

### 7.2 Health Check
```bash
curl http://localhost:11811/api/log-engine/health
```

## Related Documentation

- [Configuration Management](./07-01_config_management_unification_en.md)
- [API Reference](./api/04-05_api_reference_en.md)
- [Performance Benchmarks](./performance/06-02_benchmarks_en.md)
