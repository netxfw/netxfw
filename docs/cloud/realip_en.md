# Cloud Environment Real IP Acquisition

## Overview

In cloud provider load balancer (LB) environments, NetXFW receives connections with the LB's IP as the source IP, not the real client IP. To solve this problem, NetXFW provides **Proxy Protocol parsing** functionality to extract real client IPs from traffic forwarded by cloud LBs.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    Cloud Environment Real IP Acquisition Architecture         │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────────────────────┐    │
│  │   Client    │     │   Cloud LB  │     │         NetXFW              │    │
│  │  Real IP    │────▶│ Proxy Proto │────▶│  ┌─────────────────────┐   │    │
│  │             │     │ Add Header  │     │  │  Proxy Protocol     │   │    │
│  └─────────────┘     └─────────────┘     │  │  Parser             │   │    │
│                                          │  └──────────┬──────────┘   │    │
│                                          │             │              │    │
│                                          │             ▼              │    │
│                                          │  ┌─────────────────────┐   │    │
│                                          │  │  Real IP Manager    │   │    │
│                                          │  │  - Blacklist check  │   │    │
│                                          │  │  - Auto blocking    │   │    │
│                                          │  └─────────────────────┘   │    │
│                                          └─────────────────────────────┘    │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Supported Cloud Providers

| Cloud Provider | Identifier | Proxy Protocol Support |
|----------------|------------|------------------------|
| Alibaba Cloud | `alibaba` | ✅ Supported |
| Tencent Cloud | `tencent` | ✅ Supported |
| AWS | `aws` | ✅ Supported |
| Azure | `azure` | ✅ Supported |
| GCP | `gcp` | ✅ Supported |
| Other | `other` | ✅ Supported (custom IP ranges required) |

## Configuration

### Configuration File

Add cloud environment configuration to `/etc/netxfw/config.yaml`:

```yaml
# ═══════════════════════════════════════════════════════════════
# Cloud Environment Configuration
# ═══════════════════════════════════════════════════════════════
cloud:
  # Enable cloud environment support
  enabled: true
  
  # Cloud provider: alibaba, tencent, aws, azure, gcp, other
  provider: "alibaba"
  
  # Proxy Protocol configuration
  proxy_protocol:
    # Enable Proxy Protocol parsing
    enabled: true
    
    # Trusted LB IP ranges (connections from these IPs will be parsed for Proxy Protocol)
    # Predefined ranges will be added based on provider
    trusted_lb_ranges:
      - "10.0.0.0/8"       # Alibaba/Tencent internal network
      - "100.64.0.0/10"    # Carrier-grade NAT
      - "192.168.0.0/16"   # Custom VPC
    
    # Cache TTL for real IP mappings
    cache_ttl: "5m"
```

### Default Configuration by Provider

#### Alibaba Cloud (alibaba)

```yaml
cloud:
  provider: "alibaba"
  proxy_protocol:
    enabled: true
    trusted_lb_ranges:
      - "10.0.0.0/8"      # Alibaba internal network
      - "100.64.0.0/10"   # SLB internal network
```

#### Tencent Cloud (tencent)

```yaml
cloud:
  provider: "tencent"
  proxy_protocol:
    enabled: true
    trusted_lb_ranges:
      - "10.0.0.0/8"      # Tencent internal network
      - "100.64.0.0/10"   # CLB internal network
```

#### AWS (aws)

```yaml
cloud:
  provider: "aws"
  proxy_protocol:
    enabled: true
    trusted_lb_ranges:
      - "10.0.0.0/8"      # VPC internal network
      - "172.16.0.0/12"   # VPC internal network
```

## Usage

### 1. Enable Cloud Environment Support

```bash
# Edit configuration file
sudo vim /etc/netxfw/config.yaml

# Hot reload configuration
sudo netxfw system reload
```

### 2. Real IP Blacklist Management

Real IP blacklist is managed via API/CLI, not stored in configuration file:

```bash
# Block real IP
sudo netxfw cloud block 192.168.1.100 --reason "Malicious attack" --duration "24h"

# Unblock IP
sudo netxfw cloud unblock 192.168.1.100

# View blacklist
sudo netxfw cloud blacklist list
```

### 3. Auto Blocking

When a real IP triggers rate limiting rules, it can be automatically added to the blacklist:

```yaml
rate_limit:
  enabled: true
  auto_block: true
  auto_block_expiry: "5m"
```

## How It Works

### Proxy Protocol Parsing Flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        Proxy Protocol Parsing Flow                            │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. Connection arrives at NetXFW                                             │
│     └─▶ Source IP: 10.0.1.100 (LB IP)                                       │
│                                                                              │
│  2. Check if from trusted LB                                                 │
│     └─▶ 10.0.1.100 in 10.0.0.0/8 range → Trusted LB                         │
│                                                                              │
│  3. Parse Proxy Protocol header                                              │
│     └─▶ PROXY TCP4 192.168.1.100 10.0.1.100 54321 80                        │
│     └─▶ Real IP: 192.168.1.100                                              │
│                                                                              │
│  4. Check real IP blacklist                                                  │
│     └─▶ 192.168.1.100 in blacklist → DROP                                   │
│     └─▶ 192.168.1.100 not in blacklist → Continue processing                │
│                                                                              │
│  5. Cache real IP mapping                                                    │
│     └─▶ Connection ID → Real IP (Cache TTL: 5m)                             │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Proxy Protocol Versions

NetXFW supports two Proxy Protocol versions:

| Version | Format | Characteristics |
|---------|--------|-----------------|
| V1 | Text format | Good readability, easy debugging |
| V2 | Binary format | Higher performance, more protocol support |

**V1 Example:**
```
PROXY TCP4 192.168.1.100 10.0.1.100 54321 80\r\n
```

**V2 Example:**
```
\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x11\x00\x0C\xC0\xA8\x01\x64\x0A\x00\x01\x64\xD4\x31\x00\x50
```

## Blacklist Storage

Real IP blacklist is stored in the `dynamic_blacklist` Map, shared with the dynamic blacklist:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Blacklist Storage Architecture                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────────┐  │
│  │  API/CLI        │     │  RealIP Manager │     │  XDP Map            │  │
│  │  netxfw cloud   │────▶│  AddToBlacklist │────▶│  dynamic_blacklist  │  │
│  │  block/unblock  │     │  (SDK Callback) │     │  (LRU Hash)         │  │
│  └─────────────────┘     └─────────────────┘     └─────────────────────┘  │
│                                                           │                │
│                                                           ▼                │
│                                                  ┌─────────────────────┐  │
│                                                  │  XDP Program        │  │
│                                                  │  Check real IP      │  │
│                                                  │  Match → DROP       │  │
│                                                  └─────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Important Notes

### 1. Cloud LB Configuration

Ensure your cloud provider's load balancer has Proxy Protocol enabled:

**Alibaba Cloud SLB:**
```bash
# Enable Proxy Protocol in SLB console
# Or configure via API
```

**Tencent Cloud CLB:**
```bash
# Enable Proxy Protocol in CLB console
# Listener config → Advanced config → Enable Proxy Protocol
```

**AWS ALB/NLB:**
```bash
# ALB supports Proxy Protocol v2 by default
# NLB requires manual enabling
aws elbv2 modify-load-balancer-attributes \
  --load-balancer-arn <arn> \
  --attributes Key=proxy_protocol_v2.enabled,Value=true
```

### 2. Performance Impact

- Proxy Protocol parsing happens in user space, minimal impact on XDP performance
- Real IP caching mechanism avoids repeated parsing
- Recommended to set reasonable cache TTL (default 5 minutes)

### 3. Security Considerations

- Only trust Proxy Protocol headers from trusted LB IP ranges
- Do not add public IPs to trusted ranges
- Regularly review blacklist entries

## Troubleshooting

### Check if Configuration is Effective

```bash
# View system status
sudo netxfw system status

# Check cloud configuration
sudo netxfw cloud config show
```

### Test Proxy Protocol Parsing

```bash
# Use demo program
go run test/demo/cloud_demo.go

# View logs
sudo journalctl -u netxfw -f
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Cannot get real IP | LB doesn't have Proxy Protocol enabled | Enable in cloud console |
| Parsing failed | LB IP not in trusted range | Add to trusted_lb_ranges |
| Blacklist not working | XDP program not loaded | Run `netxfw system on` |

## Related Documentation

- [Architecture Design](../architecture.md)
- [CLI Command Manual](../cli/cli_en.md)
- [Plugin Development Guide](../plugins/plugins_en.md)
