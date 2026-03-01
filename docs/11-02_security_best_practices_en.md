# Security Best Practices

This document provides security best practices for deploying netxfw in production environments.

## Table of Contents

1. [Principle of Least Privilege](#principle-of-least-privilege)
2. [Network Security Configuration](#network-security-configuration)
3. [Access Control](#access-control)
4. [Logging and Auditing](#logging-and-auditing)
5. [Rule Management](#rule-management)
6. [Monitoring and Alerting](#monitoring-and-alerting)
7. [Incident Response](#incident-response)

---

## Principle of Least Privilege

### Process Privileges

```bash
# Run as dedicated user (recommended)
sudo useradd -r -s /sbin/nologin netxfw
sudo chown -R netxfw:netxfw /etc/netxfw
sudo chown -R netxfw:netxfw /var/log/netxfw

# Use capabilities instead of root
sudo setcap cap_bpf,cap_net_admin,cap_sys_admin,cap_ipc_lock+ep /usr/bin/netxfw
```

### File Permissions

```bash
# Configuration file permissions
sudo chmod 600 /etc/netxfw/config.yaml
sudo chmod 600 /etc/netxfw/lock_list.txt
sudo chmod 600 /etc/netxfw/whitelist.txt

# Log directory permissions
sudo chmod 750 /var/log/netxfw

# PID file permissions
sudo chmod 644 /var/run/netxfw.pid
```

### API Access Control

```yaml
# config.yaml
web:
  enabled: true
  port: 11811
  # Bind to localhost (recommended)
  bind: "127.0.0.1"
  # Enable authentication
  auth:
    enabled: true
    type: basic  # basic, token, mTLS
    # Store passwords using environment variables or secret files
    # htpasswd -n admin
```

---

## Network Security Configuration

### Default Policy

```yaml
# Recommended default deny policy
base:
  default_deny: true
  allow_return_traffic: true  # Allow return traffic for established connections
  allow_icmp: false           # Disable ICMP in production
```

### Whitelist Configuration

```yaml
# Always configure management whitelist
whitelist:
  - "10.0.0.0/8"        # Internal network
  - "192.168.0.0/16"    # Internal network
  - "172.16.0.0/12"     # Internal network
  - "YOUR_OFFICE_IP/32" # Office network
```

### Minimize Port Exposure

```yaml
# Only open necessary ports
allowed_ports:
  - port: 22      # SSH
    action: allow
  - port: 80      # HTTP
    action: allow
  - port: 443     # HTTPS
    action: allow
  # Management port only from internal network
  - port: 11811
    action: allow
    source: "10.0.0.0/8"
```

---

## Access Control

### API Authentication

```yaml
# Basic authentication
web:
  auth:
    enabled: true
    type: basic
    htpasswd_file: /etc/netxfw/htpasswd

# Token authentication
web:
  auth:
    enabled: true
    type: token
    token_file: /etc/netxfw/api_tokens
```

```bash
# Create htpasswd file
sudo htpasswd -c /etc/netxfw/htpasswd admin

# Create API Token
echo "admin:$(openssl rand -hex 32)" | sudo tee /etc/netxfw/api_tokens
sudo chmod 600 /etc/netxfw/api_tokens
```

### mTLS Configuration

```yaml
web:
  auth:
    enabled: true
    type: mtls
    ca_cert: /etc/netxfw/certs/ca.crt
    server_cert: /etc/netxfw/certs/server.crt
    server_key: /etc/netxfw/certs/server.key
    client_cn: "netxfw-client"  # Verify client CN
```

### RBAC Configuration

```yaml
# Role definitions
roles:
  admin:
    permissions:
      - "rule:*"      # All rule operations
      - "config:*"    # All configuration operations
      - "status:read" # Status read
  operator:
    permissions:
      - "rule:read"
      - "rule:add"
      - "rule:delete"
      - "status:read"
  viewer:
    permissions:
      - "status:read"
      - "rule:read"
```

---

## Logging and Auditing

### Log Configuration

```yaml
log:
  level: info
  output: /var/log/netxfw/daemon.log
  # Log rotation
  max_size: 100    # MB
  max_backups: 10
  max_age: 30      # days
  compress: true

# Audit log
audit:
  enabled: true
  output: /var/log/netxfw/audit.log
  # Log all rule changes
  log_rule_changes: true
  # Log all API access
  log_api_access: true
```

### Audit Log Format

```
2024-01-01T12:00:00Z [AUDIT] user=admin action=rule_add ip=1.2.3.4 result=success
2024-01-01T12:00:01Z [AUDIT] user=admin action=config_reload result=success
2024-01-01T12:00:02Z [AUDIT] user=operator action=rule_delete ip=5.6.7.8 result=success
```

### Log Monitoring

```bash
# Real-time audit log monitoring
sudo tail -f /var/log/netxfw/audit.log

# Search for specific operations
sudo grep "action=rule_add" /var/log/netxfw/audit.log

# Count operation types
sudo grep -oP 'action=\w+' /var/log/netxfw/audit.log | sort | uniq -c
```

---

## Rule Management

### Rule Change Process

1. **Change Request**: Submit rule change request
2. **Approval**: Security team approval
3. **Testing**: Validate in test environment
4. **Implementation**: Implement in production
5. **Verification**: Verify rule effectiveness
6. **Documentation**: Record change log

### Rule Backup

```bash
# Regular rule backup
sudo netxfw rule export /backup/netxfw/rules_$(date +%Y%m%d).yaml

# Automatic backup script
cat << 'EOF' | sudo tee /etc/cron.daily/netxfw-backup
#!/bin/bash
BACKUP_DIR=/backup/netxfw
mkdir -p $BACKUP_DIR
/usr/bin/netxfw rule export $BACKUP_DIR/rules_$(date +%Y%m%d).yaml
# Keep last 30 days
find $BACKUP_DIR -name "rules_*.yaml" -mtime +30 -delete
EOF
sudo chmod +x /etc/cron.daily/netxfw-backup
```

### Rule Validation

```bash
# Validate rule syntax
sudo netxfw rule validate /etc/netxfw/rules.yaml

# Test rules (without affecting existing rules)
sudo netxfw rule test /etc/netxfw/rules.yaml

# Rule comparison
sudo netxfw rule diff /etc/netxfw/rules.yaml /backup/netxfw/rules.yaml
```

---

## Monitoring and Alerting

### Key Metrics Monitoring

```yaml
# Prometheus metrics exposure
metrics:
  enabled: true
  port: 9090
  path: /metrics
```

### Alert Rules

```yaml
# alertmanager/rules.yml
groups:
  - name: netxfw
    rules:
      - alert: HighDropRate
        expr: rate(netxfw_packets_dropped_total[5m]) > 1000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High packet drop rate detected"

      - alert: BlacklistNearCapacity
        expr: netxfw_blacklist_count / netxfw_blacklist_capacity > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Blacklist near capacity"

      - alert: ConntrackNearCapacity
        expr: netxfw_conntrack_count / netxfw_conntrack_capacity > 0.9
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Conntrack table near capacity"
```

### Log Alerting

```bash
# Use logwatch to monitor logs
sudo apt install logwatch

# Configure logwatch
cat << 'EOF' | sudo tee /etc/logwatch/conf/logfiles/netxfw.conf
LogFile = /var/log/netxfw/*.log
EOF
```

---

## Incident Response

### Emergency Procedures

1. **DDoS Attack**
   ```bash
   # Enable emergency mode
   sudo netxfw emergency enable

   # Add attack sources to blacklist
   sudo netxfw deny add <attacker_ip> --ttl 1h

   # Enable rate limiting
   sudo netxfw limit add 0.0.0.0/0 --rate 1000 --burst 2000
   ```

2. **Accidentally Blocked Legitimate IP**
   ```bash
   # Immediately unblock
   sudo netxfw deny del <ip>

   # Add to whitelist to prevent re-blocking
   sudo netxfw allow add <ip>
   ```

3. **Service Unavailable**
   ```bash
   # Emergency stop
   sudo netxfw stop

   # Check logs
   sudo tail -100 /var/log/netxfw/error.log

   # Restore default configuration
   sudo netxfw start --config /etc/netxfw/config.yaml.default
   ```

### SSH Lockout Recovery

```bash
# Method 1: Via console/VNC
sudo netxfw allow add <your_ip>

# Method 2: Direct BPF Map operation
sudo bpftool map update name whitelist key <your_ip_hex> value 1

# Method 3: Stop firewall
sudo netxfw stop

# Method 4: Unload XDP program
sudo ip link set dev eth0 xdp off
```

### Emergency Contacts

```
Security Team: security@example.com
Operations Team: ops@example.com
On-call Phone: +1-xxx-xxx-xxxx
```

---

## Security Checklist

### Pre-deployment Checklist

- [ ] Configuration file permissions correct (600)
- [ ] API authentication enabled
- [ ] Management whitelist configured
- [ ] Audit logging enabled
- [ ] Default deny policy configured
- [ ] Minimized open ports
- [ ] Log rotation configured

### Regular Checks

- [ ] Review blacklist rules
- [ ] Audit log analysis
- [ ] Check for abnormal traffic
- [ ] Verify backup effectiveness
- [ ] Update security policies
- [ ] Check certificate validity

### Security Hardening

- [ ] Disable unnecessary features
- [ ] Configure mTLS
- [ ] Enable RBAC
- [ ] Configure alert rules
- [ ] Regular penetration testing
- [ ] Security training

---

## Compliance Requirements

### Log Retention

| Log Type | Retention Period | Storage Requirements |
|----------|------------------|---------------------|
| Audit logs | 1 year | Encrypted storage |
| Access logs | 90 days | Encrypted storage |
| Error logs | 30 days | Normal storage |

### Data Protection

- Sensitive data encrypted at rest
- Regular data cleanup
- Minimized access permissions
- Encrypted data transmission
