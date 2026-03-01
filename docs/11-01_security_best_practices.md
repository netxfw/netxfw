# 安全最佳实践 (Security Best Practices)

本文档提供 netxfw 生产环境部署的安全最佳实践指南。

## 目录

1. [最小权限原则](#最小权限原则)
2. [网络安全配置](#网络安全配置)
3. [访问控制](#访问控制)
4. [日志与审计](#日志与审计)
5. [规则管理](#规则管理)
6. [监控与告警](#监控与告警)
7. [应急响应](#应急响应)

---

## 最小权限原则

### 进程权限

```bash
# 使用专用用户运行（推荐）
sudo useradd -r -s /sbin/nologin netxfw
sudo chown -R netxfw:netxfw /etc/netxfw
sudo chown -R netxfw:netxfw /var/log/netxfw

# 使用 capabilities 替代 root
sudo setcap cap_bpf,cap_net_admin,cap_sys_admin,cap_ipc_lock+ep /usr/bin/netxfw
```

### 文件权限

```bash
# 配置文件权限
sudo chmod 600 /etc/netxfw/config.yaml
sudo chmod 600 /etc/netxfw/lock_list.txt
sudo chmod 600 /etc/netxfw/whitelist.txt

# 日志目录权限
sudo chmod 750 /var/log/netxfw

# PID 文件权限
sudo chmod 644 /var/run/netxfw.pid
```

### API 访问控制

```yaml
# config.yaml
web:
  enabled: true
  port: 11811
  # 绑定到本地地址（推荐）
  bind: "127.0.0.1"
  # 启用认证
  auth:
    enabled: true
    type: basic  # basic, token, mTLS
    # 使用环境变量或密钥文件存储密码
    # htpasswd -n admin
```

---

## 网络安全配置

### 默认策略

```yaml
# 推荐默认拒绝策略
base:
  default_deny: true
  allow_return_traffic: true  # 允许已建立连接的返回流量
  allow_icmp: false           # 生产环境建议禁用 ICMP
```

### 白名单配置

```yaml
# 始终配置管理白名单
whitelist:
  - "10.0.0.0/8"        # 内网
  - "192.168.0.0/16"    # 内网
  - "172.16.0.0/12"     # 内网
  - "YOUR_OFFICE_IP/32" # 办公网络
```

### 端口暴露最小化

```yaml
# 只开放必要端口
allowed_ports:
  - port: 22      # SSH
    action: allow
  - port: 80      # HTTP
    action: allow
  - port: 443     # HTTPS
    action: allow
  # 管理端口只允许内网访问
  - port: 11811
    action: allow
    source: "10.0.0.0/8"
```

---

## 访问控制

### API 认证

```yaml
# 基本认证
web:
  auth:
    enabled: true
    type: basic
    htpasswd_file: /etc/netxfw/htpasswd

# Token 认证
web:
  auth:
    enabled: true
    type: token
    token_file: /etc/netxfw/api_tokens
```

```bash
# 创建 htpasswd 文件
sudo htpasswd -c /etc/netxfw/htpasswd admin

# 创建 API Token
echo "admin:$(openssl rand -hex 32)" | sudo tee /etc/netxfw/api_tokens
sudo chmod 600 /etc/netxfw/api_tokens
```

### mTLS 配置

```yaml
web:
  auth:
    enabled: true
    type: mtls
    ca_cert: /etc/netxfw/certs/ca.crt
    server_cert: /etc/netxfw/certs/server.crt
    server_key: /etc/netxfw/certs/server.key
    client_cn: "netxfw-client"  # 验证客户端 CN
```

### RBAC 配置

```yaml
# 角色定义
roles:
  admin:
    permissions:
      - "rule:*"      # 所有规则操作
      - "config:*"    # 所有配置操作
      - "status:read" # 状态读取
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

## 日志与审计

### 日志配置

```yaml
log:
  level: info
  output: /var/log/netxfw/daemon.log
  # 日志轮转
  max_size: 100    # MB
  max_backups: 10
  max_age: 30      # days
  compress: true

# 审计日志
audit:
  enabled: true
  output: /var/log/netxfw/audit.log
  # 记录所有规则变更
  log_rule_changes: true
  # 记录所有 API 访问
  log_api_access: true
```

### 审计日志格式

```
2024-01-01T12:00:00Z [AUDIT] user=admin action=rule_add ip=1.2.3.4 result=success
2024-01-01T12:00:01Z [AUDIT] user=admin action=config_reload result=success
2024-01-01T12:00:02Z [AUDIT] user=operator action=rule_delete ip=5.6.7.8 result=success
```

### 日志监控

```bash
# 实时监控审计日志
sudo tail -f /var/log/netxfw/audit.log

# 搜索特定操作
sudo grep "action=rule_add" /var/log/netxfw/audit.log

# 统计操作类型
sudo grep -oP 'action=\w+' /var/log/netxfw/audit.log | sort | uniq -c
```

---

## 规则管理

### 规则变更流程

1. **变更申请**: 提交规则变更申请
2. **审批**: 安全团队审批
3. **测试**: 在测试环境验证
4. **实施**: 在生产环境实施
5. **验证**: 验证规则生效
6. **记录**: 记录变更日志

### 规则备份

```bash
# 定期备份规则
sudo netxfw rule export /backup/netxfw/rules_$(date +%Y%m%d).yaml

# 自动备份脚本
cat << 'EOF' | sudo tee /etc/cron.daily/netxfw-backup
#!/bin/bash
BACKUP_DIR=/backup/netxfw
mkdir -p $BACKUP_DIR
/usr/bin/netxfw rule export $BACKUP_DIR/rules_$(date +%Y%m%d).yaml
# 保留最近 30 天
find $BACKUP_DIR -name "rules_*.yaml" -mtime +30 -delete
EOF
sudo chmod +x /etc/cron.daily/netxfw-backup
```

### 规则验证

```bash
# 验证规则语法
sudo netxfw rule validate /etc/netxfw/rules.yaml

# 测试规则（不影响现有规则）
sudo netxfw rule test /etc/netxfw/rules.yaml

# 规则对比
sudo netxfw rule diff /etc/netxfw/rules.yaml /backup/netxfw/rules.yaml
```

---

## 监控与告警

### 关键指标监控

```yaml
# Prometheus 指标暴露
metrics:
  enabled: true
  port: 9090
  path: /metrics
```

### 告警规则

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

### 日志告警

```bash
# 使用 logwatch 监控日志
sudo apt install logwatch

# 配置 logwatch
cat << 'EOF' | sudo tee /etc/logwatch/conf/logfiles/netxfw.conf
LogFile = /var/log/netxfw/*.log
EOF
```

---

## 应急响应

### 应急预案

1. **DDoS 攻击**
   ```bash
   # 启用紧急模式
   sudo netxfw emergency enable

   # 添加攻击源到黑名单
   sudo netxfw deny add <attacker_ip> --ttl 1h

   # 启用速率限制
   sudo netxfw limit add 0.0.0.0/0 --rate 1000 --burst 2000
   ```

2. **误封合法 IP**
   ```bash
   # 立即解封
   sudo netxfw deny del <ip>

   # 添加到白名单防止再次封禁
   sudo netxfw allow add <ip>
   ```

3. **服务不可用**
   ```bash
   # 紧急停止
   sudo netxfw stop

   # 检查日志
   sudo tail -100 /var/log/netxfw/error.log

   # 恢复默认配置
   sudo netxfw start --config /etc/netxfw/config.yaml.default
   ```

### SSH 锁定恢复

```bash
# 方法1: 通过控制台/VNC
sudo netxfw allow add <your_ip>

# 方法2: 直接操作 BPF Map
sudo bpftool map update name whitelist key <your_ip_hex> value 1

# 方法3: 停止防火墙
sudo netxfw stop

# 方法4: 卸载 XDP 程序
sudo ip link set dev eth0 xdp off
```

### 紧急联系人

```
安全团队: security@example.com
运维团队: ops@example.com
值班电话: +86-xxx-xxxx-xxxx
```

---

## 安全检查清单

### 部署前检查

- [ ] 配置文件权限正确 (600)
- [ ] 启用 API 认证
- [ ] 配置管理白名单
- [ ] 启用审计日志
- [ ] 配置默认拒绝策略
- [ ] 最小化开放端口
- [ ] 配置日志轮转

### 定期检查

- [ ] 审查黑名单规则
- [ ] 审计日志分析
- [ ] 检查异常流量
- [ ] 验证备份有效性
- [ ] 更新安全策略
- [ ] 检查证书有效期

### 安全加固

- [ ] 禁用不必要功能
- [ ] 配置 mTLS
- [ ] 启用 RBAC
- [ ] 配置告警规则
- [ ] 定期渗透测试
- [ ] 安全培训

---

## 合规要求

### 日志保留

| 日志类型 | 保留期限 | 存储要求 |
|----------|----------|----------|
| 审计日志 | 1 年 | 加密存储 |
| 访问日志 | 90 天 | 加密存储 |
| 错误日志 | 30 天 | 普通存储 |

### 数据保护

- 敏感数据加密存储
- 定期数据清理
- 访问权限最小化
- 数据传输加密
