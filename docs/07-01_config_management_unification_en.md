# Unified Configuration Management Module

## Overview

To solve the problem of scattered configuration management logic, we created a unified configuration management module that centralizes all configuration-related operations in one place.

## Design Goals

1. **Centralized Management** - Centralize all configuration loading, saving, and access logic into one manager
2. **Thread Safety** - Use read-write locks to protect concurrent access
3. **Backward Compatibility** - Keep existing APIs unchanged but use the new manager
4. **Easy Maintenance** - Provide clear interfaces and documentation

## Core Components

### 1. ConfigManager Structure
```go
type ConfigManager struct {
    configPath string
    mutex      sync.RWMutex
    config     *types.GlobalConfig
}
```

### 2. Configurable Interface
Defines a unified interface for configuration management, facilitating testing and extension.

### 3. Singleton Pattern
Provides singleton access through the `GetConfigManager()` function.

## Key Features

### Configuration Loading and Saving
- `LoadConfig()` - Load configuration from file
- `SaveConfig()` - Save configuration to file
- `UpdateConfig()` - Update current configuration

### Type-Safe Accessors
Dedicated getters and setters for each configuration section:
- `GetBaseConfig()` / `SetBaseConfig()`
- `GetWebConfig()` / `SetWebConfig()`
- `GetMetricsConfig()` / `SetMetricsConfig()`
- And more...

### Concurrent Safety
Uses read-write locks to ensure safe access in multi-goroutine environments.

## Usage

### Get Configuration Manager
```go
cfgManager := config.GetConfigManager()
```

### Load Configuration
```go
err := cfgManager.LoadConfig()
if err != nil {
    // Handle error
}
```

### Access Configuration
```go
cfg := cfgManager.GetConfig()
baseCfg := cfgManager.GetBaseConfig()
```

### Update Configuration
```go
newBaseCfg := types.BaseConfig{...}
cfgManager.SetBaseConfig(newBaseCfg)
err := cfgManager.SaveConfig()  // Save to file
```

## Updated Files

The following files have been updated to use the new configuration manager:

1. `/internal/api/server.go` - API server configuration loading
2. `/cmd/netxfw/commands/agent/*.go` - CLI command configuration access
3. `/internal/plugins/manager.go` - Plugin manager configuration

## Configuration Structure

```yaml
# Base configuration
base:
  default_deny: true
  allow_return_traffic: false
  allow_icmp: true
  persist_rules: true
  cleanup_interval: "1m"

# Connection tracking
conntrack:
  enabled: true
  max_entries: 100000
  tcp_timeout: "1h"
  udp_timeout: "5m"

# Rate limiting
rate_limit:
  enabled: true
  auto_block: true
  auto_block_expiry: "10m"

# Web interface
web:
  enabled: true
  port: 11811

# Metrics
metrics:
  enabled: true
  server_enabled: false
  port: 11812

# BPF Map capacity
capacity:
  lock_list: 2000000
  dyn_lock_list: 2000000
  whitelist: 65536
  ip_port_rules: 65536
```

## Best Practices

### 1. Use Singleton
Always use `GetConfigManager()` to get the configuration manager instance, do not create new instances.

### 2. Save After Modification
After modifying configuration, call `SaveConfig()` to persist changes.

### 3. Error Handling
Always check for errors when loading or saving configuration.

### 4. Thread Safety
The configuration manager is thread-safe, but avoid frequent configuration updates in hot paths.

## Related Documentation

- [Web API Metrics Unification](./07-02_unified_web_api_metrics_en.md)
- [Architecture Overview](./02-02_architecture_en.md)
- [CLI Reference](./cli/03-02_cli_en.md)
