# Go Plugin Development Guide

## Overview

netxfw supports extending functionality through the Go Plugin mechanism. Go plugins are primarily used for control plane extensions, such as API middleware, rule processors, and monitoring hooks. Go plugins provide higher flexibility than XDP plugins and can access the complete Go standard library.

## Environment Requirements

- Go 1.18+
- Go modules support
- Use the same Go version as the main program during compilation

## Plugin Interface Definition

Go plugins must implement specific interfaces to be recognized and loaded by netxfw. Main interfaces include:

### 1. RuleProcessor Interface

Used to extend rule processing logic:

```go
type RuleProcessor interface {
    Process(rule Rule) error
    Validate(rule Rule) error
    Name() string
}
```

### 2. APIMiddleware Interface

Used to extend API functionality:

```go
type APIMiddleware interface {
    Handler(next http.HandlerFunc) http.HandlerFunc
    Priority() int  // Smaller number means higher priority
}
```

### 3. MonitorHook Interface

Used for monitoring and alerts:

```go
type MonitorHook interface {
    OnEvent(event Event) error
    EventType() string
}
```

## Quick Start

### 1. Create Plugin Project

Create a new Go project as a plugin:

```bash
mkdir -p ~/my-netxfw-plugin
cd ~/my-netxfw-plugin
go mod init my-netxfw-plugin
```

### 2. Implement Plugin Interface

Create `main.go` file:

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "time"
    
    "netxfw/types"  // Assume this is netxfw's type package
)

// Implement rule processor
type MyRuleProcessor struct{}

func (p *MyRuleProcessor) Name() string {
    return "my-rule-processor"
}

func (p *MyRuleProcessor) Validate(rule types.Rule) error {
    // Custom validation logic
    if rule.IP == "0.0.0.0" {
        return fmt.Errorf("invalid IP: 0.0.0.0")
    }
    return nil
}

func (p *MyRuleProcessor) Process(rule types.Rule) error {
    log.Printf("Processing rule: %+v", rule)
    
    // Custom processing logic
    // Example: Record to external system, send notifications, etc.
    return nil
}

// Implement API middleware
type MyAPIMiddleware struct{}

func (m *MyAPIMiddleware) Priority() int {
    return 10
}

func (m *MyAPIMiddleware) Handler(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        
        log.Printf("Request received: %s %s", r.Method, r.URL.Path)
        
        // Call next handler
        next(w, r)
        
        log.Printf("Request completed in %v", time.Since(start))
    }
}

// Implement monitoring hook
type MyMonitorHook struct{}

func (h *MyMonitorHook) EventType() string {
    return "rule_change"  // Listen to rule change events
}

func (h *MyMonitorHook) OnEvent(event types.Event) error {
    eventData, _ := json.MarshalIndent(event, "", "  ")
    log.Printf("Rule change event: %s", eventData)
    
    // Can send alerts, record to external system, etc. here
    return nil
}

// Export plugin instances
var (
    RuleProcessorInstance RuleProcessor = &MyRuleProcessor{}
    APIMiddlewareInstance APIMiddleware = &MyAPIMiddleware{}
    MonitorHookInstance   MonitorHook   = &MyMonitorHook{}
)
```

### 3. Compile Plugin

Compile as `.so` file:

```bash
go build -buildmode=plugin -o my_plugin.so
```

## Plugin Types Explained

### 1. Rule Processor (RuleProcessor)

Used to extend rule validation and processing logic:

```go
type RuleProcessor interface {
    Process(rule Rule) error      // Process rule
    Validate(rule Rule) error     // Validate rule
    Name() string                // Plugin name
}
```

Typical application scenarios:
- Validate rules against specific policies
- Synchronize rules to external systems
- Record rule operation logs

### 2. API Middleware (APIMiddleware)

Used to extend API functionality:

```go
type APIMiddleware interface {
    Handler(next http.HandlerFunc) http.HandlerFunc
    Priority() int
}
```

Typical application scenarios:
- Authentication and authorization
- Request logging
- Rate limiting
- Request/response modification

### 3. Monitoring Hook (MonitorHook)

Used to monitor system events:

```go
type MonitorHook interface {
    OnEvent(event Event) error
    EventType() string
}
```

Typical application scenarios:
- Event alerts
- Metric collection
- Audit logs

## Advanced Features

### 1. Configuration Management

Plugins can have their own configuration files:

```go
type ConfigurablePlugin interface {
    LoadConfig(configPath string) error
    GetConfig() interface{}
}
```

### 2. State Management

Plugins can maintain their own state:

```go
type StatefulPlugin interface {
    Init() error
    Cleanup() error
}
```

### 3. Communication with Other Plugins

Use shared event bus:

```go
type EventBus interface {
    Subscribe(topic string, handler EventHandler)
    Publish(topic string, data interface{})
}
```

## Plugin Loading

### 1. Configuration File Method

Specify plugin path in netxfw configuration file:

```yaml
plugins:
  go:
    - path: /path/to/my_plugin.so
      enabled: true
      config:
        param1: value1
        param2: value2
```

### 2. Command Line Method

Load plugins through command line arguments:

```bash
./netxfw daemon --plugin-dir=/path/to/plugins
```

## Best Practices

### 1. Error Handling
- Plugin errors should not affect main program operation
- Implement graceful degradation mechanism
- Record detailed error logs

### 2. Performance Considerations
- Avoid time-consuming operations on critical paths
- Use caching to reduce repeated calculations
- Use concurrency appropriately

### 3. Security
- Validate all external inputs
- Avoid executing arbitrary code
- Implement appropriate access control

### 4. Testing
- Write unit tests for plugins
- Perform integration tests
- Validate error handling logic

## Debugging Tips

### 1. Logging
Use structured logging to record plugin activities:

```go
log.Printf("[PLUGIN: %s] Action: %s, Result: %v", pluginName, action, result)
```

### 2. Configuration Validation
Validate configuration during plugin initialization:

```go
func (p *MyPlugin) Init() error {
    if p.config.Param1 == "" {
        return fmt.Errorf("param1 is required")
    }
    return nil
}
```

## Limitations and Notes

1. **Version Compatibility**: Plugin must be compiled with the same Go version as the main program
2. **Platform Limitations**: Go plugins do not support cross-compilation
3. **Lifecycle**: Plugins cannot be unloaded at runtime
4. **Dependency Management**: Plugin's dependency versions must be compatible with the main program

## Example Plugins

Can refer to example implementations in the `internal/plugins/` directory.

## Troubleshooting

- **Plugin cannot be loaded**: Check Go version compatibility
- **Interface mismatch**: Ensure correct interface methods are implemented
- **Performance issues**: Check for blocking operations in plugin
- **Memory leaks**: Ensure Cleanup method is correctly implemented