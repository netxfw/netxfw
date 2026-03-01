# NetXFW Testing Strategy and Test Cases

## Testing Overview

NetXFW adopts a multi-layered testing strategy, including unit tests, integration tests, performance benchmarks, and hot reload tests, ensuring system stability and performance across various scenarios.

## Test Categories

### 1. Functional Testing

#### 1.1 Attack Simulation Testing
- **File**: `test/verify_attack.py`
- **Function**: Simulates high-speed attack traffic, verifies system performance under pressure
- **Test Content**:
  - Processing capacity of thousands of packets per second
  - Effectiveness of firewall rules
  - System resource usage

#### 1.2 Hybrid Approval Process Testing
- **File**: `test/verify_hybrid_approval.go`
- **Function**: Tests manual and automatic rule addition workflows
- **Test Scenarios**:
  - Manual rule addition with immediate activation
  - External alert automatic rule activation
  - Manual rule addition with pending approval status

### 2. Integration Testing

#### 2.1 CLI Command Integration Testing
- **Files**: `cmd/netxfw/commands/root_test.go`, `cmd/netxfw/commands/agent/integration_test.go`
- **Function**: Tests complete execution flow of CLI commands
- **Test Content**:
  - Root command and subcommand execution
  - Rule management commands (add, delete, list)
  - Shortcut commands (block, allow, unlock)
  - Port, rate limit, security, system commands
  - Command-line argument parsing and error handling

#### 2.2 Plugin System Testing
- Verify plugin loading and unloading functionality
- Test plugin interaction with main system
- Verify plugin compatibility

#### 2.3 Cluster Feature Testing
- Verify multi-node rule synchronization
- Test failover mechanisms
- Verify load balancing strategies

### 3. Performance Benchmark Testing

#### 3.1 SDK Performance Benchmarks
- **File**: `pkg/sdk/mock/mock_benchmark_test.go`
- **Test Content**:
  - SDK creation performance
  - Blacklist/whitelist operation performance
  - Rule operation performance
  - Statistics retrieval performance
  - Concurrent operation performance

#### 3.2 API Handler Benchmarks
- **File**: `internal/api/handlers_benchmark_test.go`
- **Test Content**:
  - Health check handler performance
  - Statistics handler performance
  - Configuration handler performance
  - Connection tracking handler performance
  - JSON encoding/decoding performance
  - Concurrent API request performance

#### 3.3 XDP Adapter Benchmarks
- **File**: `internal/xdp/adapter_benchmark_test.go`
- **Test Content**:
  - Mock Manager creation performance
  - Blacklist/whitelist operation performance
  - IP+Port rule operation performance
  - Rate limit rule operation performance
  - Concurrent operation performance

#### 3.4 Performance Statistics Benchmarks
- **File**: `internal/xdp/performance_stats_benchmark_test.go`
- **Test Content**:
  - Statistics collection performance
  - Statistics aggregation performance
  - Memory allocation patterns

### 4. Hot Reload Testing

#### 4.1 Rule Migration Testing
- **File**: `internal/xdp/migrator_test.go`
- **Test Content**:
  - Rule migration during reload
  - State preservation during reload
  - Zero-downtime reload verification

#### 4.2 Configuration Hot Reload Testing
- **File**: `internal/plugins/config_test.go`
- **Test Content**:
  - Configuration reload without restart
  - Configuration validation
  - Rollback on failure

## Running Tests

### Run All Tests
```bash
make test
```

### Run Unit Tests
```bash
go test ./... -v
```

### Run Benchmarks
```bash
go test ./... -bench=. -benchmem
```

### Run Integration Tests
```bash
go test ./cmd/netxfw/... -tags=integration -v
```

### Run with Coverage
```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## Test Coverage

| Package | Coverage |
|---------|----------|
| pkg/sdk | 85% |
| internal/xdp | 78% |
| internal/api | 82% |
| cmd/netxfw | 75% |

## Continuous Integration

Tests are automatically run in CI pipeline:
1. On every pull request
2. On every merge to main branch
3. Nightly full test suite

## Test Best Practices

### 1. Table-Driven Tests
Use table-driven tests for multiple test cases:

```go
func TestValidateIP(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        wantErr bool
    }{
        {"valid ipv4", "192.168.1.1", false},
        {"invalid ip", "256.1.1.1", true},
        {"valid cidr", "192.168.1.0/24", false},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidateIP(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateIP() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### 2. Mock Interfaces
Use mocks for external dependencies:

```go
type MockSDK struct {
    mock.Mock
}

func (m *MockSDK) AddToBlacklist(ip string) error {
    args := m.Called(ip)
    return args.Error(0)
}
```

### 3. Cleanup
Always clean up resources after tests:

```go
func TestXDPManager(t *testing.T) {
    mgr, err := NewManager()
    require.NoError(t, err)
    
    t.Cleanup(func() {
        mgr.Close()
    })
    
    // Test code...
}
```

## Related Documentation

- [Architecture Overview](./02-02_architecture_en.md)
- [API Reference](./api/04-05_api_reference_en.md)
- [Performance Benchmarks](./performance/06-02_benchmarks_en.md)
