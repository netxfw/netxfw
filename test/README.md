# netxfw Tests

This directory contains all test suites for the netxfw project organized by test type.

## Directory Structure

- [unit/](./unit/) - Unit tests for individual components (coming soon)
- [integration/](./integration/) - Integration tests for system workflows
- [performance/](./performance/) - Performance and stress tests

## Running Tests

### Integration Tests
Integration tests validate the complete workflow of the system, particularly the hybrid approval process.

To run integration tests:
```bash
cd test/integration
go run verify_hybrid_approval.go
```

### Performance Tests
Performance tests simulate high-volume traffic to evaluate system resilience under load.

To run performance tests:
```bash
cd test/performance
sudo python3 verify_attack.py
```

> Note: Performance tests require root privileges to send raw packets directly to the network interface.

## Test Categories

### Integration Tests
- Hybrid Approval Workflow (`verify_hybrid_approval.go`)
  - Tests manual rule addition with auto-activation
  - Tests external alert processing
  - Validates crisis list integration

### Performance Tests
- Attack Simulation (`verify_attack.py`)
  - Simulates high-speed packet flooding
  - Tests system resilience under load
  - Evaluates rate limiting effectiveness

## Adding New Tests

When adding new tests, place them in the appropriate subdirectory:
- Unit tests for individual functions → `unit/`
- Multi-component workflow tests → `integration/`
- Load/stress tests → `performance/`