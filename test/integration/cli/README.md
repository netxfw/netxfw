# CLI Integration Tests

This directory contains integration tests for the `netxfw` Command Line Interface.

## Files
- `verify_fix.go`: A Go script that programmatically tests rule listing and removal logic (verifying bug fixes).
- `run_tests.sh`: A shell script that builds the binary, runs `verify_fix.go`, and performs additional shell-based verification for `import` and `sync` commands.
- `import_test.txt`: Sample data for testing the `rule import` command.

## Running Tests
Run the shell script as root (required for BPF map access):
```bash
sudo ./run_tests.sh
```

## Coverage
- `rule list deny`: Verifies correct display of blacklist (checks for regression of whitelist display bug).
- `rule remove deny`: Verifies persistence removal.
- `rule import deny`: Verifies batch import of IPv4 and IPv6 addresses.
- `system sync`: Verifies configuration synchronization.
