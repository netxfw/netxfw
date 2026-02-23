# Universal Interface and Config Parameter Support

## Overview

netxfw supports universal interface (`-i`) and config file (`-c`) parameters for multiple commands, enabling flexible multi-network-card management and configuration management. This design allows multiple commands to operate on specific network interfaces and supports specifying configuration files.

## Feature Highlights

### 1. Universal Interface Parameter Support
- Multiple commands support `-i` or `--interface` parameter to specify network interfaces
- Supports specifying single or multiple network interfaces
- Supports specifying interfaces via positional parameters
- Uses default interfaces from config file when no interface is specified

### 2. Universal Config File Parameter Support
- Multiple commands support `-c` or `--config` parameter to specify configuration file
- Configuration file specified via command line has higher priority than default config file
- Supports combining interface and config file parameters

### 3. Interface-Specific PID File Management
- When running with specific interfaces, individual PID files are created for each interface: `/var/run/netxfw_<interface>.pid`
- When no interface is specified, the default PID file is used: `/var/run/netxfw.pid`
- Supports running multiple independent instances on the same system

### 4. Flexible Configuration
- Supports specifying default interfaces via the `base.interfaces` field in the configuration file
- Supports overriding interface settings in the configuration file via command-line parameters
- Command-line parameters take precedence over configuration file settings

## Usage

### Command-Line Usage

```bash
# Start Agent using interfaces specified in the configuration file
sudo netxfw system agent

# Start Agent on specific interface
sudo netxfw system agent -i eth0

# Start Agent on multiple interfaces
sudo netxfw system agent -i eth0,eth1

# Use command-line parameters to override interface settings in config file
sudo netxfw system agent -i eth2 eth3

# Start Agent using a specific configuration file
sudo netxfw system agent -c /path/to/config.yaml

# Start Agent using a specific configuration file and specific interface
sudo netxfw system agent -c /path/to/config.yaml -i eth0

# Start daemon using interfaces specified in the configuration file
sudo netxfw system daemon

# Start daemon on specific interface
sudo netxfw system daemon -i eth0

# Start daemon on multiple interfaces
sudo netxfw system daemon -i eth0,eth1

# Start daemon using a specific configuration file
sudo netxfw system daemon -c /path/to/config.yaml

# Start daemon using a specific configuration file and specific interface
sudo netxfw system daemon -c /path/to/config.yaml -i eth0

# Check system status
sudo netxfw system status

# Check status for specific interfaces
sudo netxfw system status -i eth0

# Check status using a specific configuration file
sudo netxfw system status -c /path/to/config.yaml

# Check status using a specific configuration file and specific interfaces
sudo netxfw system status -c /path/to/config.yaml -i eth0,eth1
```

### Configuration File Settings

In `/etc/netxfw/config.yaml`:

```yaml
base:
  # Specify default network interfaces
  interfaces: ["eth0", "eth1"]
  # Other configurations...
```

## PID File Management

### Naming Convention
- Interface-specific: `/var/run/netxfw_<interface>.pid` (e.g., `/var/run/netxfw_eth0.pid`)
- Default: `/var/run/netxfw.pid`

### Lifecycle Management
- On startup: Create corresponding PID files based on the interface list
- On shutdown: Clean up all associated PID files
- On abnormal termination: Automatically clean up stale PID files on next startup

## System Status Checks

### Basic Status Check
```bash
# Check system status
sudo netxfw system status
```

### Status Check with Specific Configuration File
```bash
# Check status using a specific configuration file
sudo netxfw system status -c /path/to/custom/config.yaml
```

## Best Practices

### 1. Production Deployment
- Pre-set commonly used interfaces in the configuration file
- Use command-line parameters for temporary debugging
- Monitor multiple PID files to ensure all interface-specific Agent instances are running normally

### 2. Operational Considerations
- Ensure sufficient permissions to manage PID files under the `/var/run/` directory
- Regularly check the integrity of PID files
- Pay attention to PID file persistence issues in containerized environments

## Troubleshooting

### PID File Conflicts
- Check for leftover PID files
- Verify if the corresponding process is still running
- Manually clean up stale PID files and restart the service

### Interface Unavailability
- Confirm that the specified network interface exists and is active
- Check the spelling of the interface name
- Verify sufficient permissions to access the network interface