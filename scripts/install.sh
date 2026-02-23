#!/bin/bash

# NetXFW Quick Deployment Script / NetXFW 快速部署脚本
# Version: 1.0.20
# Supported OS: Linux (Kernel 5.4+)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}"
echo "  _   _      _  __  _____  __        __"
echo " | \ | | ___| |_\ \/ / __| \ \      / /"
echo " |  \| |/ _ \ __|\  /| |_   \ \ /\ / / "
echo " | |\  |  __/ |_ /  \|  _|   \ V  V /  "
echo " |_| \_|\___|\__/_/\_\_|      \_/\_/   "
echo -e "${NC}"
echo -e "--- eBPF/XDP Firewall Deployment Tool ---"
echo ""

# 1. Check Root Privilege
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root / 请以 root 权限运行${NC}"
    exit 1
fi

# 2. Check Kernel Version (XDP requires 4.18+, 5.4+ recommended)
KERNEL_MAJOR=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2)
if [ "$KERNEL_MAJOR" -lt 4 ] || ([ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -lt 18 ]); then
    echo -e "${RED}Error: Kernel version $(uname -r) is too old. Requires 4.18+ (5.4+ recommended).${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Kernel $(uname -r) detected${NC}"

# 3. Check Dependencies
echo -e "${YELLOW}Checking dependencies...${NC}"
MISSING_DEPS=()
for dep in clang llvm bpftool make go; do
    if ! command -v $dep &> /dev/null; then
        MISSING_DEPS+=($dep)
    fi
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo -e "${YELLOW}Installing missing dependencies: ${MISSING_DEPS[*]}...${NC}"
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y clang llvm libelf-dev bpftool make golang-go
    elif command -v yum &> /dev/null; then
        yum install -y clang llvm elfutils-libelf-devel make golang
    else
        echo -e "${RED}Error: Package manager not supported. Please install: ${MISSING_DEPS[*]}${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}✓ Dependencies satisfied${NC}"

# 4. Build and Install
echo -e "${YELLOW}Building NetXFW...${NC}"
make generate
make build

echo -e "${YELLOW}Installing to system...${NC}"
make install

# 5. Initialize Configuration if not exists
if [ ! -f /etc/netxfw/config.yaml ]; then
    echo -e "${YELLOW}Initializing default configuration...${NC}"
    /usr/local/bin/netxfw system init --config /etc/netxfw/config.yaml
else
    echo -e "${BLUE}ℹ Configuration already exists at /etc/netxfw/config.yaml${NC}"
fi

# 6. Setup Systemd Service
echo -e "${YELLOW}Setting up systemd service...${NC}"
if [ -f "netxfw.service" ]; then
    cp netxfw.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable netxfw
    echo -e "${GREEN}✓ Service netxfw enabled${NC}"
else
    echo -e "${RED}Warning: netxfw.service file not found in current directory.${NC}"
fi

# 7. Final Instructions
echo ""
echo -e "${GREEN}====================================================${NC}"
echo -e "${GREEN}   NetXFW Installation Completed Successfully!      ${NC}"
echo -e "${GREEN}====================================================${NC}"
echo ""
echo -e "Quick Commands:"
echo -e "  - Start service:       ${YELLOW}systemctl start netxfw${NC}"
echo -e "  - Check status:        ${YELLOW}netxfw system status${NC}"
echo -e "  - View logs:           ${YELLOW}journalctl -u netxfw -f${NC}"
echo -e "  - Management CLI:      ${YELLOW}netxfw --help${NC}"
echo ""
echo -e "Config location:         ${BLUE}/etc/netxfw/config.yaml${NC}"
echo -e "Documentation:           ${BLUE}https://github.com/netxfw/netxfw${NC}"
echo ""
echo -e "${YELLOW}Reminder: SSH port 22 is allowed by default in the initial config.${NC}"
