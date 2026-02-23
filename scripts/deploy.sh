#!/bin/bash

# NetXFW Quick Binary Deployment/Update Script
# Automatically downloads the latest release from GitHub

set -e

# Configuration
REPO="netxfw/netxfw"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/netxfw"
SERVICE_NAME="netxfw"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}--- NetXFW Deployment & Update Tool ---${NC}"

# 1. Root check
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root${NC}"
    exit 1
fi

# 2. Detect Architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)  BINARY_ARCH="x86_64" ;;
    aarch64) BINARY_ARCH="arm64" ;;
    arm64)   BINARY_ARCH="arm64" ;;
    *)       echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
esac

# 3. Get Latest Version info
echo -e "${YELLOW}Fetching latest release info from GitHub...${NC}"
LATEST_RELEASE=$(curl -s https://api.github.com/repos/$REPO/releases/latest)
VERSION=$(echo "$LATEST_RELEASE" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$VERSION" ]; then
    echo -e "${RED}Error: Could not find latest release.${NC}"
    exit 1
fi

# 4. Check Current Version for Update
if [ -f "$INSTALL_DIR/netxfw" ]; then
    # Try to get version from binary. Assuming 'netxfw version' exists.
    # If not, we still proceed with update if requested or if we're forced.
    CURRENT_VERSION=$($INSTALL_DIR/netxfw version --short 2>/dev/null || echo "unknown")
    echo -e "Current version: ${BLUE}$CURRENT_VERSION${NC}"
    echo -e "Latest version:  ${GREEN}$VERSION${NC}"
    
    if [ "$CURRENT_VERSION" == "$VERSION" ] && [ "$1" != "--force" ]; then
        echo -e "${GREEN}NetXFW is already up to date.${NC}"
        exit 0
    fi
    echo -e "${YELLOW}Updating NetXFW...${NC}"
fi

# 5. Extract Download URL for tar.gz
# Pattern: netxfw_Linux_x86_64.tar.gz or netxfw_Linux_arm64.tar.gz
DOWNLOAD_URL=$(echo "$LATEST_RELEASE" | grep "browser_download_url" | grep "Linux" | grep "$BINARY_ARCH" | grep "tar.gz" | cut -d '"' -f 4 | head -n 1)

if [ -z "$DOWNLOAD_URL" ]; then
    echo -e "${RED}Error: Could not find suitable asset for $BINARY_ARCH Linux.${NC}"
    exit 1
fi

echo -e "${YELLOW}Downloading: $DOWNLOAD_URL${NC}"
TMP_DIR=$(mktemp -d)
curl -L -o "$TMP_DIR/netxfw.tar.gz" "$DOWNLOAD_URL"

# 6. Extract and Install
echo -e "${YELLOW}Extracting and installing...${NC}"
tar -xzf "$TMP_DIR/netxfw.tar.gz" -C "$TMP_DIR"
# The binary in the tarball is likely named 'netxfw'
if [ -f "$TMP_DIR/netxfw" ]; then
    mv "$TMP_DIR/netxfw" "$INSTALL_DIR/netxfw"
    chmod +x "$INSTALL_DIR/netxfw"
else
    # Try to find any executable named netxfw in case of subdirectories
    FIND_BIN=$(find "$TMP_DIR" -type f -name "netxfw" | head -n 1)
    if [ -n "$FIND_BIN" ]; then
        mv "$FIND_BIN" "$INSTALL_DIR/netxfw"
        chmod +x "$INSTALL_DIR/netxfw"
    else
        echo -e "${RED}Error: Could not find 'netxfw' binary in the package.${NC}"
        ls -R "$TMP_DIR"
        exit 1
    fi
fi
rm -rf "$TMP_DIR"

# 7. Initialize/Update Config
echo -e "${YELLOW}Checking configuration...${NC}"
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    "$INSTALL_DIR/netxfw" system init --config "$CONFIG_DIR/config.yaml"
    echo -e "${GREEN}✓ Configuration initialized.${NC}"
fi
touch "$CONFIG_DIR/lock_list.txt"

# 8. Setup/Restart Service
if [ ! -f "/etc/systemd/system/netxfw.service" ]; then
    echo -e "${YELLOW}Creating systemd service...${NC}"
    cat <<EOF > /etc/systemd/system/netxfw.service
[Unit]
Description=NetXFW - eBPF/XDP Firewall Service
After=network.target

[Service]
Type=simple
ExecStartPre=$INSTALL_DIR/netxfw system load
ExecStart=$INSTALL_DIR/netxfw system daemon --mode agent
Restart=always
RestartSec=5
LimitMEMLOCK=infinity
WorkingDirectory=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable netxfw
    echo -e "${GREEN}✓ Service created and enabled.${NC}"
fi

# Restart service to apply update
if systemctl is-active --quiet netxfw; then
    echo -e "${YELLOW}Restarting netxfw service...${NC}"
    systemctl restart netxfw
    echo -e "${GREEN}✓ Service restarted.${NC}"
else
    echo -e "${BLUE}ℹ Service is not running. Start it with: systemctl start netxfw${NC}"
fi

# 9. Optional: Setup Auto-Update Cron (Daily check)
if [ "$1" == "--enable-auto-update" ] || [ ! -f "/etc/cron.daily/netxfw-update" ]; then
    echo -e "${YELLOW}Setting up daily auto-update check...${NC}"
    cat <<EOF > /etc/cron.daily/netxfw-update
#!/bin/bash
# Automatically check for NetXFW updates
/usr/bin/curl -sSL https://raw.githubusercontent.com/netxfw/netxfw/main/scripts/deploy.sh | bash > /var/log/netxfw-update.log 2>&1
EOF
    chmod +x /etc/cron.daily/netxfw-update
    echo -e "${GREEN}✓ Daily auto-update check scheduled via cron.${NC}"
fi

echo ""
echo -e "${GREEN}====================================================${NC}"
echo -e "${GREEN}   NetXFW $VERSION Deployed/Updated Successfully!   ${NC}"
echo -e "${GREEN}====================================================${NC}"
echo ""
