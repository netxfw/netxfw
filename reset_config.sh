#!/bin/bash

# 删除现有配置文件，以便应用新默认值
echo "Removing existing config file to apply new defaults..."
rm -f /etc/netxfw/config.yaml

# 创建 netxfw 目录（如果不存在）
mkdir -p /etc/netxfw

echo "Starting netxfw to generate new config with safe defaults..."
cd /root/netxfw && go run cmd/netxfw/main.go init

echo "New configuration has been generated with safer defaults."
echo "DefaultDeny is now set to false to prevent network interruption."