#!/bin/bash
# netxfw 一键脚本 - 简化版 XDP/eBPF 防火墙管理
# 自动识别网卡，一键执行，中文提示
# 支持 ufw 风格命令：enable/disable/deny/delete/reset

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETXFW_BIN="${SCRIPT_DIR}/netxfw"

# 检查是否以 root 权限运行
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}❌ 错误: 请使用 root 权限运行此脚本${NC}"
        echo "使用: sudo $0"
        exit 1
    fi
}

# 检查 netxfw 二进制文件是否存在
check_netxfw() {
    if [ ! -f "$NETXFW_BIN" ]; then
        echo -e "${YELLOW}⚠️  未找到 netxfw 二进制文件，正在编译...${NC}"
        cd "$SCRIPT_DIR"
        if ! go build -o netxfw ./cmd/netxfw; then
            echo -e "${RED}❌ 编译失败${NC}"
            exit 1
        fi
        echo -e "${GREEN}✅ 编译成功${NC}"
    fi
}

# 显示菜单
show_menu() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}   🔥 netxfw 一键防火墙管理 🔥${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo -e "${GREEN}【1】启动防火墙 (enable/start)${NC}"
    echo -e "${GREEN}【2】停止防火墙 (disable/stop)${NC}"
    echo -e "${GREEN}【3】查看状态 (status)${NC}"
    echo -e "${GREEN}【4】封禁 IP (deny/block)${NC}"
    echo -e "${GREEN}【5】解封 IP (delete/unblock)${NC}"
    echo -e "${GREEN}【6】查看封禁列表 (list)${NC}"
    echo -e "${GREEN}【7】重置防火墙 (reset)${NC}"
    echo -e "${GREEN}【8】重载配置 (reload)${NC}"
    echo -e "${YELLOW}【0】退出${NC}"
    echo ""
}

# 启动防火墙
start_firewall() {
    echo -e "${BLUE}🚀 正在启动防火墙...${NC}"
    echo -e "${YELLOW}ℹ️  自动识别网卡中...${NC}"
    
    if "$NETXFW_BIN" enable; then
        echo -e "${GREEN}✅ 防火墙启动成功！${NC}"
    else
        echo -e "${RED}❌ 防火墙启动失败${NC}"
    fi
    read -p "按回车键继续..."
}

# 停止防火墙
stop_firewall() {
    echo -e "${YELLOW}⚠️  正在停止防火墙...${NC}"
    
    if "$NETXFW_BIN" disable; then
        echo -e "${GREEN}✅ 防火墙已停止${NC}"
    else
        echo -e "${RED}❌ 防火墙停止失败${NC}"
    fi
    read -p "按回车键继续..."
}

# 查看状态
show_status() {
    echo -e "${BLUE}📊 防火墙状态${NC}"
    echo "----------------------------------------"
    "$NETXFW_BIN" status
    echo "----------------------------------------"
    read -p "按回车键继续..."
}

# 封禁 IP
block_ip() {
    read -p "请输入要封禁的 IP 地址: " ip
    if [ -z "$ip" ]; then
        echo -e "${RED}❌ IP 地址不能为空${NC}"
        read -p "按回车键继续..."
        return
    fi
    
    echo -e "${BLUE}🔒 正在封禁 IP: $ip${NC}"
    if "$NETXFW_BIN" deny "$ip"; then
        echo -e "${GREEN}✅ IP $ip 已成功封禁！${NC}"
    else
        echo -e "${RED}❌ 封禁失败${NC}"
    fi
    read -p "按回车键继续..."
}

# 解封 IP
unblock_ip() {
    read -p "请输入要解封的 IP 地址: " ip
    if [ -z "$ip" ]; then
        echo -e "${RED}❌ IP 地址不能为空${NC}"
        read -p "按回车键继续..."
        return
    fi
    
    echo -e "${BLUE}🔓 正在解封 IP: $ip${NC}"
    if "$NETXFW_BIN" delete "$ip"; then
        echo -e "${GREEN}✅ IP $ip 已成功解封！${NC}"
    else
        echo -e "${RED}❌ 解封失败${NC}"
    fi
    read -p "按回车键继续..."
}

# 查看封禁列表
list_blocked() {
    echo -e "${BLUE}📋 当前封禁的 IP 列表${NC}"
    echo "----------------------------------------"
    "$NETXFW_BIN" list
    echo "----------------------------------------"
    read -p "按回车键继续..."
}

# 重置防火墙
reset_firewall() {
    echo -e "${YELLOW}⚠️  警告：此操作将清空所有封禁的 IP！${NC}"
    read -p "确认要继续吗？(y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}🗑️  正在重置防火墙...${NC}"
        if "$NETXFW_BIN" reset; then
            echo -e "${GREEN}✅ 防火墙已重置${NC}"
        else
            echo -e "${RED}❌ 重置失败${NC}"
        fi
    else
        echo -e "${YELLOW}ℹ️  操作已取消${NC}"
    fi
    read -p "按回车键继续..."
}

# 重载配置
reload_config() {
    echo -e "${BLUE}🔄 正在重载配置...${NC}"
    if "$NETXFW_BIN" reload; then
        echo -e "${GREEN}✅ 配置重载成功${NC}"
    else
        echo -e "${RED}❌ 配置重载失败${NC}"
    fi
    read -p "按回车键继续..."
}

# 主循环
main() {
    check_root
    check_netxfw
    
    while true; do
        show_menu
        read -p "请选择操作 [0-8]: " choice
        
        case $choice in
            1)
                start_firewall
                ;;
            2)
                stop_firewall
                ;;
            3)
                show_status
                ;;
            4)
                block_ip
                ;;
            5)
                unblock_ip
                ;;
            6)
                list_blocked
                ;;
            7)
                reset_firewall
                ;;
            8)
                reload_config
                ;;
            0)
                echo -e "${GREEN}👋 再见！${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ 无效的选择，请重新输入${NC}"
                sleep 1
                ;;
        esac
    done
}

# 如果直接执行此脚本，则运行主程序
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
