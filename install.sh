#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
PLAIN='\033[0m'

REPO="Hamster-Prime/DNS_automatic_traffic_splitting"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/doh-autoproxy"
BINARY_NAME="doh-autoproxy"
SERVICE_NAME="doh-autoproxy"

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}请使用 root 权限运行此脚本 (sudo su)${PLAIN}"
        exit 1
    fi
}

check_sys() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64)
            ARCH="arm64"
            ;;
        *)
            echo -e "${RED}不支持的架构: $ARCH${PLAIN}"
            exit 1
            ;;
    esac
    OS="linux"
    echo -e "${GREEN}检测到系统: $OS/$ARCH${PLAIN}"
}

get_latest_version() {
    echo -e "正在获取最新版本信息..."
    LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$LATEST_TAG" ]; then
        echo -e "${RED}获取最新版本失败，请检查网络连接。${PLAIN}"
        return 1
    fi
    echo -e "${GREEN}最新版本: $LATEST_TAG${PLAIN}"
    return 0
}

install_app() {
    get_latest_version
    if [ $? -ne 0 ]; then return; fi

    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_TAG/doh-autoproxy-$OS-$ARCH"
    echo -e "正在下载: $DOWNLOAD_URL"

    curl -L -o "$INSTALL_DIR/$BINARY_NAME" "$DOWNLOAD_URL"
    if [ $? -ne 0 ]; then
        echo -e "${RED}下载失败！${PLAIN}"
        return
    fi
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    echo -e "${GREEN}主程序安装/更新成功！${PLAIN}"
    
    install_service
}

install_service() {
    if [ -f "/etc/systemd/system/$SERVICE_NAME.service" ]; then
        echo "服务文件已存在，正在更新..."
    fi

    mkdir -p "$CONFIG_DIR"
    
    cat <<EOF > /etc/systemd/system/$SERVICE_NAME.service
[Unit]
Description=DoH Automatic Traffic Splitting Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$CONFIG_DIR
ExecStart=$INSTALL_DIR/$BINARY_NAME
Restart=always
RestartSec=5
Environment="DOH_AUTOPROXY_CONFIG=$CONFIG_DIR/config.yaml"

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    echo -e "${GREEN}Systemd 服务已安装/更新。${PLAIN}"
}

update_config() {
    mkdir -p "$CONFIG_DIR"
    
    echo -e "正在下载最新配置文件模板..."
    curl -L -o "$CONFIG_DIR/config.yaml.example" "https://raw.githubusercontent.com/$REPO/main/config.yaml.example"
    
    if [ -f "$CONFIG_DIR/config.yaml" ]; then
        echo -e "${YELLOW}检测到已存在 config.yaml${PLAIN}"
        read -p "是否覆盖现有配置？(覆盖前会备份为 config.yaml.bak) [y/N]: " choice
        case "$choice" in
            [yY][eE][sS]|[yY])
                cp "$CONFIG_DIR/config.yaml" "$CONFIG_DIR/config.yaml.bak"
                cp "$CONFIG_DIR/config.yaml.example" "$CONFIG_DIR/config.yaml"
                echo -e "${GREEN}配置已覆盖，旧配置备份为 config.yaml.bak${PLAIN}"
                ;;
            *)
                echo -e "${GREEN}已跳过覆盖配置。你可以参考 $CONFIG_DIR/config.yaml.example 手动修改。${PLAIN}"
                ;;
        esac
    else
        cp "$CONFIG_DIR/config.yaml.example" "$CONFIG_DIR/config.yaml"
        echo -e "${GREEN}已创建默认配置文件: $CONFIG_DIR/config.yaml${PLAIN}"
    fi
    
    touch "$CONFIG_DIR/hosts.txt"
    touch "$CONFIG_DIR/rule.txt"
}

manage_service() {
    echo -e "------------------------"
    echo -e "  服务管理"
    echo -e "------------------------"
    echo -e "1. 启动服务"
    echo -e "2. 停止服务"
    echo -e "3. 重启服务"
    echo -e "4. 查看状态"
    echo -e "5. 查看日志"
    echo -e "0. 返回主菜单"
    echo -e "------------------------"
    read -p "请输入选项: " choice
    case "$choice" in
        1) systemctl start $SERVICE_NAME && echo -e "${GREEN}服务已启动${PLAIN}" ;;
        2) systemctl stop $SERVICE_NAME && echo -e "${GREEN}服务已停止${PLAIN}" ;;
        3) systemctl restart $SERVICE_NAME && echo -e "${GREEN}服务已重启${PLAIN}" ;;
        4) systemctl status $SERVICE_NAME ;;
        5) journalctl -u $SERVICE_NAME -f ;;
        0) return ;;
        *) echo -e "${RED}无效选项${PLAIN}" ;;
    esac
}

uninstall() {
    read -p "确定要卸载吗？(配置文件夹将被保留) [y/N]: " choice
    case "$choice" in
        [yY][eE][sS]|[yY])
            systemctl stop $SERVICE_NAME
            systemctl disable $SERVICE_NAME
            rm -f "/etc/systemd/system/$SERVICE_NAME.service"
            systemctl daemon-reload
            rm -f "$INSTALL_DIR/$BINARY_NAME"
            echo -e "${GREEN}卸载完成。配置文件保留在 $CONFIG_DIR${PLAIN}"
            ;;
        *)
            echo -e "已取消。"
            ;;
    esac
}

show_menu() {
    clear
    echo -e "----------------------------------------------"
    echo -e "  DNS Automatic Traffic Splitting 安装脚本"
    echo -e "  OS: $OS Arch: $ARCH"
    echo -e "----------------------------------------------"
    echo -e "1. 安装 / 更新 主程序"
    echo -e "2. 更新 配置文件 (config.yaml)"
    echo -e "3. 服务管理 (启动/停止/日志)"
    echo -e "4. 卸载程序"
    echo -e "0. 退出"
    echo -e "----------------------------------------------"
    read -p "请输入选项 [0-4]: " num

    case "$num" in
        1)
            install_app
            ;;
        2)
            update_config
            ;;
        3)
            manage_service
            ;;
        4)
            uninstall
            ;;
        0)
            exit 0
            ;;
        *)
            echo -e "${RED}无效选项，请重新输入${PLAIN}"
            ;;
    esac
    
    echo -e ""
    read -p "按回车键返回主菜单..."
}

check_root
check_sys

while true; do
    show_menu
done
