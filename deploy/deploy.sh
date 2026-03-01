#!/bin/bash
# ============================================
# Go Server 部署脚本 - opluspro.top
# 在 Linux 服务器上运行此脚本
# ============================================

set -e

APP_NAME="go-server"
APP_DIR="/opt/go-server"
SERVICE_FILE="/etc/systemd/system/go-server.service"
NGINX_CONF="/etc/nginx/sites-available/opluspro.conf"
NGINX_LINK="/etc/nginx/sites-enabled/opluspro.conf"

echo "========================================="
echo "  部署 Go Server -> opluspro.top"
echo "========================================="

# 1. 创建应用目录
echo "[1/6] 创建应用目录 ${APP_DIR}..."
mkdir -p ${APP_DIR}

# 2. 复制文件（假设当前目录有这些文件）
echo "[2/6] 复制文件..."
cp server-linux ${APP_DIR}/server-linux
cp config.yaml ${APP_DIR}/config.yaml
chmod +x ${APP_DIR}/server-linux
chown -R www-data:www-data ${APP_DIR}

# 3. 安装 systemd 服务
echo "[3/6] 配置 systemd 服务..."
cp go-server.service ${SERVICE_FILE}
systemctl daemon-reload
systemctl enable go-server
systemctl restart go-server
echo "      服务状态:"
systemctl status go-server --no-pager || true

# 4. 配置 Nginx
echo "[4/6] 配置 Nginx 反向代理..."
cp nginx-opluspro.conf ${NGINX_CONF}
ln -sf ${NGINX_CONF} ${NGINX_LINK}

# 删除默认站点（如果存在）
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

echo "[5/6] 测试 Nginx 配置..."
nginx -t

echo "[6/6] 重载 Nginx..."
systemctl reload nginx

echo ""
echo "========================================="
echo "  部署完成！"
echo "========================================="
echo ""
echo "  域名: http://opluspro.top/"
echo "  服务: systemctl status go-server"
echo "  日志: journalctl -u go-server -f"
echo ""
echo "  API 路由:"
echo "    POST http://opluspro.top/api/platform/login"
echo "    POST http://opluspro.top/api/tools/login"
echo "    POST http://opluspro.top/api/tools/sign"
echo "    POST http://opluspro.top/api/sign/sign"
echo "    POST http://opluspro.top/api/sign/login"
echo "    POST http://opluspro.top/api/flash/get_versions"
echo "    GET  http://opluspro.top/crypto/cert/upgrade"
echo "    GET  http://opluspro.top/crypto/cert/upgradein"
echo ""
echo "  ⚠️  记得修改 config.yaml 中的数据库密码和 Telegram 配置！"
echo "========================================="
