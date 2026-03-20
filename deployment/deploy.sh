#!/usr/bin/env bash
# HySP Certificate API - Deployment Script (pull from ghcr.io)
# Usage: sudo bash /hysp/hycert-api/deployment/deploy.sh

set -euo pipefail

APP_DIR="/hysp/hycert-api"
IMAGE="ghcr.io/robert7528/hycert-api:latest"
QUADLET_SRC="$APP_DIR/deployment/hycert-api.container"
QUADLET_DEST="/etc/containers/systemd/hycert-api.container"
NGINX_SRC="$APP_DIR/deployment/nginx-hycert-api.conf"
NGINX_DEST="/etc/nginx/conf.d/service/hycert-api.conf"
ENV_FILE="/etc/hycert/api.env"

echo "=== [1/4] Pull latest source (configs / quadlet / nginx) ==="
cd "$APP_DIR"
git pull

echo "=== [2/4] Setup env file (if not exists) ==="
if [ ! -f "$ENV_FILE" ]; then
    mkdir -p /etc/hycert
    cp "$APP_DIR/deployment/api.env.example" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    echo ""
    echo "  !! 請編輯 $ENV_FILE 填入正確設定後重新執行 !!"
    echo "  !! 必填：JWT_SECRET（需與 hyadmin-api 一致）   !!"
    echo ""
    exit 1
fi

echo "=== [3/5] Create data directory ==="
mkdir -p /hysp/hycert/data

echo "=== [4/5] Pull & start container ==="
podman pull "$IMAGE"

cp "$QUADLET_SRC" "$QUADLET_DEST"
systemctl daemon-reload
systemctl restart hycert-api
systemctl status hycert-api --no-pager

echo "=== [5/5] Install nginx config ==="
mkdir -p "$(dirname "$NGINX_DEST")"
cp "$NGINX_SRC" "$NGINX_DEST"
nginx -t && systemctl reload nginx

echo ""
echo "Done."
echo "  API:  http://127.0.0.1:8082/api/v1/health"
echo "  Log:  journalctl -u hycert-api -f"
