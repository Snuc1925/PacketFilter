#!/bin/bash

# Kiểm tra có truyền tham số chưa
if [ -z "$1" ]; then
  echo "Usage: $0 <config-folder>"
  exit 1
fi

CONFIG_DIR="$1"

# Đường dẫn thư mục gốc (chính là thư mục chứa script)
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

# File nguồn
NGINX_CONF_SRC="$BASE_DIR/$CONFIG_DIR/nginx.conf"
DEFAULT_CONF_SRC="$BASE_DIR/$CONFIG_DIR/default"

# File đích
NGINX_CONF_DEST="/etc/nginx/nginx.conf"
DEFAULT_CONF_DEST="/etc/nginx/sites-available/default"

# Kiểm tra file tồn tại
if [ ! -f "$NGINX_CONF_SRC" ]; then
  echo "Error: $NGINX_CONF_SRC not found"
  exit 1
fi

if [ ! -f "$DEFAULT_CONF_SRC" ]; then
  echo "Error: $DEFAULT_CONF_SRC not found"
  exit 1
fi

echo "Copying configs from $CONFIG_DIR ..."

# Copy file với sudo
sudo cp "$NGINX_CONF_SRC" "$NGINX_CONF_DEST"
sudo cp "$DEFAULT_CONF_SRC" "$DEFAULT_CONF_DEST"

# Kiểm tra cấu hình nginx
echo "Testing nginx configuration..."
sudo nginx -t
if [ $? -ne 0 ]; then
  echo "Nginx config test failed. Not restarting."
  exit 1
fi

# Restart nginx
echo "Restarting nginx..."
sudo systemctl restart nginx

echo "Done!"
