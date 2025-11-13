#!/bin/bash
set -euo pipefail

APP_NAME="ritapi-plugin"
APP_DIR="/opt/new-archangel/services/minifw/plugins/${APP_NAME}"
SERVICE_FILE="/lib/systemd/system/${APP_NAME}.service"
LOG_DIR="/var/log/${APP_NAME}"
RUN_DIR="/var/run/${APP_NAME}"
CONF_DIR="/etc/${APP_NAME}"
STAMP_DIR="/var/lib/${APP_NAME}"

echo "[*] Stopping systemd service if running..."
if systemctl list-units --full -all | grep -q "${APP_NAME}.service"; then
    systemctl stop "${APP_NAME}.service" || true
    systemctl disable "${APP_NAME}.service" || true
fi

echo "[*] Removing systemd service file..."
rm -f "${SERVICE_FILE}"
systemctl daemon-reload

echo "[*] Removing application directory..."
rm -rf "${APP_DIR}"

echo "[*] Removing logs, runtime, configs, and stamp data..."
rm -rf "${LOG_DIR}" "${RUN_DIR}" "${CONF_DIR}" "${STAMP_DIR}"

echo "[*] Removing remaining plugin subdir (if any)..."
rm -rf "/opt/new-archangel/services/minifw/plugins/${APP_NAME}"

echo "[✔] ${APP_NAME} uninstalled successfully."
