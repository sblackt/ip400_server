#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${VENV_DIR:-${REPO_DIR}/.venv}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "[IP400] Using repository at ${REPO_DIR}"

if [ ! -x "$(command -v "${PYTHON_BIN}")" ]; then
  echo "[IP400] Python interpreter '${PYTHON_BIN}' not found. Install python3 before continuing." >&2
  exit 1
fi

if [ ! -d "${VENV_DIR}" ]; then
  echo "[IP400] Creating virtual environment at ${VENV_DIR}"
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi

echo "[IP400] Upgrading pip and installing Python dependencies"
"${VENV_DIR}/bin/pip" install --upgrade pip
"${VENV_DIR}/bin/pip" install -r "${REPO_DIR}/requirements.txt"

echo "[IP400] Installing configuration template (if missing)"
sudo install -d -m 755 /etc/ip400
if [ ! -f /etc/ip400/ip400.env ]; then
  sudo install -m 644 "${REPO_DIR}/config/ip400.env.example" /etc/ip400/ip400.env
  echo "[IP400] Created /etc/ip400/ip400.env (edit this file to customize ports or paths)"
else
  echo "[IP400] Existing /etc/ip400/ip400.env preserved"
fi

echo "[IP400] Installing systemd units"
sudo install -m 644 "${REPO_DIR}/systemd/ip400_spi.service" /etc/systemd/system/ip400_spi.service
sudo install -m 644 "${REPO_DIR}/systemd/ip400_server.service" /etc/systemd/system/ip400_server.service

echo "[IP400] Reloading systemd and enabling services"
sudo systemctl daemon-reload
sudo systemctl enable --now ip400_spi.service ip400_server.service

echo "[IP400] Installation complete."
echo "  - Edit /etc/ip400/ip400.env to adjust SPI or web settings."
echo "  - Check service status with: sudo systemctl status ip400_spi.service ip400_server.service"
