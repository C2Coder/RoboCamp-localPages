#!/bin/bash

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="robocamp-local-pages"
SERVICE_FILE="${SERVICE_NAME}.service"

# Check if .env exists
if [ ! -f "${SCRIPT_DIR}/.env" ]; then
    echo "Error: .env file not found in ${SCRIPT_DIR}"
    exit 1
fi

# Check if .venv exists
if [ ! -d "${SCRIPT_DIR}/.venv" ]; then
    echo "Error: .venv directory not found in ${SCRIPT_DIR}"
    echo "Please create a virtual environment first: python3 -m venv .venv"
    exit 1
fi

# Copy service file to systemd
sudo cp "${SCRIPT_DIR}/${SERVICE_FILE}" /etc/systemd/system/

# Reload systemd daemon
sudo systemctl daemon-reload

# Enable the service
sudo systemctl enable ${SERVICE_NAME}

echo "Service ${SERVICE_NAME} installed and enabled."
echo "To start: sudo systemctl start ${SERVICE_NAME}"
echo "To check status: sudo systemctl status ${SERVICE_NAME}"
echo "To view logs: sudo journalctl -u ${SERVICE_NAME} -f"