#!/bin/bash
# setup_env.sh - Script to set up Python environment for BLE_WIFi project
# Usage: source setup_env.sh OR ./setup_env.sh

set -e

# Create virtual environment if not exists
#echo "[INFO] Creating Python virtual environment in .venv..."
#python3 -m venv .venv

# Activate the virtual environment
echo "[INFO] Activating virtual environment..."
source .venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
if [ -f requirements.txt ]; then
    echo "[INFO] Installing dependencies from requirements.txt..."
    pip install -r requirements.txt
else
    echo "[WARN] requirements.txt not found. Skipping dependency installation."
fi

echo "[INFO] Python environment setup complete."
