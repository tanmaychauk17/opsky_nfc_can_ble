#!/bin/bash

echo "Killing zmqhub.py, nfc_service.py, and can_j1939_service.py..."

pkill -f zmqhub.py
pkill -f nfc_service.py
pkill -f can_j1939_service.py
pkill -f opsky_simulator.py

echo "All relevant processes have been terminated."
