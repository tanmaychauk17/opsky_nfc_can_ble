#!/bin/bash

# Start the ZeroMQ hub
python3 zmqhub.py > zmqhub.log 2>&1 &

# Wait a moment to ensure the hub is up
sleep 2

# Start the NFC service (system Python, outside venv)
sudo python3 nfc_service.py > nfc_service.log 2>&1 &
sleep 2

sudo ip link set can0 up type can bitrate 250000
sleep 2
# Start the CAN J1939 service (in venv, if needed)
# source /path/to/venv/bin/activate
./can_start.sh > can_j1939_service.log 2>&1 &

#source opsky_ble/venv/bin/activate
#python3 opsky_ble/opsky_simulator.py > opsky_ble/opsky_simulator.log

wait
