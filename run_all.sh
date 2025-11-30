#!/bin/bash

# Start the ZeroMQ hub
python zmqhub.py > zmqhub.log 2>&1 &

# Wait a moment to ensure the hub is up
#sleep 2

# Start the NFC service (system Python, outside venv)
#sudo python nfc_service.py > nfc_service.log 2>&1 &
#sleep 2

#sudo ip link set can0 up type can bitrate 250000
#sleep 2
# Start the CAN J1939 service (in venv, if needed)
# source /path/to/venv/bin/activate
#./can_start.sh > can_j1939_service.log 2>&1 &

# Start the UWB service
#python uwb_service.py > uwb_service.log #2>&1 &

# Start the BLE service
# source opsky_ble_scripts/venv/bin/activate
python opsky_ble_scripts/opsky_simulator.py > opsky_ble_scripts/opsky_simulator.log #2>&1

wait
