#!/bin/bash
#
#sudo ip link set can0 up type can bitrate 500000  #CAN standard

sudo ip link set can0 down

sudo ip link set can0 up type can bitrate 250000  #CAN extended

dir=$(pwd)

source $dir/venv/bin/activate

python can_j1939_service.py
