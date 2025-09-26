# NFC to CAN J1939 Bridge Setup Guide

This document describes how to set up and run the NFC-to-CAN J1939 bridge system using the provided Python services.

## Prerequisites

- **Hardware:**
  - Raspberry Pi 4B (or compatible Linux SBC)
  - PN532 NFC module (UART connection)
  - CAN interface (e.g., PiCAN2, USB-CAN, or similar)

- **Software:**
  - Python 3.7+
  - System CAN drivers (e.g., `socketcan`)
  - Required Python packages (see below)

---

## Raspberry Pi 4B Wiring

### PN532 NFC HAT (UART mode)
| PN532 Pin | Connects to Raspberry Pi 4B |
|-----------|-----------------------------|
| RXD       | GPIO14 (TXD, Pin 8)         |
| TXD       | GPIO15 (RXD, Pin 10)        |
| RST       | GPIO20 (Pin 38)             |
| VCC       | 3.3V (Pin 1) or 5V (Pin 2/4)|
| GND       | GND (Pin 6/9/etc.)          |

### PiCAN2 (SPI CAN HAT)
| PiCAN2 Pin | Connects to Raspberry Pi 4B |
|------------|-----------------------------|
| MOSI       | GPIO10 (Pin 19)             |
| MISO       | GPIO9 (Pin 21)              |
| SCLK       | GPIO11 (Pin 23)             |
| CE0        | GPIO8 (Pin 24)              |
| INT        | GPIO25 (Pin 22)             |
| 5V         | 5V (Pin 2/4)                |
| GND        | GND (Pin 6/9/etc.)          |

**Note:** UART and SPI can be used simultaneously on the Pi 4B.  
Enable both interfaces in `raspi-config`.

---

## Installation

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd opsky_nfc_can_ble
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   Ensure you have the following packages:
   - python-can
   - can-j1939
   - pyzmq
   - zmq.asyncio
   - RPi.GPIO

3. **Enable CAN interface:**
   - For SocketCAN (e.g., PiCAN2):
     ```bash
     sudo ip link set can0 up type can bitrate 250000
     ```
   - Confirm CAN interface is up:
     ```bash
     ifconfig can0
     ```

---

## Configuration

- **Global parameters** can be set in `can_j1939_service.py`:
  - `SEND_INTERVAL`: CAN send interval (seconds)
  - `PGN_VALUE`: J1939 PGN to use
  - `SOURCE_ADDRESS`: J1939 source address
  - `DEST_ADDRESS`: J1939 destination address

- **NFC parameters** (in `nfc_service.py`):
  - UART reset pin (default: 20)
  - ZMQ XSUB address (from `zmqhub.py`)

---

## Running the Services

1. **Start the ZMQ Hub:**
   ```bash
   python zmqhub.py
   ```
   (Keep this running in a terminal)

2. **Start the NFC Service:**
   ```bash
   python nfc_service.py
   ```
   (This will read NFC tags and publish data over ZMQ)

3. **Start the CAN J1939 Service:**
   ```bash
   python can_j1939_service.py
   ```
   (This will receive NFC data from ZMQ and send it over CAN J1939)

4. **(Optional) Use provided scripts:**
   - `run_all.sh`: Start all services
   - `kill_all.sh`: Stop all services
   
5. ** for now BLE test code is maintained separately in other repository https://github.com/sayu-agiliad/BLE_WIFi
   - checkout to opsky_device_prototype branch
   - execute opsky_simulator.py files after installing specified requirements

---

## Data Flow

1. NFC tag is scanned by PN532.
2. `nfc_service.py` publishes UID as JSON on the `nfc_data` topic via ZMQ.
3. `can_j1939_service.py` subscribes to `nfc_data`, receives UID, and sends it as a J1939 message over CAN.
4. 'bleToCan' and 'canToBle' are subscribed by can_j1939_service.py and opsky_simulator.py and exchanges the respective data. 

---

## Troubleshooting

- Ensure all dependencies are installed and hardware is connected.
- Check CAN interface status with `ifconfig can0`.
- Use `dmesg` or `candump can0` for CAN debugging.
- Review logs printed by each service for errors.

---

## Customization

- Edit global variables in `can_j1939_service.py` for CAN timing and addressing.
- Edit `nfc_service.py` for NFC read interval or UART pin if needed.

---

## Support

For further help, contact the project maintainer or open an issue in the repository.
