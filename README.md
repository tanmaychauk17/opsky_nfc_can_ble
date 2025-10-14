# Opsky NFC, CAN, BLE & UWB Integration

Multi-protocol bridge system supporting NFC (PN532), CAN J1939, BLE peripherals, and UWB ranging for Opsky mobile applications.

## Project Structure

```
opsky_nfc_can_ble/
├── README.md                    # This file
├── SETUP.md                     # Detailed setup instructions
├── config.json                  # Global configuration
├── zmqhub.py                    # ZMQ message hub for inter-service communication
├── 
├── NFC Services/
│   ├── nfc_service.py           # Main NFC service with DESFire support
│   ├── nfc_desfire.py           # DESFire authentication logic
│   ├── cmac_calc.py             # CMAC calculation utilities
│   └── pn532/                   # PN532 driver library
│
├── CAN Services/
│   ├── can_j1939_service.py     # J1939 CAN service
│   ├── can_service.py           # Basic CAN service
│   └── can_start.sh             # CAN interface setup script
│
├── BLE & UWB Services/
│   ├── opsky_ble/               # BLE peripheral services directory
│   │   ├── opsky_service.py     # Main Opsky BLE GATT service
│   │   ├── opsky_simulator.py   # BLE device simulator/manager
│   │   ├── uwb_ble_service.py   # UWB-BLE bridge service
│   │   ├── uwb_ble_bridge.py    # UWB controller (DWM3001CDK)
│   │   ├── connection_monitor_simple.py # BLE connection monitoring
│   │   └── BLE_UWB_MobileApp_Flow.txt   # Mobile app integration guide
│
└── Scripts & Utilities/
    ├── run_all.sh               # Start all services
    ├── kill_all.sh              # Stop all services
    ├── opsky_service.service    # Systemd service file
    └── test_*.py                # Test scripts
```

## Key Features

### 🔷 NFC Support
- **PN532 NFC HAT** with UART communication
- **DESFire authentication** with CMAC session keys
- **Multi-card support** with secure authentication flow

### 🚗 CAN J1939 Support  
- **Vehicle communication** via CAN bus
- **J1939 protocol** for heavy-duty vehicles
- **Bidirectional data exchange** (NFC ↔ CAN)

### 📱 BLE Peripheral Services
- **Multi-service BLE peripheral** using bluez_peripheral
- **Opsky GATT service** with authentication and command handling
- **UWB-BLE bridge** for iPhone Nearby Interaction integration
- **Session-based security** with operator ID validation

### 📏 UWB Ranging Support
- **DWM3001CDK UWB module** integration
- **iPhone UWB discovery token** handling
- **Zone-based proximity detection** (ACCESS, WELCOME, NO_ZONE)
- **BLE notification** for command responses only

## Quick Start

### 1. Hardware Setup
```bash
# Enable UART for NFC
sudo raspi-config 
# Interface options -> Serial port -> login shell: no -> Serial port hardware: yes

# Setup CAN interface
sudo ip link set can0 up type can bitrate 250000
```

### 2. Install Dependencies
```bash
# Core packages
sudo python3 -m pip install python3-can can-j1939 pyzmq --break-system-packages

# BLE dependencies (in opsky_ble directory)
cd opsky_ble
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Start Services
```bash
# Start all services
./run_all.sh

# OR start individual services:
python zmqhub.py &
python nfc_service.py &
python can_j1939_service.py &
cd opsky_ble && python opsky_simulator.py &
cd opsky_ble && python uwb_ble_service.py &
```

## BLE-UWB Mobile Integration

For iOS app developers, see `opsky_ble/BLE_UWB_MobileApp_Flow.txt` for detailed integration instructions:

- **BLE Service UUID**: `E1C7A1B0-7E2A-4B1A-9C1D-1F2E3D4C5B6A`
- **Main Characteristic UUID**: `E1C7A1B1-7E2A-4B1A-9C1D-1F2E3D4C5B6A`
- **Protocol**: Write `TOKEN:<token>` then `RANGE` commands
- **Notifications**: Command responses and errors only

## Configuration

Edit `config.json` for global settings:
```json
{
  "ble_adv_name": "OPSKY_DEVICE_1",
  "can_interface": "can0",
  "nfc_reset_pin": 20
}
```

## Branch Information

- **opsky_nfc_can_ble_v2**: Current stable branch with UWB support
- **opsky_uwb_prep**: Development branch for UWB features

## Documentation

- **SETUP.md**: Detailed hardware setup and wiring
- **BLE_UWB_MobileApp_Flow.txt**: Mobile app integration guide
- Service-specific documentation in individual Python files

## Support

For technical questions or integration support, contact the development team.