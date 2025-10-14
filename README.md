# Opsky NFC, CAN, BLE Integration System

Multi-protocol bridge system supporting NFC (PN532), CAN J1939, and BLE peripherals for Opsky mobile applications with advanced Protocol Version 3 support.

## Project Structure

```
opsky_nfc_can_ble_v3/
├── README.md                    # This file
├── SETUP.md                     # Detailed setup instructions  
├── PROTOCOL_V3_FLOW.md         # Protocol Version 3 flow documentation
├── config.json                  # Global configuration
├── zmqhub.py                    # ZMQ message hub for inter-service communication
│
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
├── BLE Services/
│   └── opsky_ble_scripts/       # BLE peripheral services directory
│       ├── opsky_service.py     # Main Opsky BLE GATT service (Protocol v3)
│       ├── opsky_simulator.py   # BLE device simulator/manager
│       ├── simulate_v3_mobile.py # Protocol v3 mobile app simulator
│       ├── connection_monitor_simple.py # BLE connection monitoring
│       ├── ecdsa_utils.py       # ECDSA cryptographic utilities
│       ├── keys/                # ECDSA public/private key storage
│       ├── requirements.txt     # BLE-specific dependencies
│       ├── setup_env.sh         # BLE environment setup
│       └── zmqhub.py            # BLE-specific ZMQ hub
│
└── Scripts & Utilities/
    ├── run_all.sh               # Start all services
    ├── kill_all.sh              # Stop all services
    ├── opsky_service.service    # Systemd service file
    ├── requirement.txt          # Core dependencies
    ├── requirements_j1939.txt   # J1939-specific dependencies
    └── testApk/                 # Test applications
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
- **Opsky GATT service** with Protocol Version 3 support
- **ECDSA signature authentication** for enhanced security
- **Session-based security** with operator ID validation

### 🔐 Protocol Version 3 Features
- **ECDSA Authentication**: Elliptic curve digital signatures
- **Enhanced Security**: Each command cryptographically signed
- **UWB Integration**: Ultra-wideband proximity support (same as v2)
- **Advanced Command Verification**: Multi-layer security validation
- **Cross-Version Compatibility**: UWB characteristic identical to v2

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

# BLE dependencies (in opsky_ble_scripts directory)
cd opsky_ble_scripts
pip install -r requirements.txt
bash setup_env.sh
```

### 3. Start Services
```bash
# Start all services
./run_all.sh

# OR start individual services:
python zmqhub.py &
python nfc_service.py &
python can_j1939_service.py &
cd opsky_ble_scripts && python opsky_simulator.py &
```

## Protocol Version 3 Integration

For mobile app developers integrating Protocol Version 3:

### BLE GATT Services
- **Primary Service UUID**: `6DF722E0-AC7B-4C63-8226-FFE665B82697`
- **Command Characteristic**: `6DF722E1-AC7B-4C63-8226-FFE665B82697` (WRITE)
- **Response Characteristic**: `6DF722E2-AC7B-4C63-8226-FFE665B82697` (READ, INDICATE)
- **Protocol Version**: `6DF722E3-AC7B-4C63-8226-FFE665B82697` (READ)
- **Notification/UWB**: `6DF722E4-AC7B-4C63-8226-FFE665B82697` (READ, WRITE, NOTIFY)

### Authentication Flow
1. **Connect** to BLE device
2. **Read Protocol Version** (returns version 3)
3. **Send ECDSA-signed MDID** for authentication
4. **Exchange UWB keys** via notification/UWB characteristic
5. **Send signed commands** with payload + signature

### UWB/Notification Characteristic
The **Notification/UWB characteristic** (`6DF722E4-AC7B-4C63-8226-FFE665B82697`) provides:
- **Read Operation**: Returns BLE advertising name from config.json
- **Write Operation**: Receives UWB key for proximity-based security
- **Notify Operation**: Sends acknowledgments and error notifications
- **ZMQ Integration**: UWB keys forwarded to other services via ZMQ

**Usage Example:**
- Write: `TOKEN:<uwb_token>` → Device responds with `UWB_KEY_RECEIVED`
- Read: Returns device advertising name (e.g., `OPSKY_DEVICE_1`)
- Notifications: `UWB_KEY_RECEIVED` or `UWB_KEY_ERROR`

For detailed flow documentation, see `PROTOCOL_V3_FLOW.md`.

## Configuration

Edit `config.json` for global settings:
```json
{
  "ble_adv_name": "OPSKY_DEVICE_1",
  "nfc_permitted_uids": [
    "opsky1",
    "opsky2"
  ]
}
```

## Data Flow

```
Mobile App ←→ BLE (Protocol v3) ←→ ZMQ Hub ←→ CAN J1939 ←→ Vehicle/Machine
     ↓              ↓                  ↓
UWB Keys ←→ ECDSA Verification ←→ NFC Authentication
```

### UWB Integration Data Flow
1. **UWB Key Exchange**: Mobile sends UWB token via notification characteristic
2. **ZMQ Forwarding**: Device forwards UWB key to other services
3. **Proximity Validation**: UWB subsystem validates device proximity
4. **Command Authorization**: Both ECDSA and proximity checks required

## Testing & Simulation

### Protocol v3 Mobile Simulator
```bash
cd opsky_ble_scripts
python simulate_v3_mobile.py
```

### BLE Device Simulator
```bash
cd opsky_ble_scripts
python opsky_simulator.py
```

## Branch Information

- **opsky_nfc_can_ble_v3**: Current branch with Protocol Version 3 and ECDSA authentication
- **opsky_nfc_can_ble_v2**: Previous branch with UWB support and Protocol Version 2
- **Protocol v3 vs v2**: Enhanced security, ECDSA signatures, UWB preparation

## Documentation

- **SETUP.md**: Detailed hardware setup and wiring instructions
- **PROTOCOL_V3_FLOW.md**: Complete Protocol Version 3 flow documentation
- Service-specific documentation in individual Python files

## Security Features

### ECDSA Authentication
- Elliptic curve digital signature algorithm
- Per-command signature verification
- MDID-based device identification
- Protection against replay attacks

### Future UWB Integration
- Proximity-based command validation (implemented same as v2)
- Enhanced anti-theft protection
- iPhone Nearby Interaction compatibility
- Cross-version UWB characteristic compatibility

## Troubleshooting

### Common Issues
- **CAN Interface**: Check `ifconfig can0` and bitrate settings
- **NFC Module**: Verify UART configuration and wiring
- **BLE Permissions**: Ensure proper BlueZ and D-Bus permissions
- **ECDSA Keys**: Verify key pair integrity in `keys/` directory

### Debugging
- Monitor service logs for error messages
- Use `candump can0` for CAN bus debugging
- Check ZMQ message flow between services
- Verify ECDSA signature generation/verification

## Support

For technical questions or integration support:
- Review `SETUP.md` and `PROTOCOL_V3_FLOW.md` documentation
- Check troubleshooting section above
- Open an issue in the repository
- Contact the development team