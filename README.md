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

### 3. Configure Protocol
```bash
# Edit config.json to set protocol version and device settings
nano config.json

# Example configuration:
{
  "ble_adv_name": "OPSKY_DEVICE_1",
  "protocol_version": 3,
  "nfc_permitted_uids": ["opsky1", "opsky2"]
}
```

### 4. Start Services
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
3. **Send ECDSA-signed MDID** for authentication (receives success/error response)
4. **Exchange UWB keys** via notification/UWB characteristic
5. **Send signed commands** with payload + signature (silent execution - no responses)

### Command Structure & Parsing
Protocol v3 uses a streamlined command structure optimized for most common operations:

**Data Format**: `OPCODE (2 bytes) + PAYLOAD (optional) + DER_SIGNATURE (variable)`

**Common Case (95% of commands)**:
- **Structure**: `OPCODE + DER_SIGNATURE` (no payload)
- **Examples**: GET_FUEL_LEVEL (0x0014), WORK_LIGHT_ON (0x0009), HORN (0x0008)
- **DER Detection**: Signature starts immediately after 2-byte opcode with 0x30 tag
- **Processing**: Fast-path detection with O(1) parsing efficiency

**Special Cases (commands with payload)**:
- **Structure**: `OPCODE + PAYLOAD + DER_SIGNATURE`
- **Examples**: SET_HVAC_TEMP with temperature value
- **DER Detection**: Fallback search algorithm finds signature boundary
- **Processing**: Comprehensive DER length parsing with multi-byte support

**Enhanced DER Signature Parsing**:
- **Short Form**: Length < 128 bytes (single length byte)
- **Long Form**: Length ≥ 128 bytes (multi-byte length encoding)
- **Validation**: Total signature length verified against remaining data
- **Security**: Only valid DER signatures accepted for command execution

### Command Response Behavior
Protocol v3 implements a **silent execution model** for enhanced security:

**Authentication Phase** (MDID verification):
- ✅ **Success Response**: `00 00 00 01 01` (authentication confirmed)
- ❌ **Error Response**: `FF FF 00 01 00` (authentication failed + disconnect)

**Command Phase** (after authentication):
- ✅ **Success**: No BLE response sent (silent execution)
- ❌ **Failure**: No BLE response sent (immediate disconnection)
- 📋 **Logging**: All operations logged locally for debugging

**Benefits**:
- **Reduced BLE Traffic**: Eliminates unnecessary acknowledgment messages
- **Enhanced Security**: Failed commands trigger immediate disconnection
- **Cleaner Protocol**: Client detects success by connection persistence

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

## Technical Implementation Details

### ECDSA Key Management
The system uses **asymmetric cryptography** with ECDSA (Elliptic Curve Digital Signature Algorithm):

**Key Distribution**:
- **Private Keys**: Stored securely on mobile devices (signing operations)
- **Public Keys**: Stored on BLE service device in `keys/` directory (verification only)
- **Key Format**: PEM-encoded ECDSA keys with secp256r1 curve
- **Key Naming**: `public_key_<mdid_hex>.pem` (e.g., `public_key_ff0000000001.pem`)

**Security Model**:
- BLE service **never** accesses private keys
- Public key cryptography ensures non-repudiation
- Each MDID has unique key pair for device-specific authentication
- Signature verification performed using cryptography library

### Data Parsing Engine
The Protocol v3 parser implements a **two-tier approach** for optimal performance:

**Tier 1 - Fast Path (Typical Commands)**:
```python
# Most commands: OPCODE + DER_SIGNATURE
if data[0] == 0x30:  # DER sequence tag
    der_length = data[1]  # Short form length
    if 2 + der_length == len(data):  # Validate total length
        payload = bytes()  # Empty payload
        signature = data  # Entire data is signature
```

**Tier 2 - Comprehensive Parsing (Special Commands)**:
```python
# Commands with payload: OPCODE + PAYLOAD + DER_SIGNATURE
for i in range(len(data)):
    if data[i] == 0x30:  # Find DER tag
        # Parse multi-byte DER length encoding
        # Verify signature spans to end of data
        payload = data[:i]
        signature = data[i:]
```

**DER Length Encoding Support**:
- **Short Form**: `30 XX` (length ≤ 127 bytes)
- **Long Form**: `30 8Y XX...` (length > 127 bytes, Y = number of length bytes)
- **Validation**: Total calculated length must match actual data length

### Logging and Debugging
Enhanced logging provides comprehensive insight into Protocol v3 operations:

**Signature Verification Logging**:
```
[ECDSA] Verifying signature for MDID: FF0000000001
[ECDSA] Loaded public key: public_key_ff0000000001.pem
[ECDSA] Message: FF0000000001
[ECDSA] Signature: 3045022059FD1D16F3D132D5919262B907B637B3...
[ECDSA] Signature verification: OK
```

**Command Processing Logging**:
```
[PROTOCOL V3] Parsing opcode 0x0014, data length: 71
[PROTOCOL V3] Opcode: 0x0014, Empty payload, Signature length: 71
[PROTOCOL V3] Opcode 0014 signature verified for MDID FF0000000001.
```

**Error Handling Logging**:
```
[PROTOCOL V3] Could not find valid DER signature in data.
[PROTOCOL V3] Opcode signature verification failed for MDID FF0000000001.
```

## Configuration

Edit `config.json` for global settings:
```json
{
  "ble_adv_name": "OPSKY_DEVICE_1",
  "protocol_version": 3,
  "nfc_permitted_uids": [
    "opsky1",
    "opsky2"
  ]
}
```

**Configuration Options:**
- **`ble_adv_name`**: BLE advertising name returned by UWB/notification characteristic
- **`protocol_version`**: BLE protocol version (2 or 3) - determines authentication method
- **`nfc_permitted_uids`**: List of permitted NFC card UIDs for access control

## Data Flow

```
Mobile App ←→ BLE (Protocol v3) ←→ ZMQ Hub ←→ CAN J1939 ←→ Vehicle/Machine
     ↓              ↓                  ↓           ↓
UWB Keys ←→ ECDSA Verification ←→ Command Forwarding ←→ Vehicle Control
     ↓              ↓                  ↓
   Proximity ←→ NFC Authentication ←→ Access Control
```

**Protocol v3 Flow**:
1. **Authentication**: NFC UID → MDID validation → Session established
2. **Command Execution**: BLE command → ECDSA signature verification → CAN forwarding
3. **Security**: Silent execution (no responses), automatic disconnect on failure

### UWB Integration Data Flow
1. **UWB Key Exchange**: Mobile sends UWB token via notification characteristic
2. **ZMQ Forwarding**: Device forwards UWB key to other services
3. **Proximity Validation**: UWB subsystem validates device proximity
4. **Command Authorization**: Both ECDSA and proximity checks required

### CAN System Integration Data Flow
**Protocol v3 Command Forwarding**:
1. **BLE Reception**: Mobile app sends signed command via BLE
2. **ECDSA Verification**: Device verifies signature using public key
3. **CAN Forwarding**: Verified commands automatically forwarded to CAN system
4. **ZMQ Protocol**: Uses `{"BleToCan": [opcode_bytes, payload_bytes]}` format
5. **Silent Execution**: No BLE responses sent (security through obscurity)

**CAN Message Format**:
```json
{
  "BleToCan": [0x12, 0x34, 0x56, 0x78]  // opcode (2 bytes) + payload (variable)
}
```

**Integration Points**:
- **Success Path**: BLE → ECDSA Verify → CAN Forward via ZMQ
- **Failure Path**: BLE → ECDSA Fail → Silent Disconnect (no CAN forwarding)
- **Logging**: `[CAN FORWARD]` logs track successful command forwarding

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
- **Elliptic Curve Digital Signatures**: secp256r1 curve with SHA-256 hashing
- **Per-Command Signature Verification**: Every command cryptographically verified
- **MDID-Based Device Identification**: 6-byte unique device identifiers
- **Protection Against Replay Attacks**: Signature verification prevents command reuse
- **Public Key Infrastructure**: BLE service uses only public keys for verification
- **Silent Execution Security**: Failed verification triggers immediate disconnection

### Enhanced Data Integrity
- **DER Signature Format**: Industry-standard ASN.1 DER encoding
- **Multi-Tier Parsing**: Fast-path and comprehensive parsing for all command types
- **Length Validation**: Signature length verified against DER header specifications
- **Boundary Detection**: Precise payload/signature separation for commands with data

### Command Security Model
- **Authentication Phase**: MDID signature verification with BLE responses
- **Command Phase**: Silent execution without BLE acknowledgments
- **Failure Handling**: Immediate disconnection on any verification failure
- **Session Management**: Per-device authentication with stored MDID validation

### Future UWB Integration
- **Proximity-Based Command Validation**: Ultra-wideband distance verification
- **Enhanced Anti-Theft Protection**: Physical proximity requirements
- **iPhone Nearby Interaction Compatibility**: iOS integration support
- **Cross-Version UWB Characteristic Compatibility**: Seamless v2/v3 interoperability

## Troubleshooting

### Common Issues
- **CAN Interface**: Check `ifconfig can0` and bitrate settings
- **NFC Module**: Verify UART configuration and wiring
- **BLE Permissions**: Ensure proper BlueZ and D-Bus permissions
- **ECDSA Keys**: Verify key pair integrity in `keys/` directory
- **DER Signature Format**: Ensure mobile app generates valid DER-encoded signatures
- **Command Structure**: Verify opcode + signature format (most commands have no payload)

### Protocol v3 Debugging
**Signature Verification Issues**:
- Check MDID format (6 bytes hex, e.g., FF0000000001)
- Verify DER signature starts with 0x30 (sequence tag)
- Ensure signature length matches DER header declaration
- Confirm public key file exists: `keys/public_key_<mdid_hex>.pem`

**Data Parsing Issues**:
- Monitor `[PROTOCOL V3] Parsing opcode` logs for correct opcode extraction
- Check `Empty payload` vs `Payload length: X` to verify parsing tier
- Verify total data length matches expected `OPCODE (2) + SIGNATURE (N)` format
- Look for `Could not find valid DER signature` warnings

**Performance Optimization**:
- Most commands should use fast-path parsing (Tier 1)
- Fallback to comprehensive parsing only for commands with payload
- Monitor parsing time - should be O(1) for typical commands

### Debugging Commands
```bash
# Monitor BLE service logs
cd opsky_ble_scripts && python opsky_simulator.py

# Test signature verification manually
python3 -c "
from ecdsa_utils import verify_signature
mdid = bytes.fromhex('FF0000000001')
signature = bytes.fromhex('3045022...')  # Your signature
print(verify_signature(mdid, signature))
"

# Check DER signature format
python3 -c "
data = bytes.fromhex('001430450221...')  # Your data
print('Opcode:', hex(int.from_bytes(data[:2], 'big')))
print('DER tag:', hex(data[2]) if len(data) > 2 else 'None')
print('DER length:', data[3] if len(data) > 3 else 'None')
"
```

## Support

For technical questions or integration support:
- Review `SETUP.md` and `PROTOCOL_V3_FLOW.md` documentation
- Check troubleshooting section above
- Open an issue in the repository
- Contact the development team