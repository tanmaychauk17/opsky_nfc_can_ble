# Protocol Version 3 Flow Documentation

## Overview
This document describes the complete flow for Protocol Version 3 in the Opsky BLE service, including authentication, UWB integration, and command processing.

## Flow Steps

### 1. Connection Establishment
- Mobile app initiates BLE connection to the Opsky device
- Device accepts connection and updates session state to `CONNECTED`

### 2. Service Discovery and Notification Setup
- Mobile app performs GATT service discovery
- Mobile app discovers the primary service with UUID: `6DF722E0-AC7B-4C63-8226-FFE665B82697`
- Mobile app subscribes to notifications on relevant characteristics:
  - `READFROMMACHINE_CHAR_UUID` (6DF722E2-AC7B-4C63-8226-FFE665B82697)
  - `READWRITE_NOTIFY_CHAR_UUID` (6DF722E4-AC7B-4C63-8226-FFE665B82697)

### 3. Protocol Version Negotiation
- Mobile app reads the Protocol Version characteristic (`PROTOCOL_VERSION_CHAR_UUID`)
- Device responds with version information: `[0x00, protocol_version]`
  - For Version 3: `[0x00, 0x03]`
- Device transitions session state to `PROTOCOL_VERIFIED` then `WAITING_FOR_MDID`
- Device starts MDID timeout timer (5 seconds)

### 4. Authentication Mechanism (Version 3)
Protocol Version 3 uses signature-based authentication with ECDSA:

#### 4.1 Initial Authentication
- Mobile app sends authentication request via `SENDTOMACHINE_CHAR_UUID`
- Format: `OPCODE (2 bytes) + MDID (6 bytes) + ECDSA_SIGNATURE (variable DER format)`
- Device extracts MDID and signature from the payload
- Device verifies ECDSA signature against the MDID using stored public key
- If signature verification succeeds:
  - Device sets session state to `AUTHENTICATED`
  - Device stores `authenticated_mdid` for future command verification
  - Device responds with success: `[SUCCESS_CODE, OPCODE, 0x01]`
  - Device updates service state to `USER_AUTHENTICATED`
- If signature verification fails:
  - Device responds with error: `[ERROR_CODE, OPCODE, 0x00]`
  - Device disconnects the BLE connection

### 5. UWB Integration (Post-Authentication)
Once authentication is successful, UWB (Ultra-Wideband) integration begins:

#### 5.1 UWB Key Exchange
- Mobile app sends UWB key over the newly added characteristic (`READWRITE_NOTIFY_CHAR_UUID`)
- Key format: Implementation-specific (to be defined based on UWB requirements)
- Device receives and stores the UWB key for ranging/positioning

#### 5.2 UWB Behavior Initiation
- Device initiates UWB behavior/ranging after receiving the key
- UWB subsystem begins proximity detection and ranging operations
- Device may start advertising UWB capabilities to the mobile app

### 6. Command Processing Flow
After successful authentication and UWB setup, normal command processing begins:

#### 6.1 Command Structure (Version 3)
All commands from mobile app follow this structure:
```
OUTER_OPCODE (2 bytes) + INNER_OPCODE (2 bytes) + PAYLOAD (N bytes) + ECDSA_SIGNATURE (variable DER)
```

#### 6.2 Command Verification Process
1. **Receive Command**: Device receives command via `SENDTOMACHINE_CHAR_UUID`
2. **Extract Components**: 
   - Parse outer opcode (first 2 bytes)
   - Extract inner opcode, payload, and signature
   - Try different signature split points to find valid DER signature
3. **Signature Verification**:
   - Verify ECDSA signature against: `INNER_OPCODE + PAYLOAD + AUTHENTICATED_MDID`
   - Use stored public key corresponding to the authenticated MDID
4. **Command Processing**:
   - If signature valid: Process the command
   - If signature invalid: Reject and optionally disconnect

#### 6.3 CAN Bus Forwarding
For verified commands:
1. **Strip Signature**: Remove ECDSA signature from the command
2. **Forward to CAN**: Send only `INNER_OPCODE + PAYLOAD` to CAN bus via ZMQ
3. **Response Handling**: 
   - Send immediate `PENDING` response to mobile app
   - Forward actual CAN response when received

## State Machine
```
IDLE -> CONNECTED -> PROTOCOL_VERIFIED -> WAITING_FOR_MDID -> AUTHENTICATED
```

### Error States
- `MDID_UNAUTHORIZED`: Invalid MDID provided
- `TIMEOUT`: MDID not provided within timeout period
- `DISCONNECTED`: Connection lost or forced disconnect

## Security Features

### ECDSA Signature Verification
- Uses elliptic curve cryptography for command authentication
- Each command must be signed with the private key corresponding to the MDID
- Prevents replay attacks and unauthorized command execution

### UWB Integration
- Adds proximity-based security layer
- Ensures commands can only be executed when mobile device is in close proximity
- Provides additional anti-theft protection

## Characteristics Used

| Characteristic | UUID | Purpose | Flags |
|---|---|---|---|
| SENDTOMACHINE | 6DF722E1-AC7B-4C63-8226-FFE665B82697 | Mobile→Device commands | WRITE |
| READFROMMACHINE | 6DF722E2-AC7B-4C63-8226-FFE665B82697 | Device→Mobile responses | READ, INDICATE |
| PROTOCOL_VERSION | 6DF722E3-AC7B-4C63-8226-FFE665B82697 | Version negotiation | READ |
| READWRITE_NOTIFY | 6DF722E4-AC7B-4C63-8226-FFE665B82697 | UWB key exchange, notifications | READ, WRITE, NOTIFY |

## Error Handling

### Authentication Failures
- Invalid signature → Error response + disconnect
- Timeout waiting for MDID → Timeout notification + disconnect
- Unauthorized MDID → Error response + disconnect

### Command Processing Failures
- Invalid signature on command → Error response + optional disconnect
- Malformed command → Error response
- CAN bus communication failure → Error response

## Implementation Notes

### ZMQ Integration
- Commands forwarded to CAN bus via ZMQ publish socket
- CAN responses received via ZMQ subscribe socket
- Topic: "bleToCan" for outgoing, "canToBle" for incoming

### Logging
- All BLE RX/TX operations logged in hex format
- Authentication events logged with MDID information
- State transitions logged for debugging

### Timeouts
- MDID timeout: 5 seconds after protocol version read
- Additional timeouts can be implemented for UWB operations

## Future Enhancements
- UWB ranging distance thresholds
- Multiple MDID support
- Command rate limiting
- Enhanced error recovery mechanisms