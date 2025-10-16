
# BLE GATT and ZMQ imports for BLE service, characteristics, and inter-process communication
from bluez_peripheral.gatt.service import Service 
from bluez_peripheral.gatt.characteristic import characteristic, CharacteristicFlags as CharFlags
from bluez_peripheral.gatt.descriptor import descriptor, DescriptorFlags as DescFlags
from enum import Enum, auto
import time
import logging
import asyncio
import zmq
import zmq.asyncio
import json
import os


logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
level=logging.INFO)

counter = 1
# BLE GATT UUIDs for service and characteristics
PRIMARY_SERVICE_UUID = "6DF722E0-AC7B-4C63-8226-FFE665B82697"
SENDTOMACHINE_CHAR_UUID = "6DF722E1-AC7B-4C63-8226-FFE665B82697"
READFROMMACHINE_CHAR_UUID = "6DF722E2-AC7B-4C63-8226-FFE665B82697"
PROTOCOL_VERSION_CHAR_UUID = "6DF722E3-AC7B-4C63-8226-FFE665B82697"
READWRITE_NOTIFY_CHAR_UUID = "6DF722E4-AC7B-4C63-8226-FFE665B82697"

# Special response code for internal use
hack_response = 0x2000
# Byte order for all protocol fields
BYTEORDER = 'big'

class BLESessionState(Enum):
    """
    State machine for BLE authentication and session lifecycle.
    """
    IDLE = auto()
    CONNECTED = auto()
    PROTOCOL_VERIFIED = auto()
    WAITING_FOR_MDID = auto()
    MDID_RECEIVED = auto()
    MDID_AUTHORIZED = auto()
    MDID_UNAUTHORIZED = auto()
    AUTH_CHALLENGE_SENT = auto()
    AUTHENTICATED = auto()
    DISCONNECTED = auto()
    TIMEOUT = auto()

class AuthState(Enum):
    """
    Tracks user authentication state for BLE session.
    """
    USER_UNAUTHENTICATED = 0x01
    USER_AUTHENTICATED = 0x02

class OpskyCommands(Enum):
    """
    All supported opcodes for BLE-to-machine protocol.
    """
    DOOR_LOCK = 0x000C
    DOOR_UNLOCK = 0x000D
    SET_OPID = 0x0001
    WORK_LIGHT_ON = 0x0009
    WORK_LIGHT_OFF = 0x000A
    HVAC_ON = 0x000F
    HVAC_OFF = 0x0010
    HORN = 0x0008
    REMOTE_START = 0x0004
    REMOTE_STOP = 0x0005
    GET_WORK_LIGHT = 0x000B
    GET_HVAC = 0x0011
    GET_DOOR_LOCK = 0x000E
    GET_OPID = 0x0002
    GET_FUEL_LEVEL = 0x0014
    GET_APPLICATION_SOFTWARE_VERSION = 0x0016
    GET_PRODUCT_ID = 0x0015
    AUTH_CHALLENGE = 0x0003
    ENGINE_STATE = 0x0004
    GET_ENGINE_STATE = 0x0005
    SET_HVAC_TEMP = 0x0012
    GET_HVAC_TEMP = 0x0013
    GET_REMOTE_FEATURE = 0x0007
    UNSOLICITED_OPCODE = 0xFFFC
    UNSOLICITED_EVENT = 0xFFFD
    SUCCESS = 0x0000
    PENDING = 0xFFFE
    ERROR = 0xFFFF

class MachineState:
    """
    Simulated machine state for demo/testing.
    """
    def __init__(self):
        self.lights = 1
        self.hvac = 1
        self.locks = 1
    
class OpskyService(Service):
    """
    Main BLE GATT service for Opsky protocol, handling authentication,
    command routing, and state management. Integrates with CAN/NFC via ZMQ.
    """
    def __init__(self, connection_monitor=None, protocol_version=None):
        super().__init__(PRIMARY_SERVICE_UUID, True)
        self.ServiceID = PRIMARY_SERVICE_UUID
        # Track authentication and session state
        self.servicestate = AuthState.USER_UNAUTHENTICATED
        self.session_state = BLESessionState.IDLE
        self.session_timer = None
        self.challenge = None
        self.mdid = None
        self.connection_monitor = connection_monitor
        self.connectedDevice = None  # Set on BLE connect
        
        # Load protocol version from config, fallback to parameter or default
        self.protocol_version = self._load_protocol_version(protocol_version)

        # ZeroMQ PUB/SUB sockets for CAN/NFC inter-process communication
        self.ctx = zmq.asyncio.Context.instance()
        self.pub_socket = self.ctx.socket(zmq.PUB)
        self.sub_socket = self.ctx.socket(zmq.SUB)
        import sys
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from zmqhub import XSUB_ADDR, XPUB_ADDR
        self.pub_socket.connect(XSUB_ADDR)
        self.pub_socket.setsockopt(zmq.LINGER, 0)
        self.sub_socket.connect(XPUB_ADDR)
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, "canToBle")
        self.sub_socket.setsockopt(zmq.LINGER, 0)

        # Load BLE advertising name from config for UWB functionality
        self.ble_adv_name = self._load_ble_adv_name()

        # UWB key storage
        self.uwb_key = None

    def _publish_mdid_to_can(self, mdid_hex: str):
        """
        Publish MDID to CAN service via opskyState topic.

        Args:
            mdid_hex: MDID as hex string (e.g., "FF0000000001" or "FFFFFFFFFFFF")
        """
        try:
            mdid_msg = f"opskyState MDID_{mdid_hex}"
            self.pub_socket.send_string(mdid_msg)
            logger.info(f"[MDID] Published to CAN: {mdid_msg}")
        except Exception as e:
            logger.error(f"[MDID] Error publishing to CAN: {e}")

    def _load_ble_adv_name(self):
        """Load BLE advertising name from config.json"""
        try:
            BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
            with open(CONFIG_PATH) as f:
                config = json.load(f)
            return config.get("ble_adv_name", "OPSKY_DEVICE_DEFAULT")
        except FileNotFoundError:
            logger.warning(f"Config file not found, using default BLE name.")
            return "OPSKY_DEVICE_DEFAULT"
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return "OPSKY_DEVICE_DEFAULT"

    def _load_protocol_version(self, fallback_version):
        """Load protocol version from config.json"""
        try:
            BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
            with open(CONFIG_PATH) as f:
                config = json.load(f)
            version = config.get("protocol_version", fallback_version or 3)
            logger.info(f"Loaded protocol version from config: {version}")
            return version
        except FileNotFoundError:
            version = fallback_version or 3
            logger.warning(f"Config file not found, using protocol version: {version}")
            return version
        except Exception as e:
            version = fallback_version or 3
            logger.error(f"Error loading protocol version from config: {e}, using: {version}")
            return version

    def _get_opcode_data(self, message):
        """
        Extracts response code, opcode, and data from incoming BLE message.
        Handles both normal and response-wrapped opcodes.
        """
        try:
            if len(message) < 2:
                logger.error("Message too short to extract opcode.")
                return hack_response, 0, []
            response_code = hack_response
            opcode = int.from_bytes(message[0:2], byteorder=BYTEORDER)
            if (opcode == OpskyCommands.SUCCESS.value or opcode == OpskyCommands.ERROR.value):
                if len(message) < 4:
                    logger.error("Message too short to extract response opcode.")
                    return hack_response, 0, []
                response_code = opcode
                opcode = int.from_bytes(message[2:4], byteorder=BYTEORDER)
                data = message[4:]
            else:
                data = message[2:]
            return response_code, opcode, data
        except Exception as e:
            logger.error(f"Error in _get_opcode_data: {e}")
            return hack_response, 0, []

    def _set_opcode_data(self, opcode, data):
        """
        Format opcode and data for BLE transmission (opcode first, then data).
        """
        temp = list(opcode.to_bytes(2, byteorder=BYTEORDER))
        temp.extend(data)
        return temp

    def _set_response_data(self, opcode, response, data):
        """
        Format response code, opcode, and data for BLE response.
        """
        temp = list(response.to_bytes(2, byteorder=BYTEORDER))
        temp.extend(list(opcode.to_bytes(2, byteorder=BYTEORDER)))
        temp.extend(data)
        return temp

    def _set_unsolicited_opcode_notification_data(self, opcode, response, data):
        """
        Format unsolicited event/notification for BLE (opcode, response, data).
        """
        temp = list(opcode.to_bytes(2, byteorder=BYTEORDER))
        temp.extend(list(response.to_bytes(2, byteorder=BYTEORDER)))
        temp.extend(data)
        return temp

    async def _start_mdid_timeout(self):
        """
        Waits for MDID to be set after protocol negotiation. Disconnects if timeout.
        """
        await asyncio.sleep(5)
        if self.session_state == BLESessionState.WAITING_FOR_MDID:
            logger.info("MDID not set in time, sending timeout notification and disconnecting.")
            tosend = self._set_unsolicited_opcode_notification_data(
                OpskyCommands.UNSOLICITED_EVENT.value,
                OpskyCommands.ERROR.value,
                [0x00, 0x00]
            )
            self.send_machine.changed(bytes(tosend))
            self.session_state = BLESessionState.TIMEOUT
            # Disconnect BLE device if possible
            if self.connection_monitor and self.connectedDevice:
                logger.info("Disconnecting BLE device due to MDID timeout.")
                await self.connection_monitor.disconnect_device(self.connectedDevice)
            else:
                logger.warning("No connection monitor or connected device to disconnect.")

    def _is_mdid_authorized(self, mdid):
        """
        Checks if the provided MDID is authorized. (Stub: always True)
        """
        # TODO: Implement real MDID authorization logic
        return True

    def _verify_challenge_response(self, response):
        """
        Verifies challenge response for protocol v2 authentication. (Stub)
        """
        # TODO: Implement real challenge/response verification
        return True

    def _forward_command_to_can(self, opcode, payload):
        """
        Forwards verified BLE command to CAN system via ZMQ.
        Uses the same format as Protocol v2: "bleToCan {json_payload}"
        """
        try:
            # Create CAN forwarding message using the established Protocol v2 pattern
            can_data = list(opcode.to_bytes(2, byteorder=BYTEORDER))
            if payload:
                can_data.extend(list(payload))

            json_payload = json.dumps({"BleToCan": can_data})
            msg = f"bleToCan {json_payload}"
            self.pub_socket.send_string(msg)
            
            logger.info(f"[OPSKY_BLE]: Command forwarded to CAN task: {msg}")
        except Exception as e:
            logger.error(f"[CAN FORWARD] Failed to forward command {opcode:04X}: {e}")

    def _handle_command(self, response_code, opcode, data):
        """
        Main BLE command handler. Routes opcodes, manages authentication,
        and handles protocol v2/v3 branching and signature verification.
        """
        try:
            # Log RX opcode/data in hex (space-separated, capital)
            rx_bytes = []
            if response_code != hack_response:
                rx_bytes += [(response_code >> 8) & 0xFF, response_code & 0xFF]
            if isinstance(opcode, int):
                rx_bytes += list(opcode.to_bytes(2, byteorder=BYTEORDER))
            if isinstance(data, list):
                rx_bytes += data
            rx_hex = ' '.join(f'{b:02X}' for b in rx_bytes)
            logger.info(f"[BLE RX] {rx_hex}")
            logger.info(f"💡💡 Received opcode {opcode} (Response {response_code if response_code != hack_response else ''})")
            # Only accept commands if authenticated, except for authentication flow
            if not (self.session_state == BLESessionState.AUTHENTICATED or 
                    (self.session_state == BLESessionState.WAITING_FOR_MDID and opcode == OpskyCommands.SET_OPID.value) or
                    (self.session_state == BLESessionState.AUTH_CHALLENGE_SENT and opcode == OpskyCommands.AUTH_CHALLENGE.value)):
                logger.warning(f"[BLE RX] Command {opcode} ignored: user not authenticated.")
                return
            # Protocol version branching
            if self.protocol_version == 2:
                if self.session_state == BLESessionState.WAITING_FOR_MDID and opcode == OpskyCommands.SET_OPID.value:
                    self.mdid = data
                    ENFORCE_MDID_LENGTH = True  # Set to True to require exactly 6 bytes
                    if ENFORCE_MDID_LENGTH and len(data) != 6:
                        logger.warning(f"[BLE RX] MDID length invalid: {len(data)} bytes (expected 6). Rejecting.")
                        # Send normal error response
                        tosend = self._set_response_data(opcode, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        # Send unsolicited event for MDID error (FFFD 0002 00 00)
                        unsolicited = self._set_unsolicited_opcode_notification_data(
                            OpskyCommands.UNSOLICITED_EVENT.value,
                            OpskyCommands.SUCCESS.value,
                            [0x00, 0x02]
                        )
                        logger.info(f"[BLE TX] (UNSOLICITED) {' '.join(f'{b:02X}' for b in unsolicited)}")
                        self.send_machine.changed(bytes(unsolicited))
                        if self.connection_monitor and self.connectedDevice:
                            logger.info("Disconnecting BLE device due to invalid MDID length.")
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connectedDevice))
                        return
                    if self._is_mdid_authorized(self.mdid):
                        self.session_state = BLESessionState.MDID_AUTHORIZED
                        tosend = self._set_response_data(opcode, OpskyCommands.SUCCESS.value, [0x01])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        logger.info("Operator ID set. Issuing challenge..")
                        self.challenge = [0x01] * 16  # Replace with random if needed
                        tosend = self._set_opcode_data(OpskyCommands.AUTH_CHALLENGE.value, self.challenge)
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        self.session_state = BLESessionState.AUTH_CHALLENGE_SENT
                    else:
                        self.session_state = BLESessionState.MDID_UNAUTHORIZED
                        tosend = self._set_response_data(opcode, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        if self.connection_monitor and self.connectedDevice:
                            logger.info("Disconnecting BLE device due to unauthorized MDID.")
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connectedDevice))
                elif self.session_state == BLESessionState.AUTH_CHALLENGE_SENT and opcode == OpskyCommands.AUTH_CHALLENGE.value:
                    if self._verify_challenge_response(data):
                        self.session_state = BLESessionState.AUTHENTICATED
                        logger.info("User authenticated!")
                        tosend = self._set_response_data(opcode, OpskyCommands.SUCCESS.value, [0x01])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        self.servicestate = AuthState.USER_AUTHENTICATED
                        # Publish authenticated status to ZMQ immediately
                        try:
                            device_path = self.connectedDevice if self.connectedDevice else "unknown"
                            import json
                            auth_msg = json.dumps({"status": "authenticated", "device": device_path})
                            self.pub_socket.send_string(f"bleStatus {auth_msg}")
                            logger.info(f"Published BLE status: {auth_msg}")
                        except Exception as e:
                            logger.error(f"Failed to publish authenticated status to ZMQ: {e}")

                        # Publish authenticated MDID to CAN service (Protocol v2)
                        if self.mdid and len(self.mdid) >= 6:
                            mdid_hex = ''.join(f'{b:02X}' for b in self.mdid[:6])
                            self._publish_mdid_to_can(mdid_hex)
                        else:
                            logger.warning("Protocol v2: Invalid MDID for CAN publishing")
                    else:
                        logger.info("Authentication failed.")
                        # Send normal error response
                        tosend = self._set_response_data(opcode, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        # Send unsolicited event for auth failure (FFFD 0002 00 00)
                        unsolicited = self._set_unsolicited_opcode_notification_data(
                            OpskyCommands.UNSOLICITED_EVENT.value,
                            OpskyCommands.SUCCESS.value,
                            [0x00, 0x02]
                        )
                        logger.info(f"[BLE TX] (UNSOLICITED) {' '.join(f'{b:02X}' for b in unsolicited)}")
                        self.send_machine.changed(bytes(unsolicited))
                        if self.connection_monitor and self.connectedDevice:
                            logger.info("Disconnecting BLE device due to failed authentication.")
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connectedDevice))
                else:
                    # For all opcodes. Send the same data over J1939
                    import json
                    payload = json.dumps({"BleToCan": list(opcode.to_bytes(2, byteorder=BYTEORDER))})
                    msg = f"bleToCan {payload}"
                    self.pub_socket.send_string(msg)
                    logger.info(f"[OPSKY_BLE]: Command forwarded to CAN task: {msg}")
                    tosend = self._set_response_data(opcode, OpskyCommands.PENDING.value, [])
                    logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                    self.send_machine.changed(bytes(tosend))
                    logger.info(f"[OPSKY_BLE]: Pending response sent on BLE {tosend}")
            elif self.protocol_version == 3:
                from ecdsa_utils import verify_signature, verify_opcode_signature_v3
                if self.session_state != BLESessionState.AUTHENTICATED:
                    if len(data) < 6 + 8:  # 6 bytes MDID + minimal DER signature
                        logger.warning(f"[PROTOCOL V3] Data too short for MDID+signature. Got {len(data)} bytes.")
                        tosend = self._set_response_data(opcode, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        return
                    mdid = bytes(data[:6])
                    signature = bytes(data[6:])  # Convert signature list to bytes
                    if verify_signature(mdid, signature):
                        self.session_state = BLESessionState.AUTHENTICATED
                        self.authenticated_mdid = mdid  # Store for future commands
                        logger.info(f"[PROTOCOL V3] MDID {mdid.hex().upper()} signature verified. User authenticated!")
                        tosend = self._set_response_data(opcode, OpskyCommands.SUCCESS.value, [0x01])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        self.servicestate = AuthState.USER_AUTHENTICATED
                        # Publish authenticated status to ZMQ immediately
                        try:
                            device_path = self.connectedDevice if self.connectedDevice else "unknown"
                            import json
                            auth_msg = json.dumps({"status": "authenticated", "device": device_path})
                            self.pub_socket.send_string(f"bleStatus {auth_msg}")
                            logger.info(f"Published BLE status: {auth_msg}")
                        except Exception as e:
                            logger.error(f"Failed to publish authenticated status to ZMQ: {e}")

                        # Publish authenticated MDID to CAN service
                        mdid_hex = mdid.hex().upper()
                        self._publish_mdid_to_can(mdid_hex)
                    else:
                        logger.warning(f"[PROTOCOL V3] Signature verification failed for MDID {mdid.hex().upper()}")
                        tosend = self._set_response_data(opcode, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        # TODO: Add unsolicited event for failed signature verification (like Protocol v2)
                        # This would improve error handling consistency between protocols
                        if self.connection_monitor and self.connectedDevice:
                            logger.info("Disconnecting BLE device due to failed signature verification.")
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connectedDevice))
                    return
                else:
                    # After authentication, expect: OPCODE (already extracted) + DATA contains PAYLOAD + SIGNATURE
                    # Most requests are just OPCODE + SIGNATURE (no payload in data)
                    if len(data) < 8:  # Minimal DER signature
                        logger.warning(f"[PROTOCOL V3] Data too short for signature. Got {len(data)} bytes.")
                        # TODO: Consider sending ERROR response instead of silent return for better debugging
                        # Current silent behavior prioritizes security but makes debugging harder
                        # Note: No response sent - just return on insufficient data
                        return

                    logger.info(f"[PROTOCOL V3] Parsing opcode 0x{opcode:04X}, data length: {len(data)}")

                    # For most commands, data contains only DER signature (starts with 0x30)
                    # Check if data starts with DER signature (0x30)
                    if len(data) > 0 and data[0] == 0x30:
                        # Parse DER length to verify this is a complete signature
                        if len(data) > 1:
                            length_byte = data[1]
                            if length_byte & 0x80 == 0:
                                # Short form DER length
                                der_length = length_byte
                                header_size = 2  # 0x30 + length byte
                                if header_size + der_length == len(data):
                                    # Data contains only DER signature (no payload)
                                    payload = bytes()  # Empty payload
                                    signature = bytes(data)
                                    logger.info(f"[PROTOCOL V3] Opcode: 0x{opcode:04X}, Empty payload, Signature length: {len(signature)}")

                                    if verify_opcode_signature_v3(opcode, payload, signature, self.authenticated_mdid.hex()):
                                        logger.info(f"[PROTOCOL V3] Opcode {opcode:04X} signature verified for MDID {self.authenticated_mdid.hex().upper()}.")
                                        # Forward verified command to CAN system
                                        self._forward_command_to_can(opcode, payload)
                                        # Send PENDING response like Protocol v2
                                        tosend = self._set_response_data(opcode, OpskyCommands.PENDING.value, [])
                                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                                        self.send_machine.changed(bytes(tosend))
                                        logger.info(f"[OPSKY_BLE]: Pending response sent on BLE {tosend}")
                                        return
                                    else:
                                        logger.warning(f"[PROTOCOL V3] Opcode signature verification failed for MDID {self.authenticated_mdid.hex().upper()}.")
                                        # TODO: Consider sending ERROR response before disconnect for better debugging
                                        # Current silent behavior prioritizes security but makes debugging harder
                                        # Note: No response sent - just disconnect on signature failure
                                        if self.connection_monitor and self.connectedDevice:
                                            logger.info("Disconnecting BLE device due to failed opcode signature.")
                                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connectedDevice))
                                        return

                    # Fallback: Look for DER signature anywhere in the data (for commands with payload)
                    logger.info(f"[PROTOCOL V3] Data doesn't start with DER signature, searching for payload+signature split...")
                    signature_start = -1
                    for i in range(0, len(data)):
                        if data[i] == 0x30:  # DER SEQUENCE tag
                            # Parse DER length (can be 1 byte or multi-byte)
                            if i + 1 < len(data):
                                length_byte = data[i + 1]
                                if length_byte & 0x80 == 0:
                                    # Short form: length is in the single byte
                                    der_length = length_byte
                                    header_size = 2  # 0x30 + length byte
                                else:
                                    # Long form: length is in multiple bytes
                                    length_bytes = length_byte & 0x7F
                                    if i + 1 + length_bytes < len(data):
                                        der_length = 0
                                        for j in range(length_bytes):
                                            der_length = (der_length << 8) + data[i + 2 + j]
                                        header_size = 2 + length_bytes  # 0x30 + length encoding
                                    else:
                                        continue  # Not enough bytes for length encoding

                                # Verify the DER signature length matches remaining data
                                if i + header_size + der_length == len(data):
                                    signature_start = i
                                    logger.info(f"[PROTOCOL V3] Found valid DER signature at position {i}, length: {der_length}")
                                    break

                    if signature_start == -1:
                        logger.warning(f"[PROTOCOL V3] Could not find valid DER signature in data.")
                        logger.warning(f"[PROTOCOL V3] Searched data: {' '.join(f'{b:02X}' for b in data)}")
                        # TODO: Consider sending ERROR response instead of silent return for better debugging
                        # Current silent behavior prioritizes security but makes debugging harder
                        # Note: No response sent - just return on invalid DER
                        return

                    payload = bytes(data[:signature_start])
                    signature = bytes(data[signature_start:])
                    logger.info(f"[PROTOCOL V3] Opcode: 0x{opcode:04X}, Payload length: {len(payload)}, Signature length: {len(signature)}")

                    if verify_opcode_signature_v3(opcode, payload, signature, self.authenticated_mdid.hex()):
                        logger.info(f"[PROTOCOL V3] Opcode {opcode:04X} signature verified for MDID {self.authenticated_mdid.hex().upper()}.")
                        # Forward verified command to CAN system
                        self._forward_command_to_can(opcode, payload)
                        # Send PENDING response like Protocol v2
                        tosend = self._set_response_data(opcode, OpskyCommands.PENDING.value, [])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        logger.info(f"[OPSKY_BLE]: Pending response sent on BLE {tosend}")
                    else:
                        logger.warning(f"[PROTOCOL V3] Opcode signature verification failed for MDID {self.authenticated_mdid.hex().upper()}.")
                        # TODO: Consider sending ERROR response before disconnect for better debugging
                        # Current silent behavior prioritizes security but makes debugging harder
                        # Note: No response sent - just disconnect on signature failure
                        if self.connection_monitor and self.connectedDevice:
                            logger.info("Disconnecting BLE device due to failed opcode signature.")
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connectedDevice))
                    return
            else:
                logger.warning(f"Unknown protocol version: {self.protocol_version}")
        except Exception as e:
            logger.error(f"Error in _handle_command: {e}")

    @characteristic(SENDTOMACHINE_CHAR_UUID, CharFlags.WRITE)
    def write_char(self, value: bytes, options):
        """
        BLE GATT write handler for RX from mobile. Dispatches to setter.
        """
        self.setter(value, options)

    @write_char.setter
    def setter(self, value, options):
        """
        Processes incoming BLE write, extracts opcode/data, and routes to handler.
        """
        try:
            response_code, opcode, data = self._get_opcode_data(list(value))
            self._handle_command(response_code, opcode, data)
        except Exception as e:
            logger.error(f"Error in setter: {e}")

    @characteristic(READFROMMACHINE_CHAR_UUID, CharFlags.INDICATE | CharFlags.READ)
    def send_machine(self, options):
        """
        BLE GATT read/indicate handler for TX to mobile. (Demo only)
        """
        logger.info(f"📖📖 Attempting to read {READFROMMACHINE_CHAR_UUID}")
        tx = [0x01]
        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tx)}")
        return tx

    @characteristic(PROTOCOL_VERSION_CHAR_UUID, CharFlags.READ)
    def read_version(self, options):
        """
        BLE GATT read handler for protocol version negotiation.
        Triggers MDID timeout and state transition.
        """
        logger.info(f"📖📖 Attempting to read Protocol version - sending version {self.protocol_version}")
        if self.session_state in [BLESessionState.IDLE, BLESessionState.CONNECTED]:
            self.session_state = BLESessionState.PROTOCOL_VERIFIED
            self.session_state = BLESessionState.WAITING_FOR_MDID
            asyncio.create_task(self._start_mdid_timeout())
        return [0x00, self.protocol_version]

    @characteristic(READWRITE_NOTIFY_CHAR_UUID, CharFlags.READ | CharFlags.WRITE | CharFlags.NOTIFY)
    def readwrite_notify_char(self, options):
        """
        UWB/Notification characteristic - on read returns BLE advertisement name.
        Same implementation as UWB characteristic in v2.
        """
        logger.info(f"[UWB BLE] Read requested - returning BLE adv name: {self.ble_adv_name}")
        # Convert string to bytes and then to list of integers
        return list(self.ble_adv_name.encode('utf-8'))

    @readwrite_notify_char.setter
    def readwrite_notify_setter(self, value, options):
        """
        UWB/Notification characteristic - on write receives UWB key from mobile.
        Same implementation as UWB characteristic in v2.
        """
        logger.info(f"[UWB BLE RX] {' '.join(f'{b:02X}' for b in value)}")
        try:
            # Decode the received UWB key
            msg = bytes(value).decode('utf-8', errors='ignore').strip()
            logger.info(f"[UWB BLE] Received UWB key: {msg}")

            # Store the UWB key
            self.uwb_key = msg

            # Forward UWB key to ZMQ for further processing
            payload = json.dumps({"UwbKey": msg})
            zmq_msg = f"uwbKey {payload}"
            self.pub_socket.send_string(zmq_msg)
            logger.info(f"[UWB BLE]: UWB key forwarded to ZMQ: {zmq_msg}")

            # Send acknowledgment notification (optional - can be used for errors later)
            ack_msg = b"UWB_KEY_RECEIVED"
            self.readwrite_notify_char.changed(ack_msg)
            logger.info(f"[UWB BLE TX] Notification sent: {ack_msg}")

        except Exception as e:
            logger.error(f"[UWB BLE] Error processing UWB key: {e}")
            # Send error notification
            error_msg = b"UWB_KEY_ERROR"
            self.readwrite_notify_char.changed(error_msg)
            logger.error(f"[UWB BLE TX] Error notification sent: {error_msg}")

    def send_custom_notification(self, data):
        """
        Public method to send custom notifications from external code.
        Uses the UWB/notification characteristic (same as v2 implementation).
        """
        try:
            logger.info(f"[UWB BLE NOTIFICATION] {' '.join(f'{b:02X}' for b in data)}")
            # Trigger notification by changing the characteristic value
            self.readwrite_notify_char.changed(bytes(data))
        except Exception as e:
            logger.error(f"Error in send_custom_notification: {e}")

    def on_ble_connected(self, device_path):
        """
        BLE connection event handler. Updates state and stores device path.
        """
        logger.info("BLE Connected")
        self.session_state = BLESessionState.CONNECTED
        self.connectedDevice = device_path

        # Publish default MDID to CAN service on new connection
        self._publish_mdid_to_can("FFFFFFFFFFFF")

    def on_ble_disconnected(self):
        """
        BLE disconnection event handler. Resets session state and clears sensitive data.
        """
        logger.info("BLE Disconnected")
        self.session_state = BLESessionState.IDLE
        self.challenge = None
        self.mdid = None
        self.connectedDevice = None

        # Publish default MDID to CAN service on disconnection
        self._publish_mdid_to_can("FFFFFFFFFFFF")
