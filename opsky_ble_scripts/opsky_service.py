
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
        self.authenticated_mdid = None  # For Protocol v3
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
        
        # For Protocol v3: Start ZMQ listener for CAN responses
        if self.protocol_version == 3:
            asyncio.create_task(self._listen_can_responses())

    def _publish_mdid_to_can(self, mdid_hex: str):
        """
        Publishes MDID to CAN service for tracking authenticated devices.
        """
        try:
            payload = json.dumps({"mdid": mdid_hex})
            msg = f"opskyMDID {payload}"
            self.pub_socket.send_string(msg)
            logger.info(f"[MDID PUBLISH] Published to CAN: {msg}")
        except Exception as e:
            logger.error(f"[MDID PUBLISH] Error publishing MDID: {e}")

    async def _listen_can_responses(self):
        """
        Listen for CAN responses and forward them as signed messages to mobile app (Protocol v3 only).
        """
        logger.info("[PROTOCOL V3] Starting CAN response listener...")
        while True:
            try:
                msg = await self.sub_socket.recv_string()
                topic, payload = msg.split(" ", 1)
                
                if topic == "canToBle":
                    logger.info(f"[CAN RESPONSE] Received: {payload}")
                    try:
                        data_dict = json.loads(payload)
                        can_data = data_dict.get("data", [])
                        
                        if len(can_data) >= 2:
                            # Extract opcode from CAN response
                            opcode = (can_data[0] << 8) | can_data[1]
                            response_data = can_data[2:] if len(can_data) > 2 else []
                            
                            # Send signed SUCCESS response with CAN data
                            tosend = self._set_response_data_v3(opcode, OpskyCommands.SUCCESS.value, response_data)
                            logger.info(f"[BLE TX] Signed CAN response: {' '.join(f'{b:02X}' for b in tosend)}")
                            self.send_machine.changed(bytes(tosend))
                        else:
                            logger.warning(f"[CAN RESPONSE] Insufficient data in response: {can_data}")
                            
                    except Exception as e:
                        logger.error(f"[CAN RESPONSE] Error processing response: {e}")
                        
            except Exception as e:
                logger.error(f"[CAN RESPONSE] Error receiving ZMQ message: {e}")
                await asyncio.sleep(0.5)

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

    def _set_response_data_v3(self, opcode, response, data):
        """
        Format signed response for Protocol v3: [SIG_LEN][SIGNATURE][RESPONSE_CODE][OPCODE][DATA]
        Signs the [RESPONSE_CODE][OPCODE][DATA] content.
        """
        try:
            from ecdsa_utils import sign_data
            
            # Prepare the data to sign: [RESPONSE_CODE][OPCODE][DATA]
            response_bytes = response.to_bytes(2, byteorder=BYTEORDER)
            opcode_bytes = opcode.to_bytes(2, byteorder=BYTEORDER)
            
            data_to_sign = list(response_bytes) + list(opcode_bytes) + data
            
            # Sign the data
            signature = sign_data(bytes(data_to_sign))
            sig_length = len(signature)
            
            # Format: [SIG_LEN][SIGNATURE][RESPONSE_CODE][OPCODE][DATA]
            result = [sig_length] + list(signature) + data_to_sign
            return result
            
        except Exception as e:
            logger.error(f"Error signing Protocol v3 response: {e}")
            # Fallback to unsigned response
            return self._set_response_data(opcode, response, data)

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
            # Protocol version branching - handle v3 differently from v2
            if self.protocol_version == 2:
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
                
                # Protocol v3: No header, extract opcode from data
                # Authentication: [SIG_LEN][SIGNATURE_OF_OPCODE+MDID][OPCODE][MDID]
                # Commands: [SIG_LEN][SIGNATURE_OF_OPCODE][OPCODE]
                
                # Log raw received data first
                rx_hex = ' '.join(f'{b:02X}' for b in data)
                logger.info(f"[BLE RX] {rx_hex}")
                
                if self.session_state != BLESessionState.AUTHENTICATED:
                    # Authentication: [SIG_LEN][SIGNATURE_OF_OPCODE+MDID][OPCODE][MDID]
                    if len(data) < 1:  # Need at least signature length byte
                        logger.warning(f"[PROTOCOL V3] No signature length byte")
                        tosend = self._set_response_data_v3(OpskyCommands.SET_OPID.value, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        if self.connection_monitor and self.connectedDevice:
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connectedDevice))
                        return
                    
                    sig_length = data[0]
                    if sig_length == 0:
                        logger.warning(f"[PROTOCOL V3] Zero signature length")
                        tosend = self._set_response_data_v3(OpskyCommands.SET_OPID.value, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        if self.connection_monitor and self.connectedDevice:
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connectedDevice))
                        return
                    
                    if len(data) < 1 + sig_length + 2 + 6:  # sig_len + signature + opcode + mdid
                        logger.warning(f"[PROTOCOL V3] Insufficient data: need {1+sig_length+2+6}, got {len(data)}")
                        tosend = self._set_response_data_v3(OpskyCommands.SET_OPID.value, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        if self.connection_monitor and self.connectedDevice:
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connectedDevice))
                        return
                    
                    signature = bytes(data[1:1+sig_length])
                    auth_opcode_bytes = data[1+sig_length:1+sig_length+2]
                    mdid = bytes(data[1+sig_length+2:1+sig_length+2+6])
                    
                    # Extract actual opcode from data (no header in v3)
                    opcode = int.from_bytes(auth_opcode_bytes, byteorder=BYTEORDER)
                    logger.info(f"💡💡 Received Protocol v3 authentication opcode {opcode:04X}")
                    
                    # Only SET_OPID (0x0001) is allowed for authentication
                    if opcode != OpskyCommands.SET_OPID.value:
                        logger.warning(f"[PROTOCOL V3] Invalid authentication opcode: {opcode:04X}")
                        tosend = self._set_response_data_v3(opcode, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        if self.connection_monitor and self.connectedDevice:
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connectedDevice))
                        return
                    
                    # Verify signature of [opcode + mdid]
                    opcode_mdid_data = auth_opcode_bytes + list(mdid)
                    if verify_signature(bytes(opcode_mdid_data), signature):
                        self.session_state = BLESessionState.AUTHENTICATED
                        self.authenticated_mdid = mdid
                        logger.info(f"[PROTOCOL V3] MDID {mdid.hex().upper()} authenticated")
                        #tosend = self._set_response_data_v3(opcode, OpskyCommands.SUCCESS.value, [0x01])
                        #logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        #self.send_machine.changed(bytes(tosend))
                        self.servicestate = AuthState.USER_AUTHENTICATED
                        
                        # Publish authenticated status to ZMQ
                        try:
                            device_path = self.connectedDevice if self.connectedDevice else "unknown"
                            auth_msg = json.dumps({"status": "authenticated", "device": device_path})
                            self.pub_socket.send_string(f"bleStatus {auth_msg}")
                            logger.info(f"Published BLE status: {auth_msg}")
                        except Exception as e:
                            logger.error(f"Failed to publish authenticated status to ZMQ: {e}")

                        # Publish authenticated MDID to CAN service
                        mdid_hex = mdid.hex().upper()
                        self._publish_mdid_to_can(mdid_hex)
                    else:
                        logger.warning(f"[PROTOCOL V3] Signature verification failed")
                        tosend = self._set_response_data_v3(opcode, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        if self.connection_monitor and self.connectedDevice:
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connectedDevice))
                    return
                else:
                    # Commands: [SIG_LEN][SIGNATURE_OF_OPCODE][OPCODE]  
                    if len(data) < 3:  # Need at least sig_len + 2 bytes for opcode
                        logger.warning(f"[PROTOCOL V3] No signature length byte or insufficient data")
                        tosend = self._set_response_data_v3(0x0000, OpskyCommands.ERROR.value, [0x00])  # Default opcode
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        if self.connection_monitor and self.connectedDevice:
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connectedDevice))
                        return
                    
                    sig_length = data[0]
                    if len(data) < 1 + sig_length + 2:  # sig_len + signature + opcode
                        logger.warning(f"[PROTOCOL V3] Insufficient command data: need {1+sig_length+2}, got {len(data)}")
                        # Try to extract opcode if possible for error response
                        error_opcode = 0x0000
                        if len(data) >= 3:  # At least sig_len + 2 bytes for opcode
                            try:
                                temp_sig_len = data[0] 
                                if len(data) >= 1 + temp_sig_len + 2:
                                    error_opcode = int.from_bytes(data[1+temp_sig_len:1+temp_sig_len+2], byteorder=BYTEORDER)
                            except:
                                pass
                        tosend = self._set_response_data_v3(error_opcode, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        if self.connection_monitor and self.connectedDevice:
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connectedDevice))
                        return
                    
                    signature = bytes(data[1:1+sig_length])
                    cmd_opcode_bytes = data[1+sig_length:1+sig_length+2]
                    
                    # Extract actual opcode from data (no header in v3)
                    opcode = int.from_bytes(cmd_opcode_bytes, byteorder=BYTEORDER)
                    logger.info(f"💡💡 Received Protocol v3 command opcode {opcode:04X}")
                    
                    # Verify opcode signature
                    if (self.authenticated_mdid is not None and 
                        verify_opcode_signature_v3(opcode, bytes(), signature, self.authenticated_mdid.hex())):
                        logger.info(f"[PROTOCOL V3] Command {opcode:04X} verified")
                        self._forward_command_to_can(opcode, bytes())
                        tosend = self._set_response_data_v3(opcode, OpskyCommands.PENDING.value, [])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                    else:
                        logger.warning(f"[PROTOCOL V3] Command signature verification failed")
                        tosend = self._set_response_data_v3(opcode, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        if self.connection_monitor and self.connectedDevice:
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
            if self.protocol_version == 3:
                # Protocol v3: No header, pass entire message as data
                # Opcode will be extracted from within the message data
                self._handle_command(hack_response, 0, list(value))
            else:
                # Protocol v2: Extract opcode from header
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
            #.readwrite_notify_char.changed(ack_msg)
            logger.info(f"[UWB BLE TX] Notification sent: {ack_msg}")

        except Exception as e:
            logger.error(f"[UWB BLE] Error processing UWB key: {e}")
            # Send error notification
            error_msg = b"UWB_KEY_ERROR"
#           self.readwrite_notify_char.changed(error_msg)
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

        # Publish default MDID and WELCOME_ZONE on new connection
        self._publish_mdid_to_can("FFFFFFFFFFFF")
        try:
            welcome_msg = "opskyState WELCOME_ZONE"
            self.pub_socket.send_string(welcome_msg)
            logger.info(f"[DEFAULT ZONE] Published to CAN: {welcome_msg}")
        except Exception as e:
            logger.error(f"[DEFAULT ZONE] Error publishing WELCOME_ZONE: {e}")

    def on_ble_disconnected(self):
        """
        BLE disconnection event handler. Resets session state and clears sensitive data.
        """
        logger.info("BLE Disconnected")
        self.session_state = BLESessionState.IDLE
        self.challenge = None
        self.mdid = None
        self.connectedDevice = None

        # Publish default MDID and NO_ZONE on disconnection
        self._publish_mdid_to_can("FFFFFFFFFFFF")
        try:
            no_zone_msg = "opskyState NO_ZONE"
            self.pub_socket.send_string(no_zone_msg)
            logger.info(f"[NO ZONE] Published to CAN: {no_zone_msg}")
        except Exception as e:
            logger.error(f"[NO ZONE] Error publishing NO_ZONE: {e}")
