
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
    def __init__(self, connection_monitor=None, protocol_version=3):
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
        self.protocol_version = protocol_version  # Protocol version (2 or 3)

        # ZeroMQ PUB/SUB sockets for CAN/NFC inter-process communication
        self.ctx = zmq.asyncio.Context.instance()
        self.pub_socket = self.ctx.socket(zmq.PUB)
        self.sub_socket = self.ctx.socket(zmq.SUB)
        from zmqhub import XSUB_ADDR, XPUB_ADDR
        self.pub_socket.connect(XSUB_ADDR)
        self.pub_socket.setsockopt(zmq.LINGER, 0)
        self.sub_socket.connect(XPUB_ADDR)
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, "canToBle")
        self.sub_socket.setsockopt(zmq.LINGER, 0)

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
                        tosend = self._set_response_data(opcode, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
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
                    else:
                        logger.info("Authentication failed.")
                        tosend = self._set_response_data(opcode, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
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
                    signature = data[6:]  # All bytes after MDID
                    if verify_signature(mdid, signature):
                        self.session_state = BLESessionState.AUTHENTICATED
                        self.authenticated_mdid = mdid  # Store for future commands
                        logger.info(f"[PROTOCOL V3] MDID {mdid.hex().upper()} signature verified. User authenticated!")
                        tosend = self._set_response_data(opcode, OpskyCommands.SUCCESS.value, [0x01])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        self.servicestate = AuthState.USER_AUTHENTICATED
                    else:
                        logger.warning(f"[PROTOCOL V3] Signature verification failed for MDID {mdid.hex().upper()}")
                        tosend = self._set_response_data(opcode, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        if self.connection_monitor and self.connectedDevice:
                            logger.info("Disconnecting BLE device due to failed signature verification.")
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connectedDevice))
                    return
                else:
                    # After authentication, expect: OPCODE (2) + PAYLOAD (N) + SIGNATURE (DER, variable)
                    if len(data) < 2 + 8:  # 2 bytes opcode + minimal DER signature
                        logger.warning(f"[PROTOCOL V3] Data too short for opcode+signature. Got {len(data)} bytes.")
                        tosend = self._set_response_data(opcode, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
                        return
                    opcode_bytes = data[:2]
                    # Try all possible splits: signature must be valid DER, so try from minimal to maximal
                    verified = False
                    for sig_start in range(2, len(data)):
                        payload = data[2:sig_start]
                        signature = data[sig_start:]
                        opcode_val = int.from_bytes(opcode_bytes, 'big')
                        if verify_opcode_signature_v3(opcode_val, payload, signature, self.authenticated_mdid.hex()):
                            logger.info(f"[PROTOCOL V3] Opcode {opcode_val} signature verified for MDID {self.authenticated_mdid.hex().upper()}.")
                            tosend = self._set_response_data(opcode_val, OpskyCommands.SUCCESS.value, [0x01])
                            logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                            self.send_machine.changed(bytes(tosend))
                            verified = True
                            break
                    if not verified:
                        logger.warning(f"[PROTOCOL V3] Opcode signature verification failed for MDID {self.authenticated_mdid.hex().upper()}.")
                        tosend = self._set_response_data(opcode_val, OpskyCommands.ERROR.value, [0x00])
                        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                        self.send_machine.changed(bytes(tosend))
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
        BLE GATT write handler for RX from mobile. Logs and dispatches to setter.
        """
        logger.info(f"[BLE RX] {' '.join(f'{b:02X}' for b in value)}")
        self.setter(value, options)

    @write_char.setter
    def setter(self, value, options):
        """
        Processes incoming BLE write, extracts opcode/data, and routes to handler.
        """
        try:
            logger.info(f"[BLE RX] {' '.join(f'{b:02X}' for b in value)}")
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
        BLE GATT characteristic with read, write, and notify capabilities.
        This method handles READ operations and returns advertising name from config.json.
        Write operations are handled by the setter method below.
        """
        logger.info(f"📖📖 Attempting to read {READWRITE_NOTIFY_CHAR_UUID}")
        return self._handle_readwrite_notify_read(options)

    @readwrite_notify_char.setter
    def readwrite_notify_setter(self, value, options):
        """
        Setter for write operations on the read/write/notify characteristic.
        """
        try:
            logger.info(f"[RW_NOTIFY SETTER] {' '.join(f'{b:02X}' for b in value)}")
            self._handle_readwrite_notify_write(value, options)
        except Exception as e:
            logger.error(f"Error in readwrite_notify_setter: {e}")

    def _handle_readwrite_notify_write(self, value, options):
        """
        Handle write operations to the read/write/notify characteristic.
        """
        try:
            logger.info(f"[RW_NOTIFY] Processing write: {' '.join(f'{b:02X}' for b in value)}")
            # Process the written data - can be customized based on requirements
            # For now, echo the data back via notification
            self._send_notification(value)
        except Exception as e:
            logger.error(f"Error in _handle_readwrite_notify_write: {e}")

    def _handle_readwrite_notify_read(self, options):
        """
        Handle read operations from the read/write/notify characteristic.
        Returns the advertising name from config.json as bytes.
        """
        try:
            logger.info("[RW_NOTIFY] Processing read request")
            
            # Read advertising name from config.json
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    adv_name = config.get('ble_adv_name', 'OPSKY_DEFAULT')
                    # Convert string to bytes (UTF-8 encoded)
                    adv_name_bytes = list(adv_name.encode('utf-8'))
                    logger.info(f"[RW_NOTIFY READ] Advertising name: {adv_name}")
                    logger.info(f"[RW_NOTIFY READ] {' '.join(f'{b:02X}' for b in adv_name_bytes)}")
                    return adv_name_bytes
            except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
                logger.error(f"Error reading config.json: {e}")
                # Fallback to default name
                default_name = "OPSKY_DEFAULT"
                default_bytes = list(default_name.encode('utf-8'))
                logger.info(f"[RW_NOTIFY READ] Using default name: {default_name}")
                logger.info(f"[RW_NOTIFY READ] {' '.join(f'{b:02X}' for b in default_bytes)}")
                return default_bytes
                
        except Exception as e:
            logger.error(f"Error in _handle_readwrite_notify_read: {e}")
            return [0x00]  # Return error status

    def _send_notification(self, data):
        """
        Send notification to connected BLE client via the read/write/notify characteristic.
        """
        # Not sending anything for now - keeping method blank
        logger.debug(f"[RW_NOTIFY NOTIFICATION] Notification disabled: {' '.join(f'{b:02X}' for b in data)}")
        pass

    def send_custom_notification(self, data):
        """
        Public method to send custom notifications from external code.
        """
        self._send_notification(data)

    def on_ble_connected(self, device_path):
        """
        BLE connection event handler. Updates state and stores device path.
        """
        logger.info("BLE Connected")
        self.session_state = BLESessionState.CONNECTED
        self.connectedDevice = device_path

    def on_ble_disconnected(self):
        """
        BLE disconnection event handler. Resets session state and clears sensitive data.
        """
        logger.info("BLE Disconnected")
        self.session_state = BLESessionState.IDLE
        self.challenge = None
        self.mdid = None
        self.connectedDevice = None
