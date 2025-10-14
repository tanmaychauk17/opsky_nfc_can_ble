from bluez_peripheral.gatt.service import Service 
from bluez_peripheral.gatt.characteristic import characteristic, CharacteristicFlags as CharFlags
from bluez_peripheral.gatt.descriptor import descriptor, DescriptorFlags as DescFlags
from enum import Enum, auto
import time
import logging
import asyncio
import zmq
import zmq.asyncio
import os
import json


logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
level=logging.INFO)

counter = 1
PRIMARY_SERVICE_UUID = "6DF722E0-AC7B-4C63-8226-FFE665B82697"
SENDTOMACHINE_CHAR_UUID = "6DF722E1-AC7B-4C63-8226-FFE665B82697"
READFROMMACHINE_CHAR_UUID = "6DF722E2-AC7B-4C63-8226-FFE665B82697"
PROTOCOL_VERSION_CHAR_UUID = "6DF722E3-AC7B-4C63-8226-FFE665B82697"
UWB_CHAR_UUID = "6DF722E4-AC7B-4C63-8226-FFE665B82697"
hack_response = 0x2000
BYTEORDER = 'big'

class BLESessionState(Enum):
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
    USER_UNAUTHENTICATED = 0x01
    USER_AUTHENTICATED = 0x02

class OpskyCommands(Enum):
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
    def __init__(self):
        self.lights = 1
        self.hvac = 1
        self.locks = 1
    
class OpskyService(Service):
    def __init__(self, connection_monitor=None, protocol_version=2):
        super().__init__(PRIMARY_SERVICE_UUID, True)
        self.ServiceID = PRIMARY_SERVICE_UUID
        self.servicestate = AuthState.USER_UNAUTHENTICATED
        self.session_state = BLESessionState.IDLE
        self.session_timer = None
        self.challenge = None
        self.mdid = None
        self.connection_monitor = connection_monitor
        self.connectedDevice = None  # Set this on connect
        self.protocol_version = protocol_version  # Explicit protocol version

        # ZeroMQ PUB socket for NFC data
        self.ctx = zmq.asyncio.Context.instance()
        self.pub_socket = self.ctx.socket(zmq.PUB)
        self.sub_socket = self.ctx.socket(zmq.SUB)
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

    def _get_opcode_data(self, message):
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
        temp = list(opcode.to_bytes(2, byteorder=BYTEORDER))
        temp.extend(data)
        return temp

    def _set_response_data(self, opcode, response, data):
        temp = list(response.to_bytes(2, byteorder=BYTEORDER))
        temp.extend(list(opcode.to_bytes(2, byteorder=BYTEORDER)))
        temp.extend(data)
        return temp

    def _set_unsolicited_opcode_notification_data(self, opcode, response, data):
        temp = list(opcode.to_bytes(2, byteorder=BYTEORDER))
        temp.extend(list(response.to_bytes(2, byteorder=BYTEORDER)))
        temp.extend(data)
        return temp

    async def _start_mdid_timeout(self):
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
        # Simulate: allow all for now, or check against a list
        return True

    def _verify_challenge_response(self, response):
        # Simulate: always accept for now, or implement real check
        return True

    def _handle_command(self, response_code, opcode, data):
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
                # Placeholder for protocol v3 authentication flow
                logger.info("[PROTOCOL V3] Authentication flow not implemented yet.")
                # Implement v3 sequence here
                # Example: reject all for now
                tosend = self._set_response_data(opcode, OpskyCommands.ERROR.value, [0x00])
                logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tosend)}")
                self.send_machine.changed(bytes(tosend))
            else:
                logger.warning(f"Unknown protocol version: {self.protocol_version}")
        except Exception as e:
            logger.error(f"Error in _handle_command: {e}")


    @characteristic(SENDTOMACHINE_CHAR_UUID, CharFlags.WRITE)
    def write_char(self, value: bytes, options):
        # Log RX from mobile in hex (space-separated, capital)
        logger.info(f"[BLE RX] {' '.join(f'{b:02X}' for b in value)}")
        self.setter(value, options)

    @write_char.setter
    def setter(self, value, options):
        try:
            response_code, opcode, data = self._get_opcode_data(list(value))
            self._handle_command(response_code, opcode, data)
        except Exception as e:
            logger.error(f"Error in setter: {e}")

    @characteristic(READFROMMACHINE_CHAR_UUID, CharFlags.INDICATE | CharFlags.READ)
    def send_machine(self, options):
        logger.info(f"📖📖 Attempting to read {READFROMMACHINE_CHAR_UUID}")
        # Log TX to mobile in hex (space-separated, capital)
        tx = [0x01]
        logger.info(f"[BLE TX] {' '.join(f'{b:02X}' for b in tx)}")
        return tx

    @characteristic(PROTOCOL_VERSION_CHAR_UUID, CharFlags.READ)
    def read_version(self, options):
        logger.info(f"📖📖 Attempting to read Protocol version - returning version {self.protocol_version}")
        if self.session_state in [BLESessionState.IDLE, BLESessionState.CONNECTED]:
            self.session_state = BLESessionState.PROTOCOL_VERIFIED
            self.session_state = BLESessionState.WAITING_FOR_MDID
            asyncio.create_task(self._start_mdid_timeout())
        # Return protocol version as [0x00, version]
        logger.info(f"[BLE TX] Protocol version response: [0x00, 0x{self.protocol_version:02X}]")
        return [0x00, self.protocol_version]

    @characteristic(UWB_CHAR_UUID, CharFlags.READ | CharFlags.WRITE | CharFlags.NOTIFY)
    def uwb_char(self, options):
        """UWB characteristic - on read returns BLE advertisement name"""
        logger.info(f"[UWB BLE] Read requested - returning BLE adv name: {self.ble_adv_name}")
        # Convert string to bytes and then to list of integers
        return list(self.ble_adv_name.encode('utf-8'))

    @uwb_char.setter
    def uwb_char(self, value, options):
        """UWB characteristic - on write receives UWB key from mobile"""
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
            self.uwb_char.changed(ack_msg)
            logger.info(f"[UWB BLE TX] Notification sent: {ack_msg}")

        except Exception as e:
            logger.error(f"[UWB BLE] Error processing UWB key: {e}")
            # Send error notification
            error_msg = b"UWB_KEY_ERROR"
            self.uwb_char.changed(error_msg)
            logger.error(f"[UWB BLE TX] Error notification sent: {error_msg}")

    def on_ble_connected(self, device_path):
        logger.info(f"BLE Connected: device_path={device_path}")
        self.session_state = BLESessionState.CONNECTED
        self.connectedDevice = device_path
        logger.info(f"[DEBUG] on_ble_connected: connection_monitor={self.connection_monitor}, connectedDevice={self.connectedDevice}")

    def on_ble_disconnected(self):
        logger.info(f"BLE Disconnected: connectedDevice={self.connectedDevice}")
        logger.info(f"[DEBUG] on_ble_disconnected: connection_monitor={self.connection_monitor}, connectedDevice={self.connectedDevice}")
        self.session_state = BLESessionState.IDLE
        self.challenge = None
        self.mdid = None
        self.connectedDevice = None
