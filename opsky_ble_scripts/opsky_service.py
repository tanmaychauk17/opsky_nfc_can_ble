"""
Copyright (C) Caterpillar Inc. All Rights Reserved.
Caterpillar: Confidential Yellow

File:        opsky_service.py
Description: Contains the logic to support the BLE implementation layer.
"""
import sys
import logging
import json
import asyncio
from enum import Enum, auto
from pathlib import Path as MakePath
from typing import List, Optional

# Add current directory to path for opsky_protocol import
sys.path.insert(0, str(MakePath(__file__).parent))
import opsky_protocol as opsky

# BLE GATT for BLE service, characteristics
from bluez_peripheral.gatt.service import Service
from bluez_peripheral.gatt.characteristic import characteristic, CharacteristicFlags as CharFlags
# from bluez_peripheral.gatt.descriptor import descriptor, DescriptorFlags as DescFlags

import zmq
import zmq.asyncio

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("opsky_service")

# Add paths to import custom Python scripts or other files using this Python file location as reference
BASE_DIR = MakePath(__file__).absolute().parent.parent
sys.path.append(str(BASE_DIR))

try:
    from zmqhub import XSUB_ADDR, XPUB_ADDR
except ImportError:
    logger.error("*** ERROR: file 'opsky_nfc_can_ble/zmqhub.py' not found ***\n")
    logger.error("Ensure the location for this file is properly set in this script before importing the file.")
    sys.exit(1)

# BLE GATT UUIDs for service and characteristics
PRIMARY_SERVICE_UUID = "6DF722E0-AC7B-4C63-8226-FFE665B82697"
MOBILE_TO_MACHINE_MSG_CHAR_UUID = "6DF722E1-AC7B-4C63-8226-FFE665B82697"
MACHINE_TO_MOBILE_MSG_CHAR_UUID = "6DF722E2-AC7B-4C63-8226-FFE665B82697"
PROTOCOL_VERSION_CHAR_UUID = "6DF722E3-AC7B-4C63-8226-FFE665B82697"
READWRITE_NOTIFY_CHAR_UUID = "6DF722E4-AC7B-4C63-8226-FFE665B82697"

# Byte order for all protocol fields (Big Endian = 'big')
BYTEORDER = 'big'

EXPECTED_MDID_SIZE_IN_BYTES = 6

class BLESessionState(Enum):
    """
    State machine for BLE authentication and session lifecycle.
    """
    IDLE_DISCONNECTED = auto()
    BLE_LINK_ESTABLISHED = auto()
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
    def __init__(self, connection_monitor=None, default_protocol_version=None):
        self.BASE_DIR = BASE_DIR
        self.CONFIG_FILE_PATH = BASE_DIR.joinpath('config.json')
        self.ServiceID = PRIMARY_SERVICE_UUID
        self._machine_to_mobile_msg_value = bytes()
        self._mobile_to_machine_msg_value = bytes()
        super().__init__(self.ServiceID, True)

        # Get configuration settings
        self.protocol_version = self._load_protocol_version(default_protocol_version)
        self.mdid_provision_timeout_in_seconds = self._load_mdid_provision_timeout(5)
        self.ble_adv_name = self._load_ble_adv_name("OPSKY_DEVICE_DEFAULT")

        # Track authentication and session state
        self.service_state = AuthState.USER_UNAUTHENTICATED
        self.session_state = BLESessionState.IDLE_DISCONNECTED
        self.session_timer = None
        self.challenge = None
        self.mdid: bytes = opsky.BLANK_MDID
        self.connection_monitor = connection_monitor
        self.connected_device_path = None

        # Initialize ZMQ PUBlisher and SUBscriber sockets
        self.ctx = zmq.asyncio.Context.instance()
        self.pub_socket = self.ctx.socket(zmq.PUB)
        self.sub_socket = self.ctx.socket(zmq.SUB)

        # Subscriber socket connects to publisher data
        self.sub_socket.connect(XPUB_ADDR)
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, "CanToBle")
        self.sub_socket.setsockopt(zmq.LINGER, 0)

        # Publisher socket connects to subscriber data
        self.pub_socket.connect(XSUB_ADDR)
        self.pub_socket.setsockopt(zmq.LINGER, 0)

        # Other variables
        self._mdid_provision_timeout_task = None

        # UWB key storage
        self.uwb_key = None
        
        # For Protocol v3: Start ZMQ listener for CAN responses
        if self.protocol_version == 3:
            asyncio.create_task(self._listen_can_responses())

    @characteristic(MOBILE_TO_MACHINE_MSG_CHAR_UUID, CharFlags.WRITE)
    def mobile_to_machine_msg_characteristic(self, options):
        """
        BLE GATT method to be called when a client reads this characteristic (if read is supported).
        """
        pass

    @mobile_to_machine_msg_characteristic.setter
    def mobile_to_machine_msg_characteristic(self, value: bytes, options):
        """
         BLE GATT method to be called when a client writes to this characteristic.
        """
        try:
            logger.info(f"✏️ Writing characteristic {MOBILE_TO_MACHINE_MSG_CHAR_UUID}")
            data_length = len(value)
            logger.info(f"[BLE RX] value = {value}, size = {data_length}")

            if not isinstance(value, bytes):
                logger.warning(f"[BLE RX] Incoming message ignored: the received value does not contain bytes as expected.")
                return

            if data_length < 2:
                logger.warning(f"[BLE RX] Ignoring message due to size ({data_length}) is less than the minimum required.")
                return

            opcode = int.from_bytes(value[0:2], byteorder=BYTEORDER)

            if opcode not in opsky.Opcodes._value2member_map_:
                logger.warning(f"[BLE RX] Ignoring message due to received opcode is not supported.")
                return

            if opcode in [opsky.Opcodes.SUCCESS_RESPONSE.value,
                          opsky.Opcodes.PENDING_RESPONSE.value,
                          opsky.Opcodes.ERROR_RESPONSE.value,
                          opsky.Opcodes.UNSOLICITED_EVENT_NOTIFICATION.value,
                          opsky.Opcodes.UNSOLICITED_OPCODE_NOTIFICATION.value]:

                if data_length < 4:
                    logger.warning(f"[BLE RX] Ignoring message due to size ({data_length}) is less than the minimum required.")
                    return

                rsp_opcode = int.from_bytes(value[2:4], byteorder=BYTEORDER)

                if rsp_opcode not in opsky.Opcodes._value2member_map_:
                    logger.warning(f"[BLE RX] Ignoring message due to received opcode in response is not supported.")
                    return

                if data_length > 4:
                    data = value[4:]
                    self._opsky_command_handler(opcode, data=data, rsp_opcode=rsp_opcode)
                else:
                    self._opsky_command_handler(opcode, rsp_opcode=rsp_opcode)
            elif data_length > 2:
                data = value[2:]
                self._opsky_command_handler(opcode, data=data)
            else:
                self._opsky_command_handler(opcode)

            self._mobile_to_machine_msg_value = value
        except Exception as e:
            logger.error(f"Error in mobile_to_machine_msg_characteristic: {e}")

    @characteristic(MACHINE_TO_MOBILE_MSG_CHAR_UUID, CharFlags.READ | CharFlags.INDICATE)
    def machine_to_mobile_msg_characteristic(self, options):
        """
        BLE GATT method to be called when a client reads this characteristic.
        """
        logger.info(f"📖 Reading characteristic {MACHINE_TO_MOBILE_MSG_CHAR_UUID}")
        tx_buffer = self._machine_to_mobile_msg_value
        logger.info(f"[BLE TX] Data {':' if tx_buffer else 'is empty:'} {[f'0x{b:02X}' for b in tx_buffer]}")
        return tx_buffer

    @characteristic(PROTOCOL_VERSION_CHAR_UUID, CharFlags.READ)
    def opsky_protocol_version(self, options):
        """
        BLE GATT method to be called when a client reads this characteristic.
        Triggers MDID timeout and state transition.
        """
        logger.info(f"📖 Reading characteristic {PROTOCOL_VERSION_CHAR_UUID}")
        logger.info(f"Current self.session_state is 0x{self.session_state.value:02X} '{self.session_state.name}'")

        if self.session_state in [BLESessionState.IDLE_DISCONNECTED, BLESessionState.BLE_LINK_ESTABLISHED]:
           self.session_state = BLESessionState.PROTOCOL_VERIFIED

        logger.info(f"[BLE TX] Opsky Protocol version - sending version 0x{self.protocol_version:04X}")
        return list(self.protocol_version.to_bytes(2, byteorder=BYTEORDER))

    @characteristic(READWRITE_NOTIFY_CHAR_UUID, CharFlags.READ | CharFlags.WRITE | CharFlags.NOTIFY)
    def readwrite_notify_char(self, options):
        """
        OpSky BLE characteristic - on read returns BLE advertisement name.
        Immediately sends UWB config data via notify after serving the read.
        """
        logger.info(f"[OPSKY BLE] Read requested - returning: {self.ble_adv_name}")
        
        # Schedule immediate auto-notify with UWB config data
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self._immediate_notify_uwb_config())
            else:
                asyncio.ensure_future(self._immediate_notify_uwb_config())
            logger.info("[OPSKY BLE] Auto-notify scheduled")
        except Exception as e:
            logger.error(f"[OPSKY BLE] Failed to schedule auto-notify: {e}")
        
        # Convert string to bytes and then to list of integers
        return list(self.ble_adv_name.encode('utf-8'))

    async def _immediate_notify_uwb_config(self):
        """
        Immediately notify UWB config data after characteristic read.
        This implements the OpSky flow where config data is sent right after read response.
        """
        try:
            logger.info("[OPSKY BLE] Getting UWB config data...")
            
            config_data = await self.request_uwb_config()
            if config_data:
                logger.info(f"[OPSKY BLE] ✅ Config received: {len(config_data)} bytes")
                
                try:
                    self.readwrite_notify_char.changed(config_data)
                    logger.info(f"[OPSKY BLE] ✅ Notification sent: {config_data.hex()}")
                except Exception as notify_error:
                    logger.error(f"[OPSKY BLE] ❌ Notification failed: {notify_error}")
            else:
                logger.error("[OPSKY BLE] ❌ Failed to get UWB config")
                try:
                    error_data = b"CONFIG_ERROR"
                    self.readwrite_notify_char.changed(error_data)
                    logger.warning("[OPSKY BLE] Error notification sent")
                except Exception as e:
                    logger.error(f"[OPSKY BLE] Failed to send error notification: {e}")
                
        except Exception as e:
            logger.error(f"[OPSKY BLE] Immediate notify error: {e}")
            import traceback
            traceback.print_exc()

    @readwrite_notify_char.setter
    def readwrite_notify_setter(self, value, options):
        """
        OpSky BLE characteristic - on write receives data from app.
        Handles both iPhone init requests (0x0A) and UWB keys.
        """
        logger.info(f"[OPSKY BLE RX] {' '.join(f'{b:02X}' for b in value)}")
        
        try:
            # Check if it's iPhone init request (0x0A)
            if len(value) == 1 and value[0] == 0x0A:
                logger.info("[IPHONE] Init request (0x0A) received")
                asyncio.create_task(self.handle_iphone_init_request())
                return
            
            # Check for empty writes
            if not value:
                logger.warning("[OPSKY BLE] Empty write received")
                return
                
            # Otherwise, treat as UWB key (existing flow)
            try:
                msg = bytes(value).decode('utf-8', errors='ignore').strip()
                if msg:
                    logger.info(f"[OPSKY BLE] UWB key received: {msg}")
                    self.uwb_key = msg
                    
                    # Forward UWB key to ZMQ for further processing
                    payload = json.dumps({"UwbKey": msg})
                    zmq_msg = f"uwbKey {payload}"
                    self.pub_socket.send_string(zmq_msg)
                    logger.info(f"[OPSKY BLE] UWB key forwarded to ZMQ")
                else:
                    logger.warning("[OPSKY BLE] Empty UWB key received")
            except UnicodeDecodeError:
                logger.warning(f"[OPSKY BLE] Non-UTF8 data received: {value.hex()}")

        except Exception as e:
            logger.error(f"[OPSKY BLE] Error processing write: {e}")
            # Send error notification
            try:
                error_msg = b"OPSKY_ERROR"
                self.readwrite_notify_char.changed(error_msg)
                logger.warning("[OPSKY BLE] Error notification sent")
            except Exception as notify_error:
                logger.error(f"[OPSKY BLE] Failed to send error notification: {notify_error}")

    def _load_protocol_version(self, default_value: int) -> int:
        """
        Load protocol version from config.json

        Parameters
        ----------
        default_value: int - Default integer value to use if unable to get the value from the file.

        Returns
        -------
        int: An integer representing the Opsky Protocol version to be used.
        """
        try:
            with open(str(self.CONFIG_FILE_PATH)) as f:
                config = json.load(f)
            version = config.get("protocol_version", default_value)
            logger.info(f"Loaded protocol version from config: {version}")
        except FileNotFoundError:
            version = default_value
            logger.warning(f"Config file {str(self.CONFIG_FILE_PATH)} not found, using protocol version: {version}")
        except Exception as e:
            version = default_value
            logger.error(f"Error when loading config file {str(self.CONFIG_FILE_PATH)}: {e}, using: {version}")

        return version

    async def _listen_can_responses(self):
        """
        Listen for CAN responses and forward them as signed messages to mobile app (Protocol v3 only).
        """
        logger.info("[PROTOCOL V3] Starting CAN response listener...")
        try:
            while True:
                msg = await self.sub_socket.recv_string(zmq.NOBLOCK)
                if msg.startswith("CanToBle "):
                    payload = msg[9:]  # Remove "CanToBle " prefix
                    logger.info(f"[CAN RESPONSE] Received: {payload}")
                    try:
                        import json
                        can_data = json.loads(payload).get("CanToBle", [])
                        if len(can_data) >= 2:
                            # Extract opcode from CAN response
                            opcode = int.from_bytes(can_data[:2], byteorder=BYTEORDER)
                            response_data = can_data[2:] if len(can_data) > 2 else []
                            
                            # Send signed SUCCESS response with CAN data
                            tosend = opsky.set_response_data_v3(response_type=opsky.Opcodes.SUCCESS_RESPONSE,
                                                               opcode=opsky.Opcodes(opcode),
                                                               data=bytes(response_data))
                            logger.info(f"[BLE TX] Signed CAN response: {' '.join(f'{b:02X}' for b in tosend)}")
                            self.machine_to_mobile_msg_char_indication(bytes(tosend))
                        else:
                            logger.warning(f"[CAN RESPONSE] Insufficient data in response: {can_data}")
                    except Exception as e:
                        logger.error(f"[CAN RESPONSE] Error processing response: {e}")
                await asyncio.sleep(0.1)  # Small delay to prevent busy waiting
        except asyncio.CancelledError:
            logger.info("[PROTOCOL V3] CAN response listener cancelled")
        except Exception as e:
            logger.error(f"[CAN RESPONSE] Error receiving ZMQ message: {e}")

    def _load_mdid_provision_timeout(self, default_value: int) -> int:
        """
        Load MDID Provision Timeout value from config.json

        Parameters
        ----------
        default_value: int - Default integer value to use if unable to get the value from the file.

        Returns
        -------
        int: An integer representing the MDID Provision Timeout value to be used.
        """
        try:
            with open(str(self.CONFIG_FILE_PATH)) as f:
                config = json.load(f)
            timeout = config.get("mdid_provision_timeout_in_seconds", default_value)
            logger.info(f"Loaded MDID Provision Timeout value from config: {timeout}")
        except FileNotFoundError:
            timeout = default_value
            logger.warning(f"Config file {str(self.CONFIG_FILE_PATH)} not found, using MDID Provision Timeout value: {timeout}")
        except Exception as e:
            timeout = default_value
            logger.error(f"Error when loading config file {str(self.CONFIG_FILE_PATH)}: {e}, using: {timeout}")

        return timeout

    def _load_ble_adv_name(self, default_value: str) -> str:
        """
        Load BLE advertising name from config.json file.

        Parameters
        ----------
        default_value: str - Default value to be used in case of file retrieval failure.

        Returns
        -------
        str: A string containing the device name to be used during advertising.
        """
        try:
            with open(str(self.CONFIG_FILE_PATH)) as f:
                config = json.load(f)
            return config.get("ble_adv_name", default_value)
        except FileNotFoundError:
            logger.warning(f"Config file {str(self.CONFIG_FILE_PATH)} not found, using '{default_value}'.")
            return default_value
        except Exception as e:
            logger.error(f"Error when loading config file {str(self.CONFIG_FILE_PATH)}: {e}, using '{default_value}'.")
            return default_value

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

    def _opsky_command_handler(self, opcode: int, data: bytes = bytes(), rsp_opcode: int = None) -> None:
        """
        Opsky Message BLE command handler. Routes opcodes, manages authentication,
        and handles protocol v2/v3 branching and signature verification.

        Parameters
        ----------
        opcode: int - The Opsky Opcode received in message (required).

        data: bytes - Supporting data (optional).

        rsp_opcode: int - Opcode present in the response (optional).

        Returns
        -------
        None
        """
        try:
            logger.info(f"[BLE RX] Opcode 0x{opsky.Opcodes(opcode).value:04X} '{opsky.Opcodes(opcode).name}'")

            if not isinstance(data, bytes):
                data = bytes()

            if isinstance(rsp_opcode, int):
                logger.info(f"[BLE RX] Response Opcode 0x{opsky.Opcodes(rsp_opcode).value:04X} '{opsky.Opcodes(rsp_opcode).name}'")
            else:
                logger.info(f"[BLE RX] Response Opcode is {rsp_opcode}")

            logger.info(f"[BLE RX] Data {[hex(num) for num in data] if data else f'is empty: {data}'}")

            # Only accept commands if authenticated, except for authentication flow
            if not ((self.session_state == BLESessionState.AUTHENTICATED) or

                    ((self.session_state == BLESessionState.WAITING_FOR_MDID) and \
                     (opcode == opsky.Opcodes.SET_MDID.value)) or

                    ((self.session_state == BLESessionState.AUTH_CHALLENGE_SENT) and \
                     (opcode == opsky.Opcodes.SUCCESS_RESPONSE.value) and \
                     (rsp_opcode == opsky.Opcodes.AUTHENTICATION_CHALLENGE.value))):
                logger.warning(f"[BLE RX] Command 0x{opsky.Opcodes(opcode).value:04X} '{opsky.Opcodes(opcode).name}' ignored: user not authenticated.")
                return

            # Protocol version branching
            if self.protocol_version == 2:
                if (self.session_state == BLESessionState.WAITING_FOR_MDID) and \
                   (opcode == opsky.Opcodes.SET_MDID.value):

                    if len(data) != EXPECTED_MDID_SIZE_IN_BYTES:
                        logger.warning(f"[BLE RX] MDID length invalid: {len(data)} bytes (expected {EXPECTED_MDID_SIZE_IN_BYTES}). Rejecting.")

                        data_to_send = opsky.set_response_data(response_type=opsky.Opcodes.ERROR_RESPONSE,
                                                               opcode=opsky.Opcodes.SET_MDID,
                                                               data=data,
                                                               error_code=opsky.SpecificErrorCodes.COMMAND_NOT_SUPPORTED)
                        if data_to_send:
                            logger.info(f"[BLE TX] {[f'0x{b:02X}' for b in data_to_send]}")
                            self.machine_to_mobile_msg_char_indication(bytes(data_to_send))

                        if self.connection_monitor and self.connected_device_path:
                            logger.info("[BLE TX] Disconnecting BLE device due to invalid MDID length.")
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connected_device_path))

                        return

                    if not self._is_mdid_authorized(data):
                        self.session_state = BLESessionState.MDID_UNAUTHORIZED
                        data_to_send = opsky.set_response_data(response_type=opsky.Opcodes.ERROR_RESPONSE,
                                                               opcode=opsky.Opcodes.SET_MDID,
                                                               data=data,
                                                               error_code=opsky.SpecificErrorCodes.MDID_NOT_AUTHORIZED)

                        if data_to_send:
                            logger.info(f"[BLE TX] {[f'0x{b:02X}' for b in data_to_send]}")
                            self.machine_to_mobile_msg_char_indication(bytes(data_to_send))

                        if self.connection_monitor and self.connected_device_path:
                            logger.info("Disconnecting BLE device due to unauthorized MDID.")
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connected_device_path))

                        return

                    self.mdid = data
                    self.session_state = BLESessionState.MDID_AUTHORIZED
                    data_to_send = opsky.set_response_data(response_type=opsky.Opcodes.SUCCESS_RESPONSE,
                                                           opcode=opsky.Opcodes.SET_MDID,
                                                           data=data)
                    if data_to_send:
                        logger.info(f"[BLE TX] {[f'0x{b:02X}' for b in data_to_send]}")
                        self.machine_to_mobile_msg_char_indication(bytes(data_to_send))

                    logger.info("[BLE TX] MDID set. Issuing challenge...")
                    self.challenge = [num for num in range(0,16,1)]  # Replace with random number if needed
                    data_to_send = opsky.set_request_data(request_type=opsky.Opcodes.AUTHENTICATION_CHALLENGE,
                                                          data=bytes(self.challenge))
                    if data_to_send:
                        logger.info(f"[BLE TX] {[f'0x{b:02X}' for b in data_to_send]}")
                        self.machine_to_mobile_msg_char_indication(bytes(data_to_send))

                    self.session_state = BLESessionState.AUTH_CHALLENGE_SENT

                elif (self.session_state == BLESessionState.AUTH_CHALLENGE_SENT) and \
                     (opcode == opsky.Opcodes.SUCCESS_RESPONSE.value) and \
                     (rsp_opcode == opsky.Opcodes.AUTHENTICATION_CHALLENGE.value):

                    if not self._verify_challenge_response(data):
                        logger.info("Authentication failed.")

                        unsolicited = opsky.set_unsolicited_notification_data(
                                        notification_type=opsky.Opcodes.UNSOLICITED_EVENT_NOTIFICATION,
                                        event=opsky.SpecificUnsolicitedEventCodes.AUTH_CHALLENGE_FAILED)
                        if unsolicited:
                            logger.info(f"[BLE TX] {[f'0x{b:02X}' for b in data_to_send]}")
                            self.machine_to_mobile_msg_char_indication(bytes(unsolicited))

                        if self.connection_monitor and self.connected_device_path:
                            logger.info("Disconnecting BLE device due to failed authentication.")
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connected_device_path))

                        return

                    self._mdid_provision_timeout_task.cancel()
                    self.session_state = BLESessionState.AUTHENTICATED
                    self.service_state = AuthState.USER_AUTHENTICATED
                    logger.info("User authenticated!")

                    # Publish authenticated status to ZMQ immediately
                    try:
                        device_path = self.connected_device_path if self.connected_device_path else "unknown"
                        import json
                        msg = json.dumps({"status": "authenticated", "device": device_path})
                        self.pub_socket.send_string(f"BleStatus {msg}")
                        logger.info(f"Published BLE status: {msg}")
                    except Exception as e:
                        logger.error(f"Failed to publish authenticated status to ZMQ: {e}")

                    # Publish authenticated MDID to CAN service (Protocol v2)
                    if self.mdid and (len(self.mdid) == EXPECTED_MDID_SIZE_IN_BYTES):
                        mdid = bytes(self.mdid)
                        mdid_hex = mdid.hex().upper()
                        self.publish_mdid_to_can(mdid_hex)
                    else:
                        logger.warning(f"Protocol v2: Invalid MDID for CAN publishing (self.mdid = '{self.mdid}')")

                else:

                    data_to_send = opsky.set_response_data(response_type=opsky.Opcodes.PENDING_RESPONSE,
                                                           opcode=opsky.Opcodes(opcode),
                                                           data=data)

                    if data_to_send:
                        logger.info(f"[BLE TX] {[f'0x{b:02X}' for b in data_to_send]}")
                        self.machine_to_mobile_msg_char_indication(bytes(data_to_send))

                    # For all opcodes. Send the same data over J1939
                    import json
                    can_data = list(opcode.to_bytes(2, byteorder=BYTEORDER))

                    if data:
                        can_data.extend(data)

                    payload = json.dumps({"BleToCan": can_data})
                    msg = f"BleToCan {payload}"
                    self.pub_socket.send_string(msg)
                    logger.info(f"[OPSKY_BLE]: Command forwarded to CAN task: {msg}")

            elif self.protocol_version == 3:
                from ecdsa_utils import verify_signature, verify_opcode_signature_v3
                if self.session_state != BLESessionState.AUTHENTICATED:
                    if len(data) < 6 + 8:  # 6 bytes MDID + minimal DER signature
                        logger.warning(f"[PROTOCOL V3] Data too short for MDID+signature. Got {len(data)} bytes.")
                        data_to_send = opsky.set_response_data_v3(response_type=opsky.Opcodes.ERROR_RESPONSE,
                                                                  opcode=opsky.Opcodes(opcode),
                                                                  data=data,
                                                                  error_code=opsky.SpecificErrorCodes.COMMAND_NOT_SUPPORTED)
                        if data_to_send:
                            logger.info(f"[BLE TX] Signed v3 short data error: {[f'0x{b:02X}' for b in data_to_send]}")
                            self.machine_to_mobile_msg_char_indication(bytes(data_to_send))
                        return
                    mdid = bytes(data[:6])
                    signature = bytes(data[6:])  # Convert signature list to bytes
                    if verify_signature(mdid, signature):
                        self.session_state = BLESessionState.AUTHENTICATED
                        self.authenticated_mdid = mdid  # Store for future commands
                        logger.info(f"[PROTOCOL V3] MDID {mdid.hex().upper()} signature verified. User authenticated!")
                        # V3 Protocol: No automatic response sent for auth success
                        self.service_state = AuthState.USER_AUTHENTICATED
                        # Publish authenticated status to ZMQ immediately
                        try:
                            device_path = self.connected_device_path if self.connected_device_path else "unknown"
                            import json
                            auth_msg = json.dumps({"status": "authenticated", "device": device_path})
                            self.pub_socket.send_string(f"BleStatus {auth_msg}")
                            logger.info(f"Published BLE status: {auth_msg}")
                        except Exception as e:
                            logger.error(f"Failed to publish authenticated status to ZMQ: {e}")

                        # Publish authenticated MDID to CAN service
                        mdid_hex = mdid.hex().upper()
                        self.publish_mdid_to_can(mdid_hex)
                    else:
                        logger.warning(f"[PROTOCOL V3] Signature verification failed for MDID {mdid.hex().upper()}")
                        data_to_send = opsky.set_response_data_v3(response_type=opsky.Opcodes.ERROR_RESPONSE,
                                                                  opcode=opsky.Opcodes(opcode),
                                                                  data=data,
                                                                  error_code=opsky.SpecificErrorCodes.COMMAND_NOT_SUPPORTED)
                        logger.info(f"[BLE TX] Signed v3 error response: {' '.join(f'{b:02X}' for b in data_to_send)}")
                        self.machine_to_mobile_msg_char_indication(bytes(data_to_send))
                        # TODO: Add unsolicited event for failed signature verification (like Protocol v2)
                        # This would improve error handling consistency between protocols
                        if self.connection_monitor and self.connected_device_path:
                            logger.info("Disconnecting BLE device due to failed signature verification.")
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connected_device_path))
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
                                        self.forward_command_to_can(opcode, payload)
                                        # V3 Protocol: Send PENDING response, SUCCESS will come from CAN listener
                                        data_to_send = opsky.set_response_data_v3(response_type=opsky.Opcodes.PENDING_RESPONSE,
                                                                                  opcode=opsky.Opcodes(opcode),
                                                                                  data=payload)
                                        if data_to_send:
                                            logger.info(f"[BLE TX] Signed v3 PENDING response: {[f'0x{b:02X}' for b in data_to_send]}")
                                            self.machine_to_mobile_msg_char_indication(bytes(data_to_send))
                                        logger.info(f"[PROTOCOL V3] PENDING response sent, waiting for CAN response")
                                        return
                                    else:
                                        logger.warning(f"[PROTOCOL V3] Opcode signature verification failed for MDID {self.authenticated_mdid.hex().upper()}.")
                                        # TODO: Consider sending ERROR response before disconnect for better debugging
                                        # Current silent behavior prioritizes security but makes debugging harder
                                        # Note: No response sent - just disconnect on signature failure
                                        if self.connection_monitor and self.connected_device_path:
                                            logger.info("Disconnecting BLE device due to failed opcode signature.")
                                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connected_device_path))
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
                        self.forward_command_to_can(opcode, payload)
                        # V3 Protocol: Send PENDING response, SUCCESS will come from CAN listener
                        data_to_send = opsky.set_response_data_v3(response_type=opsky.Opcodes.PENDING_RESPONSE,
                                                                  opcode=opsky.Opcodes(opcode),
                                                                  data=payload)
                        if data_to_send:
                            logger.info(f"[BLE TX] Signed v3 PENDING response: {[f'0x{b:02X}' for b in data_to_send]}")
                            self.machine_to_mobile_msg_char_indication(bytes(data_to_send))
                        logger.info(f"[PROTOCOL V3] PENDING response sent, waiting for CAN response")
                    else:
                        logger.warning(f"[PROTOCOL V3] Opcode signature verification failed for MDID {self.authenticated_mdid.hex().upper()}.")
                        # TODO: Consider sending ERROR response before disconnect for better debugging
                        # Current silent behavior prioritizes security but makes debugging harder
                        # Note: No response sent - just disconnect on signature failure
                        if self.connection_monitor and self.connected_device_path:
                            logger.info("Disconnecting BLE device due to failed opcode signature.")
                            asyncio.create_task(self.connection_monitor.disconnect_device(self.connected_device_path))
                    return
            else:
                logger.warning(f"Unknown protocol version: {self.protocol_version}")
        except Exception as e:
            logger.error(f"Error in _opsky_command_handler: {e}")

    async def _mdid_provision_timeout_handler(self):
        """
        When called, this task is created and waits for a timeout of 5 seconds waiting for a MDID to be set after
        protocol negotiation. Disconnects upon timeout.
        """
        try:
            logger.info("🚀 MDID Provision/Authentication Timeout task has been launched")
            self.session_state = BLESessionState.WAITING_FOR_MDID
            await asyncio.sleep(self.mdid_provision_timeout_in_seconds)

            if self.session_state in [BLESessionState.IDLE_DISCONNECTED,
                                      BLESessionState.BLE_LINK_ESTABLISHED,
                                      BLESessionState.PROTOCOL_VERIFIED,
                                      BLESessionState.WAITING_FOR_MDID,
                                      BLESessionState.AUTH_CHALLENGE_SENT]:
                logger.info("MDID not provided/authenticated in time, sending timeout notification and disconnecting.")

                data_to_send = opsky.set_unsolicited_notification_data(
                                    notification_type=opsky.Opcodes.UNSOLICITED_EVENT_NOTIFICATION,
                                    event=opsky.SpecificUnsolicitedEventCodes.MDID_WAIT_TIMEOUT)

                if data_to_send:
                    self.machine_to_mobile_msg_char_indication(bytes(data_to_send))

                self.session_state = BLESessionState.TIMEOUT

                if self.connection_monitor is None:
                    logger.warning("No connection monitor or connected device to disconnect.")
                    return

                logger.info("Disconnecting BLE device due to MDID provision/authentication timeout.")
                await self.connection_monitor.disconnect_device(self.connected_device_path)

        except asyncio.CancelledError:
            logger.info(f"❌ MDID Provision/Authentication Timeout task was cancelled!")
        except Exception as e:
            logger.error(f"Coroutine '_mdid_provision_timeout_handler' had an exception: {e}")
        finally:
            logger.info(f"💀 MDID Provision/Authentication Timeout task has ended")

    def publish_mdid_to_can(self, mdid_hex: str):
        """
        Publish MDID to CAN service via OpskyState topic.

        Args:
            mdid_hex: MDID as hex string (e.g., "FF0000000001" or "FFFFFFFFFFFF")
        """
        try:
            msg = f"OpskyState MDID_{mdid_hex}"
            self.pub_socket.send_string(msg)
            logger.info(f"[MDID] Published to CAN: {msg}")
        except Exception as e:
            logger.error(f"[MDID] Error publishing to CAN: {e}")

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

    def on_ble_connected(self, device_path: str = None) -> None:
        """
        BLE connection event handler. Updates state and stores device path.
        """
        logger.info(f"🔗 BLE Link established with device '{device_path}'")
        self.session_state = BLESessionState.BLE_LINK_ESTABLISHED
        self.connected_device_path = device_path
        self._mdid_provision_timeout_task = asyncio.create_task(self._mdid_provision_timeout_handler())

    def on_ble_disconnected(self, device_path: str = None) -> None:
        """
        BLE disconnection event handler. Resets session state and clears sensitive data.
        """
        logger.info("⛓️‍💥 BLE Link has been broken")
        self.session_state = BLESessionState.IDLE_DISCONNECTED
        self.challenge = None
        self.mdid = None
        self.connected_device_path = None

        if self._mdid_provision_timeout_task:
            self._mdid_provision_timeout_task.cancel()

    def forward_command_to_can(self, opcode: int, payload: Optional[List[int]] = None) -> None:
        """
        Forwards verified BLE command to CAN system via ZMQ.
        Uses the same format as Protocol v2: "BleToCan {json_payload}"

        Parameters
        ----------
        opcode: int - The Opsky Opcode value to be sent.

        payload: Optional list - List of bytes to support the opcode message.

        Returns
        -------
        None
        """
        try:
            # Create CAN forwarding message using the established Protocol v2 pattern
            can_data = list(opcode.to_bytes(2, byteorder=BYTEORDER))
            if payload:
                can_data.extend(list(payload))

            json_payload = json.dumps({"BleToCan": can_data})
            msg = f"BleToCan {json_payload}"
            self.pub_socket.send_string(msg)

            logger.info(f"[OPSKY_BLE]: Command forwarded to CAN task: {msg}")
        except Exception as e:
            logger.error(f"[CAN FORWARD] Failed to forward command {opcode:04X}: {e}")

    def machine_to_mobile_msg_char_indication(self, new_value: bytes) -> None:
        """
        BLE GATT method for sending indications.

        Parameters
        ----------
        new_value: bytes - Raw bytes to be sent.

        Returns
        -------
        None
        """
        try:
            self._machine_to_mobile_msg_value = new_value
            logger.info(f"[BLE TX] Sending notification data: {[f'0x{b:02X}' for b in new_value]}")
            self.machine_to_mobile_msg_characteristic.changed(self._machine_to_mobile_msg_value)
        except Exception as e:
            logger.error(f"Error in machine_to_mobile_msg_char_indication: {e}")

    async def request_uwb_config(self) -> Optional[bytes]:
        """
        Request UWB configuration data from UWB service for iPhone handshake.
        Returns config data as bytes or None if failed.
        """
        try:
            import uuid
            import asyncio
            import time
            
            # Generate unique request ID
            request_id = str(uuid.uuid4())[:8]
            
            # Send config request via ZMQ
            payload = json.dumps({"request_id": request_id})
            msg = f"uwbConfig {payload}"
            
            self.pub_socket.send_string(msg)
            logger.info(f"[UWB CONFIG] Request sent: {request_id}")
            
            # Subscribe to config responses
            config_sub = self.ctx.socket(zmq.SUB)
            config_sub.connect(XPUB_ADDR)  # Connect to XPUB for receiving responses
            config_sub.setsockopt_string(zmq.SUBSCRIBE, "uwbConfigResp")
            config_sub.setsockopt(zmq.LINGER, 0)
            
            # Wait for response with timeout
            start_time = time.time()
            timeout = 10.0  # 10 second timeout
            
            while time.time() - start_time < timeout:
                try:
                    # Check for response (non-blocking with proper async handling)
                    try:
                        msg = await asyncio.wait_for(config_sub.recv_string(), timeout=0.1)
                        topic, payload = msg.split(" ", 1)
                        
                        if topic == "uwbConfigResp":
                            response = json.loads(payload)
                            if response.get("request_id") == request_id:
                                config_sub.close()
                                
                                if response.get("status") == "success":
                                    config_hex = response.get("config_data")
                                    if config_hex:
                                        logger.info(f"[UWB CONFIG] ✅ Config received: {len(config_hex)//2} bytes")
                                        return bytes.fromhex(config_hex)
                                    else:
                                        logger.error("[UWB CONFIG] ❌ Empty config data")
                                        return None
                                else:
                                    logger.error(f"[UWB CONFIG] ❌ Request failed: {response.get('status', 'unknown')}")
                                    return None
                                
                    except asyncio.TimeoutError:
                        # No message available, continue waiting
                        pass
                        
                except Exception as e:
                    logger.error(f"[UWB CONFIG] Error in message receive loop: {e}")
                    
                await asyncio.sleep(0.1)
            
            config_sub.close()
            logger.error("[UWB CONFIG] Timeout waiting for config response")
            return None
            
        except Exception as e:
            logger.error(f"[UWB CONFIG] Error requesting config: {e}")
            import traceback
            traceback.print_exc()
            return None

    async def handle_iphone_init_request(self) -> bool:
        """
        Handle iPhone Init (0x0A) request - get UWB config and send to iPhone.
        Returns True if successful, False otherwise.
        """
        try:
            logger.info("[IPHONE INIT] Processing iPhone init request (0x0A)")
            
            # Request UWB configuration from UWB service
            config_data = await self.request_uwb_config()
            
            if config_data:
                # Format response as AccessoryConfigurationData (0x01)
                response = bytearray()
                response.append(0x01)  # Message ID: accessoryConfigurationData
                response.append(1)     # majorVersion
                response.append(0)     # minorVersion  
                response.append(20)    # preferredUpdateRate
                response.append(len(config_data))  # uwbConfigDataLength
                response.extend(config_data)       # uwbConfigData
                
                # Send response via UWB notification characteristic
                self.send_custom_notification(bytes(response))
                logger.info(f"[IPHONE INIT] Sent config data ({len(config_data)} bytes) to iPhone")
                return True
            else:
                logger.error("[IPHONE INIT] Failed to get UWB config data")
                return False
                
        except Exception as e:
            logger.error(f"[IPHONE INIT] Error handling init request: {e}")
            return False
