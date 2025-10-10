import logging
# Global configuration
SEND_INTERVAL   = 1.0  # seconds
PGN_VALUE       = 0x00EF
SOURCE_ADDRESS  = 0xDC
DEST_ADDRESS    = 0xFF #0x19
PRIORITY        = 6
OPCODE_NFC_ID   = 0x0018

import zmq
import zmq.asyncio

# Refactored to match can_service.py async structure
import asyncio
import can
import j1939
import random
import time
import json

can_message_queue = asyncio.Queue()
can_pub_queue = asyncio.Queue()
ble_to_can_queue = asyncio.Queue()  # <-- Added queue for BLE-to-CAN messages

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("can_j1939_service")

class CANModule:
    def __init__(self, loop=None, send_interval=SEND_INTERVAL, pgn=PGN_VALUE, source_address=SOURCE_ADDRESS, dest_address=DEST_ADDRESS):
        self.ecu = None
        self.ca = None
        self.nfc_data = None
        self.nfc_data_pending = False
        self.ble_status = None  # <-- Add class-level variable for BLE status
        self.send_interval = send_interval
        self.pgn = pgn
        self.source_address = source_address
        self.dest_address = dest_address
        self.loop = loop or asyncio.get_event_loop()
        self.ctx = zmq.asyncio.Context.instance()
        self.sub_socket = self.ctx.socket(zmq.SUB)
        self.pub_socket = self.ctx.socket(zmq.PUB)
        from zmqhub import XPUB_ADDR
        from zmqhub import XSUB_ADDR
        self.sub_socket.connect(XPUB_ADDR)
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, "nfc_data")
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, "bleToCan")
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, "bleStatus")  # <-- Subscribe to BLE status
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, "opskyState")
        self.sub_socket.setsockopt(zmq.LINGER, 0)
        self.pub_socket.connect(XSUB_ADDR)
        self.pub_socket.setsockopt(zmq.LINGER, 0)
        self.PAAK_State = False # false = disabled, true = enabled
        self.work_zone  = 0  # 0 = no zone, 1 = welcome zone, 2 = access zone

    def handle_can_opcode(self, filtered_data):
        """
        Checks the opcode in filtered_data.
        If a CAN-only response is needed, prepares the response and puts it on ble_to_can_queue.
        Returns False if handled (do not forward to BLE), True otherwise.
        """
        if len(filtered_data) >= 2:
            opcode = (filtered_data[0] << 8) | filtered_data[1]
            CAN_ONLY_OPCODES = [0x0204, 0x0202]  # Replace with your actual opcodes

            if opcode in CAN_ONLY_OPCODES:
                can_data = []
                # Prepare CAN response data
                if opcode == 0x0204:    #get the work zone - no zone, welcome zone, access zone
                    can_data = [0x02, 0x04, 0x00, self.work_zone]  # sending no zone by default

                if opcode == 0x0202:    #get the PAAK state - enabled or disabled
                    paak_state_byte = 0x00 if self.PAAK_State else 0x01
                    can_data = [0x02, 0x02, 0x00, paak_state_byte]  # sending disabled by default

                can_payload = json.dumps({"CanOnlyResponse": can_data})
                self.loop.call_soon_threadsafe(ble_to_can_queue.put_nowait, can_payload)
                logger.info(f"CAN-only opcode {hex(opcode)} handled, response queued.")
                return False  # Already handled, do not forward to BLE

        return True  # Not handled, forward to BLE

    async def opsky_state_send(self, payload):
        try:
            # Accepts payload in the format: 'opskyState OPSKY_PAAK_ENABLED'
            if isinstance(payload, str) and payload.startswith("opskyState "):
                state = payload[len("opskyState "):].strip()
            else:
                # fallback: try to parse as JSON or use as is
                try:
                    data = json.loads(payload)
                    state = data.get("state") if isinstance(data, dict) else str(data)

                except Exception:
                    state = str(payload)

            if state == "OPSKY_PAAK_ENABLED":
                logger.info("Handling opskyState: ENABLED")
                can_data = [0x02, 0x00]
                self.PAAK_State = True
            elif state == "OPSKY_PAAK_DISABLED":
                logger.info("Handling opskyState: DISABLED")
                can_data = [0x02, 0x01]
                self.PAAK_State = False
            elif state == "NO_ZONE":
                logger.info("Handling opskyState: NO_ZONE")
                can_data = [0x02, 0x03, 0x00, 0x00]
            elif state == "WELCOME_ZONE":
                logger.info("Handling opskyState: WELCOME_ZONE")
                can_data = [0x02, 0x03, 0x00, 0x01]
            elif state == "ACCESS_ZONE":
                logger.info("Handling opskyState: ACCESS_ZONE")
                can_data = [0x02, 0x03, 0x00, 0x02]
            else:
                logger.info(f"Handling opskyState: Unknown state {state}")
                can_data = []

        except Exception as e:
            logger.error(f"Error in opsky_state_send: {e}")
            can_data = []

        #logger.info(f"opsky_state_send - {state}")
        if can_data:
            can_payload = json.dumps({"OpSkyStateToCan": can_data})
            await ble_to_can_queue.put(can_payload)

    async def listen_sub_data(self):
        logger.info("[NFC ZMQ] Listening for subscribed topics...")
        while True:
            try:
                msg = await self.sub_socket.recv_string()
                logger.info(f"[NFC ZMQ] Received: {msg}")
                try:
                    topic, payload = msg.split(" ", 1)
                    if topic == "nfc_data":
                        self.nfc_data = payload
                        self.nfc_data_pending = True

                    if topic == "bleToCan":
                        logger.info("Received data over bleToCan topic")
                        await ble_to_can_queue.put(payload)

                    if topic == "bleStatus":
                        logger.info(f"BLE status update: {payload}")
                        try:
                            status_obj = json.loads(payload)
                            if status_obj.get("status") == "connected":
                                self.ble_status = True
                            else:
                                self.ble_status = False
                        except Exception as e:
                            logger.error(f"Failed to parse BLE status JSON: {e}")
                            self.ble_status = False

                    if topic == "opskyState":
                        logger.info(f"Received opskyState: {payload}")
                        await self.opsky_state_send(payload)

                except Exception as e:
                    logger.error(f"[NFC ZMQ] Error parsing message: {e}")
            except Exception as e:
                logger.error(f"[NFC ZMQ] Error receiving message: {e}")
                await asyncio.sleep(0.5)

    async def pub_worker(self):
        while True:
            msg = await can_pub_queue.get()
            try:
                self.pub_socket.send_string(msg)
                logger.info("[CanToBle PUB] Published: %s", msg)
            except Exception as e:
                logger.error(f"[CanToBle PUB] Error publishing: {e}")
                await asyncio.sleep(0.5)

    async def init_j1939(self, can_channel='can0', bustype='socketcan'):
        logger.info("Initializing J1939 CAN bus...")
        try:
            name = j1939.Name(
                arbitrary_address_capable=1,
                industry_group=j1939.Name.IndustryGroup.Industrial,
                vehicle_system_instance=1,
                vehicle_system=1,
                function=1,
                function_instance=1,
                ecu_instance=1,
                manufacturer_code=666,
                identity_number=1234567
            )
            self.ca = j1939.ControllerApplication(name, self.source_address)
            self.ecu = j1939.ElectronicControlUnit()
            self.ecu.connect(bustype=bustype, channel=can_channel)
            self.ecu.add_ca(controller_application=self.ca)
            self.ca.subscribe(self.on_message_received)
            self.ca.start()
            logger.info("J1939: Address claiming started...")
            await asyncio.sleep(2)
            logger.info("J1939: Initialization complete.")
        except Exception as e:
            logger.error(f"[CAN ERROR] Error during J1939 initialization: {e}")
            self.ca = None
            self.ecu = None

    def on_message_received(self, priority, pgn, source, timestamp, data):
        logger.info(f"[J1939 RX] PGN: {hex(pgn)} Source: {hex(source)} Data: {data.hex()}")

        if len(data) >= 2 and data[0] == 0xFF and data[1] == 0xF2 and data[2] == 0x00:
            filtered_data = data[2:]
            # Call your handler
            if not self.handle_can_opcode(filtered_data):
                return  # Already handled, do not forward to BLE

            # If not handled, forward to BLE as before
            import json
            payload = json.dumps({"data": list(filtered_data)})
            msg = f"canToBle {payload}"
            try:
                self.loop.call_soon_threadsafe(can_pub_queue.put_nowait, msg)
            except Exception as e:
                logger.error(f"[CanToBle PUB] Error queueing for publish: {e}")

    def convert_to_hex_bytes(self, str_uid):
        # Pad to 12 hex chars (6 bytes)
        str_uid = str_uid.zfill(12)
        logger.info(f"[J1939 TX] convert_to_hex_bytes 1 : {str_uid}")
        try:
            hex_uid = list(bytes.fromhex(str_uid)[-6:])
        except Exception:
            hex_uid = [0xFE, 0x00, 0x00, 0x00, 0x00, 0x01]

        return hex_uid

    async def send_message(self):
        while True:
            try:
                if self.ca is None:
                    logger.warning("[J1939] ControllerApplication not initialized. Attempting re-init...")
                    await self.init_j1939()
                    await asyncio.sleep(2)
                    continue
                while self.ca.state != j1939.ControllerApplication.State.NORMAL:
                    logger.info("Waiting for CA to claim address...")
                    await asyncio.sleep(1)
                pgn = self.pgn

                # NFC data sending (preserves cyclicity, not queued)
                if self.nfc_data_pending and self.nfc_data:
                    try:
                        import json
                        nfc_payload = json.loads(self.nfc_data)
                        data_bytes = b''
                        if isinstance(nfc_payload, dict) and 'user_id' in nfc_payload:
                            user_id = nfc_payload['user_id']
                            hex_user_id = self.convert_to_hex_bytes(user_id)
                            logger.info(f"[J1939 TX] Data bytes : {hex_user_id}")
                        else:
                            logger.error("[J1939 TX] No valid user_id in NFC payload.")
                            hex_user_id = [0xFF] * 6
                    except Exception as e:
                        logger.error(f"[J1939 TX] Exception: {e}")
                        hex_user_id = [0xFF] * 6

                    CAN_Tx_data = bytearray(b'\xFF' * 10)
                    CAN_Tx_data[0] = 0xFF
                    CAN_Tx_data[1] = 0xF1
                    CAN_Tx_data[2] = 0x00
                    CAN_Tx_data[3] = ((OPCODE_NFC_ID >> 8) & 0xFF)
                    CAN_Tx_data[4] = (OPCODE_NFC_ID & 0xFF)
                    #CAN_Tx_data[4:10] = data_bytes[:6] + b'\xFF' * (6 - min(len(data_bytes), 6))
                    CAN_Tx_data[5:11] = bytes(hex_user_id)

                    logger.info(f"[J1939 TX] Sending NFC data: {CAN_Tx_data}")
                    self.ca.send_pgn(PRIORITY, pgn, DEST_ADDRESS, SOURCE_ADDRESS, list(CAN_Tx_data))
                    self.nfc_data_pending = False  # Only send once per new NFC data

                # BLE-to-CAN data sending (queue-based, no loss)
                try:
                    ble_payload = await asyncio.wait_for(ble_to_can_queue.get(), timeout=0.01)
                    import json
                    bleToCan_payload = json.loads(ble_payload)
                    if isinstance(bleToCan_payload, dict):
                        if 'BleToCan' in bleToCan_payload:
                            data_bytes = bytes(bleToCan_payload['BleToCan'])
                            logger.info(f'[J1939 TX] BleToCan databytes: {data_bytes}')
                        elif 'OpSkyStateToCan' in bleToCan_payload:
                            data_bytes = bytes(bleToCan_payload['OpSkyStateToCan'])
                            logger.info(f'[J1939 TX] OpSkyStateToCan databytes: {data_bytes}')
                        elif 'CanOnlyResponse' in bleToCan_payload:
                            data_bytes = bytes(bleToCan_payload['CanOnlyResponse'])
                            logger.info(f'[J1939 TX] CanOnlyResponse databytes: {data_bytes}')
                        else:
                            data_bytes = ble_payload.encode()
                    else:
                        data_bytes = ble_payload.encode()

                    if len(data_bytes) <= 5:
                        logger.info(f"[J1939 TX] if - databytes: {data_bytes}")
                        CAN_Tx_data_buf2 = bytearray(b'\xFF' * 8)
                        CAN_Tx_data_buf2[0] = 0xFF
                        CAN_Tx_data_buf2[1] = 0xF1
                        CAN_Tx_data_buf2[2] = 0x00
                        for i in range(len(data_bytes)):
                            CAN_Tx_data_buf2[3+i] = data_bytes[i]
                    else:
                        logger.info(f"[J1939 TX] else - databytes: {data_bytes}")
                        CAN_Tx_data_buf2 = bytearray(b'\xFF' * (3 + len(data_bytes)))
                        CAN_Tx_data_buf2[0] = 0xFF
                        CAN_Tx_data_buf2[1] = 0xF1
                        CAN_Tx_data_buf2[2] = 0x00
                        for i in range(len(data_bytes)):
                            CAN_Tx_data_buf2[3+i] = data_bytes[i]

                    logger.info(f"[J1939 TX] Sending BleToCan data: {CAN_Tx_data_buf2}")
                    self.ca.send_pgn(PRIORITY, pgn, DEST_ADDRESS, SOURCE_ADDRESS, list(CAN_Tx_data_buf2))
                except asyncio.TimeoutError:
                    pass  # No BLE-to-CAN message this cycle

            except Exception as e:
                logger.error(f"[CAN ERROR] {e}. Re-initializing J1939...")
                self.ca = None
                self.ecu = None
            await asyncio.sleep(0.01)  # Fast loop for BLE-to-CAN, does not affect NFC cyclicity

    async def listen_async(self):
        # Optionally process messages from queue
        while True:
            await asyncio.sleep(1)

    async def start(self):
        try:
            await self.init_j1939()
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger.info("CAN: Exiting CAN Module...")
            await self.shutdown()

    async def shutdown(self):
        if self.ca:
            self.ca.stop()
        if self.ecu:
            self.ecu.disconnect()
        self.sub_socket.close()
        self.pub_socket.close()
        logger.info("CAN: Service Shutdown....")


async def main():
    loop = asyncio.get_event_loop()
    can_module = CANModule(loop=loop, send_interval=SEND_INTERVAL, pgn=PGN_VALUE, source_address=SOURCE_ADDRESS, dest_address=DEST_ADDRESS)
    can_task = asyncio.create_task(can_module.start())
    can_receive_task = asyncio.create_task(can_module.listen_async())
    can_send_task = asyncio.create_task(can_module.send_message())
    sub_task = asyncio.create_task(can_module.listen_sub_data())
    pub_task = asyncio.create_task(can_module.pub_worker())
    await asyncio.gather(can_task, can_receive_task, can_send_task, sub_task, pub_task)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Exiting...")
