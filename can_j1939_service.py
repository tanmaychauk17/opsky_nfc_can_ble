import logging
# Global configuration
SEND_INTERVAL   = 1.0  # seconds
PGN_VALUE       = 0x00EF
SOURCE_ADDRESS  = 0xDC
DEST_ADDRESS    = 0x19
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
        self.sub_socket.setsockopt(zmq.LINGER, 0)
        self.pub_socket.connect(XSUB_ADDR)
        self.pub_socket.setsockopt(zmq.LINGER, 0)

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
                    '''
                    else:
                        logger.warning(f"[NFC ZMQ] Unexpected topic: {topic}")
                    '''
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
        # Always print/log the received message
        logger.info(f"[J1939 RX] PGN: {hex(pgn)} Source: {hex(source)} Data: {data.hex()}")

        # Only push to pub queue if BLE is connected and data has FF F2 prefix
        if (
            #self.ble_status and
            len(data) >= 2 and
            data[0] == 0xFF and data[1] == 0xF2
        ):
            filtered_data = data[2:]
            import json
            payload = json.dumps({"data": list(filtered_data)})
            msg = f"canToBle {payload}"
            try:
                self.loop.call_soon_threadsafe(can_pub_queue.put_nowait, msg)
            except Exception as e:
                logger.error(f"[CanToBle PUB] Error queueing for publish: {e}")

    '''
    def convert_to_hex_bytes(self, str_uid):
        # Ensure input is string
        if isinstance(str_uid, bytes):
            str_uid = str_uid.decode('ascii')
        hardcoded_map = {
            "FE0000000001": [0xFE, 0x00, 0x00, 0x00, 0x00, 0x01],
            "FE0000000002": [0xFE, 0x00, 0x00, 0x00, 0x00, 0x02],
            "FE0000000003": [0xFE, 0x00, 0x00, 0x00, 0x00, 0x03],
            "FE0000000004": [0xFE, 0x00, 0x00, 0x00, 0x00, 0x04],
            "FE0000000005": [0xFE, 0x00, 0x00, 0x00, 0x00, 0x05],
            "FE0000000006": [0xFE, 0x00, 0x00, 0x00, 0x00, 0x06],
        }
        return hardcoded_map.get(str_uid, [0xFF] * 6)


    def convert_to_hex_bytes(self,str_uid):
        hex_uid = [0xFE, 0x00, 0x00, 0x00, 0x00, 0x01]
        str_uid = str_uid.decode('utf-8')

        if(str_uid == "FE0000000001"):
            hex_uid = [0xFE, 0x00, 0x00, 0x00, 0x00, 0x01]
        elif(str_uid == "FE0000000002"):
            hex_uid = [0xFE, 0x00, 0x00, 0x00, 0x00, 0x02]
        elif(str_uid == "FE0000000003"):
            hex_uid = [0xFE, 0x00, 0x00, 0x00, 0x00, 0x03]
        elif(str_uid == "FE0000000004"):
            hex_uid = [0xFE, 0x00, 0x00, 0x00, 0x00, 0x04]
        
        return hex_uid
    '''

    def convert_to_hex_bytes(self, str_uid):
        # Ensure input is string
        if isinstance(str_uid, bytes):
            str_uid = str_uid.decode('ascii')
        # Pad to 12 hex chars (6 bytes)
        str_uid = str_uid.zfill(12)
        try:
            hex_uid = list(bytes.fromhex(str_uid)[-6:])
        except Exception:
            hex_uid = [0xFF] * 6

        hex_data = 0
        hex_data = ((hex_uid[0] << 4) & 0xF0 | (hex_uid[1] >> 4) & 0x0F)
        logger.info(f"[J1939 TX] convert_to_hex_bytes {hex_data}")

        hex_uid[0] = hex_data
        hex_uid[1] = 0x00

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
                    CAN_Tx_data[2] = ((OPCODE_NFC_ID >> 8) & 0xFF)
                    CAN_Tx_data[3] = (OPCODE_NFC_ID & 0xFF)
                    #CAN_Tx_data[4:10] = data_bytes[:6] + b'\xFF' * (6 - min(len(data_bytes), 6))
                    CAN_Tx_data[4:10] = bytes(hex_user_id)

                    logger.info(f"[J1939 TX] Sending NFC data: {CAN_Tx_data}")
                    self.ca.send_pgn(PRIORITY, pgn, DEST_ADDRESS, SOURCE_ADDRESS, list(CAN_Tx_data))
                    self.nfc_data_pending = False  # Only send once per new NFC data

                # BLE-to-CAN data sending (queue-based, no loss)
                try:
                    ble_payload = await asyncio.wait_for(ble_to_can_queue.get(), timeout=0.01)
                    import json
                    bleToCan_payload = json.loads(ble_payload)
                    if isinstance(bleToCan_payload, dict) and 'BleToCan' in bleToCan_payload:
                        data_bytes = bytes(bleToCan_payload['BleToCan'])
                    else:
                        data_bytes = ble_payload.encode()

                    if len(data_bytes) <= 6:
                        CAN_Tx_data = bytearray(b'\xFF' * 8)
                        CAN_Tx_data[0] = 0xFF
                        CAN_Tx_data[1] = 0xF1
                        CAN_Tx_data[2:2+len(data_bytes)] = data_bytes
                    else:
                        CAN_Tx_data = bytearray(b'\xFF' * (2 + len(data_bytes)))
                        CAN_Tx_data[0] = 0xFF
                        CAN_Tx_data[1] = 0xF1
                        CAN_Tx_data[2:2+len(data_bytes)] = data_bytes

                    logger.info(f"[J1939 TX] Sending BleToCan data: {CAN_Tx_data}")
                    self.ca.send_pgn(PRIORITY, pgn, DEST_ADDRESS, SOURCE_ADDRESS, list(CAN_Tx_data))
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