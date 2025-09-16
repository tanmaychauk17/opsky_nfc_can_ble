import logging
# Global configuration
SEND_INTERVAL   = 1.0  # seconds
PGN_VALUE       = 0x00DC
SOURCE_ADDRESS  = 0xDC
DEST_ADDRESS    = 0xFF
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
        self.sub_socket.setsockopt(zmq.LINGER, 0)
        self.pub_socket.connect(XSUB_ADDR)
        self.pub_socket.setsockopt(zmq.LINGER, 0)

    async def listen_sub_data(self):
        logger.info("[NFC ZMQ] Listening for NFC data...")
        while True:
            try:
                msg = await self.sub_socket.recv_string()
                logger.info(f"[NFC ZMQ] Received: {msg}")
                try:
                    topic, payload = msg.split(" ", 1)
                    if topic == "nfc_data":
                        self.nfc_data = payload
                        self.nfc_data_pending = True  # Only the latest NFC data is kept, preserving cyclicity
                    elif topic == "bleToCan":
                        logger.info("Received data over bleToCan topic")
                        await ble_to_can_queue.put(payload)  # Queue every BLE-to-CAN message
                    else:
                        logger.warning(f"[NFC ZMQ] Unexpected topic: {topic}")
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
        import json
        payload = json.dumps({"data": list(data)})
        msg = f"canToBle {payload}"
        try:
            self.loop.call_soon_threadsafe(can_pub_queue.put_nowait, msg)
        except Exception as e:
            logger.error(f"[CanToBle PUB] Error queueing for publish: {e}")

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
                        if isinstance(nfc_payload, dict) and 'data' in nfc_payload:
                            data_bytes = bytes(nfc_payload['data'])
                        else:
                            data_bytes = self.nfc_data.encode()
                    except Exception:
                        data_bytes = self.nfc_data.encode()

                    CAN_Tx_data = bytearray(b'\xFF' * 8)
                    CAN_Tx_data[0] = ((OPCODE_NFC_ID >> 8) & 0xFF)
                    CAN_Tx_data[1] = (OPCODE_NFC_ID & 0xFF)
                    CAN_Tx_data[2:8] = data_bytes[:6] + b'\xFF' * (6 - min(len(data_bytes), 6))

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

                    CAN_Tx_data = bytearray(b'\xFF' * 8)
                    CAN_Tx_data[0:len(data_bytes)] = data_bytes

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