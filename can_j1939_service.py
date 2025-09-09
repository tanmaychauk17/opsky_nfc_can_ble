
# Global configuration
SEND_INTERVAL   = 1.0  # seconds
PGN_VALUE       = 0x00DC
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

class CANModule:
    def __init__(self, loop=None, send_interval=SEND_INTERVAL, pgn=PGN_VALUE, source_address=SOURCE_ADDRESS, dest_address=DEST_ADDRESS):
        self.ecu = None
        self.ca = None
        self.nfc_data_available = False
        self.nfc_data = None
        self.nfc_data_pending = False
        self.send_interval = send_interval  # CAN send interval in seconds
        self.pgn = pgn  # Configurable PGN
        self.source_address = source_address  # Configurable source address
        self.dest_address = dest_address      # Configurable destination address
        self.loop = loop or asyncio.get_event_loop()
        # ZeroMQ async context and subscriber for NFC data
        self.ctx = zmq.asyncio.Context.instance()
        self.sub_socket = self.ctx.socket(zmq.SUB)
        from zmqhub import XPUB_ADDR
        self.sub_socket.connect(XPUB_ADDR)
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, "nfc_data")
        self.sub_socket.setsockopt(zmq.LINGER, 0)

    async def listen_nfc_data(self):
        print("[NFC ZMQ] Listening for NFC data...")
        while True:
            msg = await self.sub_socket.recv_string()
            print(f"[NFC ZMQ] Received: {msg}")
            try:
                topic, payload = msg.split(" ", 1)
                if topic != "nfc_data":
                    print(f"[NFC ZMQ] Unexpected topic: {topic}")
                    continue
                self.nfc_data = payload  # Store latest NFC data (raw string or JSON)
                self.nfc_data_pending = True  # Mark as pending to send
            except Exception as e:
                print(f"[NFC ZMQ] Error parsing message: {e}")
                continue

    async def init_j1939(self, can_channel='can0', bustype='socketcan'):
        print("Initializing J1939 CAN bus...")
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
            print("J1939: Address claiming started...")
            await asyncio.sleep(2)
            print("J1939: Initialization complete.")
        except Exception as e:
            print(f"[CAN ERROR] Error during J1939 initialization: {e}")
            self.ca = None
            self.ecu = None

    def on_message_received(self, priority, pgn, source, timestamp, data):
        print(f"[J1939 RX] PGN: {hex(pgn)} Source: {hex(source)} Data: {data.hex()}")
        # Optionally, put message in queue for async processing
        # await can_message_queue.put((priority, pgn, source, timestamp, data))

    async def send_message(self):
        # **** Uncomment the following lines to enable backoff on repeated CAN send failures: ****
        # error_count = 0
        # backoff_time = self.send_interval
        while True:
            try:
                # Wait until CA is in NORMAL state (address claimed)
                if self.ca is None:
                    print("[J1939] ControllerApplication not initialized. Attempting re-init...")
                    await self.init_j1939()
                    await asyncio.sleep(2)
                    # error_count = 0  # Reset error count on re-init
                    continue
                while self.ca.state != j1939.ControllerApplication.State.NORMAL:
                    print("Waiting for CA to claim address...")
                    await asyncio.sleep(1)
                pgn = self.pgn
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

                    # CAN tx data  = OPCODE FOR NFC (0x0018) + 6 bytes of NFC data
                    CAN_Tx_data = bytearray(8)
                    CAN_Tx_data[0] = ((OPCODE_NFC_ID >> 8) & 0xFF)
                    CAN_Tx_data[1] = (OPCODE_NFC_ID & 0xFF)
                    CAN_Tx_data[2:8] = data_bytes[:6] + b'\x00' * (6 - len(data_bytes))     #appending zeros if received length is smaller than 6 bytes
                                                                                            #in case of DESFire and NTAG cards 7 bytes are received, only 6 being used

                    '''
                    # Ensure always 8 bytes: pad with zeros if needed
                    if len(data_bytes) < 8:
                        data_bytes = b'\x00' * (8 - len(data_bytes)) + data_bytes
                    elif len(data_bytes) > 8:
                        data_bytes = data_bytes[:8]
                    '''
                    print(f"[J1939 TX] Sending NFC data: {CAN_Tx_data}")
                    self.ca.send_pgn(PRIORITY, pgn, DEST_ADDRESS, SOURCE_ADDRESS, list(CAN_Tx_data))
                    self.nfc_data_pending = False  # Only send once
                    # error_count = 0  # Reset error count on success
                    # backoff_time = self.send_interval
                else:
                    print('.')
                    #CAN_Tx_data = bytes([((OPCODE_NFC_ID >> 8) & 0xFF), (OPCODE_NFC_ID & 0xFF), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                    #print(f"[J1939 TX] Sending default data: {CAN_Tx_data}")
                    #self.ca.send_pgn(PRIORITY, pgn, DEST_ADDRESS, SOURCE_ADDRESS, list(CAN_Tx_data))
                    # error_count = 0
                    # backoff_time = self.send_interval
            except Exception as e:
                print(f"[CAN ERROR] {e}. Re-initializing J1939...")
                self.ca = None
                self.ecu = None
                # error_count += 1
                # if error_count > 3:
                #     backoff_time = min(30, self.send_interval * (2 ** (error_count - 3)))
                #     print(f"[CAN BACKOFF] Too many errors, backing off for {backoff_time} seconds.")
                # else:
                #     backoff_time = self.send_interval
            # await asyncio.sleep(backoff_time)  # Use backoff_time if enabled
            await asyncio.sleep(self.send_interval)  # Default behavior

    async def listen_async(self):
        # Optionally process messages from queue
        while True:
            await asyncio.sleep(1)

    async def start(self):
        try:
            await self.init_j1939()
            while True:
                print("Task : Start : CAN Module Running...")
                self.nfc_data_available = random.randint(0, 1)
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("CAN: Exiting CAN Module...")
            await self.shutdown()

    async def shutdown(self):
        if self.ca:
            self.ca.stop()
        if self.ecu:
            self.ecu.disconnect()
        print("CAN: Service Shutdown....")


async def main():
    loop = asyncio.get_event_loop()
    can_module = CANModule(loop=loop, send_interval=SEND_INTERVAL, pgn=PGN_VALUE, source_address=SOURCE_ADDRESS, dest_address=DEST_ADDRESS)
    can_task = asyncio.create_task(can_module.start())
    can_receive_task = asyncio.create_task(can_module.listen_async())
    can_send_task = asyncio.create_task(can_module.send_message())
    nfc_task = asyncio.create_task(can_module.listen_nfc_data())
    await asyncio.gather(can_task, can_receive_task, can_send_task, nfc_task)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Exiting...")