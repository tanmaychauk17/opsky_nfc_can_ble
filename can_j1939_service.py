
# Refactored to match can_service.py async structure
import asyncio
import can
import j1939
import random
import time

can_message_queue = asyncio.Queue()

class CANModule:
    def __init__(self):
        self.ecu = None
        self.ca = None
        self.nfc_data_available = False

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
            self.ca = j1939.ControllerApplication(name, 0x03)
            self.ecu = j1939.ElectronicControlUnit()
            self.ecu.connect(bustype=bustype, channel=can_channel)
            self.ecu.add_ca(controller_application=self.ca)
            self.ca.subscribe(self.on_message_received)
            self.ca.start()
            print("J1939: Address claiming started...")
            await asyncio.sleep(2)
            print("J1939: Initialization complete.")
        except Exception as e:
            print(f"Error during J1939 initialization: {e}")

    def on_message_received(self, priority, pgn, source, timestamp, data):
        print(f"[J1939 RX] PGN: {hex(pgn)} Source: {hex(source)} Data: {data.hex()}")
        # Optionally, put message in queue for async processing
        # await can_message_queue.put((priority, pgn, source, timestamp, data))

    async def send_message(self):
        while True:
            # Wait until CA is in NORMAL state (address claimed)
            while self.ca.state != j1939.ControllerApplication.State.NORMAL:
                print("Waiting for CA to claim address...")
                await asyncio.sleep(1)
            # Example PGN and data
            pgn = 0xFE8C

            data_blank = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            data_nfc_data = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])

            self.nfc_data_available
            print(f"[J1939 TX] Sending PGN {hex(pgn)} broadcast...")
            # For broadcast, dest = 0xFF, priority = 6
            if self.nfc_data_available == 0:
                self.ca.send_pgn(0, pgn, 0xFF, 6, list(data_blank))
            else:
                self.ca.send_pgn(0, pgn, 0xFF, 6, list(data_nfc_data))
            await asyncio.sleep(1)

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
    can_module = CANModule()
    can_task = asyncio.create_task(can_module.start())
    can_receive_task = asyncio.create_task(can_module.listen_async())
    can_send_task = asyncio.create_task(can_module.send_message())
    await asyncio.gather(can_task, can_receive_task, can_send_task)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Exiting...")