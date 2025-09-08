import asyncio
import subprocess
import sys
import os
import time

import can
import threading
import queue

import random

# Create a thread-safe queue
can_message_queue = queue.Queue()

blank_msg = can.Message(
        arbitration_id=0x123,
        data=[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        is_extended_id=False
    )

nfc_data_msg = can.Message(
        arbitration_id=0x123,
        data=[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        is_extended_id=False
    ) 

class CANModule:
    def __init__(self):
        self.bus = can.interface.Bus(channel='can0', bustype='socketcan')
        print("CAN: Service Initialized....")
        self.notifier = can.Notifier(self.bus, [self.on_message_received])
        self.nfc_data_available = False

    def on_message_received(self, msg):
        print(f"CAN: Message received: {msg}")
        can_message_queue.put(msg)

    async def send_message(self):
        while True:
            print("Task: Send : CAN Module Sending Message...")
            try:
                if self.nfc_data_available == 0:
                    self.bus.send(blank_msg)
                    print(f"CAN: Blank Message sent: {blank_msg}")
                else:
                    self.bus.send(nfc_data_msg)
                    print(f"CAN: Message sent: {nfc_data_msg}")
            except can.CanError as e:
                print(f"CAN: Message NOT sent: {e}")
            
            await asyncio.sleep(1)
    
    def shutdown(self):
        self.notifier.stop()
        self.bus.shutdown()
        print("CAN: Service Shutdown....")
    
    async def listen_async(self):
        while True:
            # This is kept for can message receiving in async style
            # Needs to be integrated with the NFC module so that both can run concurrently
            print("Task: Listen : CAN Module Listening...")
            msg = self.bus.recv(timeout=0.5)
            if msg:
                print(f"CAN: Message received in async listen: {msg}")
                can_message_queue.put(msg)
            else:
                print("CAN: No message received.")
            await asyncio.sleep(1)

    async def start(self):
        try:
            while True:
                print("Task : Start : CAN Module Running...")
                self.nfc_data_available = random.randint(0, 1)
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("CAN: Exiting CAN Module...")
            self.shutdown()


async def main():
    can_module = CANModule()
    can_task = asyncio.create_task(can_module.start())
    can_receive_task = asyncio.create_task(can_module.listen_async())
    can_send_task = asyncio.create_task(can_module.send_message())
    await asyncio.gather(can_task, can_send_task)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Exiting...")