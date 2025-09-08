import zmq
import zmq.asyncio
"""
This example shows connecting to the PN532 and reading an M1
type RFID tag
"""

import RPi.GPIO as GPIO
import pn532.pn532 as nfc
from pn532 import *
import asyncio
import subprocess
import sys
import os
import time

class NFCModule:
    def __init__(self, loop=None):
        self.loop = loop or asyncio.get_event_loop()
        self.init_pn532()
        # ZeroMQ PUB socket for NFC data
        self.ctx = zmq.asyncio.Context.instance()
        self.pub_socket = self.ctx.socket(zmq.PUB)
        # Replace with your actual XSUB address if different
        from zmqhub import XSUB_ADDR
        self.pub_socket.connect(XSUB_ADDR)
        self.pub_socket.setsockopt(zmq.LINGER, 0)

    def init_pn532(self):
        try:
            self.pn532 = PN532_UART(debug=False, reset=20)
            ic, ver, rev, support = self.pn532.get_firmware_version()
            print('NFC: Found PN532 with firmware version: {0}.{1}'.format(ver, rev))
            self.pn532.SAM_configuration()
            print ("NFC: Service Initialized....")
        except Exception as e:
            print(f"[NFC ERROR] Failed to initialize PN532: {e}")
            self.pn532 = None

    async def listen_async(self):
        while True:
            try:
                if self.pn532 is None:
                    print("[NFC] Attempting to re-initialize PN532...")
                    self.init_pn532()
                    await asyncio.sleep(2)
                    continue
                # Check if a card is available to read
                uid = self.pn532.read_passive_target(timeout=0.5)
                print('.', end="")
                if uid is not None:
                    print('NFC: Card detected:', [hex(i) for i in uid])
                    # Example: send UID as NFC data (customize as needed)
                    import json
                    payload = json.dumps({"data": list(uid)})
                    msg = f"nfc_data {payload}"
                    await self.pub_socket.send_string(msg)
                    print(f"[NFC PUB] Published: {msg}")
            except Exception as e:
                print(f"[NFC ERROR] {e}. Re-initializing PN532...")
                self.init_pn532()
            await asyncio.sleep(1)

    async def start(self):
        try:
            await self.listen_async()
        except KeyboardInterrupt:
            print("NFC: Exiting NFC Module...")


async def main():
    loop = asyncio.get_event_loop()
    nfc = NFCModule(loop=loop)
    nfc_task = asyncio.create_task(nfc.start())
    await asyncio.gather(nfc_task)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Exiting...")