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
    def __init__(self):
        self.pn532 = None
        self.pn532 = PN532_UART(debug=False, reset=20)
        ic, ver, rev, support = self.pn532.get_firmware_version()
        print('NFC: Found PN532 with firmware version: {0}.{1}'.format(ver, rev))

        # Configure PN532 to communicate with MiFare cards
        self.pn532.SAM_configuration()
        print ("NFC: Service Initialized....")

    async def listen_async(self):
        while True:
            # Check if a card is available to read
            uid = self.pn532.read_passive_target(timeout=0.5)
            print('.', end="")
            # Try again if no card is available.
            if uid is not None:
                print('NFC: Card detected:', [hex(i) for i in uid])
            else:
                continue
            time.sleep(1)

    async def start(self):
        try:
            await self.listen_async()
        except KeyboardInterrupt:
            print("NFC: Exiting NFC Module...")


async def main():
    nfc = NFCModule()
    nfc_task = asyncio.create_task(nfc.start())
    await asyncio.gather(nfc_task)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Exiting...")