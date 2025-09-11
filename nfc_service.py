import zmq
import zmq.asyncio
import logging
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
import math

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("nfc_service")

class NFCModule:
    def __init__(self, loop=None):
        self.loop = loop or asyncio.get_event_loop()
        self.init_pn532()
        # ZeroMQ PUB socket for NFC data
        self.ctx = zmq.asyncio.Context.instance()
        self.pub_socket = self.ctx.socket(zmq.PUB)
        # Replace with your actual XSUB address if different
        from zmqhub import XPUB_ADDR
        self.pub_socket.connect(XSUB_ADDR)
        self.pub_socket.setsockopt(zmq.LINGER, 0)

    def init_pn532(self):
        try:
            self.pn532 = PN532_UART(debug=False, reset=20)
            ic, ver, rev, support = self.pn532.get_firmware_version()
            logger.info('NFC: Found PN532 with firmware version: %s.%s', ver, rev)
            self.pn532.SAM_configuration()
            logger.info("NFC: Service Initialized....")
        except Exception as e:
            logger.error(f"[NFC ERROR] Failed to initialize PN532: {e}")
            self.pn532 = None

    async def listen_async(self):
        while True:
            try:
                if self.pn532 is None:
                    logger.warning("[NFC] Attempting to re-initialize PN532...")
                    self.init_pn532()
                    await asyncio.sleep(2)
                    continue
                # Check if a card is available to read
                uid = self.pn532.read_passive_target(timeout=0.5)
                print('.', end="")
                if uid is not None:
                    logger.info('NFC: Card detected: %s', [hex(i) for i in uid])
                    # Example: send UID as NFC data (customize as needed)
                    import json
                    payload = json.dumps({"data": list(uid)})
                    msg = f"nfc_data {payload}"
                    await self.pub_socket.send_string(msg)
                    logger.info(f"[NFC PUB] Published: {msg}")
#*******************************To be commented*************************************#
                    '''
                    block4 = self.pn532.ntag2xx_read_block(4)   #handling to be added if block is not found

                    ndef_length = block4[1]
                    print("NDEF length:",ndef_length)

                    total_bytes = 2 + ndef_length
                    total_blocks = math.ceil(total_bytes / 4) #need better approach to round off

                    blocks = [block4]
                    for i in range (1,total_blocks):
                        block = self.pn532.ntag2xx_read_block(4 + i)
                        if block:
                            blocks.append(block)
                        else:
                            print("Failed to read block")

                    raw_data = b''.join(blocks)
                    payload = raw_data[2:2 + ndef_length]

                    try:
                        text = payload.decode('utf-8',errors='ignore')
                        print("NDEF text:", text)
                    except Exception as e:
                        print("NDEF text: Error in payload")
                    '''
#***********************************************************************************#
            except Exception as e:
                logger.error(f"[NFC ERROR] {e}. Re-initializing PN532...")
                self.init_pn532()
            await asyncio.sleep(0.5)

    async def start(self):
        try:
            await self.listen_async()
        except KeyboardInterrupt:
            logger.info("NFC: Exiting NFC Module...")


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