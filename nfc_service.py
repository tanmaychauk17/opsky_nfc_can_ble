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

from nfc_desfire import PN532Desfire

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
        from zmqhub import XSUB_ADDR
        self.pub_socket.connect(XSUB_ADDR)
        self.pub_socket.setsockopt(zmq.LINGER, 0)
        self.desfire = PN532Desfire(self.pn532)
        self.session_key = None
        self.last_uid = None

    def init_pn532(self):
        try:
            self.pn532 = PN532_UART(debug=False, reset=20)
            ic, ver, rev, support = self.pn532.get_firmware_version()
            logger.info('[NFC INIT]: Found PN532 with firmware version: %s.%s', ver, rev)
            self.pn532.SAM_configuration()
            logger.info("[NFC INIT]: Service Initialized....")
        except Exception as e:
            logger.error(f"[NFC ERROR] Failed to initialize PN532: {e}")
            self.pn532 = None

    async def listen_async(self):
        last_uid = None
        card_present = False
        last_sent = 0
        send_interval = 5  # seconds

        FILE_NO = 0
        FILE_SIZE = 6
        KEY = b'\x00' * 16
        KEY_NO = 0x03
        APP_AID = [0xA3, 0xA2, 0xA1]

        while True:
            try:
                if self.pn532 is None:
                    logger.warning("[NFC] Attempting to re-initialize PN532...")
                    self.init_pn532()
                    await asyncio.sleep(2)
                    continue

                now = time.time()
                if (now - last_sent >= send_interval):
                    uid = self.pn532.read_passive_target(timeout=0.5)
                    if uid is not None:
                        logger.info(f"[NFC] Detected card with UID: {uid}")
                        data = self.desfire.read_data(FILE_NO, 0, FILE_SIZE, KEY_NO, KEY, uid=uid)
                        if data:
                            await self._send_uid(data)
                            last_sent = now
                    else:
                        logger.debug("[NFC] No card detected.")

                # Sleep only the remaining time to hit exactly 5 seconds
                sleep_time = max(0, send_interval - (time.time() - last_sent))
                await asyncio.sleep(min(0.1, sleep_time))

            except Exception as e:
                logger.error(f"[NFC ERROR] {e}. Re-initializing PN532...")
                self.init_pn532()
                await asyncio.sleep(0.1)
            #await asyncio.sleep(0.1)  # Faster polling for better responsiveness

    async def _send_uid(self, uid):
        import json
        payload = json.dumps({"data": list(uid)})
        msg = f"nfc_data {payload}"
        await self.pub_socket.send_string(msg)
        logger.info(f"[NFC PUB] Published: {msg}")

    async def start(self):
        try:
            await self.listen_async()
        except KeyboardInterrupt:
            logger.info("NFC: Exiting NFC Module...")
            await self.shutdown()
    
    async def shutdown(self):
        self.pub_socket.close()
        self.ctx.term()


async def main():
    loop = asyncio.get_event_loop()
    nfc = NFCModule(loop=loop)
    nfc_task = asyncio.create_task(nfc.start())
    try:
        await asyncio.gather(nfc_task)
    except KeyboardInterrupt:
        logger.info("Exiting...")
        await nfc.shutdown()

if __name__ == "__main__":
    asyncio.run(main())