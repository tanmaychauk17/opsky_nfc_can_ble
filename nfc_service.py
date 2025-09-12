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
        from zmqhub import XSUB_ADDR
        self.pub_socket.connect(XSUB_ADDR)
        self.pub_socket.setsockopt(zmq.LINGER, 0)

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
        first_seen = None
        last_sent = 0
        debounce_period = 5  # seconds
        fast_interval = 1    # seconds (for first 5 seconds)
        slow_interval = 5    # seconds (after debounce)
        send_count = 0

        while True:
            try:
                if self.pn532 is None:
                    logger.warning("[NFC] Attempting to re-initialize PN532...")
                    self.init_pn532()
                    await asyncio.sleep(2)
                    continue

                uid = self.pn532.read_passive_target(timeout=0.5)
                now = time.time()

                if uid is not None:
                    if last_uid != uid:
                        # New card detected
                        last_uid = uid
                        card_present = True
                        first_seen = now
                        last_sent = 0
                        send_count = 0

                    if card_present:
                        # First 5 seconds: send every second
                        if now - first_seen < debounce_period:
                            if now - last_sent >= fast_interval:
                                await self._send_uid(uid)
                                last_sent = now
                                send_count += 1
                        else:
                            # After 5 seconds: send every 5 seconds
                            if now - last_sent >= slow_interval:
                                await self._send_uid(uid)
                                last_sent = now
                else:
                    # No card detected
                    if card_present:
                        # Card was just removed
                        logger.info("[NFC] Card removed.")
                        # Optionally notify removal:
                        # await self._send_uid([])
                        last_uid = None
                        card_present = False
                        first_seen = None
                        last_sent = 0
                        send_count = 0

            except Exception as e:
                logger.error(f"[NFC ERROR] {e}. Re-initializing PN532...")
                self.init_pn532()
            await asyncio.sleep(0.1)

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