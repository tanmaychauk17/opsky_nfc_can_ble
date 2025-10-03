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

    def load_permitted_uids(self):
        import json
        try:
            with open(os.path.join(os.path.dirname(__file__), 'config.json'), 'r') as f:
                config = json.load(f)
            # Use 'nfc_permitted_uids' key
            return set(config.get('nfc_permitted_uids', []))
        except Exception as e:
            logger.error(f"[NFC CONFIG] Failed to load permitted devices: {e}")
            return set()

    def is_device_permitted(self, data):
        try:
            # Always read 32 bytes, parse as USERID,NUM_DEV,DEV1,...
            if isinstance(data, bytes):
                card_str = data.decode(errors="ignore").strip(',\x00')
            elif isinstance(data, list):
                card_str = bytes(data).decode(errors="ignore").strip(',\x00')
            else:
                logger.warning(f"[NFC] Unexpected data type in is_device_permitted: {type(data)}")
                return False
            parts = [p.strip() for p in card_str.split(',') if p.strip()]
            if len(parts) < 2:
                logger.warning(f"[NFC] Not enough data fields: {parts}")
                return False
            userid = parts[0]
            num_devices = int(parts[1])
            device_list = [d.strip() for d in parts[2:2+num_devices]]
            allowed = set(device_list) & self._nfc_permitted_uids
            print("Permitted devices from config:", self._nfc_permitted_uids)
            print("Devices from card:", device_list)
            print("Intersection:", allowed)
            if allowed:
                self._last_userid = userid
                logger.info(f"[NFC] User {userid} has access to: {allowed}")
                return True
            else:
                logger.warning(f"[NFC] User {userid} has no permitted device access.")
                return False
        except Exception as e:
            logger.error(f"[NFC] Error in is_device_permitted: {e}")
            return False

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
        # Load permitted UIDs once at startup
        self._nfc_permitted_uids = self.load_permitted_uids()

    def init_pn532(self):
        try:
            self.pn532 = PN532_UART(debug=False, reset=20)
            ic, ver, rev, support = self.pn532.get_firmware_version()
            logger.info(f"[NFC INIT]: Found PN532 with firmware version: {ver}.{rev}")
            self.pn532.SAM_configuration()
            logger.info(f"[NFC INIT]: Service Initialized....")
        except Exception as e:
            logger.error(f"[NFC ERROR] Failed to initialize PN532: {e}")
            self.pn532 = None

    async def listen_async(self):
        last_uid = None
        card_present = False
        last_sent = 0
        send_interval = 5  # seconds

        FILE_NO = 0
        FILE_SIZE = 32
        KEY = b'\x00' * 16
        KEY_NO = 0x03
        APP_AID = [0xA3, 0xA2, 0xA1]    #A1A2A3


        while True:
            try:
                if self.pn532 is None:
                    logger.warning(f"[NFC] Attempting to re-initialize PN532...")
                    self.init_pn532()
                    await asyncio.sleep(2)
                    continue

                now = time.time()
                if (now - last_sent >= send_interval):
                    uid = self.pn532.read_passive_target(timeout=0.5)
                    if uid is not None:
                        logger.info(f"[NFC] Detected card with UID: {uid}")
                        data = self.desfire.read_data(FILE_NO, 0, FILE_SIZE, KEY_NO, KEY, uid=uid)
                        #logger.info(f"[NFC] ID on card: {data}")
                        if data:
                            # Check if data is bytes or list, else log warning
                            if not isinstance(data, (bytes, list)):
                                logger.warning(f"[NFC] Unexpected data type from read_data: {type(data)}. Data: {data}")
                            else:
                                logger.info(f"[NFC] Data read from card: {list(data)}")
                                if self.is_device_permitted(data):
                                    logger.info(f"[NFC] Permitted device with data: {list(data)}")  
                                    await self._send_uid(data)
                                    last_sent = now
                                else:
                                    logger.warning(f"[NFC] Device with data {list(data)} is not permitted!")
                                    last_sent = now
                        else:
                            logger.warning(f"[NFC] No data read from card.")
                    else:
                        logger.debug(f"[NFC] No card detected.")

                # Sleep only the remaining time to hit exactly 5 seconds
                sleep_time = max(0, send_interval - (time.time() - last_sent))
                await asyncio.sleep(min(0.1, sleep_time))

            except Exception as e:
                logger.error(f"[NFC ERROR] {e}. Re-initializing PN532...")
                self.init_pn532()
                await asyncio.sleep(0.1)
            #await asyncio.sleep(0.1)  # Faster polling for better responsiveness
    def format_userid_for_can(self, userid):
        """
        Converts FE03 → FE0000000003, FE01 → FE0000000001, etc.
        """
        if userid and userid.startswith("FE") and len(userid) == 4:
            return f"{userid[:2]}{'0'*8}{userid[2:].zfill(2)}"
        return userid  # fallback: return as-is

    async def _send_uid(self, _):
        import json
        try:
            raw_userid = getattr(self, "_last_userid", None)
            can_userid = self.format_userid_for_can(raw_userid)
            payload = json.dumps({"user_id": can_userid})
            msg = f"nfc_data {payload}"
            await self.pub_socket.send_string(msg)
            logger.info(f"[NFC PUB] Published: {msg}")
        except Exception as e:
            logger.error(f"[NFC PUB] Failed to send user ID: {e}")

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