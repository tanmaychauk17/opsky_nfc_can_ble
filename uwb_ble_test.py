import asyncio
import json
import logging
import os
import sys
import time
import typing

import zmq
import zmq.asyncio

from bluez_peripheral.util import get_message_bus
from bluez_peripheral.advert import Advertisement
from bluez_peripheral.agent import NoIoAgent
from bluez_peripheral.gatt.service import Service
from bluez_peripheral.gatt.characteristic import characteristic, CharacteristicFlags as CharFlags

# Make repo root importable to access zmqhub addresses
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from zmqhub import XSUB_ADDR, XPUB_ADDR

logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', level=logging.INFO)
logger = logging.getLogger("uwb_ble_test")

# Qorvo Nearby Interaction (QNI) official UUIDs provided by user
# Service and characteristics (Swift reference):
# serviceUUID:      2E938FD0-6A61-11ED-A1EB-0242AC120002
# scCharacteristic: 2E93941C-6A61-11ED-A1EB-0242AC120002 (Session Control / Role / Params)
# rxCharacteristic: 2E93998A-6A61-11ED-A1EB-0242AC120002 (Phone -> Accessory writes token/data)
# txCharacteristic: 2E939AF2-6A61-11ED-A1EB-0242AC120002 (Accessory -> Phone notifications)

PRIMARY_SERVICE_UUID = "2E938FD0-6A61-11ED-A1EB-0242AC120002"
SC_CHAR_UUID         = "2E93941C-6A61-11ED-A1EB-0242AC120002"
RX_CHAR_UUID         = "2E93998A-6A61-11ED-A1EB-0242AC120002"
TX_CHAR_UUID         = "2E939AF2-6A61-11ED-A1EB-0242AC120002"

ZMQ_TOPIC = "uwbKey"

BUFFER_DEBOUNCE_MS = 400  # time of inactivity after which we consider a message complete


def load_ble_name() -> str:
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")) as f:
            cfg = json.load(f)
        return cfg.get("ble_adv_name", "OPSKY_UWB_TEST")
    except Exception:
        return "OPSKY_UWB_TEST"


class UWBBleTestService(Service):
    """Qorvo NI BLE service implementation (simplified prototype).

    Characteristic mapping:
      RX (write/WNR): phone writes discovery token (possibly chunked)
      TX (notify): accessory sends status / acknowledgments / ranging summaries
      SC (write): phone sends session control commands (e.g., INITF, RESPF, STOP, PARAMS)

    Token buffering logic: chunks written to RX within debounce window are concatenated and
    published over ZMQ (topic 'uwbKey') as hex. Control messages written to SC are published
    over ZMQ (topic 'uwbCtrl') as UTF-8 text.
    """

    def __init__(self, ctx: zmq.asyncio.Context):
        super().__init__(PRIMARY_SERVICE_UUID, True)
        self.ServiceID = PRIMARY_SERVICE_UUID
        self._chunks = []  # type: list
        self._debounce_task = None  # type: typing.Optional[asyncio.Task]
        self._verbose = os.environ.get("UWB_BLE_VERBOSE", "0") == "1"
        self._log_full_chunks = os.environ.get("UWB_BLE_LOG_CHUNKS", "0") == "1"
        self._event_counter = 0
        self._last_flush_hex = None  # type: typing.Optional[str]
        self._last_ctrl_hex = None  # type: typing.Optional[str]

        # ZMQ publisher (connects to the hub's XSUB input)
        self._zmq_ctx = ctx
        self._pub = self._zmq_ctx.socket(zmq.PUB)
        self._pub.connect(XSUB_ADDR)
        self._pub.setsockopt(zmq.LINGER, 0)

    # --- RX characteristic (getter + setter) ---
    @characteristic(RX_CHAR_UUID, flags=CharFlags.WRITE | CharFlags.WRITE_WITHOUT_RESPONSE | CharFlags.READ)
    def rx_characteristic(self):
        """Getter returns last assembled token (for debug reads)."""
        if self._last_flush_hex is None:
            return b""
        # Return the last flushed token bytes (not in-progress chunks) for reproducibility.
        try:
            return bytes.fromhex(self._last_flush_hex)
        except Exception:
            return b""

    @rx_characteristic.setter
    def rx_characteristic(self, value, options):  # setter invoked on WriteValue
        try:
            self._event_counter += 1
            data = bytes(value)
            self._chunks.append(data)
            hex_data = data.hex()
            head = hex_data[:64]
            tail = hex_data[-64:] if len(hex_data) > 64 else ""
            summary = head + ("..." if len(hex_data) > 64 else "")
            logger.info(
                f"[QNI RX:set] ev#{self._event_counter} chunk_len={len(data)}B hex={summary}"
            )
            if self._verbose and (self._log_full_chunks or len(hex_data) <= 256):
                logger.debug(f"[QNI RX:set] full_chunk_hex={hex_data}")
            elif self._verbose and len(hex_data) > 256:
                logger.debug(f"[QNI RX:set] head64={head} tail64={tail}")
            # Reset debounce timer
            if self._debounce_task and not self._debounce_task.done():
                self._debounce_task.cancel()
            self._debounce_task = asyncio.create_task(self._debounce_flush())
        except Exception as e:
            logger.error(f"RX write error: {e}")

    # --- TX characteristic (notify only) ---
    @characteristic(TX_CHAR_UUID, flags=CharFlags.NOTIFY | CharFlags.READ)
    def tx_characteristic(self):
        """Return empty for read; notifications pushed via .changed()."""
        return b""

    # --- SC characteristic (getter + setter) ---
    @characteristic(SC_CHAR_UUID, flags=CharFlags.WRITE | CharFlags.WRITE_WITHOUT_RESPONSE | CharFlags.READ)
    def sc_characteristic(self):
        """Return nothing useful (could store last ctrl)."""
        if self._last_ctrl_hex:
            try:
                return bytes.fromhex(self._last_ctrl_hex)
            except Exception:
                return b""
        return b""

    @sc_characteristic.setter
    def sc_characteristic(self, value, options):
        try:
            self._event_counter += 1
            cmd_bytes = bytes(value)
            hex_cmd = cmd_bytes.hex()
            self._last_ctrl_hex = hex_cmd
            is_binary = any(b < 32 or b > 126 for b in cmd_bytes)
            preview = hex_cmd if is_binary else cmd_bytes.decode(errors='ignore')
            logger.info(
                f"[QNI SC:set] ev#{self._event_counter} ctrl_len={len(cmd_bytes)}B preview={preview[:80]}{'...' if len(preview)>80 else ''}"
            )
            if self._verbose:
                logger.debug(f"[QNI SC:set] full_ctrl_hex={hex_cmd}")
            ctrl_payload = json.dumps({"ctrl": hex_cmd})
            self._pub.send_string(f"uwbCtrl {ctrl_payload}")
            # Immediate ack via TX notify
            try:
                self.tx_characteristic.changed(b"CTRL_ACK")
                logger.info("[QNI TX] sent CTRL_ACK notify")
            except Exception:
                pass
        except Exception as e:
            logger.error(f"SC write error: {e}")

    async def _debounce_flush(self):
        try:
            await asyncio.sleep(BUFFER_DEBOUNCE_MS / 1000.0)
            if not self._chunks:
                return
            full = b"".join(self._chunks)
            self._chunks.clear()
            key_hex = full.hex()
            self._last_flush_hex = key_hex
            payload = json.dumps({"UwbKey": key_hex}, separators=(",", ":"))
            self._pub.send_string(f"{ZMQ_TOPIC} {payload}")
            ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in full[:32])
            logger.info(
                f"[QNI RX->ZMQ] flush token_len={len(full)}B hex_len={len(key_hex)} ascii_preview='{ascii_preview}'"
            )
            if self._verbose:
                logger.debug(f"[QNI RX->ZMQ] token_full_hex={key_hex}")
            try:
                self.tx_characteristic.changed(b"TOKEN_ACK")
                logger.info("[QNI TX] sent TOKEN_ACK notify")
            except Exception:
                pass
        except asyncio.CancelledError:
            return
        except Exception as e:
            logger.error(f"Flush error: {e}")


async def main():
    # ZMQ context
    zmq_ctx = zmq.asyncio.Context.instance()

    # BLE setup
    bus = await get_message_bus()
    agent = NoIoAgent()
    await agent.register(bus)

    from bluez_peripheral.util import Adapter
    adapter = await Adapter.get_first(bus)

    service = UWBBleTestService(zmq_ctx)
    await service.register(bus)

    adv_name = load_ble_name()
    advert = Advertisement(adv_name, [service.ServiceID], 0, 3000)
    await advert.register(bus, adapter)

    logger.info(f"Advertising '{adv_name}' with service {service.ServiceID}")
    logger.info("Write the UWB token into the single characteristic; token will be forwarded to ZMQ as hex.")

    # Keep running until disconnect
    await bus.wait_for_disconnect()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Exiting uwb_ble_test.")
