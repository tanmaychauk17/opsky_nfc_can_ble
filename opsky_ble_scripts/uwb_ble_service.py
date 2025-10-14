UWB_MAIN_CHAR_UUID = "E1C7A1B1-7E2A-4B1A-9C1D-1F2E3D4C5B6A"  # Use the old SEND UUID for main
from bluez_peripheral.gatt.service import Service
from bluez_peripheral.gatt.characteristic import characteristic, CharacteristicFlags as CharFlags
from enum import Enum, auto
import logging
import asyncio
import zmq
import zmq.asyncio

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', level=logging.INFO)

UWB_SERVICE_UUID = "E1C7A1B0-7E2A-4B1A-9C1D-1F2E3D4C5B6A"
UWB_MAIN_CHAR_UUID = "E1C7A1B1-7E2A-4B1A-9C1D-1F2E3D4C5B6A"
BYTEORDER = 'big'

class UWBSessionState(Enum):
    IDLE = auto()
    CONNECTED = auto()
    PROTOCOL_VERIFIED = auto()
    AUTHENTICATED = auto()
    DISCONNECTED = auto()


# Import UWBController for serial bridge
from uwb_ble_bridge import UWBController

class UWBService(Service):



    @characteristic(UWB_MAIN_CHAR_UUID, CharFlags.READ | CharFlags.WRITE | CharFlags.INDICATE)
    def uwb_main(self, options):
        logger.info(f"[UWB BLE] Read requested (main char)")
        return list(b"OK")

    @uwb_main.setter
    def uwb_main(self, value, options):
        logger.info(f"[UWB BLE RX] {' '.join(f'{b:02X}' for b in value)} (main char)")
        try:
            msg = value.decode(errors='ignore').strip()
            logger.info(f"[UWB BLE RX] Decoded command: {msg}")
            notify_msg = None
            if msg.startswith('TOKEN:'):
                token = msg.split(':', 1)[1]
                response = self.uwb.set_token(token)
                logger.info(f"[UWB BLE] Set UWB token: {token}, response: {response}")
                notify_msg = b"TOKEN SET" if "error" not in response.lower() else b"ERROR: TOKEN"
            elif msg == 'RANGE':
                # Pi will process distance and zone internally
                result = self.uwb.trigger_ranging()
                logger.info(f"[UWB BLE] Ranging result: {result}")
                # Determine zone internally (not sent to iPhone)
                notify_msg = b"OK" if result else b"ERROR: RANGING"
            else:
                response = self.uwb.send_command(msg)
                logger.info(f"[UWB BLE] UWBController response: {response}")
                notify_msg = b"OK" if "error" not in response.lower() else b"ERROR"
            # Notify iPhone with response or error only
            if notify_msg:
                self.uwb_main.changed(notify_msg)
            # Forward to ZMQ as well
            import json
            payload = json.dumps({"BleToUwb": list(value)})
            msg_zmq = f"bleToUwb {payload}"
            self.pub_socket.send_string(msg_zmq)
            logger.info(f"[UWB_BLE]: Command forwarded to UWB task: {msg_zmq}")
        except Exception as e:
            logger.error(f"Error in uwb_main write: {e}")

    def __init__(self, protocol_version=1, uwb_device=None):
        super().__init__(UWB_SERVICE_UUID, True)
        self.protocol_version = protocol_version
        self.session_state = UWBSessionState.IDLE
        self.connectedDevice = None
        # ZMQ setup (PUB/SUB)
        self.ctx = zmq.asyncio.Context.instance()
        self.pub_socket = self.ctx.socket(zmq.PUB)
        self.sub_socket = self.ctx.socket(zmq.SUB)
        from zmqhub import XSUB_ADDR, XPUB_ADDR
        self.pub_socket.connect(XSUB_ADDR)
        self.pub_socket.setsockopt(zmq.LINGER, 0)
        self.sub_socket.connect(XPUB_ADDR)
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, "uwbToBle")
        self.sub_socket.setsockopt(zmq.LINGER, 0)
        # UWB serial bridge
        self.uwb = UWBController(device=uwb_device) if uwb_device else UWBController()
        self.uwb.open()





    def on_ble_connected(self, device_path):
        logger.info(f"UWB BLE Connected: device_path={device_path}")
        self.session_state = UWBSessionState.CONNECTED
        self.connectedDevice = device_path


    def on_ble_disconnected(self):
        logger.info(f"UWB BLE Disconnected: connectedDevice={self.connectedDevice}")
        self.session_state = UWBSessionState.IDLE
        self.connectedDevice = None
        self.uwb.close()



from bluez_peripheral.util import get_message_bus
from bluez_peripheral.advert import Advertisement
from bluez_peripheral.agent import NoIoAgent
from bluez_peripheral.util import Adapter
import os
import json


async def main():
    # Load BLE advertising name from config if available
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
    try:
        with open(CONFIG_PATH) as f:
            config = json.load(f)
        ble_adv_name = config.get("ble_adv_name", "UWB_BLE_Device")
    except FileNotFoundError:
        logger.warning(f"Config file not found at {CONFIG_PATH}, using default BLE name.")
        ble_adv_name = "UWB_BLE_Device"

    bus = await get_message_bus()
    agent = NoIoAgent()
    await agent.register(bus)
    adapter = await Adapter.get_first(bus)

    uwb_service = UWBService()
    await uwb_service.register(bus)
    advert = Advertisement(ble_adv_name, [UWB_SERVICE_UUID], 0, 3000)
    await advert.register(bus, adapter)
    logger.info(f"UWB BLE peripheral running as {ble_adv_name}")
    await bus.wait_for_disconnect()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Exiting...")