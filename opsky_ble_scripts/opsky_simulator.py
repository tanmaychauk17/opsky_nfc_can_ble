from bluez_peripheral.util import *
from bluez_peripheral.advert import Advertisement
from bluez_peripheral.agent import NoIoAgent
from opsky_service import OpskyService, AuthState
from connection_monitor_simple import BLEConnectionMonitor 
import asyncio
from enum import Enum
import logging
import json
import zmq
import os
import time

logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
level=logging.INFO)
logger = logging.getLogger(__name__)

class BLEStatus(Enum):
    IDLE = 1
    ADVERTISING = 2
    CONNECTED = 3
    USER_AUTHENTICATED = 4
    DISCONNECTED = 5

class UserAuthStatus(Enum):
    OPID_RECD = 1
    CHALLENGE_SENT = 2
    RESPONSE_RECD = 3

class Opsky_Simulator:
    async def listen_canToBle_data(self):
        """Listen for canToBle messages from the service's sub_socket."""
        if not self.services:
            logger.error("No services registered to listen for canToBle data.")
            return
        service = self.services[0]
        if not hasattr(service, 'sub_socket'):
            logger.error("Service does not have sub_socket for canToBle.")
            return
        logger.info("[CanToBLE] Listening for canToBle data...")
        while True:
            msg = await service.sub_socket.recv_string()
            try:
                topic, payload = msg.split(" ", 1)
                if topic == "canToBle":
                    try:
                        data_dict = json.loads(payload)
                        can_data = data_dict.get("data", [])
                        tosend = bytes(can_data)
                        if self.connectedDevice:
                            service.send_machine.changed(tosend)
                            logger.info(f"[CanToBLE] Notified BLE client with: {tosend}")
                    except Exception as e:
                        logger.error(f"Failed to process canToBle payload: {e}")
                else:
                    logger.warning(f"[CanToBLE] Unexpected topic: {topic}")
            except Exception as e:
                logger.error(f"[CanToBLE] Error parsing message: {e}")
            await asyncio.sleep(0.2)
    
    def __init__(self, devName):
        self.services = []
        self.status = BLEStatus.IDLE
        self.bus = None
        self.devName = devName
        self.connection_monitor = BLEConnectionMonitor()
        self.connection_monitor.set_connection_callback(self.on_device_connected)
        self.connection_monitor.set_disconnect_callback(self.on_device_disconnected)
        self.connectedDevice = None

        # Initialize ZMQ PUB and SUB sockets
        self.ctx = zmq.asyncio.Context.instance()
        self.pub_socket = self.ctx.socket(zmq.PUB)
        self.sub_socket = self.ctx.socket(zmq.SUB)

        # Import XPUB_ADDR and XSUB_ADDR
        from zmqhub import XPUB_ADDR, XSUB_ADDR

        # Bind or connect sockets
        self.pub_socket.connect(XSUB_ADDR)  # Publisher connects to XSUB_ADDR
        self.sub_socket.connect(XPUB_ADDR)  # Subscriber connects to XPUB_ADDR

        # Subscribe to all topics
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, "")

        logger.info(f"ZMQ PUB socket connected to {XSUB_ADDR}")
        logger.info(f"ZMQ SUB socket connected to {XPUB_ADDR}")

        # Wait for subscribers to connect before sending any messages
        time.sleep(1)
        # Publish `opskyState` message
        self.pub_socket.send_string("opskyState OPSKY_PAAK_ENABLED")
        logger.info("Advertisement enabled and OPSKY_PAAK_ENABLED sent to CAN service.")

    def set_status(self,status):
        logger.info(f"💡💡 Status changing to {status}")
        self.status = status

    async def start(self):
        if(self.status == BLEStatus.IDLE):
            await self.connection_monitor.setup()
            await self._start_advertisement()
        else:
            logger.error("❌❌ The Simulator is already started.")

    async def _disconnect_device(self):
        logger.info(f"💡💡 Disconnecting Device {self.connectedDevice}")
        await self.connection_monitor.disconnect_device(self.connectedDevice)

    async def stop(self):
        pass

    def add_service(self,service):
        if (self.status == BLEStatus.IDLE):
            self.services.append(service)
        else:
            logger.error("❌❌ Services cannot be added.")

    async def _start_advertisement(self):
        """
        Start BLE advertisement and publish the `opskyState` message.
        """
        if self.bus is None:
            self.bus = await get_message_bus()
            agent = NoIoAgent()
            await agent.register(self.bus)
            adapter = await Adapter.get_first(self.bus)

        serviceids = []
        for service in self.services:
            await service.register(self.bus)
            serviceids.append(service.ServiceID)

        logger.info(f"💡💡 Services Advertised {serviceids}")
        advert = Advertisement(self.devName, serviceids, 0, 3000)

        await advert.register(self.bus, adapter)
        await self.bus.wait_for_disconnect()

    async def on_device_disconnected(self, device_path):
        """
        Handle BLE device disconnection and publish `bleStatus`.
        """
        logger.info(f"🟢🟢 Device {device_path} disconnected 🟢🟢")
        status_msg = json.dumps({"status": "disconnected", "device": device_path})
        self.pub_socket.send_string(f"bleStatus {status_msg}")
        logger.info(f"Published BLE status: {status_msg}")

    async def on_device_connected(self, device_path):
        """
        Handle BLE device connection and publish `bleStatus`.
        Also publishes authenticated status if/when authentication is detected.
        """
        logger.info(f"🟢🟢 Device {device_path} Connected 🟢🟢")
        self.connectedDevice = device_path
        status_msg = json.dumps({"status": "connected", "device": device_path})
        self.pub_socket.send_string(f"bleStatus {status_msg}")
        logger.info(f"Published BLE status: {status_msg}")

        # Wait for authentication, then publish authenticated status
        await asyncio.sleep(0.5)
        waited = 0
        while waited < 10:  # Wait up to 5 seconds for authentication
            if self.services[0].servicestate == AuthState.USER_AUTHENTICATED:
                auth_msg = json.dumps({"status": "authenticated", "device": device_path})
                self.pub_socket.send_string(f"bleStatus {auth_msg}")
                logger.info(f"Published BLE status: {auth_msg}")
                break
            await asyncio.sleep(0.5)
            waited += 0.5

        # Disconnect device if not authenticated
        if self.services[0].servicestate != AuthState.USER_AUTHENTICATED:
            logger.info(f" 🛑🛑 Device would be disconnected here ")
            # await self._disconnect_device()

    async def get_rssi(self, device_path):
        try:
            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            introspect = await bus.introspect('org.bluez', device_path)
            device = bus.get_proxy_object('org.bluez', device_path, introspect)
            props = device.get_interface('org.freedesktop.DBus.Properties')
            all_props = await props.call_get_all('org.bluez.Device1')
            logger.debug(f"All properties for {device_path}: {all_props}")
            if 'RSSI' in all_props:
                rssi = all_props['RSSI'].value
                logger.info(f"RSSI for {device_path}: {rssi} dBm")
                return rssi
            else:
                logger.debug(f"RSSI not available for {device_path} at this time.")
                return None
        except Exception as e:
            logger.error(f"Failed to get RSSI for {device_path}: {e}")
            return None

    def rssi_to_zone(self, rssi, connected):
        """
        Map RSSI value and connection status to a zone string.
        - Not connected or RSSI > -95: 'NO_ZONE'
        - RSSI >= -60: 'ACCESS_ZONE'
        - -75 <= RSSI < -60: 'WELCOME_ZONE'
        - RSSI < -75: 'NO_ZONE'
        """
        if not connected or rssi is None or rssi > -95:
            return 'NO_ZONE'
        if rssi >= -60:
            return 'ACCESS_ZONE'
        elif rssi >= -75:
            return 'WELCOME_ZONE'
        else:
            return 'NO_ZONE'

    async def poll_rssi_all(self, interval=2):
        logger.info("Polling RSSI- task started")
        last_zone = None
        time.sleep(1)
        # Send NO_ZONE once at startup
        self.pub_socket.send_string("opskyState NO_ZONE")
        last_zone = 'NO_ZONE'
        while True:
            if self.connectedDevice:
                rssi = await self.get_rssi(self.connectedDevice)
                logger.info(f"RSSI for {self.connectedDevice}: {rssi} dBm")
                zone = self.rssi_to_zone(rssi, True)
                if zone != last_zone:
                    self.pub_socket.send_string(f"opskyState {zone}")
                    last_zone = zone
            else:
                if last_zone != 'NO_ZONE':
                    self.pub_socket.send_string("opskyState NO_ZONE")
                    last_zone = 'NO_ZONE'
            await asyncio.sleep(interval)

    async def get_connected_devices(self):
        """
        Returns a list of device paths for currently connected BLE devices.
        """
        connected_devices = []
        try:
            bus = await get_message_bus()
            obj_manager = bus.get_proxy_object('org.bluez', '/', await bus.introspect('org.bluez', '/'))
            manager = obj_manager.get_interface('org.freedesktop.DBus.ObjectManager')
            objects = await manager.call_get_managed_objects()
            for path, interfaces in objects.items():
                if 'org.bluez.Device1' in interfaces:
                    props = interfaces['org.bluez.Device1']
                    if props.get('Connected', False):
                        connected_devices.append(path)
        except Exception as e:
            logger.error(f"Failed to get connected devices: {e}")
        return connected_devices


async def main():
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
    try:
        with open(CONFIG_PATH) as f:
            config = json.load(f)
        ble_adv_name = config.get("ble_adv_name", "OPSKY_DEFAULT_Dev")
    except FileNotFoundError:
        logger.warning(f"Config file not found at {CONFIG_PATH}, using default BLE name.")
        ble_adv_name = "OPSKY_DEFAULT_Dev"

    simulator = Opsky_Simulator(ble_adv_name)
    simulator.add_service(OpskyService())
    canToBle_listen_task = asyncio.create_task(simulator.listen_canToBle_data())
    rssi_monitor = asyncio.create_task(simulator.poll_rssi_all(interval=2))
    await asyncio.gather(
        simulator.start(),
        canToBle_listen_task
        ,rssi_monitor
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Exiting...")