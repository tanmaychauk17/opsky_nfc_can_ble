#!/usr/bin/env python3
"""
Simplified Connection Monitor for BLE Peripheral
Uses polling instead of D-Bus signals for better compatibility
"""

import asyncio
import time
from typing import Callable, Optional, Dict, Set
from dbus_next.aio import MessageBus
from dbus_next.constants import BusType
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
level=logging.INFO)
class BLEConnectionMonitor:
    def __init__(self):
        self.bus = None
        self.connected_devices: Dict[str, float] = {}  # device -> connection_time
        self.connection_callback: Optional[Callable] = None
        self.disconnect_callback: Optional[Callable] = None
        self.idle_timeout = 5.0  # 5 seconds
        self.monitoring_task = None
        self.poll_interval = 1.0  # Poll every second
        self.obj_manager = None
        
    async def setup(self):
        """Setup D-Bus connection monitoring using polling"""
        try:
            self.bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            logger.info("✅ Connection monitoring Started")
            
            # Start monitoring task
            self.monitoring_task = asyncio.create_task(self._monitor_connections())
            
            logger.info("🔍 BLE connection monitoring active (polling mode)")
            
        except Exception as e:
            logger.error(f"Failed to setup connection monitoring: {e}")
            raise
    
    async def _get_bluez_devices(self):
        """Get all BlueZ device paths and their connection status"""
        try:
            # Get BlueZ object manager
            introspection = await self.bus.introspect('org.bluez', '/')
            bluez_proxy = self.bus.get_proxy_object('org.bluez', '/', introspection)
            self.obj_manager = bluez_proxy.get_interface('org.freedesktop.DBus.ObjectManager')
            
            # Get all managed objects
            self.managed_objects = await self.obj_manager.call_get_managed_objects()
            
            connected_devices = {}
            
            for object_path, interfaces in managed_objects.items():
                if 'org.bluez.Device1' in interfaces:
                    device_props = interfaces['org.bluez.Device1']
                    
                    # Check if device is connected
                    if 'Connected' in device_props and device_props['Connected'].value:
                        # Extract device ID from path
                        device_id = object_path.split('/')[-1].replace('dev_', '').replace('_', ':')
                        connected_devices[device_id] = object_path
            
            return connected_devices
            
        except Exception as e:
            logger.error(f"Error getting BlueZ devices: {e}")
            return {}
    
    async def _monitor_connections(self):
        """Monitor connections using polling"""
        def interface_added_handler(self,interface):
            print(f"Interface added {interface}")
        
        introspection = await self.bus.introspect('org.bluez', '/')
        bluez_proxy = self.bus.get_proxy_object('org.bluez', '/', introspection)
        self.obj_manager = bluez_proxy.get_interface('org.freedesktop.DBus.ObjectManager')
        self.obj_manager.on_interfaces_added(interface_added_handler)
        self.managed_objects = await self.obj_manager.call_get_managed_objects()


        async def watch_device(bus, device_path):
            d_introspect = await bus.introspect('org.bluez', device_path)
            d_proxy = bus.get_proxy_object('org.bluez', device_path, d_introspect)
            d_props = d_proxy.get_interface('org.freedesktop.DBus.Properties')

            async def on_props_changed(iface, changed, invalidated):
                if iface == 'org.bluez.Device1' and 'Connected' in changed:
                    state = changed['Connected'].value
                    print(f'{"✅ Connected" if state else "❌ Disconnected"}: {device_path}')
                
                    if(state):
                        await self.connection_callback(device_path)
                    else:
                        await self.disconnect_callback(device_path)

            d_props.on_properties_changed(on_props_changed)
            
        print(f"✅ Listening for connections..")
        await asyncio.gather(*(watch_device(self.bus, path)
                           for path, ifs in self.managed_objects.items() if 'org.bluez.Device1' in ifs))
        while(True ):
            await asyncio.sleep(1)
        
    async def disconnect_device(self, device_path: str):
        """Forcefully disconnect a device"""
        pass
        try:
            # Convert device ID back to D-Bus path format
            #device_path = f"/org/bluez/hci0/dev_{device_id.replace(':', '_')}"
            
            # Get the device introspection and proxy
            device_introspection = await self.bus.introspect('org.bluez', device_path)
            device_proxy = self.bus.get_proxy_object('org.bluez', device_path, device_introspection)
            device_interface = device_proxy.get_interface('org.bluez.Device1')
            await device_interface.call_disconnect()
            
            logger.info(f"🚫 Initiated disconnect for idle device: {device_path}")
            
        except Exception as e:
            logger.error(f"Failed to disconnect device {device_id}: {e}")
    
    def set_connection_callback(self, callback: Callable):
        """Set callback for connection events: callback(connected: bool, device_id: str)"""
        self.connection_callback = callback
    
    def set_disconnect_callback(self, callback: Callable):
        """Set callback for disconnect events: callback(connected: bool, device_id: str)"""
        self.disconnect_callback = callback
    
    def set_idle_timeout(self, timeout_seconds: float):
        """Set the idle timeout in seconds"""
        self.idle_timeout = timeout_seconds
        logger.info(f"⏱️ Idle timeout set to {timeout_seconds} seconds")
    
    def set_poll_interval(self, interval_seconds: float):
        """Set how often to poll for connection changes"""
        self.poll_interval = interval_seconds
        logger.info(f"🔄 Poll interval set to {interval_seconds} seconds")
    
    async def _safe_callback(self, callback, *args):
        """Safely execute callback"""
        try:
            if asyncio.iscoroutinefunction(callback):
                await callback(*args)
            else:
                callback(*args)
        except Exception as e:
            logger.error(f"Error in callback: {e}")
    
    async def stop(self):
        """Stop connection monitoring"""
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        if self.bus:
            self.bus.disconnect()
            
        logger.info("🛑 Connection monitoring stopped")
    
    def get_connected_devices(self) -> Set[str]:
        """Get currently connected devices"""
        return set(self.connected_devices.keys())
    
    def get_device_connection_time(self, device_id: str) -> float:
        """Get how long a device has been connected"""
        if device_id in self.connected_devices:
            return time.time() - self.connected_devices[device_id]
        return 0.0

def your_connect_function():
    logging.info(" 🔗 Connected.")


def your_disconnect_function():
    logging.info(" ⛓️‍💥 Disconnected.")

async def main():
    monitor = BLEConnectionMonitor()
    monitor.set_connection_callback(your_connect_function)
    monitor.set_disconnect_callback(your_disconnect_function)
    monitor.set_idle_timeout(5.0)
    await monitor.setup()
    await asyncio.sleep(100)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Exiting...")