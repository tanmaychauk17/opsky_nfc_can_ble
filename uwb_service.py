import zmq
import zmq.asyncio
import serial_asyncio  # Use pyserial-asyncio
import asyncio
import logging
import json
import sys
import os
from typing import Optional

# Add path to import zmqhub and connect to the correct socket
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from zmqhub import XPUB_ADDR

ZMQ_SUB_TOPIC = "uwbKey"
ZMQ_CTRL_TOPIC = "uwbCtrl"
UART_PORT = "/dev/ttyACM0"  # Change as needed
UART_BAUD = 115200

logger = logging.getLogger("uwb_service")
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', level=logging.INFO)

class UWBService:
    def __init__(self, uart_port=UART_PORT, uart_baud=UART_BAUD):
        self.ctx = zmq.asyncio.Context.instance()
        self.sub_socket = self.ctx.socket(zmq.SUB)
        self.sub_socket.connect(XPUB_ADDR)  # Subscribers connect to the XPUB socket
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, ZMQ_SUB_TOPIC)
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, ZMQ_CTRL_TOPIC)
        self.uart_port = uart_port
        self.uart_baud = uart_baud
        self.serial_reader = None
        self.serial_writer = None
        self.uart_reader_task = None

    async def setup_uart(self):
        try:
            # Use pyserial-asyncio for non-blocking serial operations
            self.serial_reader, self.serial_writer = await serial_asyncio.open_serial_connection(url=self.uart_port, baudrate=self.uart_baud)
            logger.info(f"UART connected: {self.uart_port} @ {self.uart_baud}")
            
            # Send 'help' command to check connectivity
            logger.info("Sending 'help' command to check UWB module connection...")
            self.serial_writer.write(b"help\r\n")
            await self.serial_writer.drain()
            
            return True
        except Exception as e:
            logger.error(f"Failed to open UART: {e}")
            return False

    async def read_uart_loop(self):
        logger.info("Starting UART read loop.")
        while True:
            try:
                line = await self.serial_reader.readline()
                if line:
                    logger.info(f"UWB> {line.decode('utf-8', errors='ignore').strip()}")
            except Exception as e:
                logger.error(f"UART read loop error: {e}")
                # Stop the loop if the serial connection is lost
                break
        logger.info("UART read loop stopped.")

    async def run(self):
        if not await self.setup_uart():
            logger.error("Cannot start UWBService without UART. Exiting.")
            return

        # Start the UART reader as a background task
        self.uart_reader_task = asyncio.create_task(self.read_uart_loop())

        logger.info("UWBService main loop started. Waiting for UWB key / control...")
        while True:
            try:
                msg = await self.sub_socket.recv_string()
                topic, payload = msg.split(" ", 1)
                if topic == ZMQ_SUB_TOPIC:
                    logger.info(f"[ZMQ] uwbKey payload: {payload[:200]}{'...' if len(payload)>200 else ''}")
                    try:
                        data = json.loads(payload)
                        uwb_key = data.get("UwbKey", "")
                        if uwb_key:
                            await self.handle_uwb_key(uwb_key)
                        else:
                            logger.warning("Received empty UWB key.")
                    except Exception as e:
                        logger.error(f"Error parsing UWB key payload: {e}")
                elif topic == ZMQ_CTRL_TOPIC:
                    logger.info(f"[ZMQ] uwbCtrl payload: {payload[:200]}{'...' if len(payload)>200 else ''}")
                    try:
                        data = json.loads(payload)
                        ctrl_hex = data.get("ctrl", "")
                        if ctrl_hex:
                            await self.handle_ctrl(ctrl_hex)
                        else:
                            logger.warning("Received empty ctrl payload.")
                    except Exception as e:
                        logger.error(f"Error parsing ctrl payload: {e}")
            except Exception as e:
                logger.error(f"Error in ZMQ loop: {e}")
                await asyncio.sleep(1)

    async def handle_uwb_key(self, uwb_key_string: str):
        """Handle a key string coming from BLE via ZMQ.
        Accepts hex text. If the decoded bytes look like a bplist (starts with b"bplist"),
        parse it to extract rawToken and send NIQSTART command. Otherwise, treat bytes as
        the raw discovery token and format to VUPPER (colon-separated uppercase hex) for INITF.
        """
        if not self.serial_writer:
            logger.warning("UART not connected; cannot send key.")
            return

        try:
            raw = bytes.fromhex(uwb_key_string)
        except Exception as e:
            logger.error(f"Invalid hex for uwbKey: {e}")
            return

        try:
            if raw.startswith(b"bplist"):
                logger.info("Received bplist NIDiscoveryToken - parsing for rawToken...")
                raw_token = self._parse_plist_raw_token(raw)
                if raw_token:
                    # Send NIQSTART with 0x0B message ID + rawToken
                    raw_token_hex = raw_token.hex().upper()
                    logger.info(f"Extracted rawToken ({len(raw_token)} bytes): {raw_token_hex}")
                    await self._send_uart_cmd(f"NIQSTART 0B{raw_token_hex}\r\n")
                    logger.info("NIQSTART command sent with rawToken.")
                else:
                    logger.error("Failed to extract rawToken from plist.")
                return

            # Treat as raw token bytes -> format VUPPER
            formatted_token = raw.hex(':').upper()
            logger.info(f"Formatted token (VUPPER): {formatted_token}")

            await self._send_uart_cmd(f"INITF -VUPPER={formatted_token}\r\n")
            await asyncio.sleep(0.1)
            await self._send_uart_cmd("THREAD\r\n")
            logger.info("INITF/THREAD sequence sent.")
        except Exception as e:
            logger.error(f"Failed to send INITF/THREAD: {e}")

    def _parse_plist_raw_token(self, plist_data: bytes) -> Optional[bytes]:
        """Parse binary plist to extract rawToken field.
        
        Binary plist structure (simplified):
        - Header: "bplist00"
        - Objects table with various types
        - rawToken is typically a data object marked with 0x4F 0x10 <length>
        
        This is a simple parser that looks for the data object pattern.
        For production, consider using biplist or plistlib libraries.
        """
        try:
            # Look for data object marker: 0x4F 0x10 followed by length byte
            # In your example: 4F 10 22 means data object with 0x22 (34) bytes
            idx = 0
            while idx < len(plist_data) - 3:
                if plist_data[idx] == 0x4F and plist_data[idx + 1] == 0x10:
                    length = plist_data[idx + 2]
                    if length > 0 and length <= 64:  # rawToken should be ~34 bytes
                        start = idx + 3
                        end = start + length
                        if end <= len(plist_data):
                            token = plist_data[start:end]
                            logger.info(f"Found data object at offset {idx}, length={length}")
                            return token
                idx += 1
            
            logger.warning("Could not find rawToken data object in plist")
            return None
        except Exception as e:
            logger.error(f"Error parsing plist: {e}")
            return None

    async def handle_ctrl(self, ctrl_hex: str):
        """Handle control messages from SC characteristic.
        Expects hex. If hex decodes to ASCII, forward as-is to UART. Otherwise, ignore.
        """
        if not self.serial_writer:
            logger.warning("UART not connected; cannot send control.")
            return
        try:
            data = bytes.fromhex(ctrl_hex)
        except Exception as e:
            logger.error(f"Invalid hex for ctrl: {e}")
            return
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            logger.warning("Control payload not UTF-8; ignoring.")
            return
        # Safety: ensure ends with CRLF
        if not text.endswith("\r\n"):
            text = text.rstrip("\n") + "\r\n"
        await self._send_uart_cmd(text)
        logger.info(f"Forwarded control to UART: {text.strip()}")

    async def _send_uart_cmd(self, cmd: str):
        if isinstance(cmd, str):
            data = cmd.encode('utf-8')
        else:
            data = cmd
        self.serial_writer.write(data)
        await self.serial_writer.drain()
        try:
            shown = data.decode('utf-8', errors='ignore').strip()
        except Exception:
            shown = str(data)
        logger.info(f"UART<= {shown}")

if __name__ == "__main__":
    service = UWBService()
    try:
        asyncio.run(service.run())
    except KeyboardInterrupt:
        logger.info("UWBService stopped by user.")
