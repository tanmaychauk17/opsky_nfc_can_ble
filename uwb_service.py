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
from zmqhub import XPUB_ADDR, XSUB_ADDR

ZMQ_SUB_TOPIC = "uwbKey"
ZMQ_CTRL_TOPIC = "uwbCtrl"
ZMQ_CONFIG_TOPIC = "uwbConfig"
UART_PORT = "/dev/ttyACM0"  # Change as needed
UART_BAUD = 115200

logger = logging.getLogger("uwb_service")
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', level=logging.INFO)

class UWBService:
    def __init__(self, uart_port=UART_PORT, uart_baud=UART_BAUD, mock_mode=False):
        self.ctx = zmq.asyncio.Context.instance()
        self.sub_socket = self.ctx.socket(zmq.SUB)
        self.sub_socket.connect(XPUB_ADDR)  # Subscribers connect to the XPUB socket
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, ZMQ_SUB_TOPIC)
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, ZMQ_CTRL_TOPIC)
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, ZMQ_CONFIG_TOPIC)
        self.uart_port = uart_port
        self.uart_baud = uart_baud
        self.serial_reader = None
        self.serial_writer = None
        self.uart_reader_task = None
        self.mock_mode = mock_mode
        self.hardware_connected = False
        
        # Config response handling
        self.pending_config_response = None
        self.config_response_received = False

    async def setup_uart(self):
        if self.mock_mode:
            logger.info("🔧 Mock mode: UWB hardware simulation active")
            self.hardware_connected = False
            return True
            
        try:
            # Use pyserial-asyncio for non-blocking serial operations
            self.serial_reader, self.serial_writer = await asyncio.wait_for(
                serial_asyncio.open_serial_connection(
                    url=self.uart_port, 
                    baudrate=self.uart_baud
                ),
                timeout=5.0  # 5 second connection timeout
            )
            logger.info(f"✅ UART connected: {self.uart_port} @ {self.uart_baud}")
            
            # Send 'help' command to check connectivity
            logger.info("Testing UWB module connection...")
            self.serial_writer.write(b"help\r\n")
            await self.serial_writer.drain()
            
            self.hardware_connected = True
            return True
            
        except asyncio.TimeoutError:
            logger.warning(f"⚠️ UART connection timeout: {self.uart_port}")
            logger.info("🔧 Continuing in mock mode")
            self.hardware_connected = False
            return True  # Continue in mock mode
        except Exception as e:
            logger.warning(f"⚠️ UWB hardware not available: {e}")
            logger.info("🔧 Continuing in mock mode (software simulation)")
            self.hardware_connected = False
            self.mock_mode = True
            return True

    async def read_uart_loop(self):
        logger.info("Starting UART read loop.")
        while True:
            try:
                line = await self.serial_reader.readline()
                if line:
                    response = line.decode('utf-8', errors='ignore').strip()
                    
                    # Log only important responses, filter out noise
                    if response and response != "ok" and not response.startswith("GETCONFIG:"):
                        logger.info(f"UWB> {response}")
                    
                    # Check for CONFIG_DATA response
                    if response.startswith("CONFIG_DATA "):
                        config_hex = response[12:].strip()  # Remove "CONFIG_DATA " prefix
                        if len(config_hex) > 0:
                            self.pending_config_response = config_hex
                            self.config_response_received = True
                            logger.info(f"✅ CONFIG_DATA captured: {len(config_hex)//2} bytes")
                        else:
                            logger.error("❌ Empty CONFIG_DATA received")
                            self.pending_config_response = "ERROR"
                            self.config_response_received = True
                    elif response.startswith("ERROR:") and hasattr(self, 'pending_config_response'):
                        self.pending_config_response = "ERROR"
                        self.config_response_received = True
                        logger.error(f"❌ CONFIG error: {response}")
                        
            except Exception as e:
                logger.error(f"UART read loop error: {e}")
                # Stop the loop if the serial connection is lost
                break
        logger.info("UART read loop stopped.")

    async def run(self):
        if not await self.setup_uart():
            logger.error("Critical error during startup. Exiting.")
            return

        # Start the UART reader as a background task (only if hardware is connected)
        if self.hardware_connected:
            self.uart_reader_task = asyncio.create_task(self.read_uart_loop())
            logger.info("UWB hardware reader task started")
        else:
            logger.info("Running without UWB hardware - mock responses enabled")

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
                elif topic == ZMQ_CONFIG_TOPIC:
                    logger.info(f"[ZMQ] uwbConfig request received")
                    try:
                        data = json.loads(payload)
                        request_id = data.get("request_id", "")
                        if request_id:
                            await self.handle_config_request(request_id)
                        else:
                            logger.warning("Received config request without request_id.")
                    except Exception as e:
                        logger.error(f"Error parsing config request: {e}")
            except Exception as e:
                logger.error(f"Error in ZMQ loop: {e}")
                await asyncio.sleep(1)

    async def handle_uwb_key(self, uwb_key_string: str):
        """Handle a key string coming from BLE via ZMQ.
        Accepts hex text. If the decoded bytes look like a bplist (starts with b"bplist"),
        parse it to extract rawToken and send NIQSTART command. Otherwise, treat bytes as
        the raw discovery token and format to VUPPER (colon-separated uppercase hex) for INITF.
        """
        if not self.hardware_connected and not self.mock_mode:
            logger.warning("UWB hardware not available; cannot process key.")
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
        if not self.hardware_connected:
            logger.info(f"Mock mode: Would send control command {ctrl_hex[:50]}{'...' if len(ctrl_hex)>50 else ''}")
            return
            
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
        
    async def get_uwb_config(self) -> Optional[str]:
        """Get UWB configuration data from DWM3001CDK for iPhone handshake.
        Returns hex string of config data or None if failed.
        Uses a response queue to avoid UART reader conflicts.
        """
        if not self.hardware_connected:
            logger.warning("Mock mode: Returning dummy config data")
            # Return dummy config data for testing
            return "01020304050607080910111213141516"
            
        if not self.serial_writer:
            logger.warning("UART not connected; cannot get config.")
            return None
            
        try:
            # Clear any pending config responses
            self.pending_config_response = None
            self.config_response_received = False
            
            # Send GETCONFIG command
            await self._send_uart_cmd("GETCONFIG\r\n")
            logger.info("GETCONFIG command sent")
            
            # Wait for response with timeout
            timeout_count = 0
            max_timeout = 30  # 3 seconds should be enough
            
            while timeout_count < max_timeout:
                if self.config_response_received:
                    config_hex = self.pending_config_response
                    if config_hex and config_hex != "ERROR":
                        logger.info(f"✅ UWB config received: {len(config_hex)//2} bytes")
                        return config_hex
                    else:
                        logger.error("❌ Config generation failed")
                        return None
                        
                await asyncio.sleep(0.1)
                timeout_count += 1
                
            logger.error("❌ Timeout waiting for GETCONFIG response")
            return None
            
        except Exception as e:
            logger.error(f"Error getting UWB config: {e}")
            return None
            
    async def handle_config_request(self, request_id: str):
        """Handle configuration data request from BLE service.
        Gets UWB config from DWM3001CDK and sends response via ZMQ.
        """
        logger.info(f"Config request: {request_id}")
        
        # Get UWB configuration data
        config_hex = await self.get_uwb_config()
        
        # Prepare response
        status = "success" if config_hex else "error"
        response = {
            "request_id": request_id,
            "config_data": config_hex,
            "status": status
        }
        
        # Send response back via ZMQ
        try:
            # Create a temporary publisher to send response
            pub_socket = self.ctx.socket(zmq.PUB)
            pub_socket.connect(XSUB_ADDR)  # Connect to XSUB for publishing responses
            
            # Give socket time to connect
            await asyncio.sleep(0.1)
            
            response_msg = json.dumps(response)
            pub_socket.send_string(f"uwbConfigResp {response_msg}")
            if config_hex:
                logger.info(f"✅ Config response sent: {len(config_hex)//2} bytes")
            else:
                logger.error("❌ Config response sent: FAILED")
            
            pub_socket.close()
            
        except Exception as e:
            logger.error(f"Error sending config response: {e}")

    async def _send_uart_cmd(self, cmd: str):
        if isinstance(cmd, str):
            data = cmd.encode('utf-8')
        else:
            data = cmd
            
        if not self.hardware_connected:
            try:
                shown = data.decode('utf-8', errors='ignore').strip()
            except Exception:
                shown = str(data)
            logger.info(f"Mock UART<= {shown}")
            return
            
        if not self.serial_writer:
            logger.warning("UART not connected; cannot send command.")
            return
            
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
