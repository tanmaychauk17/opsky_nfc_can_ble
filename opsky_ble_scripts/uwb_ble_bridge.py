import serial
import time

DEVICE_PATH = '/dev/ttyACM0'  # Adjust if needed

class UWBController:
    def __init__(self, device=DEVICE_PATH, baudrate=115200, timeout=1):
        self.device = device
        self.baudrate = baudrate
        self.timeout = timeout
        self.ser = None

    def open(self):
        try:
            self.ser = serial.Serial(self.device, baudrate=self.baudrate, timeout=self.timeout)
            print(f"[UWB] Connected to {self.device}")
        except Exception as e:
            print(f"[UWB][ERROR] Failed to open serial port {self.device}: {e}")
            self.ser = None

    def close(self):
        if self.ser:
            self.ser.close()
            print("[UWB] Serial closed.")

    def send_command(self, cmd):
        if not self.ser:
            print(f"[UWB][ERROR] Serial port not open when sending command: {cmd}")
            return "[UWB][ERROR] Serial port not open"
        try:
            self.ser.write((cmd + '\r\n').encode())
            response = b''
            max_wait = 2.0
            poll_interval = 0.05
            waited = 0.0
            while waited < max_wait:
                if self.ser.in_waiting > 0:
                    response += self.ser.read(self.ser.in_waiting)
                    time.sleep(poll_interval)
                    if self.ser.in_waiting == 0:
                        break
                else:
                    time.sleep(poll_interval)
                    waited += poll_interval
            return response.decode(errors='ignore')
        except Exception as e:
            print(f"[UWB][ERROR] Failed to send command '{cmd}': {e}")
            return f"[UWB][ERROR] Failed to send command '{cmd}': {e}"

    def start_listener(self):
        return self.send_command('LISTENER')

    def get_status(self):
        return self.send_command('STAT')

    def get_lstat(self):
        return self.send_command('LSTAT')

    def stop(self):
        return self.send_command('STOP')

if __name__ == "__main__":
    uwb = UWBController()
    uwb.open()
    print("[BLE] Simulated BLE: start_listener")
    print(uwb.start_listener())
    print("[BLE] Simulated BLE: get_status")
    print(uwb.get_status())
    print("[BLE] Simulated BLE: get_lstat")
    print(uwb.get_lstat())
    print("[BLE] Simulated BLE: stop")
    print(uwb.stop())
    uwb.close()
