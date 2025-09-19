import logging
import itertools
import sys
import time

import sys
sys.path.append('./my_libs')

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:
    AES = None

logger = logging.getLogger("pn532_desfire")

class PN532Desfire:
    def __init__(self, pn532):
        self.pn532 = pn532

    def in_data_exchange(self, data):
        flat_data = list(itertools.chain.from_iterable(
            x if isinstance(x, (list, tuple)) else [x] for x in data
        ))
        logger.debug(f"Calling call_function with command=0x40, params={flat_data}")
        response = self.pn532.call_function(0x40, response_length=255, params=[0x01] + flat_data)
        if response and response[0] == 0x00:
            return response[1:]
        return response

    def send_apdu(self, apdu):
        try:
            print(f"APDU CMD: {' '.join(f'{b:02X}' for b in apdu)}")
            logger.debug(f"Sending APDU: {apdu}")
            response = self.in_data_exchange(apdu)
            print(f"APDU RESP: {response if response is None else ' '.join(f'{b:02X}' for b in response)}")
            logger.debug(f"APDU response: {response}")
            return response
        except Exception as e:
            logger.error(f"APDU send failed: {e}")
            return None

    def send_apdu_with_chaining(self, apdu):
        """
        Sends an APDU and automatically handles additional frames (0x91AF).
        Returns the concatenated data from all frames (excluding status bytes).
        """
        result = b''
        resp = self.send_apdu(apdu)
        while resp and resp[-2:] == b'\x91\xaf':
            result += resp[:-2]
            # Request next frame (always 5 bytes)
            resp = self.send_apdu([0x90, 0xAF, 0x00, 0x00, 0x00])
        if resp and resp[-2:] == b'\x91\x00':
            result += resp[:-2]
        return result if result else resp

    def select_application(self, aid=[0x00, 0x00, 0x00]):
        # 5 header + 3 aid + 1 Le = 9 bytes
        #apdu = [0x90, 0x5A, 0x00, 0x00, 0x03] + aid + [0x00]
        apdu = [0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00]
        return self.send_apdu(apdu)

    def create_application(self, aid, settings=0x0F, num_keys=1):
        # 5 header + 3 aid + 2 = 10 bytes
        apdu = [0x90, 0xCA, 0x00, 0x00, 0x05] + aid + [settings, num_keys]
        return self.send_apdu(apdu)

    def get_card_uid(self):
        try:
            uid = self.pn532.read_passive_target(timeout=1)
            if uid:
                print(f"Card UID: {uid.hex()}")
                return uid
            else:
                print("No card detected.")
                return None
        except Exception as e:
            logger.error(f"Failed to read card UID: {e}")
            return None

    def authenticate_aes(self, key_no=0x00, key=b'\x00'*16):
        if AES is None:
            print("pycryptodome is required for authentication.")
            return None

        # Step 1: Send AuthenticateEV2First (7 bytes: 5 header + 2 data)
        apdu = [0x90, 0x71, 0x00, 0x00, 0x02, key_no, 0x00]    #required for ev2/ev3
        #apdu = [0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00]    #required for desfire light

        print("AuthenticateEV2First APDU:", ' '.join(f'{b:02X}' for b in apdu))
        resp = self.send_apdu(apdu)
        if not resp or resp[-2:] != b'\x91\xAF':
            print("Auth step 1 failed:", resp)
            return None
        rndB_enc = resp[:-2]
        cipher = AES.new(key, AES.MODE_ECB)
        rndB = cipher.decrypt(bytes(rndB_enc))
        rndA = get_random_bytes(16)
        rndB_rot = rndB[1:] + rndB[:1]
        rndAB = rndA + rndB_rot
        rndAB_enc = cipher.encrypt(rndAB)
        apdu2 = [0x90, 0xAF, 0x00, 0x00, 0x10] + list(rndAB_enc)
        print("AuthenticateEV2Second APDU:", ' '.join(f'{b:02X}' for b in apdu2))
        resp2 = self.send_apdu(apdu2)
        if not resp2 or resp2[-2:] != b'\x91\x00':
            print("Auth step 2 failed:", resp2)
            return None
        print("Authenticated!")
        return True

    def create_std_data_file(self, file_no, file_size, comm_settings=0x00, read_key=0, write_key=0, rw_key=0, change_key=0):
        # 5 header + 7 data = 12 bytes
        apdu = [
            0x90, 0xCD, 0x00, 0x00, 0x07,
            file_no,
            comm_settings,
            ((read_key & 0x0F) << 4) | (write_key & 0x0F),
            ((rw_key & 0x0F) << 4) | (change_key & 0x0F),
            (file_size >> 16) & 0xFF,
            (file_size >> 8) & 0xFF,
            file_size & 0xFF
        ]
        return self.send_apdu(apdu)

    def write_data(self, file_no, offset, data_bytes):
        length = len(data_bytes)
        # 5 header + 7 + data length
        apdu = [
            0x90, 0x3D, 0x00, 0x00, 0x07 + length,
            file_no,
            (offset >> 16) & 0xFF,
            (offset >> 8) & 0xFF,
            offset & 0xFF,
            (length >> 16) & 0xFF,
            (length >> 8) & 0xFF,
            length & 0xFF
        ] + list(data_bytes)
        return self.send_apdu(apdu)

    def read_data(self, file_no, offset, length):
        # 5 header + 7 = 12 bytes
        apdu = [
            0x90, 0xBD, 0x00, 0x00, 0x07,
            file_no,
            (offset >> 16) & 0xFF,
            (offset >> 8) & 0xFF,
            offset & 0xFF,
            (length >> 16) & 0xFF,
            (length >> 8) & 0xFF,
            length & 0xFF
        ]
        return self.send_apdu(apdu)

    def change_key(self, key_no, old_key, new_key):
        if AES is None:
            print("pycryptodome is required for key change.")
            return None
        if not self.authenticate_aes(key_no, old_key):
            print("Authentication with old key failed.")
            return None
        # 5 header + 1 key_no + 16 new_key = 22 bytes
        apdu = [0x90, 0xC4, 0x00, 0x00, 0x11, key_no] + list(new_key)
        print("ChangeKey APDU:", ' '.join(f'{b:02X}' for b in apdu))
        resp = self.send_apdu(apdu)
        print("ChangeKey response:", resp)
        return resp

    def is_desfire_light(self):
        apdu = [0x90, 0x60, 0x00, 0x00, 0x00]  # 5 bytes
        resp = self.send_apdu_with_chaining(apdu)

        if resp and len(resp) >= 7:
            chip_type = resp[1]
            protocol_type = resp[6]
            print("chip_type (hex):", hex(chip_type), "protocol_type (hex):", hex(protocol_type))
            print("chip_type (dec):", chip_type, "protocol_type (dec):", protocol_type)
            print("resp:", resp)
            if chip_type == 0x08 and protocol_type == 0x05:
                print("DESFire Light card detected.")
                return True
            else:
                print("Not a DESFire Light card (GetVersion response does not match).")
        else:
            print("Failed to get card version or unexpected response.")
        return False

    def is_desfire_ev3(self):
        """
        Checks if the card is a DESFire EV3 card.
        Returns True if EV3, False otherwise.
        """
        apdu = [0x90, 0x60, 0x00, 0x00, 0x00]  # GetVersion command
        # Get the raw responses for each APDU
        responses = []
        resp = self.send_apdu(apdu)
        while resp and resp[-2:] == b'\x91\xaf':
            responses.append(resp)
            resp = self.send_apdu([0x90, 0xAF, 0x00, 0x00, 0x00])
        if resp and resp[-2:] == b'\x91\x00':
            responses.append(resp)
        if not responses:
            print("Failed to get card version or unexpected response.")
            return False
        # The last response is the actual GetVersion version block
        last_resp = responses[-1]
        if len(last_resp) >= 16:
            version = last_resp[:16]
            chip_type = version[0]
            protocol_type = version[9]
            print("chip_type (hex):", hex(chip_type), "protocol_type (hex):", hex(protocol_type))
            if chip_type == 0x04 and protocol_type == 0x63:
                print("DESFire EV3 card detected.")
                return True
            else:
                print("Not a DESFire EV3 card (GetVersion response does not match).")
        else:
            print("Final GetVersion response too short:", last_resp)
        return False

    def application_exists(self, aid):
        apdu = [0x90, 0x6A, 0x00, 0x00, 0x00]  # 5 bytes
        resp = self.send_apdu_with_chaining(apdu)
        if resp:
            print("application_exists response (hex):", ' '.join(f'{b:02X}' for b in resp))
        else:
            print("application_exists response: None")
        if not resp or len(resp) < 5:
            print("Failed to get application IDs or no applications present.")
            return False
        aids = [resp[i:i+3] for i in range(0, len(resp)-2, 3)]
        if any(list(a) == aid for a in aids):
            print(f"Application {aid} is present on the card.")
            return True
        print(f"Application {aid} is NOT present on the card.")
        return False

def do_config(desfire):
    # One-time setup: create app, file, write userid
    AID = [0xA1, 0xA2, 0xA3]
    FILE_NO = 1
    FILE_SIZE = 6
    USERID = b'opsky1'
    KEY = b'\x00' * 16  # Default key

    uid = desfire.get_card_uid()
    if not uid:
        return
    if not desfire.is_desfire_light():
        print("This is not a DESFire Light card. Checking for EV3...")
        if not desfire.is_desfire_ev3():
            print("This is not a DESFire EV3 card. Waiting for next card...")
            return

    print("Selecting PICC (no application) before authenticating with PICC master key...")
    desfire.select_application([0x00, 0x00, 0x00])

    print("Authenticating with PICC master key before creating application...")
    if not desfire.authenticate_aes(key_no=0x00, key=KEY):
        print("PICC master key authentication failed! Aborting setup.")
        return

    print("Checking if application exists...")
    if desfire.application_exists(AID):
        print("Application already exists. Skipping creation.")
    else:
        print("Creating application...")
        resp = desfire.create_application(AID)
        print("Create application response:", resp)
        if not resp or resp[-2:] != b'\x91\x00':
            print("Application creation failed! Aborting setup.")
            return

    print("Selecting new application...")
    resp = desfire.select_application(AID)
    print("Select application response:", resp)
    if not resp or resp[-2:] != b'\x91\x00':
        print("Application selection failed! Aborting setup.")
        return

    time.sleep(1)
    print("Authenticating (default key)...")
    desfire.authenticate_aes(key_no=0x00, key=KEY)
    print("Creating file...")
    desfire.create_std_data_file(FILE_NO, FILE_SIZE)
    print("Writing UserID...")
    desfire.write_data(FILE_NO, 0, USERID)
    print("Config complete.")

def do_tap(desfire):
    # Tap and read UserID in a loop
    AID = [0xA1, 0xA2, 0xA3]
    FILE_NO = 1
    FILE_SIZE = 6
    KEY = b'\x00' * 16  # Use your real key if changed

    print("Waiting for cards. Press Ctrl+C to exit.")
    while True:
        try:
            uid = desfire.get_card_uid()
            if not uid:
                continue
            if not desfire.is_desfire_light():
                print("This is not a DESFire Light card. Checking for EV3...")
                if not desfire.is_desfire_ev3():
                    print("This is not a DESFire EV3 card. Waiting for next card...")
                    continue

            print("Checking if application exists...")
            if not desfire.application_exists(AID):
                print("Application does not exist on this card. Waiting for next card...")
                continue
            
            print("Selecting application...")
            desfire.select_application(AID)

            print("Authenticating...")
            desfire.authenticate_aes(key_no=0x00, key=KEY)
            '''
            print("Reading UserID...")
            resp = desfire.read_data(FILE_NO, 0, FILE_SIZE)
            if resp:
                userid = bytes(resp[:-2]).decode(errors='ignore')
                print("UserID read from card:", userid)
            else:
                print("Failed to read UserID.")
            '''
            print("Remove card to continue...")
            # Wait for card removal before next loop
            while desfire.get_card_uid():
                pass
        except KeyboardInterrupt:
            print("\nExiting tap mode.")
            break

def do_change_key(desfire, old_key, new_key):
    # Change the application key
    if not desfire.is_desfire_light():
        print("This is not a DESFire Light card. Aborting key change.")
        return
    AID = [0xA1, 0xA2, 0xA3]
    desfire.get_card_uid()
    print("Selecting application...")
    desfire.select_application(AID)
    print("Changing key...")
    desfire.change_key(0x00, old_key, new_key)

if __name__ == "__main__":
    import pn532.pn532 as nfc
    from pn532 import PN532_UART

    logging.basicConfig(level=logging.INFO)
    pn532 = PN532_UART(debug=False, reset=20)
    pn532.SAM_configuration()
    desfire = PN532Desfire(pn532)

    if len(sys.argv) < 2:
        print("Usage: python nfc_desfire.py [config|tap|changekey]")
        sys.exit(1)

    cmd = sys.argv[1].lower()
    if cmd == "config":
        do_config(desfire)
    elif cmd == "tap":
        do_tap(desfire)
    elif cmd == "changekey":
        if len(sys.argv) != 4:
            print("Usage: python nfc_desfire.py changekey <oldkey_hex> <newkey_hex>")
            print("Example: python nfc_desfire.py changekey 00000000000000000000000000000000 11223344556677889900aabbccddeeff")
            sys.exit(1)
        old_key = bytes.fromhex(sys.argv[2])
        new_key = bytes.fromhex(sys.argv[3])
        do_change_key(desfire, old_key, new_key)
    else:
        print("Unknown command. Use config, tap, or changekey.")