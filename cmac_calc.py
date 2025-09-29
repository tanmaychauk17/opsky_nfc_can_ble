import sys
sys.path.append('./my_libs')

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import CMAC
except ImportError:
    AES = None

class CMACSession:
    """
    Helper class to manage session IV and verify a sequence of responses.
    """
    def __init__(self, session_key: bytes, initial_iv: bytes = None):
        self.session_key = session_key
        self.session_iv = initial_iv if initial_iv is not None else b'\x00' * 16
        self.subkey1 = generate_subkey_1(session_key)
        self.subkey2 = generate_subkey_2(self.subkey1)

    def verify_response(self, response: bytes) -> bool:
        if len(response) < 9:
            logger.error("Response too short to contain status, data, and CMAC.")
            return False
        status = response[0:1]
        data = response[1:-8]
        cmac_from_card = response[-8:]
        logger.info(f"Status: {status.hex()}")
        logger.info(f"Data: {data.hex()}")
        logger.info(f"CMAC from card: {cmac_from_card.hex()}")
        cmac_input = data + status
        cmac_calc, updated_iv = cmac_calculate(cmac_input, self.session_key, self.session_iv, self.subkey1, self.subkey2)
        logger.info(f"Calculated CMAC: {cmac_calc.hex()}")
        match = cmac_calc == cmac_from_card
        if match:
            logger.info("CMAC verification SUCCESS: matches card.")
        else:
            logger.error("CMAC verification FAILED: does not match card.")
        # Update IV for next message
        self.session_iv = updated_iv
        return match

def verify_card_response_cmac(session_key: bytes, session_iv: bytes, response: bytes) -> bool:
    """
    Verifies the CMAC in a card response.
    response: status(1) + data(N) + cmac(8)
    Returns True if CMAC matches, False otherwise.
    """
    if len(response) < 9:
        logger.error("Response too short to contain status, data, and CMAC.")
        return False
    status = response[0:1]
    data = response[1:-8]
    cmac_from_card = response[-8:]
    logger.info(f"Status: {status.hex()}")
    logger.info(f"Data: {data.hex()}")
    logger.info(f"CMAC from card: {cmac_from_card.hex()}")
    # Prepare CMAC input: data + status
    cmac_input = data + status
    cmac_input = status + data
    subkey1 = generate_subkey_1(session_key)
    subkey2 = generate_subkey_2(subkey1)
    cmac_calc, _ = cmac_calculate(cmac_input, session_key, session_iv, subkey1, subkey2)
    logger.info(f"Calculated CMAC: {cmac_calc.hex()}")
    match = cmac_calc == cmac_from_card
    if match:
        logger.info("CMAC verification SUCCESS: matches card.")
    else:
        logger.error("CMAC verification FAILED: does not match card.")
    return match


# --- Modular CMAC/CRC Implementation ---
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- Global Config ---
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import Tuple

# --- Global Config ---
session_key = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")
session_iv = b"\x00" * 16
test_data = b""  # Set this to your test data

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cmac")

def pad_data(data: bytes) -> bytes:
    """Pad data as per CMAC spec: 0x80 then 0x00s to next 16-byte boundary."""
    pad_len = 16 - (len(data) % 16)
    if pad_len == 0:
        return data
    return data + b'\x80' + b'\x00' * (pad_len - 1)

def generate_subkey_1(session_key: bytes) -> bytes:
    zero_block = b'\x00' * 16
    iv = b'\x00' * 16
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(zero_block)
    msb_set = (encrypted[0] & 0x80) != 0
    result = bytearray(encrypted)
    carry = 0
    for i in range(15, -1, -1):
        new_carry = (result[i] & 0x80) >> 7
        result[i] = ((result[i] << 1) | carry) & 0xFF
        carry = new_carry
    if msb_set:
        result[15] ^= 0x87
    logger.info(f"Subkey1: {result.hex()}")
    return bytes(result)

def generate_subkey_2(subkey_1: bytes) -> bytes:
    msb_set = (subkey_1[0] & 0x80) != 0
    result = bytearray(subkey_1)
    carry = 0
    for i in range(15, -1, -1):
        new_carry = (result[i] & 0x80) >> 7
        result[i] = ((result[i] << 1) | carry) & 0xFF
        carry = new_carry
    if msb_set:
        result[15] ^= 0x87
    logger.info(f"Subkey2: {result.hex()}")
    return bytes(result)

def crc32_custom(data: bytes) -> int:
    poly = 0xEDB88320
    crc = 0xFFFFFFFF
    for n in data:
        crc ^= n
        for b in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
    return crc

def cmac_calculate(data: bytes, session_key: bytes, session_iv: bytes, subkey1: bytes, subkey2: bytes) -> Tuple[bytes, bytes]:
    """
    Calculate CMAC for a block of data. Returns (cmac, updated_iv)
    """
    logger.info(f"CMAC input data: {data.hex()}")
    logger.info(f"CMAC encryption key: {session_key.hex()}")
    # Padding
    needs_padding = (len(data) == 0 or len(data) % 16 != 0)
    padded = pad_data(data)
    logger.info(f"Padded data: {padded.hex()}")
    # XOR last block
    last_block = bytearray(padded[-16:])
    if needs_padding:
        logger.info("Padding was added, XOR last block with subkey2")
        for i in range(16):
            last_block[i] ^= subkey2[i]
    else:
        logger.info("No padding, XOR last block with subkey1")
        for i in range(16):
            last_block[i] ^= subkey1[i]
    logger.info(f"XOR output (last block after XOR): {last_block.hex()}")
    # Replace last block
    padded = padded[:-16] + bytes(last_block)
    # Encrypt
    cipher = AES.new(session_key, AES.MODE_CBC, session_iv)
    encrypted = cipher.encrypt(padded)
    logger.info(f"CMAC encrypted: {encrypted.hex()}")
    # Update IV
    updated_iv = encrypted[-16:]
    cmac = updated_iv[:8]
    logger.info(f"CMAC: {cmac.hex()}")
    return cmac, updated_iv

if __name__ == "__main__":
    # --- Card response CMAC verification demo with session IV update ---
    session_key_bytes   = bytes.fromhex('0BC67C01B13F822DC0B7591F771726AF')
    response_bytes      = bytes.fromhex('003132333435368564572DB0B05CC7')
    session_iv_bytes    = bytes.fromhex('00000000000000000000000000000000')
    #session_iv_bytes   = bytes.fromhex('38 AA 22 3E 9C 4F 00 78 C0 23 16 DC 0B C4 94 7B')

    logger.info("\n--- Card Response CMAC Verification (with session IV tracking) ---")
    cmac_session = CMACSession(session_key_bytes)
    cmac_session.verify_response(response_bytes)
