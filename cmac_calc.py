

from Crypto.Cipher import AES
import logging
from typing import Tuple



class CMACVerificationError(Exception):
    """Raised when CMAC verification fails."""
    pass

class CMACSession:
    """
    Helper class to manage session IV and verify a sequence of responses.
    Handles CMAC calculation and verification for a session.
    Maintains session key and IV state.
    """
    def __init__(self, session_key: bytes, initial_iv: bytes = None):
        """
        Initialize with a session key (16 bytes) and optional IV.
        """
        if not isinstance(session_key, bytes) or len(session_key) != 16:
            raise ValueError("session_key must be 16 bytes")
        self.session_key: bytes = session_key
        self.session_iv: bytes = initial_iv if initial_iv is not None else b'\x00' * 16
        self.subkey1: bytes = generate_subkey_1(session_key)
        self.subkey2: bytes = generate_subkey_2(self.subkey1)

    def calculate(self, data: bytes, session_iv: bytes = None) -> Tuple[bytes, bytes]:
        """
        Calculate CMAC for a block of data. Returns (cmac, updated_iv).
        Prints all relevant cryptographic material for debugging.
        """
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        if session_iv is None:
            session_iv = self.session_iv
        logger.info(f"[CMACSession] Data:        {data.hex()}")
        logger.info(f"[CMACSession] Session Key: {self.session_key.hex()}")
        logger.info(f"[CMACSession] Subkey1:     {self.subkey1.hex()}")
        logger.info(f"[CMACSession] Subkey2:     {self.subkey2.hex()}")
        logger.info(f"[CMACSession] IV:          {session_iv.hex()}")
        # Padding logic: if data length is exactly 16 or 32, no padding. Otherwise, pad.
        if len(data) == 16 or len(data) == 32:
            padded = data
            needs_padding = False
            logger.info("[CMACSession] No padding required (len=16 or 32)")
        else:
            padded = pad_data(data)
            needs_padding = True
            logger.info("[CMACSession] Padding was added (len != 16 and != 32)")
        logger.info(f"[CMACSession] Padded data: {padded.hex()}")
        # XOR last block
        last_block = bytearray(padded[-16:])
        if needs_padding:
            #logger.info("[CMACSession] XOR last block with subkey2 (padded)")
            for i in range(16):
                last_block[i] ^= self.subkey2[i]
        else:
            #logger.info("[CMACSession] XOR last block with subkey1 (not padded)")
            for i in range(16):
                last_block[i] ^= self.subkey1[i]
        #logger.info(f"[CMACSession] XOR output (last block after XOR): {last_block.hex()}")
        # Replace last block
        padded = padded[:-16] + bytes(last_block)
        # Encrypt
        cipher = AES.new(self.session_key, AES.MODE_CBC, session_iv)
        encrypted = cipher.encrypt(padded)
        logger.info(f"[CMACSession] CMAC encrypted: {encrypted.hex()}")
        # Update IV
        updated_iv = encrypted[-16:]
        cmac = updated_iv[:8]
        logger.info(f"[CMACSession] CMAC: {cmac.hex()}")
        return cmac, updated_iv

    def verify_read_response(self, resp: bytes, updated_iv: bytes = None, logger=None) -> bytes:
        """
        Verifies the CMAC of a DESFire read response and extracts the data+status bytes.
        Returns data_bytes (32 bytes data + 1 status byte) if CMAC matches.
        Raises CMACVerificationError if verification fails.
        """
        if logger is None:
            logger = logging.getLogger("cmac")
        if updated_iv is None:
            updated_iv = self.session_iv
        if not isinstance(resp, (bytes, bytearray)):
            raise TypeError("resp must be bytes or bytearray")
        if len(resp) < 41:
            logger.error("[CMACSession] Response too short for CMAC verification.")
            raise CMACVerificationError("Response too short for CMAC verification.")
        data_bytes = resp[1:33] + resp[0:1]
        logger.info(f"[CMACSession] Read data+status (hex): {data_bytes.hex()}")
        cmac, _ = self.calculate(data_bytes, updated_iv)
        if cmac != resp[-8:]:
            logger.error(f"[CMACSession] CMAC verification FAILED: does not match card. Calculated CMAC: {cmac.hex()}, Card CMAC: {bytes(resp[-8:]).hex()}")
            raise CMACVerificationError("CMAC does not match card.")
        logger.info("[CMACSession] CMAC verification SUCCESS: matches card.")
        return data_bytes

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



if __name__ == "__main__":
    # --- Card response CMAC verification demo with session IV update ---
    session_key_bytes   = bytes.fromhex('05CA26E4AEF34BF0A7D10A82D87F699F')
    session_iv_bytes    = bytes.fromhex('00000000000000000000000000000000')

    #Calculate the CMAC for the command being sent, use this CMAC as session iv for the next calculation.
    cmac_session = CMACSession(session_key_bytes)
    data = bytes.fromhex('BD00000000200000')
    cmac_calc, updated_iv = cmac_session.calculate(data)

    print("**************Iteration 2")
    #use previously generated cmac as iv and calculate the cmac for the received data (responseData + status)
    response_bytes = bytes.fromhex('464530352C312C6F70736B79310000000000000000000000000000000000000000')
    #response_buffer =     bytes.fromhex('00464530352C312C6F70736B793100000000000000000000000000000000000000EE69E1D312FC2519')
    cmac_calc, updated_iv = cmac_session.calculate(response_bytes, updated_iv)
    #cmac_session.verify_response(response_buffer)
