"""
ECDSA Utilities for BLE Protocol v3

- Loads public keys for each MDID from the keys/ directory.
- Verifies ECDSA signatures for authentication (MDID) and command (OPCODE+PAYLOAD) steps.
- Handles both legacy (MDID+OPCODE+PAYLOAD) and v3 (OPCODE+PAYLOAD only) signature verification.
- All signatures are DER-encoded and variable length.
- Provides detailed logging for all verification steps and artifacts.

Usage:
    verify_signature(mdid: bytes, signature: bytes) -> bool
        Verifies signature over MDID for authentication.
    verify_opcode_signature_v3(opcode: int, payload: bytes, signature: bytes, mdid_hex: str) -> bool
        Verifies signature over OPCODE+PAYLOAD for commands after authentication.
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
import logging

KEYS_DIR = os.path.join(os.path.dirname(__file__), 'keys')

def get_public_key_for_mdid(mdid_hex: str):
    """
    Given MDID as hex string (e.g. 'FF0000000001'), load the corresponding public key PEM file.
    Ignores the first 4 characters (2 bytes) if present (e.g., '0001ff0000000001' -> 'ff0000000001').
    """
    # Remove first 4 characters if mdid_hex is longer than 12
    mdid_actual = mdid_hex[4:] if len(mdid_hex) > 12 else mdid_hex
    # Validation: length and hex format
    valid = True
    if len(mdid_actual) != 12:
        valid = False
    else:
        try:
            int(mdid_actual, 16)
        except ValueError:
            valid = False
    allowed_mdids = {f"ff000000000{i:x}" for i in range(1, 10)}.union({f"ff000000000{i}" for i in 'A B C D E F'.split()})
    if not valid or mdid_actual.lower() not in allowed_mdids:
        mdid_actual = "ff0000000001"
    filename = f"public_key_{mdid_actual.lower()}.pem"
    path = os.path.join(KEYS_DIR, filename)
        # Fallback: if constructed file does not exist, use default
    if not os.path.exists(path):
        fallback_path = os.path.join(KEYS_DIR, "public_key_ff0000000001.pem")
        if os.path.exists(fallback_path):
            path = fallback_path
        else:
            raise FileNotFoundError(f"Public key file not found for MDID {mdid_hex}: {path}")
    with open(path, 'rb') as f:
        pem_data = f.read()
    return load_pem_public_key(pem_data)

def verify_signature(mdid: bytes, signature: bytes) -> bool:
    """
    Verify the signature for the given MDID using the corresponding public key.
    - mdid: bytes (6 bytes)
    - signature: bytes (signature from mobile)
    Returns True if valid, False otherwise.
    """
    logger = logging.getLogger(__name__)
    mdid_hex = mdid.hex()
    # Remove first 4 chars if present for actual MDID
    mdid_actual = mdid_hex[4:] if len(mdid_hex) > 12 else mdid_hex
    try:
        logger.info(f"[ECDSA] Verifying signature for MDID: {mdid_hex.upper()} (actual for key lookup: {mdid_actual.upper()})")
        public_key = get_public_key_for_mdid(mdid_hex)
        logger.info(f"[ECDSA] Loaded public key: public_key_{mdid_actual.lower()}.pem")
        logger.info(f"[ECDSA] Message: {mdid.hex().upper()}")
        logger.info(f"[ECDSA] Signature: {signature.hex().upper()}")
        public_key.verify(
            signature,
            mdid,
            ec.ECDSA(hashes.SHA256())
        )
        logger.info(f"[ECDSA] Signature verification: OK")
        return True
    except FileNotFoundError as e:
        logger.error(f"[ECDSA] Public key file not found: {e}")
        return False
    except InvalidSignature:
        logger.warning(f"[ECDSA] Signature verification: FAILED")
        return False
    except Exception as e:
        logger.error(f"[ECDSA] Unexpected error: {e}")
        return False

def verify_opcode_signature(mdid: bytes, opcode: int, payload: bytes, signature: bytes) -> bool:
    """
    Verify the signature for the given opcode+payload using the public key for MDID.
    - mdid: bytes (6 bytes)
    - opcode: int (2 bytes, big endian)
    - payload: bytes (any length)
    - signature: bytes (signature from mobile)
    Returns True if valid, False otherwise.
    The message to sign is: mdid + opcode (2 bytes) + payload
    """
    logger = logging.getLogger(__name__)
    mdid_hex = mdid.hex()
    try:
        logger.info(f"[ECDSA] Verifying opcode signature for MDID: {mdid_hex.upper()}")
        public_key = get_public_key_for_mdid(mdid_hex)
        logger.info(f"[ECDSA] Loaded public key: public_key_{mdid_hex.lower()}.pem")
        message = mdid + opcode.to_bytes(2, 'big') + payload
        logger.info(f"[ECDSA] Message: {message.hex().upper()}")
        logger.info(f"[ECDSA] Signature: {signature.hex().upper()}")
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        logger.info(f"[ECDSA] Opcode signature verification: OK")
        return True
    except FileNotFoundError as e:
        logger.error(f"[ECDSA] Public key file not found: {e}")
        return False
    except InvalidSignature:
        logger.warning(f"[ECDSA] Opcode signature verification: FAILED")
        return False
    except Exception as e:
        logger.error(f"[ECDSA] Unexpected error: {e}")
        return False

def verify_opcode_signature_v3(opcode: int, payload: bytes, signature: bytes, mdid_hex: str) -> bool:
    """
    Verify the signature for OPCODE+PAYLOAD using the public key for MDID (v3, no MDID in message).
    - opcode: int (2 bytes, big endian)
    - payload: bytes (any length)
    - signature: bytes (signature from mobile)
    - mdid_hex: str (e.g. 'FF0000000001')
    Returns True if valid, False otherwise.
    The message to sign is: opcode (2 bytes) + payload
    """
    logger = logging.getLogger(__name__)
    try:
        logger.info(f"[ECDSA] Verifying opcode signature (v3, no MDID) for MDID: {mdid_hex.upper()}")
        public_key = get_public_key_for_mdid(mdid_hex)
        message = opcode.to_bytes(2, 'big') + payload
        logger.info(f"[ECDSA] Message: {message.hex().upper()}")
        logger.info(f"[ECDSA] Signature: {signature.hex().upper()}")
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        logger.info(f"[ECDSA] Opcode signature verification (v3): OK")
        return True
    except FileNotFoundError as e:
        logger.error(f"[ECDSA] Public key file not found: {e}")
        return False
    except InvalidSignature:
        logger.warning(f"[ECDSA] Opcode signature verification (v3): FAILED")
        return False
    except Exception as e:
        logger.error(f"[ECDSA] Unexpected error: {e}")
        return False

def get_device_private_key():
    """
    Load the device's private key for signing responses.
    Selects the key file based on BLE advertising name in config.json.
    """
    import json
    # Load advertising name from config.json
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
    try:
        with open(CONFIG_PATH) as f:
            config = json.load(f)
        adv_name = config.get("ble_adv_name", "OPSKY_DEVICE_DEFAULT")
    except Exception:
        adv_name = "OPSKY_DEVICE_DEFAULT"
    # Normalize adv_name: lowercase, replace non-alnum with _
    import re
    adv_name_norm = re.sub(r'[^a-zA-Z0-9]', '_', adv_name).lower()
    filename = f"private_key_{adv_name_norm}.pem"
    path = os.path.join(KEYS_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Device private key not found: {path}")
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    with open(path, 'rb') as f:
        pem_data = f.read()
    return load_pem_private_key(pem_data, password=None)

def sign_data(data: bytes) -> bytes:
    """
    Sign data using the device's private key for Protocol v3 responses.
    - data: bytes to sign
    Returns DER-encoded signature bytes.
    """
    logger = logging.getLogger(__name__)
    try:
        logger.info(f"[ECDSA] Signing data: {len(data)} bytes")
        private_key = get_device_private_key()

        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        logger.info(f"[ECDSA] Signature created: {len(signature)} bytes")
        return signature
    except Exception as e:
        logger.error(f"[ECDSA] Error signing data: {e}")
        raise
