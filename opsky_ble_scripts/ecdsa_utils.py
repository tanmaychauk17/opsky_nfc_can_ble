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
    """
    filename = f"public_key_{mdid_hex.lower()}.pem"
    path = os.path.join(KEYS_DIR, filename)
    if not os.path.exists(path):
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
    try:
        logger.info(f"[ECDSA] Verifying signature for MDID: {mdid_hex.upper()}")
        public_key = get_public_key_for_mdid(mdid_hex)
        logger.info(f"[ECDSA] Loaded public key: public_key_{mdid_hex.lower()}.pem")
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
