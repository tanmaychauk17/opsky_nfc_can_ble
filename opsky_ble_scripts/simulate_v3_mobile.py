"""
Protocol v3 Mobile/Transceiver Simulation

This script simulates the BLE protocol v3 data exchange between a mobile app and a transceiver.

- Generates ECDSA signatures for authentication (MDID) and command (OPCODE+PAYLOAD) steps using the user's private key.
- Constructs the exact byte packets as sent over BLE.
- Simulates the transceiver side: verifies signatures using the public key, mimicking the real device's logic.
- Handles DER-encoded, variable-length ECDSA signatures.
- Allows testing with any MDID/private key by passing as a command-line argument.
- Provides detailed logging for all steps, artifacts, and verification results.

Usage:
    python simulate_v3_mobile.py [MDID]
    # Example: python simulate_v3_mobile.py FF0000000001

Dependencies:
    - cryptography
    - keys/private_key_<mdid>.pem and keys/public_key_<mdid>.pem must exist
"""

import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import logging
from ecdsa_utils import verify_signature, verify_opcode_signature, get_public_key_for_mdid

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)

KEYS_DIR = os.path.join(os.path.dirname(__file__), 'keys')

def load_private_key(path):
    with open(path, 'rb') as f:
        return load_pem_private_key(f.read(), password=None)

def sign_message(private_key, message: bytes) -> bytes:
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def simulate_transceiver_side(auth_packet, cmd_packet, mdid_hex):
    logger.info("\n--- Transceiver Side Simulation ---")
    mdid = bytes.fromhex(mdid_hex)
    # Simulate authentication step
    recv_mdid = auth_packet[:6]
    recv_signature = auth_packet[6:]
    logger.info(f"[TRANSCEIVER] Received AUTH PACKET: {auth_packet.hex().upper()}")
    if verify_signature(recv_mdid, recv_signature):
        logger.info(f"[TRANSCEIVER] Authentication SUCCESS for MDID {recv_mdid.hex().upper()}")
    else:
        logger.error(f"[TRANSCEIVER] Authentication FAILED for MDID {recv_mdid.hex().upper()}")
        return
    # Simulate command step (after auth)
    # Use the same split as when building the packet
    opcode = int.from_bytes(cmd_packet[:2], 'big')
    payload = cmd_packet[2:2+2]  # 2 bytes for payload as in simulation
    signature = cmd_packet[2+2:]
    logger.info(f"[TRANSCEIVER] Received COMMAND PACKET: {cmd_packet.hex().upper()}")
    from ecdsa_utils import verify_opcode_signature_v3
    if verify_opcode_signature_v3(opcode, payload, signature, mdid_hex):
        logger.info(f"[TRANSCEIVER] Command signature SUCCESS for OPCODE {opcode:04X}")
    else:
        logger.error(f"[TRANSCEIVER] Command signature FAILED for OPCODE {opcode:04X}")

def simulate_v3_exchange(mdid_hex=None):
    if mdid_hex is None:
        mdid_hex = 'FF0000000001'
    mdid_hex = mdid_hex.upper()
    mdid = bytes.fromhex(mdid_hex)
    private_key_file = os.path.join(KEYS_DIR, f'private_key_{mdid_hex.lower()}.pem')
    logger.info(f"--- Protocol v3 Simulation for MDID {mdid_hex} ---")
    private_key = load_private_key(private_key_file)
    # Step 1: Mobile sends MDID + signature (for authentication)
    auth_signature = sign_message(private_key, mdid)
    auth_packet = mdid + auth_signature
    logger.info(f"[MOBILE->TRANSCEIVER] AUTH PACKET: {auth_packet.hex().upper()}")
    logger.info(f"  MDID: {mdid.hex().upper()}")
    logger.info(f"  Signature: {auth_signature.hex().upper()}")
    # Step 2: Mobile sends command (OPCODE + PAYLOAD + signature)
    opcode = 0x000C  # Example opcode
    payload = b'\x01\x02'  # Example payload
    cmd_message = opcode.to_bytes(2, 'big') + payload
    cmd_signature = sign_message(private_key, cmd_message)
    cmd_packet = cmd_message + cmd_signature
    logger.info(f"[MOBILE->TRANSCEIVER] COMMAND PACKET: {cmd_packet.hex().upper()}")
    logger.info(f"  OPCODE: {opcode:04X}")
    logger.info(f"  PAYLOAD: {payload.hex().upper()}")
    logger.info(f"  Signature: {cmd_signature.hex().upper()}")
    # Simulate transceiver side
    simulate_transceiver_side(auth_packet, cmd_packet, mdid_hex)

if __name__ == '__main__':
    mdid_arg = sys.argv[1] if len(sys.argv) > 1 else None
    simulate_v3_exchange(mdid_arg)
