#!/usr/bin/env python3
# =============================================================================
# STM32 Secure Bootloader Firmware Generator
#
# Purpose:
#   Creates a production-ready firmware image with embedded security artifacts:
#   - Encrypted AES key (for firmware decryption)
#   - Initialization Vector (IV)
#   - ECC public key (for signature verification)
#   - CRC32 checksum (for integrity verification)
#
# Security Architecture:
#   1. Layered Encryption:
#      - AES_KEY1 (encrypted with AES_KEY2) → Used for firmware decryption
#      - AES_KEY2 → Used only to decrypt AES_KEY1 (never stored in firmware)
#   2. Hardware Binding:
#      - ECC public key embedded for secure authentication
#   3. Integrity Protection:
#      - CRC32 over first 32KB of firmware
#
# Typical Workflow:
#   1. Build application binary (SecBoot_S.bin)
#   2. Run this script to inject security block at 0x8000
#   3. Deploy secured image to target (SecBoot_Bootloader.bin)
#
# Security Critical Operations:
#   - All keys loaded from secure keyring (not hardcoded)
#   - Uses FIPS-approved algorithms (AES-256-CBC, ECC P-256)
#   - Little-endian word alignment for STM32 compatibility
#
# Requirements:
#   pip install cryptography keyring
# =============================================================================

import os
import sys
import subprocess
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from binascii import unhexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import keyring

# =============================================================================
# CONFIGURATION (Production Deployment)
# =============================================================================
INPUT_BIN = "../Makefile/Secure/build/SecBoot_S.bin"          # Raw firmware binary
OUTPUT_BIN = "../Artifacts/SecBoot_Bootloader.bin"
KEY_PEM = "/home/pi/Documents/STM32/SecBoot/Script/keys/ec_private.pem"                           # ECC private key (PEM)
SEC_BLOCK_OFFSET = 0x8000                                    # Security block offset
FINAL_SIZE = 254016                                          # Enforced firmware size


# =============================================================================
# KEY MANAGEMENT (Secure Storage)
# =============================================================================

# Retrieve keys from the system keyring
AES_KEY1 = keyring.get_password("secboot_secrets", "aes_key_1")
AES_KEY2 = keyring.get_password("secboot_secrets", "aes_key_2")
AES_IV   = keyring.get_password("secboot_secrets", "aes_iv")

# Check if any key is missing
if not all([AES_KEY1, AES_KEY2, AES_IV]):
    print("[INFO] Missing keys detected. Running './store_keys.py' to generate/store keys...")
    
    try:
        subprocess.run(["python3", "./store_keys.py"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to run 'store_keys.py': {e}")
        sys.exit(1)

    # Retry retrieving keys after script execution
    AES_KEY1 = keyring.get_password("secboot_secrets", "aes_key_1")
    AES_KEY2 = keyring.get_password("secboot_secrets", "aes_key_2")
    AES_IV   = keyring.get_password("secboot_secrets", "aes_iv")

    # Final check to ensure keys are now available
    if not all([AES_KEY1, AES_KEY2, AES_IV]):
        print("[ERROR] Keys are still missing after running 'store_keys.py'. Exiting.")
        sys.exit(1)

# Convert hex strings to bytes
key_to_be_encrypted = bytes.fromhex(AES_KEY1)  # Will be encrypted and embedded
key = bytes.fromhex(AES_KEY2)                  # Used only for key encryption
iv = bytes.fromhex(AES_IV)                     # AES-CBC initialization vector

# =============================================================================
# CRYPTOGRAPHIC OPERATIONS
# =============================================================================
# Encrypt AES_KEY1 with AES_KEY2 using AES-256-CBC with PKCS7 padding
padder = padding.PKCS7(128).padder()
padded_data = padder.update(key_to_be_encrypted) + padder.finalize()
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
encrypted_key = encryptor.update(padded_data) + encryptor.finalize()

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def hex_string_to_words_le(hex_string):
    """Convert hex string to little-endian 4-byte words (STM32 compatible)"""
    data = unhexlify(hex_string)
    return [data[i:i+4][::-1] for i in range(0, len(data), 4)]

def stm32_crc32(data_bytes):
    """
    STM32-compatible CRC32 implementation
    - Polynomial: 0x04C11DB7
    - Initial value: 0xFFFFFFFF
    - No output reversal (matches hardware)
    """
    crc = 0xFFFFFFFF
    for byte in data_bytes:
        crc ^= (byte << 24)
        for _ in range(8):
            if crc & 0x80000000:
                crc = (crc << 1) ^ 0x04C11DB7
            else:
                crc = crc << 1
        crc &= 0xFFFFFFFF
    return crc

def load_ec_pubkey():
    """Extract public key components from ECC private key file"""
    with open(KEY_PEM, "rb") as f:
        priv_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
        pub_key = priv_key.public_key()
        pub_nums = pub_key.public_numbers()
        return (
            pub_nums.x.to_bytes(32, 'big'),  # QX component
            pub_nums.y.to_bytes(32, 'big')   # QY component
        )

# =============================================================================
# MAIN FIRMWARE GENERATION
# =============================================================================
def build_secure_image():
    # Validate input file existence
    if not os.path.exists(INPUT_BIN):
        raise FileNotFoundError(f"Production firmware not found at {INPUT_BIN}")

    # Read input binary with strict size checking
    with open(INPUT_BIN, "rb") as f:
        firmware = bytearray(f.read())

    if len(firmware) != FINAL_SIZE:
        raise ValueError(
            f"Firmware must be exactly {FINAL_SIZE} bytes for secure boot. "
            f"Got {len(firmware)} bytes"
        )

    # -------------------------------------------------------------------------
    # SECURITY BLOCK CONSTRUCTION
    # -------------------------------------------------------------------------
    print("\n[SECURITY] Building Authentication Block at 0x{:X}".format(SEC_BLOCK_OFFSET))
    
    # 1. Calculate CRC over protected region (first 32KB)
    crc_data = firmware[:SEC_BLOCK_OFFSET]
    crc = stm32_crc32(crc_data)
    print(f"• Integrity CRC32: 0x{crc:08X} (over 0x{SEC_BLOCK_OFFSET:X} bytes)")

    # 2. Prepare security block
    sec_block = bytearray()

    # 3. Add encrypted AES key (32 bytes)
    print("\n[ENCRYPTION] Key Material:")
    print("----------------------------------------")
    key_words = hex_string_to_words_le(encrypted_key.hex())
    for i, word in enumerate(key_words):
        sec_block += word
        print(f"• AES_KEY1 Part {i}: 0x{word[::-1].hex().upper()}")  # Show as big-endian

    # 4. Add AES IV (16 bytes)
    iv_words = hex_string_to_words_le(iv.hex())
    for i, word in enumerate(iv_words):
        sec_block += word
        if i == 0:  # Only print once to avoid clutter
            print(f"• AES_IV: 0x{iv.hex().upper()}")

    # 5. Add ECC Public Key (64 bytes)
    qx, qy = load_ec_pubkey()
    sec_block += qx
    sec_block += qy
    print("\n[AUTHENTICATION] ECC Public Key:")
    print("----------------------------------------")
    print(f"• QX: 0x{qx.hex().upper()}")
    print(f"• QY: 0x{qy.hex().upper()}")

    # 6. Add CRC (4 bytes, little-endian)
    sec_block += crc.to_bytes(4, 'little')
    print(f"\n[INTEGRITY] Final CRC32: 0x{crc.to_bytes(4, 'little').hex().upper()}")

    # -------------------------------------------------------------------------
    # FIRMWARE ASSEMBLY
    # -------------------------------------------------------------------------
    # Insert security block at predefined offset
    firmware[SEC_BLOCK_OFFSET:SEC_BLOCK_OFFSET + len(sec_block)] = sec_block

    # Write production image
    with open(OUTPUT_BIN, "wb") as f:
        f.write(firmware)

    print("\n[SUCCESS] Secure Firmware Generated:")
    print("========================================")
    print(f"• Output Path: {OUTPUT_BIN}")
    print(f"• Total Size:  {len(firmware)} bytes")
    print(f"• Security Block @ 0x{SEC_BLOCK_OFFSET:X} ({len(sec_block)} bytes)")

# =============================================================================
# ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    try:
        build_secure_image()
    except Exception as e:
        print("\n[ERROR] Secure Firmware Generation Failed:", file=sys.stderr)
        print("========================================", file=sys.stderr)
        print(f"• Reason: {str(e)}", file=sys.stderr)
        sys.exit(1)