# =============================================================================
# Secure Firmware Signing Script for STM32 Bootloader
#
# 1. Reads the raw application binary file.
# 2. Calculates the SHA-256 hash of the binary.
# 3. Signs the hash using an ECDSA private key.
# 4. Constructs a firmware header with metadata + signature.
# 5. Appends CRC and pads the header to 256 bytes with 0xFF.
# 6. Prepends the header to the binary and writes the output image.
#
# Requirements: pip install pycryptodome ecdsa
# =============================================================================
import os
import struct
from hashlib import sha256
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.backends import default_backend


def compute_crc32(data_bytes):
    """
    - Polynomial: 0x04C11DB7
    - Initial value: 0xFFFFFFFF
    - No input/output bit reversal
    - NO final XOR (matches hardware default)
    - Processes bytes in memory order
    """
    crc = 0xFFFFFFFF
    for byte in data_bytes:
        crc ^= (byte << 24)
        for _ in range(8):
            if crc & 0x80000000:
                crc = (crc << 1) ^ 0x04C11DB7
            else:
                crc = (crc << 1)
        crc &= 0xFFFFFFFF  # Ensure 32-bit
    return crc 

# --- Configuration ---
APP_BINARY_PATH = "/home/pi/Documents/STM32/SecBoot/Makefile/NonSecure/build/SecBoot_NS.bin"
OUTPUT_IMAGE_PATH = "/home/pi/Documents/STM32/SecBoot/Artifacts/Secboot_MainApp.bin"
PRIVATE_KEY_PATH = "/home/pi/Documents/STM32/SecBoot/Script/keys/ec_private.pem"

# --- Firmware Metadata ---
FW_MAGIC_NUMBER = 0xDEADBEEF
FW_VERSION_MAJOR = 1
FW_VERSION_MINOR = 0
FW_VERSION_PATCH = 0
FW_VERSION_BUILD = 0
APP_ENTRY_POINT = 0x08040100

# Read application binary
with open(APP_BINARY_PATH, "rb") as f:
    app_binary = f.read()
    image_size = len(app_binary)

print("\n[INFO] Firmware Details:")
print("========================================")
print(f"• Binary Path:    {APP_BINARY_PATH}")
print(f"• Binary Size:    {image_size} bytes")

# Calculate SHA-256 hash
firmware_hash = sha256(app_binary).digest()
print("\n[SECURITY] Cryptographic Hashes:")
print("========================================")
print(f"• SHA-256 Digest: {firmware_hash.hex().upper()}")

# Load private key (PEM, EC key)
with open(PRIVATE_KEY_PATH, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Sign the hash digest (ECDSA with SHA-256)
signature_der = private_key.sign(
    firmware_hash,
    ec.ECDSA(utils.Prehashed(hashes.SHA256()))
)

# Decode DER signature to r and s
r, s = utils.decode_dss_signature(signature_der)

# Convert r and s to 32-byte big-endian
r_bytes = r.to_bytes(32, byteorder='big')
s_bytes = s.to_bytes(32, byteorder='big')

# Concatenate r || s
signature = r_bytes + s_bytes
print("\n[SECURITY] Digital Signature:")
print("========================================")
print(f"• R Component:   {r_bytes.hex().upper()}")
print(f"• S Component:   {s_bytes.hex().upper()}")
print(f"• Full Signature: {signature.hex().upper()}")

# Construct firmware header
header_format = '<II4BI32s64s'
version_bytes = bytes([FW_VERSION_MAJOR, FW_VERSION_MINOR, FW_VERSION_PATCH, FW_VERSION_BUILD])

header_without_crc = struct.pack(
    header_format,
    FW_MAGIC_NUMBER,
    image_size,
    *version_bytes,
    APP_ENTRY_POINT,
    firmware_hash,
    signature
)

# Calculate CRC32 on header (before CRC field)
header_crc = compute_crc32(header_without_crc)
print("\n[INTEGRITY] Header Verification:")
print("========================================")
print(f"• Header CRC32:   0x{header_crc:08X}")

# Append CRC32
final_header = header_without_crc + struct.pack('<I', header_crc)

# Pad header to 256 bytes with 0xFF
padding_len = 256 - len(final_header)
if padding_len > 0:
    final_header += b'\xFF' * padding_len

print("\n[HEADER] Final Composition:")
print("========================================")
print(f"• Unpadded Size:  {len(header_without_crc)} bytes")
print(f"• Padding Added:  {padding_len} bytes")
print(f"• Final Size:     {len(final_header)} bytes")

# Write output file
with open(OUTPUT_IMAGE_PATH, "wb") as f:
    f.write(final_header)
    f.write(app_binary)

print("\n[SUCCESS] Signed Firmware Created:")
print("========================================")
print(f"• Output Path:    {OUTPUT_IMAGE_PATH}")
print(f"• Total Size:     {len(final_header) + image_size} bytes")
print(f"• Header Magic:   0x{FW_MAGIC_NUMBER:08X}")
print(f"• Entry Point:    0x{APP_ENTRY_POINT:08X}")
print(f"• Version:        {FW_VERSION_MAJOR}.{FW_VERSION_MINOR}.{FW_VERSION_PATCH}.{FW_VERSION_BUILD}")