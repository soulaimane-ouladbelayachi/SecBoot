import keyring
import os
import struct

service_name = "secboot_secrets"


# 1. AES_KEY_1
key_name_1 = "aes_key_1"
aes_key_1_bytes = os.urandom(16)
keyring.set_password(service_name, key_name_1, aes_key_1_bytes.hex())
print(f"{key_name_1} (hex): {aes_key_1_bytes.hex()}")

# 2. AES_IV
iv_name = "aes_iv"
aes_iv_bytes = os.urandom(16)
keyring.set_password(service_name, iv_name, aes_iv_bytes.hex())
print(f"{iv_name} (hex): {aes_iv_bytes.hex()}")

# 3. AES_KEY_2
key_name_2 = "aes_key_2"
aes_key_2_hex = "00240028323650032034354edeadbeef"
aes_key_2_bytes = bytes.fromhex(aes_key_2_hex)
keyring.set_password(service_name, key_name_2, aes_key_2_bytes.hex())

print(f"{key_name_2} (hex): {aes_key_2_bytes.hex()}")

