import os
from vrf import get_public_key

SECRET_KEY = bytes.fromhex(os.getenv("SECRET_KEY"))
if len(SECRET_KEY) != 32:
    raise ValueError("Missing 32-byte HEX formatted SECRET_KEY env")

print(get_public_key(SECRET_KEY).hex())
