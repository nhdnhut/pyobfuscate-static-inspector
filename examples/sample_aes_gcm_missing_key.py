"""Harmless fixture: AES-GCM encrypted payload with missing key."""

__obfuscated_by__ = 'https://pyobfuscate.com'

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

nonce = b'\x12\x34\x56\x78\x90\xab\xcd\xef\x11\x22\x33\x44'
ciphertext = b'\xa1\xb2\xc3\xd4\xe5\xf6\x07\x18\x29\x3a\x4b\x5c'
tag = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'

# Notice that 'key' is not provided in source code (e.g. downloaded remotely or passed as env)
# The inspector must detect missing_key and refuse to brute force
aes = AESGCM(key)
payload = aes.decrypt(nonce, ciphertext + tag, None)
exec(payload)
