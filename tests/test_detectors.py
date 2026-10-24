"""Tests for mechanism detectors."""

from pyobfuscate_inspector.detectors import DetectorManager


def test_signature_detector():
    code = """
__obfuscated_by__ = 'https://pyobfuscate.com'
print("hello")
"""
    mgr = DetectorManager()
    findings = mgr.detect_all(code)
    names = [f.name for f in findings]
    assert any("PyObfuscate" in n for n in names)


def test_encoding_and_compression_detector():
    code = """
import base64
import zlib
payload = zlib.decompress(base64.b64decode('eJwryc9LLVIozk/MS1cAAFU8BOs='))
s = ''.join([chr(ord(c) ^ 42) for c in 'test'])
reversed_s = s[::-1]
"""
    mgr = DetectorManager()
    findings = mgr.detect_all(code)
    names = [f.name for f in findings]
    assert any("Base64" in n for n in names)
    assert any("Compression" in n or "Decompression" in n for n in names)
    assert any("Chr/Ord" in n for n in names)
    assert any("Reversed" in n for n in names)


def test_crypto_and_xor_detector():
    code = """
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = b'0123456789abcdef'
aes = AESGCM(key)
pt = aes.decrypt(nonce, ct, None)
xor_data = bytes([b ^ 0x5a for b in pt])
"""
    mgr = DetectorManager()
    findings = mgr.detect_all(code)
    names = [f.name for f in findings]
    assert any("AES" in n for n in names)
    assert any("XOR" in n for n in names)


def test_builtins_alias_and_anti_debug_detector():
    code = """
import sys
_ = getattr(__builtins__, 'exec')
if sys.gettrace():
    sys.exit()

state = 1
while True:
    if state == 1:
        state = 2
    elif state == 2:
        state = 3
    elif state == 3:
        break
"""
    mgr = DetectorManager()
    findings = mgr.detect_all(code)
    names = [f.name for f in findings]
    assert any("getattr" in n for n in names)
    assert any("Anti-Debug" in n or "Gettrace" in n for n in names)
    assert any("Control Flow" in n for n in names)


def test_bytecode_detector():
    code = """
import marshal
code_obj = marshal.loads(b'\\xe3\\x00\\x00\\x00')
"""
    mgr = DetectorManager()
    findings = mgr.detect_all(code)
    names = [f.name for f in findings]
    assert any("Marshal" in n for n in names)
