"""Tests for XOR and AES-GCM decryption with tag verification."""

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pyobfuscate_inspector.deobfuscate.crypto_engine import (
    safe_aes_gcm_decrypt,
    safe_xor_bytes,
)
from pyobfuscate_inspector.safe_eval.limits import (
    AuthenticationFailedError,
    MissingKeyError,
)


def test_xor_bytes_single_byte():
    data = b"Hello World"
    key = 0x5A
    enc = safe_xor_bytes(data, key)
    dec = safe_xor_bytes(enc, key)
    assert dec == data


def test_xor_bytes_multi_byte():
    data = b"Secret multi-byte XOR data stream"
    key = b"KEY123"
    enc = safe_xor_bytes(data, key)
    dec = safe_xor_bytes(enc, key)
    assert dec == data


def test_aes_gcm_valid_decryption():
    key = b"0123456789abcdef"  # 16 bytes
    nonce = b"abcdef123456"     # 12 bytes
    plaintext = b"print('Successfully decrypted authenticated AES-GCM')"

    aesgcm = AESGCM(key)
    # encrypt returns ciphertext + 16-byte tag
    full_ct = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext = full_ct[:-16]
    tag = full_ct[-16:]

    decrypted = safe_aes_gcm_decrypt(
        ciphertext=ciphertext,
        key=key,
        nonce=nonce,
        tag=tag,
    )
    assert decrypted == plaintext


def test_aes_gcm_missing_key():
    with pytest.raises(MissingKeyError) as exc_info:
        safe_aes_gcm_decrypt(
            ciphertext=b"some_ct",
            key=None,
            nonce=b"123456789012",
            tag=b"1234567890123456",
        )
    assert "encryption key" in str(exc_info.value)


def test_aes_gcm_missing_tag():
    with pytest.raises(MissingKeyError) as exc_info:
        safe_aes_gcm_decrypt(
            ciphertext=b"some_ct",
            key=b"0123456789abcdef",
            nonce=b"123456789012",
            tag=None,
        )
    assert "authentication tag" in str(exc_info.value)


def test_aes_gcm_tampered_tag_fails_authentication():
    key = b"0123456789abcdef"
    nonce = b"abcdef123456"
    plaintext = b"sensitive payload"

    aesgcm = AESGCM(key)
    full_ct = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext = full_ct[:-16]
    # Corrupt the authentication tag
    corrupted_tag = bytearray(full_ct[-16:])
    corrupted_tag[0] ^= 0xFF

    with pytest.raises(AuthenticationFailedError):
        safe_aes_gcm_decrypt(
            ciphertext=ciphertext,
            key=key,
            nonce=nonce,
            tag=bytes(corrupted_tag),
        )
