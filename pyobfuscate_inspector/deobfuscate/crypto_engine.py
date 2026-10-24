"""Cryptographic and XOR decoding engine with strict authentication tag verification."""

from typing import Optional, Tuple, Union

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

from pyobfuscate_inspector.safe_eval.limits import (
    AuthenticationFailedError,
    MissingKeyError,
    SafeEvalError,
)


def safe_xor_bytes(data: bytes, key: Union[int, bytes]) -> bytes:
    """XORs bytes with a single byte or repeated byte key."""
    if isinstance(key, int):
        k = key & 0xFF
        return bytes(b ^ k for b in data)
    elif isinstance(key, (bytes, bytearray)):
        if len(key) == 0:
            raise SafeEvalError("XOR key cannot be empty")
        k_len = len(key)
        return bytes(b ^ key[i % k_len] for i, b in enumerate(data))
    else:
        raise TypeError(f"Invalid XOR key type: {type(key)}")


def safe_aes_gcm_decrypt(
    ciphertext: bytes,
    key: Optional[bytes],
    nonce: Optional[bytes],
    tag: Optional[bytes],
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Decrypts AES-GCM ciphertext strictly verifying the authentication tag.

    Raises MissingKeyError if key, nonce, or tag is missing.
    Raises AuthenticationFailedError if authentication tag validation fails.
    """
    if not HAS_CRYPTOGRAPHY:
        raise SafeEvalError("The 'cryptography' library is required for AES-GCM decryption")

    missing = []
    if key is None:
        missing.append("encryption key (key)")
    if nonce is None:
        missing.append("initialization vector / nonce (nonce)")
    if tag is None:
        missing.append("authentication tag (tag)")

    if missing:
        raise MissingKeyError(f"Cannot decrypt AES-GCM: missing parameters: {', '.join(missing)}")

    # In cryptography AESGCM, the decrypt method expects ciphertext + tag combined
    # ciphertext: bytes, nonce: bytes
    if len(key) not in (16, 24, 32):
        raise SafeEvalError(f"Invalid AES key length ({len(key)} bytes). Must be 16, 24, or 32 bytes.")

    if len(nonce) < 8:
        raise SafeEvalError(f"Nonce length ({len(nonce)} bytes) is too short for AES-GCM")

    if len(tag) != 16:
        raise SafeEvalError(f"Invalid AES-GCM tag length ({len(tag)} bytes). Must be 16 bytes.")

    payload = ciphertext + tag
    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, payload, associated_data)
        return plaintext
    except InvalidTag as e:
        raise AuthenticationFailedError("AES-GCM authentication failed: invalid tag or corrupted ciphertext") from e
    except Exception as e:
        raise SafeEvalError(f"AES-GCM decryption failed: {e}") from e
