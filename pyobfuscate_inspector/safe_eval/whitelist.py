"""Whitelisted safe functions, methods, and guarded decompression utilities."""

import base64
import binascii
import bz2
import gzip
import io
import lzma
import zlib
from typing import Any, Callable, Dict, Set

from pyobfuscate_inspector.safe_eval.limits import ResourceLimitExceeded


def safe_zlib_decompress(data: bytes, max_size: int = 25 * 1024 * 1024) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("zlib.decompress argument must be bytes")
    decompressor = zlib.decompressobj()
    chunk_size = 64 * 1024
    out = bytearray()
    
    # Process initial data
    chunk = decompressor.decompress(data, chunk_size)
    out.extend(chunk)
    if len(out) > max_size:
        raise ResourceLimitExceeded(f"Decompressed zlib size exceeded limit ({max_size} bytes)")
    
    while decompressor.unconsumed_tail:
        chunk = decompressor.decompress(decompressor.unconsumed_tail, chunk_size)
        if not chunk:
            break
        out.extend(chunk)
        if len(out) > max_size:
            raise ResourceLimitExceeded(f"Decompressed zlib size exceeded limit ({max_size} bytes)")
            
    # Flush remainder
    remainder = decompressor.flush()
    out.extend(remainder)
    if len(out) > max_size:
        raise ResourceLimitExceeded(f"Decompressed zlib size exceeded limit ({max_size} bytes)")
    return bytes(out)


def safe_gzip_decompress(data: bytes, max_size: int = 25 * 1024 * 1024) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("gzip.decompress argument must be bytes")
    bio = io.BytesIO(data)
    out = bytearray()
    with gzip.GzipFile(fileobj=bio, mode="rb") as gz:
        while True:
            chunk = gz.read(64 * 1024)
            if not chunk:
                break
            out.extend(chunk)
            if len(out) > max_size:
                raise ResourceLimitExceeded(f"Decompressed gzip size exceeded limit ({max_size} bytes)")
    return bytes(out)


def safe_bz2_decompress(data: bytes, max_size: int = 25 * 1024 * 1024) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("bz2.decompress argument must be bytes")
    decompressor = bz2.BZ2Decompressor()
    out = bytearray()
    chunk_size = 64 * 1024
    
    chunk = decompressor.decompress(data, chunk_size)
    out.extend(chunk)
    if len(out) > max_size:
        raise ResourceLimitExceeded(f"Decompressed bz2 size exceeded limit ({max_size} bytes)")
        
    while decompressor.unused_data:
        chunk = decompressor.decompress(decompressor.unused_data, chunk_size)
        if not chunk:
            break
        out.extend(chunk)
        if len(out) > max_size:
            raise ResourceLimitExceeded(f"Decompressed bz2 size exceeded limit ({max_size} bytes)")
    return bytes(out)


def safe_lzma_decompress(data: bytes, max_size: int = 25 * 1024 * 1024) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("lzma.decompress argument must be bytes")
    decompressor = lzma.LZMADecompressor()
    out = bytearray()
    chunk_size = 64 * 1024
    
    chunk = decompressor.decompress(data, chunk_size)
    out.extend(chunk)
    if len(out) > max_size:
        raise ResourceLimitExceeded(f"Decompressed lzma size exceeded limit ({max_size} bytes)")
        
    while decompressor.needs_input is False:
        chunk = decompressor.decompress(b"", chunk_size)
        if not chunk:
            break
        out.extend(chunk)
        if len(out) > max_size:
            raise ResourceLimitExceeded(f"Decompressed lzma size exceeded limit ({max_size} bytes)")
    return bytes(out)


def safe_b64decode(s: Any, max_size: int = 25 * 1024 * 1024) -> bytes:
    if isinstance(s, str):
        s = s.encode("ascii")
    res = base64.b64decode(s)
    if len(res) > max_size:
        raise ResourceLimitExceeded(f"Base64 decoded size ({len(res)}) exceeded limit ({max_size} bytes)")
    return res


def safe_b32decode(s: Any, max_size: int = 25 * 1024 * 1024) -> bytes:
    if isinstance(s, str):
        s = s.encode("ascii")
    res = base64.b32decode(s)
    if len(res) > max_size:
        raise ResourceLimitExceeded(f"Base32 decoded size exceeded limit ({max_size} bytes)")
    return res


def safe_b16decode(s: Any, max_size: int = 25 * 1024 * 1024) -> bytes:
    if isinstance(s, str):
        s = s.encode("ascii")
    res = base64.b16decode(s)
    if len(res) > max_size:
        raise ResourceLimitExceeded(f"Base16 decoded size exceeded limit ({max_size} bytes)")
    return res


def safe_unhexlify(s: Any, max_size: int = 25 * 1024 * 1024) -> bytes:
    if isinstance(s, str):
        s = s.encode("ascii")
    res = binascii.unhexlify(s)
    if len(res) > max_size:
        raise ResourceLimitExceeded(f"Unhexlify size exceeded limit ({max_size} bytes)")
    return res


def safe_chr(code: Any) -> str:
    if not isinstance(code, int):
        raise TypeError("chr() arg must be int")
    if code < 0 or code > 0x10FFFF:
        raise ValueError("chr() arg not in range(0x110000)")
    return chr(code)


def safe_range(*args: Any) -> range:
    r = range(*args)
    if len(r) > 100_000:
        raise ResourceLimitExceeded(f"Range length ({len(r)}) exceeded safe limit")
    return r


SAFE_METHODS: Set[str] = {
    "join", "decode", "encode", "split", "rsplit", "replace",
    "strip", "lstrip", "rstrip", "lower", "upper", "startswith",
    "endswith", "find", "rfind", "index", "fromhex", "hex",
}

SAFE_BUILTINS: Dict[str, Callable[..., Any]] = {
    "chr": safe_chr,
    "ord": ord,
    "len": len,
    "range": safe_range,
    "int": int,
    "str": str,
    "bytes": bytes,
    "bytearray": bytearray,
    "list": list,
    "tuple": tuple,
    "dict": dict,
    "set": set,
    "min": min,
    "max": max,
    "abs": abs,
    "sum": sum,
    "enumerate": enumerate,
    "zip": zip,
    "reversed": reversed,
    "bool": bool,
}

MODULE_WHITELIST: Dict[str, Dict[str, Callable[..., Any]]] = {
    "base64": {
        "b64decode": safe_b64decode,
        "b32decode": safe_b32decode,
        "b16decode": safe_b16decode,
        "a85decode": base64.a85decode,
        "b85decode": base64.b85decode,
    },
    "zlib": {
        "decompress": safe_zlib_decompress,
    },
    "gzip": {
        "decompress": safe_gzip_decompress,
    },
    "bz2": {
        "decompress": safe_bz2_decompress,
    },
    "lzma": {
        "decompress": safe_lzma_decompress,
    },
    "binascii": {
        "unhexlify": safe_unhexlify,
        "a2b_hex": safe_unhexlify,
        "a2b_base64": safe_b64decode,
    },
}
