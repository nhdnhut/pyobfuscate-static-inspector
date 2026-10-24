"""Tests for the multi-layer deobfuscation engine."""

import base64
import zlib
from pyobfuscate_inspector.deobfuscate.engine import DeobfuscationEngine
from pyobfuscate_inspector.models import AnalysisLimits, Status


def test_deobfuscate_single_layer_zlib_base64():
    original_code = "print('Hello from recovered code!')\nx = 10 + 20\n"
    comp = zlib.compress(original_code.encode("utf-8"))
    b64 = base64.b64encode(comp).decode("ascii")

    obfuscated_script = f"""
import base64
import zlib

__obfuscated_by__ = 'https://pyobfuscate.com'
exec(zlib.decompress(base64.b64decode('{b64}')))
"""

    engine = DeobfuscationEngine()
    result = engine.deobfuscate(obfuscated_script)

    assert result.status == Status.RECOVERED
    assert len(result.layers) >= 2
    assert "Hello from recovered code!" in result.final_code


def test_deobfuscate_multi_layer_packing():
    # Inner payload
    target_code = "SECRET_TOKEN = 'VALID_RESULT'\nprint(SECRET_TOKEN)\n"

    # Layer 2: XOR with 0x42
    xor_bytes = bytes([b ^ 0x42 for b in target_code.encode("utf-8")])
    layer2_script = f"""
payload = bytes([b ^ 0x42 for b in {list(xor_bytes)}])
exec(payload)
"""

    # Layer 1: Base64 + zlib of layer 2
    comp = zlib.compress(layer2_script.encode("utf-8"))
    b64 = base64.b64encode(comp).decode("ascii")
    layer1_script = f"""
import base64
import zlib
exec(zlib.decompress(base64.b64decode('{b64}')))
"""

    engine = DeobfuscationEngine()
    result = engine.deobfuscate(layer1_script)

    assert result.status == Status.RECOVERED
    assert len(result.layers) >= 3
    assert "VALID_RESULT" in result.final_code


def test_deobfuscate_cycle_detection():
    # An obfuscated script whose exec payload is identical to itself
    code = "exec('exec(code)')"
    # Create code that outputs itself
    cyclic_script = "code = 'exec(code)'; exec(code)"

    engine = DeobfuscationEngine()
    result = engine.deobfuscate(cyclic_script)
    # Must stop cleanly when cycle or limit detected
    assert result.status in (Status.PARTIALLY_RECOVERED, Status.RECOVERED, Status.LIMIT_EXCEEDED)


def test_deobfuscate_max_layers_limit():
    # Construct 5 layers of zlib+base64
    current = "print('deep code')"
    for _ in range(5):
        comp = zlib.compress(current.encode("utf-8"))
        b64 = base64.b64encode(comp).decode("ascii")
        current = f"import base64, zlib\nexec(zlib.decompress(base64.b64decode('{b64}')))"

    # Set limit to 2 layers
    engine = DeobfuscationEngine(limits=AnalysisLimits(max_layers=2))
    result = engine.deobfuscate(current)

    assert result.status == Status.LIMIT_EXCEEDED


def test_deobfuscate_invalid_syntax_input():
    broken_code = "def invalid_syntax( \n  print(123"
    engine = DeobfuscationEngine()
    result = engine.deobfuscate(broken_code)

    assert result.status == Status.INVALID_INPUT
    assert "not valid Python syntax" in result.status_reason
