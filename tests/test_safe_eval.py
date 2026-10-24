"""Tests for the Safe AST Evaluator and resource limits."""

import ast
import pytest
import zlib
import base64

from pyobfuscate_inspector.models import AnalysisLimits
from pyobfuscate_inspector.safe_eval.evaluator import SafeEvaluator
from pyobfuscate_inspector.safe_eval.limits import (
    ResourceLimitExceeded,
    SafeEvalError,
    UnsupportedNodeError,
)
from pyobfuscate_inspector.safe_eval.whitelist import safe_zlib_decompress


def eval_expr(expr_str: str, env: dict = None, limits: AnalysisLimits = None):
    node = ast.parse(expr_str, mode="eval").body
    evaluator = SafeEvaluator(env=env, limits=limits)
    return evaluator.evaluate(node)


def test_literals_and_arithmetic():
    assert eval_expr("42") == 42
    assert eval_expr("'hello'") == "hello"
    assert eval_expr("b'bytes'") == b"bytes"
    assert eval_expr("True") is True
    assert eval_expr("False") is False
    assert eval_expr("None") is None
    assert eval_expr("10 + 20 * 2") == 50
    assert eval_expr("(100 - 40) // 3") == 20
    assert eval_expr("17 % 5") == 2
    assert eval_expr("2 ** 8") == 256


def test_bitwise_operations():
    assert eval_expr("0x12 ^ 0x34") == 0x26
    assert eval_expr("0xFF & 0x0F") == 0x0F
    assert eval_expr("0x10 | 0x01") == 0x11
    assert eval_expr("1 << 4") == 16
    assert eval_expr("32 >> 2") == 8
    assert eval_expr("~0") == -1


def test_string_and_bytes_methods():
    assert eval_expr("'hello world'[::-1]") == "dlrow olleh"
    assert eval_expr("b'abc'[::-1]") == b"cba"
    assert eval_expr("'-'.join(['a', 'b', 'c'])") == "a-b-c"
    assert eval_expr("b'hello'.decode('utf-8')") == "hello"
    assert eval_expr("'hello'.encode('utf-8')") == b"hello"
    assert eval_expr("bytes.fromhex('616263')") == b"abc"


def test_safe_builtins():
    assert eval_expr("chr(65)") == "A"
    assert eval_expr("ord('A')") == 65
    assert eval_expr("len([1, 2, 3, 4])") == 4
    assert eval_expr("int('42')") == 42
    assert eval_expr("int('2a', 16)") == 42
    assert eval_expr("str(123)") == "123"
    assert eval_expr("list(range(5))") == [0, 1, 2, 3, 4]
    assert eval_expr("min(5, 2, 8)") == 2
    assert eval_expr("max(5, 2, 8)") == 8
    assert eval_expr("sum([1, 2, 3])") == 6


def test_comprehensions():
    # XOR decoding loop
    res = eval_expr("bytes([b ^ 0x20 for b in b'HELLO'])")
    assert res == b"hello"

    # Chr join
    res_str = eval_expr("''.join([chr(c) for c in [104, 101, 108, 108, 111]])")
    assert res_str == "hello"

    # Dict and set comprehensions
    assert eval_expr("{x: x * 2 for x in range(3)}") == {0: 0, 1: 2, 2: 4}
    assert eval_expr("{x for x in [1, 2, 2, 3]}") == {1, 2, 3}


def test_safe_decompression_and_base64():
    raw = b"Secret Payload Test"
    comp = zlib.compress(raw)
    b64 = base64.b64encode(comp).decode("ascii")

    # Evaluate base64 + zlib in interpreter
    expr = f"zlib.decompress(base64.b64decode('{b64}'))"
    assert eval_expr(expr) == raw


def test_getattr_builtins_proxy():
    # getattr(__builtins__, 'chr')(65)
    assert eval_expr("getattr(__builtins__, 'chr')(65)") == "A"
    # Disallowed getattr on builtins
    with pytest.raises(UnsupportedNodeError):
        eval_expr("getattr(__builtins__, 'eval')")


def test_rejection_of_untrusted_nodes():
    # __import__ is not whitelisted
    with pytest.raises(UnsupportedNodeError):
        eval_expr("__import__('os').system('dir')")

    # arbitrary attribute traversal
    with pytest.raises(UnsupportedNodeError):
        eval_expr("().__class__.__base__.__subclasses__()")

    # exec call
    with pytest.raises(UnsupportedNodeError):
        eval_expr("exec('print(1)')")


def test_limit_integer_pow():
    # Prevent 2 ** 999999999 DoS
    with pytest.raises(ResourceLimitExceeded):
        eval_expr("2 ** 999999")


def test_limit_large_shift():
    with pytest.raises(ResourceLimitExceeded):
        eval_expr("1 << 100000")


def test_limit_loop_iterations():
    limits = AnalysisLimits(max_loop_iterations=50)
    with pytest.raises(ResourceLimitExceeded):
        eval_expr("[x for x in range(100)]", limits=limits)


def test_limit_decompression_bomb():
    # Create bomb-like repeating data
    huge_data = b"0" * (1024 * 1024)
    compressed = zlib.compress(huge_data)
    # Set limit to 100KB
    with pytest.raises(ResourceLimitExceeded):
        safe_zlib_decompress(compressed, max_size=100 * 1024)
