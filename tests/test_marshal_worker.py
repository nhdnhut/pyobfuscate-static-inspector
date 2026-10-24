"""Tests for the isolated marshal bytecode inspection worker."""

import marshal
from pyobfuscate_inspector.deobfuscate.marshal_worker import run_isolated_marshal_inspector


def test_isolated_worker_disassembles_valid_code_object():
    # Harmless Python code
    source = "def add(a, b):\n    return a + b\nres = add(10, 20)\n"
    code_obj = compile(source, "<sample>", "exec")
    marshal_bytes = marshal.dumps(code_obj)

    result = run_isolated_marshal_inspector(marshal_bytes)
    assert result["status"] == "success"
    assert result["is_code_object"] is True
    code_info = result["code_info"]
    assert "add" in code_info["co_names"] or "res" in code_info["co_names"]
    assert "disassembly" in code_info
    assert len(code_info["disassembly"]) > 0


def test_isolated_worker_handles_corrupt_bytecode():
    corrupt_bytes = b"\xe3\xff\xff\x00\x00\x12\x34garbage"
    result = run_isolated_marshal_inspector(corrupt_bytes)
    assert result["status"] == "error"
    assert "Marshal parsing failed" in result["message"]
