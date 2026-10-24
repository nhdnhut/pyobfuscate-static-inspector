"""Verification of semantic equivalence between original and deobfuscated code."""

import base64
import json
import zlib
from pathlib import Path

from pyobfuscate_inspector.cli import build_parser, decode_command
from pyobfuscate_inspector.deobfuscate.engine import DeobfuscationEngine
from pyobfuscate_inspector.models import Status


def test_full_pipeline_semantic_equivalence(tmp_path):
    # 1. Clean reference implementation
    reference_source = """
def compute_statistics(numbers):
    total = 0
    multiplier = 5
    for n in numbers:
        total += n * multiplier
    return total
"""

    # 2. Obfuscated version:
    # - Obfuscated names (_0xfunc, _0xlist, _0xtot, _0xmul)
    # - Masked arithmetic constant: 5 -> (0x10 ^ 0x15)
    # - Control flow flattened loop for multiplier and loop setup
    # - Redundant getattr(__builtins__, 'len')
    # - Wrapped in zlib + base64 + exec loader
    inner_obfuscated = """
def _0xfunc(_0xlist):
    _0xstate = 0
    _0xtot = 0
    _0xmul = (0x10 ^ 0x15)
    while True:
        if _0xstate == 0:
            _0xstate = 1
        elif _0xstate == 1:
            for n in _0xlist:
                _0xtot += n * _0xmul
            _0xstate = 2
        elif _0xstate == 2:
            break
    if False:
        print('dead code')
    return _0xtot
"""
    comp = zlib.compress(inner_obfuscated.encode("utf-8"))
    b64 = base64.b64encode(comp).decode("ascii")

    full_obfuscated_file = f"""
__obfuscated_by__ = 'https://pyobfuscate.com'
import base64
import zlib
getattr(__builtins__, 'exec')(zlib.decompress(base64.b64decode('{b64}')))
"""

    # 3. Run Deobfuscator
    engine = DeobfuscationEngine()
    result = engine.deobfuscate(full_obfuscated_file)

    assert result.status == Status.RECOVERED
    assert result.final_code is not None

    # Check that control flow was de-flattened
    assert "while True:" not in result.final_code
    assert "_0xstate" not in result.final_code
    # Check that constant was folded: (0x10 ^ 0x15) -> 5
    assert "= 5" in result.final_code
    # Check that dead code was pruned
    assert "dead code" not in result.final_code

    # 4. Verify behavioral and semantic equivalence
    ref_ns = {}
    exec(reference_source, ref_ns)

    rec_ns = {}
    exec(result.final_code, rec_ns)

    # Find the recovered function name (from symbol_map or rec_ns)
    rec_funcs = [v for k, v in rec_ns.items() if callable(v)]
    assert len(rec_funcs) >= 1
    recovered_func = rec_funcs[0]

    test_cases = [
        [1, 2, 3],
        [10, -5, 20],
        [],
        [100, 200, 300, 400],
    ]

    for tc in test_cases:
        expected = ref_ns["compute_statistics"](tc)
        actual = recovered_func(tc)
        assert actual == expected, f"Equivalence failure for input {tc}: expected {expected}, got {actual}"

    # 5. Test CLI execution and output artifacts
    test_file = tmp_path / "target_obf.py"
    test_file.write_text(full_obfuscated_file, encoding="utf-8")
    out_dir = tmp_path / "deobf_out"

    parser = build_parser()
    args = parser.parse_args(["deobfuscate", str(test_file), "--output", str(out_dir)])
    exit_code = decode_command(args)

    assert exit_code == 0
    assert (out_dir / "recovered.py").exists()
    assert (out_dir / "recovery_report.md").exists()
    assert (out_dir / "symbol_map.json").exists()
    assert (out_dir / "layers").is_dir()

    symbol_data = json.loads((out_dir / "symbol_map.json").read_text(encoding="utf-8"))
    assert symbol_data["total_symbols_renamed"] >= 3

    report_md = (out_dir / "recovery_report.md").read_text(encoding="utf-8")
    assert "FULLY RECOVERED" in report_md
    assert "Transformation Log" in report_md
