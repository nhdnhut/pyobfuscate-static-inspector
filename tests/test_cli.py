"""Tests for CLI commands analyze and decode."""

import json
from pathlib import Path
from pyobfuscate_inspector.cli import build_parser, analyze_command, decode_command


def test_cli_analyze_command(tmp_path):
    input_file = tmp_path / "sample.py"
    input_file.write_text(
        """
__obfuscated_by__ = 'https://pyobfuscate.com'
import subprocess
print('test')
""",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out_analyze"

    parser = build_parser()
    args = parser.parse_args(["analyze", str(input_file), "--output", str(out_dir)])
    ret = analyze_command(args)

    assert ret == 0
    assert (out_dir / "report.json").exists()
    assert (out_dir / "report.md").exists()

    report_data = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    assert report_data["input_file"] == str(input_file)
    assert len(report_data["detected_mechanisms"]) > 0


def test_cli_decode_command_recovered(tmp_path):
    import base64
    import zlib

    inner = "TARGET = 'SUCCESSFUL_RECOVERY'\nprint(TARGET)\n"
    comp = zlib.compress(inner.encode("utf-8"))
    b64 = base64.b64encode(comp).decode("ascii")

    input_file = tmp_path / "obf.py"
    input_file.write_text(
        f"""
import base64
import zlib
__obfuscated_by__ = 'https://pyobfuscate.com'
exec(zlib.decompress(base64.b64decode('{b64}')))
""",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out_decode"

    parser = build_parser()
    args = parser.parse_args(["decode", str(input_file), "--output", str(out_dir), "--max-layers", "5"])
    ret = decode_command(args)

    assert ret == 0
    assert (out_dir / "report.json").exists()
    assert (out_dir / "report.md").exists()
    assert (out_dir / "recovered.py").exists()
    assert (out_dir / "layers").is_dir()

    rec_code = (out_dir / "recovered.py").read_text(encoding="utf-8")
    assert "SUCCESSFUL_RECOVERY" in rec_code

    report_data = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    assert report_data["status"] == "recovered"
    assert len(report_data["layers_summary"]) >= 2
