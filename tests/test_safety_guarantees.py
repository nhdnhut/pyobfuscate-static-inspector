"""Verification of strict safety guarantees: no payload execution and no network access."""

import os
import socket
from pathlib import Path
import pytest

from pyobfuscate_inspector.audit.scanner import SecurityScanner
from pyobfuscate_inspector.cli import build_parser, decode_command
from pyobfuscate_inspector.deobfuscate.engine import DeobfuscationEngine
from pyobfuscate_inspector.detectors import DetectorManager


def test_untrusted_payload_is_never_executed(tmp_path):
    """Proves that code inside the input file is never executed or imported."""
    canary_file = tmp_path / "canary_must_not_exist.txt"
    if canary_file.exists():
        canary_file.unlink()

    # Input file with active dangerous side-effects
    malicious_source = f"""
import os
import sys

# Side effect 1: environment variable
os.environ['TEST_PWNED_VAR'] = 'ACTIVE'

# Side effect 2: create canary file
with open(r'{canary_file}', 'w') as f:
    f.write('PWNED')

# Side effect 3: critical fatal exception
raise RuntimeError("FATAL_PAYLOAD_EXECUTION")
"""
    input_file = tmp_path / "dangerous_sample.py"
    input_file.write_text(malicious_source, encoding="utf-8")

    # Run multi-layer engine
    engine = DeobfuscationEngine()
    result = engine.deobfuscate(malicious_source)

    # 1. Ensure canary file was NOT created
    assert not canary_file.exists(), "CRITICAL FAILURE: Canary file was created by target payload!"

    # 2. Ensure environment variable was NOT set
    assert "TEST_PWNED_VAR" not in os.environ, "CRITICAL FAILURE: Payload modified environment variables!"

    # Run CLI decode
    out_dir = tmp_path / "out"
    parser = build_parser()
    args = parser.parse_args(["decode", str(input_file), "--output", str(out_dir)])
    exit_code = decode_command(args)

    assert exit_code == 0
    assert not canary_file.exists()
    assert "TEST_PWNED_VAR" not in os.environ


def test_zero_network_access(monkeypatch, tmp_path):
    """Proves that the tool performs zero network connections during analysis."""

    def forbidden_connect(*args, **kwargs):
        raise AssertionError("SECURITY VIOLATION: Network connection attempted!")

    monkeypatch.setattr(socket, "socket", forbidden_connect)

    network_heavy_sample = """
import urllib.request
import requests

url = "https://malicious-c2-server.example.com/beacon"
try:
    urllib.request.urlopen(url)
except:
    pass
"""
    input_file = tmp_path / "network_sample.py"
    input_file.write_text(network_heavy_sample, encoding="utf-8")

    # Run detectors
    det = DetectorManager()
    mechanisms = det.detect_all(network_heavy_sample)

    # Run scanner
    scanner = SecurityScanner()
    findings = scanner.scan(network_heavy_sample)

    # Run deobfuscation
    engine = DeobfuscationEngine()
    result = engine.deobfuscate(network_heavy_sample)

    # Run CLI
    out_dir = tmp_path / "net_out"
    parser = build_parser()
    args = parser.parse_args(["decode", str(input_file), "--output", str(out_dir)])
    exit_code = decode_command(args)

    assert exit_code == 0
    assert (out_dir / "report.json").exists()
    assert (out_dir / "report.md").exists()
