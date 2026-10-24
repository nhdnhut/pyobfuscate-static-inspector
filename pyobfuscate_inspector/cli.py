"""CLI interface for PyObfuscate Inspector."""

import argparse
import hashlib
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

from pyobfuscate_inspector.audit.recovery_report import RecoveryReportGenerator
from pyobfuscate_inspector.audit.reporter import AuditReporter
from pyobfuscate_inspector.audit.scanner import SecurityScanner
from pyobfuscate_inspector.deobfuscate.engine import DeobfuscationEngine
from pyobfuscate_inspector.detectors import DetectorManager
from pyobfuscate_inspector.models import (
    AnalysisLimits,
    AuditReport,
    LayerInfo,
    Status,
)


def compute_hashes(data: bytes) -> Dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def analyze_command(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    output_dir = Path(args.output) if args.output else Path("out")

    if not input_path.exists():
        print(f"[-] Error: Input file '{input_path}' not found.", file=sys.stderr)
        return 1

    try:
        raw_bytes = input_path.read_bytes()
    except Exception as e:
        print(f"[-] Error reading file: {e}", file=sys.stderr)
        return 1

    limits = AnalysisLimits(max_file_size=args.max_file_size)
    if len(raw_bytes) > limits.max_file_size:
        print(f"[-] Error: File size ({len(raw_bytes)} bytes) exceeds limit ({limits.max_file_size} bytes)", file=sys.stderr)
        return 2

    hashes = compute_hashes(raw_bytes)
    try:
        source_code = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        source_code = raw_bytes.decode("latin-1", errors="replace")

    print(f"[*] Analyzing '{input_path}' ({len(raw_bytes):,} bytes)...")

    # 1. Mechanism detection
    detector_mgr = DetectorManager()
    mechanisms = detector_mgr.detect_all(source_code)

    # 2. Security audit
    scanner = SecurityScanner()
    findings = scanner.scan(source_code)

    layer0 = LayerInfo(
        layer_index=0,
        layer_type="raw_input",
        size=len(raw_bytes),
        sha256=hashes["sha256"],
        filename=input_path.name,
        is_valid_python=True,
        content_text=source_code,
    )

    report = AuditReport(
        input_file=str(input_path),
        hashes=hashes,
        status=Status.PARTIALLY_RECOVERED,
        status_reason="Static analysis completed. Run 'decode' command to unpack layers.",
        detected_mechanisms=mechanisms,
        layers=[layer0],
        audit_findings=findings,
        limits=limits,
    )

    reporter = AuditReporter(report, output_dir)
    reporter.write_all()

    print(f"[+] Analysis complete! Output generated at: {output_dir}")
    print(f"    - Detected Mechanisms: {len(mechanisms)}")
    print(f"    - Audit Findings: {len(findings)}")
    print(f"    - Report: {output_dir / 'report.md'}")
    return 0


def decode_command(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    output_dir = Path(args.output) if args.output else Path("out")
    max_layers = args.max_layers if hasattr(args, "max_layers") else 10

    if not input_path.exists():
        print(f"[-] Error: Input file '{input_path}' not found.", file=sys.stderr)
        return 1

    try:
        raw_bytes = input_path.read_bytes()
    except Exception as e:
        print(f"[-] Error reading file: {e}", file=sys.stderr)
        return 1

    limits = AnalysisLimits(
        max_layers=max_layers,
        max_file_size=args.max_file_size,
    )

    if len(raw_bytes) > limits.max_file_size:
        print(f"[-] Error: File size exceeds limit ({limits.max_file_size} bytes)", file=sys.stderr)
        return 2

    hashes = compute_hashes(raw_bytes)
    try:
        source_code = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        source_code = raw_bytes.decode("latin-1", errors="replace")

    print(f"[*] Deobfuscating '{input_path}' (max_layers={max_layers})...")

    # 1. Mechanism detection on raw input
    detector_mgr = DetectorManager()
    mechanisms = detector_mgr.detect_all(source_code)

    # 2. Multi-layer deobfuscation
    engine = DeobfuscationEngine(limits=limits)
    result = engine.deobfuscate(source_code)

    # 3. Detect mechanisms in all subsequent layers
    all_findings = []
    scanner = SecurityScanner()

    # Scan raw input and each layer
    for layer in result.layers:
        text_to_scan = layer.content_text or ""
        if text_to_scan:
            findings = scanner.scan(text_to_scan)
            all_findings.extend(findings)
            # Detect mechanisms in layer
            layer_mechanisms = detector_mgr.detect_all(text_to_scan)
            mechanisms.extend(layer_mechanisms)

    # Deduplicate mechanisms
    seen_mech = set()
    deduped_mech = []
    for m in mechanisms:
        key = (m.name, m.category, m.evidence)
        if key not in seen_mech:
            seen_mech.add(key)
            deduped_mech.append(m)

    # Deduplicate findings
    seen_find = set()
    deduped_findings = []
    for f in all_findings:
        key = (f.category, f.item, f.evidence)
        if key not in seen_find:
            seen_find.add(key)
            deduped_findings.append(f)

    # Check for missing crypto parameters
    missing_params = result.missing_parameters
    final_status = result.status
    if missing_params:
        final_status = Status.MISSING_KEY

    report = AuditReport(
        input_file=str(input_path),
        hashes=hashes,
        status=final_status,
        status_reason=result.status_reason,
        detected_mechanisms=deduped_mech,
        layers=result.layers,
        audit_findings=deduped_findings,
        missing_parameters=missing_params,
        recovered_code=result.final_code if final_status == Status.RECOVERED else None,
        limits=limits,
    )

    reporter = AuditReporter(report, output_dir)
    reporter.write_all()

    # Generate recovery_report.md and symbol_map.json
    recovery_gen = RecoveryReportGenerator(
        input_file=str(input_path),
        status=final_status,
        status_reason=result.status_reason,
        layers=result.layers,
        symbol_map=result.symbol_map,
        transformations=result.transformations,
        unresolved_items=result.unresolved_items,
        output_dir=output_dir,
        recovered_code=result.final_code if final_status == Status.RECOVERED else None,
    )
    recovery_gen.write_all()

    print(f"[+] Deobfuscation process finished.")
    print(f"    - Status: {final_status.value.upper()}")
    print(f"    - Reason: {result.status_reason}")
    print(f"    - Total Layers: {len(result.layers)}")
    print(f"    - Output Directory: {output_dir}")
    if final_status == Status.RECOVERED:
        print(f"    - Recovered Source: {output_dir / 'recovered.py'}")
    print(f"    - Recovery Report: {output_dir / 'recovery_report.md'}")
    print(f"    - Symbol Map: {output_dir / 'symbol_map.json'}")
    print(f"    - Security Audit: {output_dir / 'report.md'}")

    return 0 if final_status in (Status.RECOVERED, Status.PARTIALLY_RECOVERED) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyobf-inspect",
        description="PyObfuscate Inspector & Deobfuscator: Reverse Engineering & Auditing Tool",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=50 * 1024 * 1024,
        help="Maximum input file size in bytes (default: 50MB)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # analyze command
    analyze_p = subparsers.add_parser("analyze", help="Perform static analysis and detect protection layers")
    analyze_p.add_argument("input", help="Path to input Python file")
    analyze_p.add_argument("--output", "-o", default="out", help="Output directory for reports (default: out/)")

    # decode command
    decode_p = subparsers.add_parser("decode", help="Unpack nested obfuscation layers and recover code")
    decode_p.add_argument("input", help="Path to input Python file")
    decode_p.add_argument("--output", "-o", default="out", help="Output directory for reports (default: out/)")
    decode_p.add_argument(
        "--max-layers",
        type=int,
        default=10,
        help="Maximum unpacking depth / iterations (default: 10)",
    )

    # deobfuscate command (alias to decode)
    deobf_p = subparsers.add_parser("deobfuscate", help="Deobfuscate, de-flatten control flow, and recover clean source")
    deobf_p.add_argument("input", help="Path to input Python file")
    deobf_p.add_argument("--output", "-o", default="out", help="Output directory for reports (default: out/)")
    deobf_p.add_argument(
        "--max-layers",
        type=int,
        default=10,
        help="Maximum unpacking depth / iterations (default: 10)",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        code = analyze_command(args)
    elif args.command in ("decode", "deobfuscate"):
        code = decode_command(args)
    else:
        parser.print_help()
        code = 1

    sys.exit(code)


if __name__ == "__main__":
    main()
