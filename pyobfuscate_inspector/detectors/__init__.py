"""Detectors registry and coordinator."""

import ast
from typing import List, Optional

from pyobfuscate_inspector.detectors.anti_analysis import AntiAnalysisDetector
from pyobfuscate_inspector.detectors.builtins_alias import BuiltinsAliasDetector
from pyobfuscate_inspector.detectors.bytecode import BytecodeDetector
from pyobfuscate_inspector.detectors.compression import CompressionDetector
from pyobfuscate_inspector.detectors.crypto import CryptoDetector
from pyobfuscate_inspector.detectors.encoding import EncodingDetector
from pyobfuscate_inspector.detectors.signatures import SignatureDetector
from pyobfuscate_inspector.models import DetectedMechanism


class DetectorManager:
    """Coordinates and runs all mechanism detectors on a target source code / AST."""

    def __init__(self):
        self.detectors = [
            SignatureDetector(),
            EncodingDetector(),
            CompressionDetector(),
            CryptoDetector(),
            BuiltinsAliasDetector(),
            AntiAnalysisDetector(),
            BytecodeDetector(),
        ]

    def detect_all(self, source_code: str, tree: Optional[ast.AST] = None) -> List[DetectedMechanism]:
        if tree is None:
            try:
                tree = ast.parse(source_code)
            except Exception:
                pass

        all_findings: List[DetectedMechanism] = []
        for detector in self.detectors:
            try:
                findings = detector.detect(source_code, tree)
                all_findings.extend(findings)
            except Exception:
                pass

        # Deduplicate
        seen = set()
        deduped: List[DetectedMechanism] = []
        for f in all_findings:
            key = (f.name, f.category, f.line, f.evidence)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return deduped
