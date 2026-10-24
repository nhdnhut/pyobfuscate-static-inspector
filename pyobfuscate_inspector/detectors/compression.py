"""Detector for compression layers: zlib, gzip, bz2, and lzma."""

import ast
from typing import List, Optional

from pyobfuscate_inspector.models import DetectedMechanism


class CompressionDetector:
    """Detects compression methods used in payload decoding."""

    COMPRESSION_MODULES = {"zlib", "gzip", "bz2", "lzma"}

    def detect(self, source_code: str, tree: Optional[ast.AST] = None) -> List[DetectedMechanism]:
        findings: List[DetectedMechanism] = []

        if not tree:
            try:
                tree = ast.parse(source_code)
            except Exception:
                pass

        # String-based rapid check
        for mod in self.COMPRESSION_MODULES:
            if f"{mod}.decompress" in source_code or f"import {mod}" in source_code or f"from {mod}" in source_code:
                findings.append(
                    DetectedMechanism(
                        name=f"Compression ({mod})",
                        category="compression",
                        evidence=f"References to compression module '{mod}' found in source",
                        confidence=0.9,
                    )
                )

        if not tree:
            return findings

        # AST-based precise check
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == "decompress":
                    mod_name = ""
                    if isinstance(func.value, ast.Name):
                        mod_name = func.value.id
                    findings.append(
                        DetectedMechanism(
                            name=f"Decompression Routine ({mod_name or 'custom'})",
                            category="compression",
                            evidence=f"Call to {mod_name + '.' if mod_name else ''}decompress()",
                            confidence=1.0,
                            line=node.lineno,
                        )
                    )

        return findings
