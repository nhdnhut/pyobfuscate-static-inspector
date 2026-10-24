"""Detector for encoding layers: Base64, hex, reversed sequences, and chr/ord/join."""

import ast
import re
from typing import List, Optional

from pyobfuscate_inspector.models import DetectedMechanism


class EncodingDetector:
    """Detects Base64, hex decoding, reversed sequences, and chr/ord string reconstruction."""

    B64_REGEX = re.compile(r"b64decode|a2b_base64|b32decode|b16decode")
    HEX_REGEX = re.compile(r"unhexlify|a2b_hex|fromhex")

    def detect(self, source_code: str, tree: Optional[ast.AST] = None) -> List[DetectedMechanism]:
        findings: List[DetectedMechanism] = []

        if not tree:
            try:
                tree = ast.parse(source_code)
            except Exception:
                pass

        # String-level heuristics
        if self.B64_REGEX.search(source_code):
            findings.append(
                DetectedMechanism(
                    name="Base64 Decoding Reference",
                    category="encoding",
                    evidence="Source code contains references to base64 decoding routines",
                    confidence=0.9,
                )
            )

        if self.HEX_REGEX.search(source_code):
            findings.append(
                DetectedMechanism(
                    name="Hex Decoding Reference",
                    category="encoding",
                    evidence="Source code contains references to hex/unhexlify decoding routines",
                    confidence=0.85,
                )
            )

        if not tree:
            return findings

        # AST inspection
        for node in ast.walk(tree):
            # Check for reversed sequence slicing: [::-1]
            if isinstance(node, ast.Subscript):
                if isinstance(node.slice, ast.Slice):
                    if (
                        isinstance(node.slice.step, ast.UnaryOp)
                        and isinstance(node.slice.step.op, ast.USub)
                        and isinstance(node.slice.step.operand, ast.Constant)
                        and node.slice.step.operand.value == 1
                    ) or (
                        isinstance(node.slice.step, ast.Constant)
                        and node.slice.step.value == -1
                    ):
                        findings.append(
                            DetectedMechanism(
                                name="Reversed Slicing",
                                category="encoding",
                                evidence="Found slice with step -1 ([::-1])",
                                confidence=1.0,
                                line=node.lineno,
                            )
                        )

            # Check for chr(ord(...)) or [chr(...) for ... in ...] join
            if isinstance(node, ast.Call):
                func = node.func
                # e.g. ''.join(...)
                if isinstance(func, ast.Attribute) and func.attr == "join":
                    for arg in node.args:
                        if isinstance(arg, (ast.ListComp, ast.GeneratorExp)):
                            elt = arg.elt
                            # e.g. chr(...) inside comprehension
                            if isinstance(elt, ast.Call) and isinstance(elt.func, ast.Name) and elt.func.id == "chr":
                                findings.append(
                                    DetectedMechanism(
                                        name="Chr/Ord Join Reconstruction",
                                        category="encoding",
                                        evidence="String dynamically reconstructed via ''.join(chr(...) for ...)",
                                        confidence=1.0,
                                        line=node.lineno,
                                    )
                                )

                # Check for bytes.fromhex(...)
                if isinstance(func, ast.Attribute) and func.attr == "fromhex":
                    if isinstance(func.value, ast.Name) and func.value.id in ("bytes", "bytearray"):
                        findings.append(
                            DetectedMechanism(
                                name="Bytes FromHex",
                                category="encoding",
                                evidence=f"{func.value.id}.fromhex() call found",
                                confidence=1.0,
                                line=node.lineno,
                            )
                        )

                # Check for base64 calls
                if isinstance(func, ast.Attribute) and func.attr in ("b64decode", "b32decode", "b16decode"):
                    findings.append(
                        DetectedMechanism(
                            name=f"Base64 ({func.attr}) Call",
                            category="encoding",
                            evidence=f"Call to {func.attr}()",
                            confidence=1.0,
                            line=node.lineno,
                        )
                    )

        return findings
