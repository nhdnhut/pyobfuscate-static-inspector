"""Detector for XOR obfuscation and cryptographic encryption (AES-GCM, Fernet, etc.)."""

import ast
import re
from typing import List, Optional

from pyobfuscate_inspector.models import DetectedMechanism


class CryptoDetector:
    """Detects XOR obfuscation patterns and symmetric encryption like AES-GCM."""

    AES_REGEX = re.compile(r"AESGCM|algorithms\.AES|modes\.GCM|cryptography|AES\.new", re.IGNORECASE)

    def detect(self, source_code: str, tree: Optional[ast.AST] = None) -> List[DetectedMechanism]:
        findings: List[DetectedMechanism] = []

        if not tree:
            try:
                tree = ast.parse(source_code)
            except Exception:
                pass

        # Check for AES patterns in source code
        if self.AES_REGEX.search(source_code):
            findings.append(
                DetectedMechanism(
                    name="Cryptographic Encryption (AES/GCM)",
                    category="crypto",
                    evidence="AES / GCM references detected in source text",
                    confidence=0.85,
                )
            )

        if not tree:
            return findings

        # Check AST for XOR and AES structures
        for node in ast.walk(tree):
            # Check for XOR in comprehensions
            if isinstance(node, (ast.ListComp, ast.GeneratorExp)):
                elt = node.elt
                # Check for `b ^ k` or `chr(ord(c) ^ k)`
                is_xor = False
                if isinstance(elt, ast.BinOp) and isinstance(elt.op, ast.BitXor):
                    is_xor = True
                elif (
                    isinstance(elt, ast.Call)
                    and isinstance(elt.func, ast.Name)
                    and elt.func.id == "chr"
                    and len(elt.args) == 1
                    and isinstance(elt.args[0], ast.BinOp)
                    and isinstance(elt.args[0].op, ast.BitXor)
                ):
                    is_xor = True

                if is_xor:
                    findings.append(
                        DetectedMechanism(
                            name="XOR Byte/String Transformation",
                            category="crypto",
                            evidence="Bitwise XOR (^) operation detected inside comprehension loop",
                            confidence=1.0,
                            line=node.lineno,
                        )
                    )

            # Check for AESGCM call in AST
            if isinstance(node, ast.Call):
                func = node.func
                # e.g. AESGCM(...)
                if isinstance(func, ast.Name) and func.id == "AESGCM":
                    findings.append(
                        DetectedMechanism(
                            name="AES-GCM Instantiation",
                            category="crypto",
                            evidence="AESGCM(key) constructor call identified in AST",
                            confidence=1.0,
                            line=node.lineno,
                        )
                    )
                # e.g. aesgcm.decrypt(...)
                if isinstance(func, ast.Attribute) and func.attr == "decrypt":
                    findings.append(
                        DetectedMechanism(
                            name="AES-GCM Decrypt Call",
                            category="crypto",
                            evidence=".decrypt(...) method call identified in AST",
                            confidence=0.9,
                            line=node.lineno,
                        )
                    )

        return findings
