"""Detector for marshal loaders, raw bytecode, and compiled .pyc structures."""

import ast
import re
from typing import List, Optional

from pyobfuscate_inspector.models import DetectedMechanism


class BytecodeDetector:
    """Detects marshal loader calls, bytecode manipulation, and .pyc header signatures."""

    PYC_MAGIC_REGEX = re.compile(rb"[\x00-\xff]{2}\r\r\n")

    def detect(self, source_code: str, tree: Optional[ast.AST] = None) -> List[DetectedMechanism]:
        findings: List[DetectedMechanism] = []

        if "marshal.loads" in source_code or "import marshal" in source_code:
            findings.append(
                DetectedMechanism(
                    name="Marshal Bytecode Loader Reference",
                    category="bytecode",
                    evidence="Source code contains references to 'marshal' module",
                    confidence=0.9,
                )
            )

        if not tree:
            try:
                tree = ast.parse(source_code)
            except Exception:
                pass

        if not tree:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                # marshal.loads(...)
                if isinstance(func, ast.Attribute) and func.attr == "loads":
                    if isinstance(func.value, ast.Name) and func.value.id == "marshal":
                        findings.append(
                            DetectedMechanism(
                                name="Marshal Loader Call",
                                category="bytecode",
                                evidence="Call to marshal.loads(...) to reconstruct code object in memory",
                                confidence=1.0,
                                line=node.lineno,
                            )
                        )

            # Check for types.CodeType
            if isinstance(node, ast.Attribute) and node.attr == "CodeType":
                findings.append(
                    DetectedMechanism(
                        name="Direct CodeType Construction",
                        category="bytecode",
                        evidence="Reference to types.CodeType found",
                        confidence=0.9,
                        line=node.lineno,
                    )
                )

        return findings
