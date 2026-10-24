"""Detector for builtin aliasing, dynamic lookups (globals, __dict__), and arithmetic constant masking."""

import ast
from typing import List, Optional

from pyobfuscate_inspector.models import DetectedMechanism


class BuiltinsAliasDetector:
    """Detects aliasing of builtins, dynamic lookups, and arithmetic-masked constants."""

    DANGEROUS_TARGETS = {"exec", "eval", "__import__", "compile", "open"}

    def detect(self, source_code: str, tree: Optional[ast.AST] = None) -> List[DetectedMechanism]:
        findings: List[DetectedMechanism] = []

        if not tree:
            try:
                tree = ast.parse(source_code)
            except Exception:
                pass

        if not tree:
            return findings

        for node in ast.walk(tree):
            # Check for globals() subscript or getattr on builtins
            # e.g. globals()['__builtins__'] or getattr(__builtins__, 'exec')
            if isinstance(node, ast.Call):
                func = node.func
                # getattr(__builtins__, 'exec')
                if isinstance(func, ast.Name) and func.id == "getattr":
                    target_arg = node.args[0] if len(node.args) > 0 else None
                    attr_arg = node.args[1] if len(node.args) > 1 else None
                    target_name = getattr(target_arg, "id", "")
                    attr_val = getattr(attr_arg, "value", "") if isinstance(attr_arg, ast.Constant) else ""
                    findings.append(
                        DetectedMechanism(
                            name="Builtins Dynamic Lookup (getattr)",
                            category="builtins_alias",
                            evidence=f"Dynamic attribute lookup via getattr({target_name or '...'}, '{attr_val or '...'}')",
                            confidence=0.95,
                            line=node.lineno,
                            details={"target": target_name, "attribute": attr_val},
                        )
                    )

            # Check for __builtins__.__dict__ or obj.__dict__
            if isinstance(node, ast.Attribute) and node.attr == "__dict__":
                findings.append(
                    DetectedMechanism(
                        name="__dict__ Access",
                        category="builtins_alias",
                        evidence="Access to __dict__ detected",
                        confidence=0.9,
                        line=node.lineno,
                    )
                )

            # Check for globals()[...]
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Call):
                if isinstance(node.value.func, ast.Name) and node.value.func.id == "globals":
                    key_val = ""
                    if isinstance(node.slice, ast.Constant):
                        key_val = str(node.slice.value)
                    findings.append(
                        DetectedMechanism(
                            name="globals() Dictionary Access",
                            category="builtins_alias",
                            evidence=f"Dynamic lookup into globals()['{key_val}']",
                            confidence=0.95,
                            line=node.lineno,
                            details={"key": key_val},
                        )
                    )

            # Check for masked arithmetic constants: e.g. (0x12 ^ 0x34) + 10 or deeply nested BinOps
            if isinstance(node, ast.BinOp):
                # Count nested BinOps in left or right
                if self._count_binops(node) >= 3:
                    findings.append(
                        DetectedMechanism(
                            name="Arithmetic/Bitwise Masked Constant",
                            category="arithmetic_const",
                            evidence="Complex arithmetic/bitwise expression used to conceal constant value",
                            confidence=0.85,
                            line=node.lineno,
                        )
                    )

        # De-duplicate findings of same name on same line
        unique_findings = []
        seen = set()
        for f in findings:
            key = (f.name, f.line)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    def _count_binops(self, node: ast.AST) -> int:
        if not isinstance(node, ast.BinOp):
            return 0
        return 1 + self._count_binops(node.left) + self._count_binops(node.right)
