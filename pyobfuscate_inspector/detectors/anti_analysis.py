"""Detector for anti-analysis techniques: debugger checks and control flow flattening."""

import ast
import re
from typing import List, Optional

from pyobfuscate_inspector.models import DetectedMechanism


class AntiAnalysisDetector:
    """Detects anti-debugging checks and control flow flattening."""

    DEBUGGER_KEYWORDS = [
        "gettrace",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "ptrace",
        "PTRACE_TRACEME",
    ]

    def detect(self, source_code: str, tree: Optional[ast.AST] = None) -> List[DetectedMechanism]:
        findings: List[DetectedMechanism] = []

        # Check raw text for debugger keywords
        for kw in self.DEBUGGER_KEYWORDS:
            if kw in source_code:
                findings.append(
                    DetectedMechanism(
                        name="Anti-Debugging Check",
                        category="anti_debug",
                        evidence=f"Debugger inspection symbol '{kw}' detected in source",
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

        # Check AST for anti-debug calls and control flow flattening
        for node in ast.walk(tree):
            # Check for sys.gettrace() call
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == "gettrace":
                    if isinstance(func.value, ast.Name) and func.value.id == "sys":
                        findings.append(
                            DetectedMechanism(
                                name="Sys Gettrace Anti-Debug",
                                category="anti_debug",
                                evidence="Call to sys.gettrace() to check for active debugger/tracer",
                                confidence=1.0,
                                line=node.lineno,
                            )
                        )

            # Check for Control Flow Flattening (CFF)
            # Characteristic: While loop with multiple conditional branches comparing a state variable
            if isinstance(node, ast.While):
                if self._is_flattened_loop(node):
                    findings.append(
                        DetectedMechanism(
                            name="Control Flow Flattening",
                            category="control_flow_flattening",
                            evidence="While loop dispatch structure detected with state variable branching",
                            confidence=0.85,
                            line=node.lineno,
                        )
                    )

        # De-duplicate
        unique_findings = []
        seen = set()
        for f in findings:
            key = (f.name, f.line, f.evidence)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    def _is_flattened_loop(self, node: ast.While) -> bool:
        """Heuristic check for control flow flattening dispatcher loop."""
        # Check if the while loop has a dispatch structure inside (e.g. if-elif chain with >= 3 branches)
        branches = 0
        for stmt in node.body:
            curr = stmt
            while isinstance(curr, ast.If):
                branches += 1
                if curr.orelse and len(curr.orelse) == 1 and isinstance(curr.orelse[0], ast.If):
                    curr = curr.orelse[0]
                else:
                    if curr.orelse:
                        branches += 1
                    break
        return branches >= 3
