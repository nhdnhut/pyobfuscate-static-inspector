"""Detector for pyobfuscate.com and known obfuscation headers/signatures."""

import ast
import re
from typing import List, Optional

from pyobfuscate_inspector.models import DetectedMechanism


class SignatureDetector:
    """Detects pyobfuscate and generic obfuscation signatures."""

    PYOBF_URL_PATTERN = re.compile(r"https?://(?:www\.)?pyobfuscate\.com", re.IGNORECASE)
    PYOBF_VAR_PATTERN = re.compile(r"__obfuscated_by__\s*=\s*['\"]([^'\"]+)['\"]")

    def detect(self, source_code: str, tree: Optional[ast.AST] = None) -> List[DetectedMechanism]:
        findings: List[DetectedMechanism] = []

        # Check raw regex matches
        var_match = self.PYOBF_VAR_PATTERN.search(source_code)
        if var_match:
            findings.append(
                DetectedMechanism(
                    name="PyObfuscate Marker",
                    category="signature",
                    evidence=f"__obfuscated_by__ = '{var_match.group(1)}'",
                    confidence=1.0,
                    details={"marker_value": var_match.group(1)},
                )
            )

        url_matches = list(self.PYOBF_URL_PATTERN.finditer(source_code))
        if url_matches and not var_match:
            findings.append(
                DetectedMechanism(
                    name="PyObfuscate URL Mention",
                    category="signature",
                    evidence=f"Found pyobfuscate.com reference in comments/strings ({len(url_matches)} occurrences)",
                    confidence=0.9,
                )
            )

        # AST-level inspection
        if tree:
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id == "__obfuscated_by__":
                            val_str = ""
                            if isinstance(node.value, ast.Constant):
                                val_str = str(node.value.value)
                            findings.append(
                                DetectedMechanism(
                                    name="PyObfuscate AST Assignment",
                                    category="signature",
                                    evidence=f"__obfuscated_by__ assigned to '{val_str}'",
                                    confidence=1.0,
                                    line=node.lineno,
                                )
                            )

        return findings
