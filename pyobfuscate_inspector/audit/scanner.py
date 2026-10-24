"""Static security audit scanner for decompiled/recovered Python code.

Inspects imports, file operations, subprocess executions, network endpoints,
and suspicious exfiltration or card-checking patterns without executing the code.
"""

import ast
import re
from typing import List, Optional, Set

from pyobfuscate_inspector.audit.redactor import SecretRedactor
from pyobfuscate_inspector.models import AuditFinding, Severity


class SecurityScanner:
    """Performs static security analysis and behavior indexing on Python code."""

    URL_REGEX = re.compile(r"https?://[a-zA-Z0-9_\-\./:%?&=#+@~]+")
    IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

    SUSPICIOUS_MODULES = {
        "socket": (Severity.MEDIUM, "Low-level network socket interface"),
        "requests": (Severity.LOW, "HTTP client library"),
        "urllib": (Severity.LOW, "Standard HTTP library"),
        "urllib.request": (Severity.LOW, "Standard HTTP request module"),
        "http.client": (Severity.LOW, "Low-level HTTP client"),
        "httpx": (Severity.LOW, "HTTP client library"),
        "aiohttp": (Severity.LOW, "Async HTTP client/server"),
        "subprocess": (Severity.HIGH, "Subprocess spawning and command execution"),
        "ctypes": (Severity.HIGH, "Direct native C memory and API invocation"),
        "winreg": (Severity.HIGH, "Windows Registry modification and querying"),
        "psutil": (Severity.MEDIUM, "System process and hardware inspection"),
        "browser_cookie3": (Severity.CRITICAL, "Browser cookie extraction utility"),
        "pynput": (Severity.HIGH, "Input hooking / potential keylogger"),
        "keyboard": (Severity.HIGH, "Keyboard event monitoring / potential keylogger"),
        "mss": (Severity.MEDIUM, "Screen capture library"),
        "pyautogui": (Severity.MEDIUM, "GUI automation / screen grabber"),
    }

    FILE_WRITE_MODES = {"w", "wb", "w+", "wb+", "a", "ab", "a+", "ab+"}

    STEALER_KEYWORDS = [
        "discord/Local Storage/leveldb",
        "Chrome/User Data/Default",
        "AppData/Roaming/Telegram Desktop",
        "Wallets",
        "Exodus",
        "seed_phrase",
        "private_key",
    ]

    CARD_CHECKER_KEYWORDS = [
        "cc_number",
        "card_number",
        "cvv",
        "exp_month",
        "exp_year",
        "luhn",
        "bin_lookup",
        "stripe_charge",
        "braintree",
        "checkout",
    ]

    def scan(self, source_code: str, tree: Optional[ast.AST] = None) -> List[AuditFinding]:
        findings: List[AuditFinding] = []

        if not tree:
            try:
                tree = ast.parse(source_code)
            except Exception:
                pass

        # 1. Text-level endpoint and keyword scanning
        self._scan_text_patterns(source_code, findings)

        if not tree:
            return findings

        # 2. AST-level inspection
        for node in ast.walk(tree):
            self._check_imports(node, findings)
            self._check_subprocess(node, findings)
            self._check_file_operations(node, findings)
            self._check_anti_debug_ast(node, findings)

        return findings

    def _scan_text_patterns(self, source_code: str, findings: List[AuditFinding]) -> None:
        # Endpoints
        for match in self.URL_REGEX.finditer(source_code):
            url = match.group(0)
            redacted_url, was_redacted = SecretRedactor.redact(url)

            # Check if this is an exfiltration target
            sev = Severity.LOW
            cat = "endpoint"
            if "discord.com/api/webhooks" in url.lower() or "api.telegram.org" in url.lower():
                sev = Severity.CRITICAL
                cat = "exfiltration"
            elif any(paste in url.lower() for paste in ["pastebin.com", "hastebin.com", "transfer.sh", "ngrok.io"]):
                sev = Severity.HIGH
                cat = "exfiltration"

            findings.append(
                AuditFinding(
                    category=cat,
                    item="Network Endpoint",
                    evidence=redacted_url,
                    severity=sev,
                    redacted=was_redacted,
                )
            )

        # IPv4 Addresses
        for match in self.IPV4_REGEX.finditer(source_code):
            ip = match.group(0)
            if not ip.startswith(("127.", "0.0.0.0", "255.255.")):
                findings.append(
                    AuditFinding(
                        category="endpoint",
                        item="IPv4 Address Literal",
                        evidence=ip,
                        severity=Severity.MEDIUM,
                    )
                )

        # Stealer & Card Checker Indicators
        for kw in self.STEALER_KEYWORDS:
            if kw.lower() in source_code.lower():
                findings.append(
                    AuditFinding(
                        category="exfiltration",
                        item="Credential Stealer Indicator",
                        evidence=f"String reference to credential/wallet path '{kw}'",
                        severity=Severity.HIGH,
                    )
                )

        for kw in self.CARD_CHECKER_KEYWORDS:
            if kw.lower() in source_code.lower():
                findings.append(
                    AuditFinding(
                        category="card_check",
                        item="Card Checker / Payment Operation Indicator",
                        evidence=f"Keyword '{kw}' associated with payment verification or card testing",
                        severity=Severity.HIGH,
                    )
                )

    def _check_imports(self, node: ast.AST, findings: List[AuditFinding]) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod_name = alias.name
                if mod_name in self.SUSPICIOUS_MODULES:
                    sev, desc = self.SUSPICIOUS_MODULES[mod_name]
                    findings.append(
                        AuditFinding(
                            category="import",
                            item=f"import {mod_name}",
                            evidence=f"{desc} (line {node.lineno})",
                            severity=sev,
                            line=node.lineno,
                        )
                    )
        elif isinstance(node, ast.ImportFrom):
            mod_name = node.module or ""
            if mod_name in self.SUSPICIOUS_MODULES:
                sev, desc = self.SUSPICIOUS_MODULES[mod_name]
                findings.append(
                    AuditFinding(
                        category="import",
                        item=f"from {mod_name} import ...",
                        evidence=f"{desc} (line {node.lineno})",
                        severity=sev,
                        line=node.lineno,
                    )
                )

    def _check_subprocess(self, node: ast.AST, findings: List[AuditFinding]) -> None:
        if isinstance(node, ast.Call):
            func = node.func
            # os.system, os.popen
            if isinstance(func, ast.Attribute):
                if isinstance(func.value, ast.Name) and func.value.id == "os":
                    if func.attr in ("system", "popen", "spawnl", "execv", "execve"):
                        findings.append(
                            AuditFinding(
                                category="subprocess",
                                item=f"os.{func.attr}()",
                                evidence=f"Shell / Command execution via os.{func.attr} (line {node.lineno})",
                                severity=Severity.HIGH,
                                line=node.lineno,
                            )
                        )
                # subprocess.run, Popen, call, check_output
                elif isinstance(func.value, ast.Name) and func.value.id == "subprocess":
                    if func.attr in ("run", "Popen", "call", "check_output", "check_call"):
                        findings.append(
                            AuditFinding(
                                category="subprocess",
                                item=f"subprocess.{func.attr}()",
                                evidence=f"Process execution via subprocess.{func.attr} (line {node.lineno})",
                                severity=Severity.HIGH,
                                line=node.lineno,
                            )
                        )

    def _check_file_operations(self, node: ast.AST, findings: List[AuditFinding]) -> None:
        if isinstance(node, ast.Call):
            func = node.func
            # open(...) call
            if isinstance(func, ast.Name) and func.id == "open":
                mode = "r"
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                    mode = str(node.args[1].value)
                sev = Severity.MEDIUM if mode in self.FILE_WRITE_MODES else Severity.LOW
                findings.append(
                    AuditFinding(
                        category="file_op",
                        item="open()",
                        evidence=f"File open call with mode '{mode}' (line {node.lineno})",
                        severity=sev,
                        line=node.lineno,
                    )
                )
            # os.remove, os.unlink, shutil.rmtree
            elif isinstance(func, ast.Attribute):
                if isinstance(func.value, ast.Name):
                    if func.value.id == "os" and func.attr in ("remove", "unlink", "rmdir"):
                        findings.append(
                            AuditFinding(
                                category="file_op",
                                item=f"os.{func.attr}()",
                                evidence=f"File / Directory deletion via os.{func.attr} (line {node.lineno})",
                                severity=Severity.HIGH,
                                line=node.lineno,
                            )
                        )
                    elif func.value.id == "shutil" and func.attr == "rmtree":
                        findings.append(
                            AuditFinding(
                                category="file_op",
                                item="shutil.rmtree()",
                                evidence=f"Recursive directory deletion via shutil.rmtree (line {node.lineno})",
                                severity=Severity.CRITICAL,
                                line=node.lineno,
                            )
                        )

    def _check_anti_debug_ast(self, node: ast.AST, findings: List[AuditFinding]) -> None:
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "gettrace":
                if isinstance(func.value, ast.Name) and func.value.id == "sys":
                    findings.append(
                        AuditFinding(
                            category="anti_debug",
                            item="sys.gettrace()",
                            evidence=f"Debugger presence inspection via sys.gettrace (line {node.lineno})",
                            severity=Severity.MEDIUM,
                            line=node.lineno,
                        )
                    )
