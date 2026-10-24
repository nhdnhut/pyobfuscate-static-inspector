"""Extracts payloads passed to exec(...) loaders without executing them."""

import ast
from typing import Any, Dict, List, Optional, Tuple

from pyobfuscate_inspector.models import AnalysisLimits
from pyobfuscate_inspector.safe_eval.evaluator import SafeEvaluator
from pyobfuscate_inspector.safe_eval.limits import SafeEvalError, UnsupportedNodeError


class ExtractedPayload:
    """Represents a payload extracted from an exec(...) call."""

    def __init__(self, raw_data: Any, line: int, source_expr: str, is_bytecode: bool = False):
        self.raw_data = raw_data
        self.line = line
        self.source_expr = source_expr
        self.is_bytecode = is_bytecode


class ExecExtractor:
    """Locates and statically extracts payloads from exec() calls and aliases."""

    def __init__(self, env: Optional[Dict[str, Any]] = None, limits: Optional[AnalysisLimits] = None):
        self.env = env or {}
        self.limits = limits or AnalysisLimits()
        self.missing_parameters: List[str] = []

    def find_and_extract(self, tree: ast.AST) -> List[ExtractedPayload]:
        payloads: List[ExtractedPayload] = []

        # Find any variable aliases to exec (e.g., _exec = exec or _exec = getattr(__builtins__, 'exec'))
        exec_aliases = {"exec"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if self._is_exec_target(node.value):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            exec_aliases.add(target.id)

        evaluator = SafeEvaluator(env=self.env, limits=self.limits)

        # Search for calls to exec or its aliases
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if self._is_call_to_exec(node, exec_aliases):
                    if len(node.args) > 0:
                        arg0 = node.args[0]
                        # Unwrap compile(code, ...) if wrapped
                        target_arg = self._unwrap_compile(arg0)
                        line_no = getattr(node, "lineno", 0)
                        expr_repr = ast.unparse(target_arg) if hasattr(ast, "unparse") else "expr"
                        try:
                            val = evaluator.evaluate(target_arg)
                            is_bc = False
                            if isinstance(val, (bytes, bytearray)):
                                # Heuristic: if starts with marshal magic or pyc
                                if len(val) >= 4 and val[0:1] in (b"\xe3", b"\x00", b"\xcb"):
                                    is_bc = True
                            payloads.append(
                                ExtractedPayload(
                                    raw_data=val,
                                    line=line_no,
                                    source_expr=expr_repr,
                                    is_bytecode=is_bc,
                                )
                            )
                        except (SafeEvalError, UnsupportedNodeError) as e:
                            # Could not safely evaluate payload expression.
                            # Inspect if this is an encrypted payload (e.g. AES-GCM) with missing parameters.
                            missing = self._detect_missing_crypto_params(target_arg, tree)
                            if missing:
                                payloads.append(
                                    ExtractedPayload(
                                        raw_data=None,
                                        line=line_no,
                                        source_expr=expr_repr,
                                        is_bytecode=False,
                                    )
                                )
                                self.missing_parameters = missing
                                return payloads

        return payloads

    def _unwrap_compile(self, node: ast.AST) -> ast.AST:
        """If node is compile(x, ...), returns x."""
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "compile":
                if len(node.args) > 0:
                    return node.args[0]
            elif isinstance(func, ast.Attribute) and func.attr == "compile":
                if len(node.args) > 0:
                    return node.args[0]
        return node

    def _is_exec_target(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name) and node.id == "exec":
            return True
        if isinstance(node, ast.Attribute) and node.attr == "exec":
            return True
        if isinstance(node, ast.Call):
            # getattr(__builtins__, 'exec')
            if isinstance(node.func, ast.Name) and node.func.id == "getattr":
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and node.args[1].value == "exec":
                    return True
        return False

    def _is_call_to_exec(self, call_node: ast.Call, exec_aliases: set) -> bool:
        func = call_node.func
        if isinstance(func, ast.Name) and func.id in exec_aliases:
            return True
        if isinstance(func, ast.Attribute) and func.attr == "exec":
            return True
        if isinstance(func, ast.Call):
            # e.g. getattr(__builtins__, 'exec')(...)
            if isinstance(func.func, ast.Name) and func.func.id == "getattr":
                if len(func.args) >= 2 and isinstance(func.args[1], ast.Constant) and func.args[1].value == "exec":
                    return True
        return False

    def _detect_missing_crypto_params(self, expr_node: ast.AST, tree: ast.AST) -> List[str]:
        """Inspects if an unevaluated exec argument relies on encrypted data with missing keys."""
        missing = []
        target_name = expr_node.id if isinstance(expr_node, ast.Name) else None

        # Look for assignment to target_name or direct decrypt call
        decrypt_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and target_name:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == target_name:
                        if isinstance(node.value, ast.Call):
                            decrypt_calls.append(node.value)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "decrypt":
                decrypt_calls.append(node)

        for call in decrypt_calls:
            if isinstance(call.func, ast.Attribute) and call.func.attr == "decrypt":
                # Check instance of decrypt: aes = AESGCM(key)
                aes_inst = call.func.value
                key_name = None
                if isinstance(aes_inst, ast.Name):
                    # Find assignment: aes = AESGCM(key)
                    for n in ast.walk(tree):
                        if isinstance(n, ast.Assign):
                            for t in n.targets:
                                if isinstance(t, ast.Name) and t.id == aes_inst.id:
                                    if isinstance(n.value, ast.Call) and len(n.value.args) > 0:
                                        first_arg = n.value.args[0]
                                        if isinstance(first_arg, ast.Name):
                                            key_name = first_arg.id
                elif isinstance(aes_inst, ast.Call) and len(aes_inst.args) > 0:
                    if isinstance(aes_inst.args[0], ast.Name):
                        key_name = aes_inst.args[0].id

                if key_name and key_name not in self.env:
                    missing.append(f"AES-GCM encryption key '{key_name}' (missing from source)")

                # Check nonce (arg 0)
                if len(call.args) > 0 and isinstance(call.args[0], ast.Name):
                    if call.args[0].id not in self.env:
                        missing.append(f"Nonce / IV '{call.args[0].id}'")

        return list(dict.fromkeys(missing))
