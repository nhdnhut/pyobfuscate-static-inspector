"""Scope-aware symbol renamer and symbol map generator.

Renames obfuscated identifiers (_0x..., IlII11, etc.) into clean neutral or
role-inferred names while strictly protecting reflection, globals(), getattr(),
dunder methods, public APIs, and avoiding scope collisions.
"""

import ast
import re
from typing import Any, Dict, List, Optional, Set, Tuple


class ProtectedSymbolDetector(ast.NodeVisitor):
    """Identifies symbols that must NOT be renamed (reflection, globals, imports, builtins)."""

    def __init__(self):
        self.protected: Set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name
            self.protected.add(name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            name = alias.asname or alias.name
            self.protected.add(name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Check getattr/setattr/hasattr
        if isinstance(node.func, ast.Name) and node.func.id in ("getattr", "setattr", "hasattr"):
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                self.protected.add(node.args[1].value)

        # Check globals().get('...') or locals().get('...')
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            if isinstance(node.func.value, ast.Call) and isinstance(node.func.value.func, ast.Name):
                if node.func.value.func.id in ("globals", "locals", "vars"):
                    if len(node.args) >= 1 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        self.protected.add(node.args[0].value)

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # globals()['var_name']
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
            if node.value.func.id in ("globals", "locals", "vars"):
                if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                    self.protected.add(node.slice.value)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        # __all__ = ['func1', 'Class1']
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "__all__":
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            self.protected.add(elt.value)
        self.generic_visit(node)


class SymbolRenamer(ast.NodeTransformer):
    """Renames obfuscated symbols and generates symbol_map.json."""

    OBF_PATTERNS = [
        re.compile(r"^_(?:0x)?[a-zA-Z0-9]{2,}$"),    # _0x1a2b, _0xfunc, _0123
        re.compile(r"^[I1lO0]{4,}$"),               # IlII11, O0OO0
        re.compile(r"^__obf_[a-zA-Z0-9_]+$"),       # __obf_var
        re.compile(r"^_[a-zA-Z0-9]{6,}$"),          # _a9f1b2c3
        re.compile(r"^_[0-9]+$"),                   # _1, _2
    ]

    PYTHON_BUILTINS = {
        "print", "len", "range", "int", "str", "bytes", "bytearray", "list",
        "tuple", "dict", "set", "min", "max", "abs", "sum", "open", "type",
        "isinstance", "issubclass", "getattr", "setattr", "hasattr", "delattr",
        "globals", "locals", "vars", "dir", "id", "hash", "input", "eval", "exec",
        "compile", "super", "property", "classmethod", "staticmethod", "zip",
        "enumerate", "reversed", "sorted", "map", "filter", "all", "any", "bool",
        "float", "chr", "ord", "hex", "bin", "oct", "slice", "object",
        "Exception", "BaseException", "ValueError", "TypeError", "KeyError",
        "IndexError", "RuntimeError", "SyntaxError", "AttributeError",
        "__name__", "__doc__", "__file__", "__package__", "__loader__", "__spec__",
        "__builtins__", "__obfuscated_by__",
    }

    def __init__(self):
        self.protected: Set[str] = set(self.PYTHON_BUILTINS)
        self.symbol_map: List[Dict[str, Any]] = []
        self.counters: Dict[str, int] = {}
        self.current_scope = "module"
        self.scope_stack: List[str] = ["module"]
        self.scope_mappings: Dict[str, Dict[str, str]] = {"module": {}}

    def rename_symbols(self, tree: ast.AST) -> Tuple[ast.AST, List[Dict[str, Any]]]:
        # 1. Collect protected symbols
        detector = ProtectedSymbolDetector()
        detector.visit(tree)
        self.protected.update(detector.protected)

        # 2. First pass: detect declarations and allocate new names
        self._analyze_declarations(tree)

        # 3. Second pass: transform AST names
        new_tree = self.visit(tree)
        ast.fix_missing_locations(new_tree)
        return new_tree, self.symbol_map

    def _is_obfuscated(self, name: str) -> bool:
        if name in self.protected:
            return False
        if name.startswith("__") and name.endswith("__"):
            return False
        for pattern in self.OBF_PATTERNS:
            if pattern.match(name):
                return True
        return False

    def _get_next_name(self, role: str) -> str:
        self.counters[role] = self.counters.get(role, 0) + 1
        return f"{role}_{self.counters[role]}"

    def _analyze_declarations(self, tree: ast.AST) -> None:
        """First pass to identify obfuscated functions, classes, and variables."""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if self._is_obfuscated(node.name):
                    new_name = self._get_next_name("func")
                    self.scope_mappings["module"][node.name] = new_name
                    self.symbol_map.append({
                        "original_name": node.name,
                        "new_name": new_name,
                        "role": "function",
                        "scope": "module",
                        "category": "suggested",
                        "rationale": "Obfuscated function name replaced with neutral identifier",
                    })

                # Check arguments
                target_func_name = self.scope_mappings["module"].get(node.name, node.name)
                func_scope = f"func:{target_func_name}"
                self.scope_mappings[func_scope] = {}
                self.scope_mappings[f"func:{node.name}"] = self.scope_mappings[func_scope]
                for arg in node.args.args:
                    if self._is_obfuscated(arg.arg):
                        arg_new = self._get_next_name("param")
                        self.scope_mappings[func_scope][arg.arg] = arg_new
                        self.symbol_map.append({
                            "original_name": arg.arg,
                            "new_name": arg_new,
                            "role": "parameter",
                            "scope": func_scope,
                            "category": "suggested",
                            "rationale": "Obfuscated parameter name replaced with neutral identifier",
                        })

            elif isinstance(node, ast.Assign):
                # Infer role based on assigned value
                role = "var"
                if isinstance(node.value, ast.Constant):
                    if isinstance(node.value.value, (bytes, bytearray)):
                        role = "buffer"
                    elif isinstance(node.value.value, str):
                        role = "text"
                    elif isinstance(node.value.value, (int, float)):
                        role = "num"
                elif isinstance(node.value, (ast.List, ast.Tuple)):
                    role = "seq"
                elif isinstance(node.value, ast.Dict):
                    role = "mapping"

                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if self._is_obfuscated(target.id):
                            if target.id not in self.scope_mappings["module"]:
                                new_name = self._get_next_name(role)
                                self.scope_mappings["module"][target.id] = new_name
                                self.symbol_map.append({
                                    "original_name": target.id,
                                    "new_name": new_name,
                                    "role": role,
                                    "scope": "module",
                                    "category": "suggested",
                                    "rationale": f"Obfuscated identifier replaced based on assigned type '{role}'",
                                })

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        # Rename function name if in module scope mapping
        if node.name in self.scope_mappings["module"]:
            node.name = self.scope_mappings["module"][node.name]

        func_scope = f"func:{node.name}"
        self.scope_stack.append(func_scope)
        self.current_scope = func_scope

        # Rename argument names
        local_map = self.scope_mappings.get(func_scope, {})
        for arg in node.args.args:
            if arg.arg in local_map:
                arg.arg = local_map[arg.arg]

        self.generic_visit(node)
        self.scope_stack.pop()
        self.current_scope = self.scope_stack[-1]
        return node

    def visit_Name(self, node: ast.Name) -> ast.AST:
        # Check local function scope first
        local_map = self.scope_mappings.get(self.current_scope, {})
        if node.id in local_map:
            node.id = local_map[node.id]
            return node

        # Check module scope
        module_map = self.scope_mappings.get("module", {})
        if node.id in module_map:
            node.id = module_map[node.id]
            return node

        return node
