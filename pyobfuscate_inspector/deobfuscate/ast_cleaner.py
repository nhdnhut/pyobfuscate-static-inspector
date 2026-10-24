"""AST Cleaner for dead code removal and builtins alias unwrapping."""

import ast
from typing import List, Set, Tuple


class ASTCleaner(ast.NodeTransformer):
    """Cleans up redundant builtins lookups and unreachable dead code."""

    SAFE_BUILTINS_UNWRAP = {
        "print", "len", "range", "int", "str", "bytes", "bytearray", "list",
        "tuple", "dict", "set", "min", "max", "abs", "sum", "open", "type",
        "isinstance", "issubclass", "getattr", "setattr", "hasattr", "delattr",
        "zip", "enumerate", "reversed", "sorted", "map", "filter", "all", "any",
        "bool", "float", "chr", "ord", "hex", "bin", "oct",
    }

    def __init__(self):
        self.cleanups_applied: List[str] = []

    def clean_tree(self, tree: ast.AST) -> Tuple[ast.AST, List[str]]:
        new_tree = self.visit(tree)
        # Remove unused imports (e.g. base64, zlib) if not used in cleaned code
        new_tree = self._remove_unused_loader_imports(new_tree)
        ast.fix_missing_locations(new_tree)
        return new_tree, self.cleanups_applied

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        # Check getattr(__builtins__, 'name')
        if isinstance(node.func, ast.Name) and node.func.id == "getattr":
            if len(node.args) >= 2:
                target = node.args[0]
                attr = node.args[1]
                target_name = getattr(target, "id", "")
                if target_name in ("__builtins__", "builtins") and isinstance(attr, ast.Constant):
                    if attr.value in self.SAFE_BUILTINS_UNWRAP:
                        self.cleanups_applied.append(f"Unwrapped getattr(__builtins__, '{attr.value}') -> {attr.value}")
                        return ast.Name(id=attr.value, ctx=ast.Load())
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.body = self._prune_unreachable_statements(node.body)
        self.generic_visit(node)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        node.body = self._prune_unreachable_statements(node.body)
        self.generic_visit(node)
        return node

    def visit_Module(self, node: ast.Module) -> ast.AST:
        node.body = self._prune_unreachable_statements(node.body)
        self.generic_visit(node)
        return node

    def _prune_unreachable_statements(self, statements: List[ast.stmt]) -> List[ast.stmt]:
        """Removes statements appearing after return, raise, break, or continue in the same block."""
        pruned = []
        for stmt in statements:
            pruned.append(stmt)
            if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                if len(pruned) < len(statements):
                    self.cleanups_applied.append("Pruned unreachable dead code following terminating statement")
                break
        return pruned

    def _remove_unused_loader_imports(self, tree: ast.AST) -> ast.AST:
        """Removes imports of base64/zlib if they are no longer referenced in the final code."""
        # Collect all used Name identifiers
        used_names: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used_names.add(node.id)

        class ImportFilter(ast.NodeTransformer):
            def __init__(self, outer):
                self.outer = outer

            def visit_Import(self, node: ast.Import) -> Any:
                filtered_names = []
                for alias in node.names:
                    name = alias.asname or alias.name
                    if name in ("base64", "zlib", "marshal", "gzip", "bz2", "lzma"):
                        if name not in used_names:
                            self.outer.cleanups_applied.append(f"Removed unused loader import '{name}'")
                            continue
                    filtered_names.append(alias)
                if not filtered_names:
                    return None
                node.names = filtered_names
                return node

        return ImportFilter(self).visit(tree)
