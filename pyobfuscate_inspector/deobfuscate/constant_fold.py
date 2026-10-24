"""AST NodeTransformer for constant folding, safe string resolution, and control flow pruning."""

import ast
from typing import Any, Dict, List, Set, Tuple

from pyobfuscate_inspector.models import AnalysisLimits
from pyobfuscate_inspector.safe_eval.evaluator import SafeEvaluator
from pyobfuscate_inspector.safe_eval.limits import SafeEvalError, UnsupportedNodeError


class ScopeAnalyzer(ast.NodeVisitor):
    """Identifies variables that are assigned exactly once at module scope with no mutations."""

    def __init__(self):
        self.assignment_counts: Dict[str, int] = {}
        self.conditional_vars: Set[str] = set()
        self.in_conditional_or_loop = 0
        self.candidate_nodes: Dict[str, ast.AST] = {}

    def visit_If(self, node: ast.If) -> None:
        self.in_conditional_or_loop += 1
        self.generic_visit(node)
        self.in_conditional_or_loop -= 1

    def visit_While(self, node: ast.While) -> None:
        self.in_conditional_or_loop += 1
        self.generic_visit(node)
        self.in_conditional_or_loop -= 1

    def visit_For(self, node: ast.For) -> None:
        self.in_conditional_or_loop += 1
        self.generic_visit(node)
        self.in_conditional_or_loop -= 1

    def visit_Try(self, node: ast.Try) -> None:
        self.in_conditional_or_loop += 1
        self.generic_visit(node)
        self.in_conditional_or_loop -= 1

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Don't track variables inside function bodies for module-level folding
        pass

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        pass

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        pass

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                self.assignment_counts[var_name] = self.assignment_counts.get(var_name, 0) + 1
                if self.in_conditional_or_loop > 0:
                    self.conditional_vars.add(var_name)
                else:
                    self.candidate_nodes[var_name] = node.value
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if isinstance(node.target, ast.Name):
            var_name = node.target.id
            self.assignment_counts[var_name] = self.assignment_counts.get(var_name, 0) + 1
            self.conditional_vars.add(var_name)
        self.generic_visit(node)


class ConstantFolder(ast.NodeTransformer):
    """Folds deterministic constants, simplifies provable control branches, and reconstructs strings."""

    def __init__(self, limits: Optional[AnalysisLimits] = None):
        self.limits = limits or AnalysisLimits()
        self.known_constants: Dict[str, Any] = {}
        self.transforms_applied: List[str] = []

    def fold_tree(self, tree: ast.AST) -> Tuple[ast.AST, List[str]]:
        """Analyzes scope, performs constant folding and branch pruning."""
        # 1. Analyze variable assignments to identify safe deterministic variables
        analyzer = ScopeAnalyzer()
        analyzer.visit(tree)

        # 2. Evaluate unambiguous module-level assignments
        evaluator = SafeEvaluator(env={}, limits=self.limits)
        for var_name, node_val in analyzer.candidate_nodes.items():
            if analyzer.assignment_counts.get(var_name, 0) == 1 and var_name not in analyzer.conditional_vars:
                try:
                    val = evaluator.evaluate(node_val)
                    if isinstance(val, (int, float, str, bytes, bool, list, tuple, dict, set, type(None))):
                        self.known_constants[var_name] = val
                except (SafeEvalError, UnsupportedNodeError):
                    pass

        # 3. Transform AST
        new_tree = self.visit(tree)
        ast.fix_missing_locations(new_tree)
        return new_tree, self.transforms_applied

    def visit_BinOp(self, node: ast.BinOp) -> ast.AST:
        self.generic_visit(node)
        return self._try_eval_node(node)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.AST:
        self.generic_visit(node)
        return self._try_eval_node(node)

    def visit_Subscript(self, node: ast.Subscript) -> ast.AST:
        self.generic_visit(node)
        return self._try_eval_node(node)

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        self.generic_visit(node)
        return self._try_eval_node(node)

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        return self._try_eval_node(node)

    def visit_IfExp(self, node: ast.IfExp) -> ast.AST:
        self.generic_visit(node)
        # Check if test is a constant
        if isinstance(node.test, ast.Constant):
            if bool(node.test.value):
                self.transforms_applied.append(f"Pruned ternary branch (condition: True) at line {node.lineno}")
                return node.body
            else:
                self.transforms_applied.append(f"Pruned ternary branch (condition: False) at line {node.lineno}")
                return node.orelse
        return node

    def visit_If(self, node: ast.If) -> Any:
        # First visit children
        node.test = self.visit(node.test)
        node.body = [self.visit(stmt) for stmt in node.body]
        node.orelse = [self.visit(stmt) for stmt in node.orelse]

        # Check if condition is provably constant
        if isinstance(node.test, ast.Constant):
            cond_val = bool(node.test.value)
            line_no = getattr(node, "lineno", 0)
            if cond_val:
                self.transforms_applied.append(f"Pruned static 'if True' branch at line {line_no}")
                return node.body
            else:
                self.transforms_applied.append(f"Pruned static 'if False' branch at line {line_no}")
                return node.orelse

        return node

    def _try_eval_node(self, node: ast.AST) -> ast.AST:
        try:
            evaluator = SafeEvaluator(env=self.known_constants, limits=self.limits)
            result = evaluator.evaluate(node)
            if isinstance(result, (int, float, str, bytes, bool, type(None))):
                line_no = getattr(node, "lineno", 0)
                desc = type(node).__name__
                self.transforms_applied.append(
                    f"Folded {desc} to constant {type(result).__name__} (line {line_no})"
                )
                new_const = ast.Constant(value=result)
                ast.copy_location(new_const, node)
                return new_const
        except (SafeEvalError, UnsupportedNodeError):
            pass
        return node
