"""Tests for constant folding and branch pruning."""

import ast
from pyobfuscate_inspector.deobfuscate.constant_fold import ConstantFolder


def fold_code(source: str) -> str:
    tree = ast.parse(source)
    folder = ConstantFolder()
    new_tree, _ = folder.fold_tree(tree)
    return ast.unparse(new_tree)


def test_arithmetic_folding():
    code = "val = (10 + 20) * 3"
    folded = fold_code(code)
    assert "val = 90" in folded


def test_string_reversal_folding():
    code = "msg = 'dlrow olleh'[::-1]"
    folded = fold_code(code)
    assert "msg = 'hello world'" in folded


def test_scope_safe_constant_tracking():
    code = """
a = 100
b = a + 50
"""
    folded = fold_code(code)
    assert "b = 150" in folded


def test_do_not_fold_uncertain_branch_variables():
    # If variable is assigned inside an if block, do NOT assume constant
    code = """
if flag:
    x = 10
else:
    x = 20
y = x + 5
"""
    folded = fold_code(code)
    # y = x + 5 should NOT be folded to constant because x is conditionally assigned
    assert "y = x + 5" in folded


def test_branch_pruning():
    code = """
if True:
    print('kept')
else:
    print('removed')
"""
    folded = fold_code(code)
    assert "print('kept')" in folded
    assert "print('removed')" not in folded
