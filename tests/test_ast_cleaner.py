"""Tests for ASTCleaner: builtin unwrapping and dead code elimination."""

import ast
from pyobfuscate_inspector.deobfuscate.ast_cleaner import ASTCleaner


def test_unwrap_getattr_builtins():
    source = """
length = getattr(__builtins__, 'len')([1, 2, 3])
msg = getattr(__builtins__, 'str')(123)
"""
    tree = ast.parse(source)
    cleaner = ASTCleaner()
    new_tree, logs = cleaner.clean_tree(tree)
    clean_code = ast.unparse(new_tree)

    assert "len([1, 2, 3])" in clean_code
    assert "str(123)" in clean_code
    assert "getattr" not in clean_code


def test_prune_dead_code_after_return():
    source = """
def calculate():
    x = 10
    return x * 2
    y = 50
    print('never reached')
"""
    tree = ast.parse(source)
    cleaner = ASTCleaner()
    new_tree, logs = cleaner.clean_tree(tree)
    clean_code = ast.unparse(new_tree)

    assert "return x * 2" in clean_code
    assert "y = 50" not in clean_code
    assert "never reached" not in clean_code


def test_remove_unused_loader_imports():
    source = """
import base64
import zlib

print("Pure user logic with no loader dependencies")
"""
    tree = ast.parse(source)
    cleaner = ASTCleaner()
    new_tree, logs = cleaner.clean_tree(tree)
    clean_code = ast.unparse(new_tree)

    assert "import base64" not in clean_code
    assert "import zlib" not in clean_code
