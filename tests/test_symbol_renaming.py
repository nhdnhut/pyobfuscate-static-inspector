"""Tests for scope-aware symbol renaming and protected symbols."""

import ast
from pyobfuscate_inspector.deobfuscate.symbol_renamer import SymbolRenamer


def test_rename_obfuscated_identifiers():
    source = """
def _0x1a2b(_0x99, _0x88):
    _0x3c = _0x99 + _0x88
    return _0x3c
"""
    tree = ast.parse(source)
    renamer = SymbolRenamer()
    new_tree, symbol_map = renamer.rename_symbols(tree)
    clean_code = ast.unparse(new_tree)

    assert "_0x1a2b" not in clean_code
    assert "_0x99" not in clean_code
    assert "_0x88" not in clean_code
    assert len(symbol_map) == 4

    # Verify execution
    ns = {}
    exec(clean_code, ns)
    func_name = symbol_map[0]["new_name"]
    assert ns[func_name](10, 20) == 30


def test_protect_reflection_and_globals():
    source = """
import os

def check():
    val = getattr(os, 'name')
    token = globals()['my_secret']
    return val, token
"""
    tree = ast.parse(source)
    renamer = SymbolRenamer()
    new_tree, symbol_map = renamer.rename_symbols(tree)
    clean_code = ast.unparse(new_tree)

    assert "getattr(os, 'name')" in clean_code
    assert "globals()['my_secret']" in clean_code
    # 'os', 'name', 'my_secret' must not be renamed
    renamed_origs = [s["original_name"] for s in symbol_map]
    assert "os" not in renamed_origs
    assert "name" not in renamed_origs
    assert "my_secret" not in renamed_origs
