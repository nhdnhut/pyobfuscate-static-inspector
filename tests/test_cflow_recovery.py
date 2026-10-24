"""Tests for control flow de-flattening."""

import ast
from pyobfuscate_inspector.deobfuscate.cflow_recovery import ControlFlowDeflattener


def test_deflatten_linear_dispatcher():
    source = """
def process():
    a = 1
    state = 0
    while True:
        if state == 0:
            a += 10
            state = 1
        elif state == 1:
            a *= 2
            state = 2
        elif state == 2:
            break
    return a
"""
    tree = ast.parse(source)
    deflattener = ControlFlowDeflattener()
    new_tree, logs = deflattener.deflatten_tree(tree)
    clean_code = ast.unparse(new_tree)

    assert "while True:" not in clean_code
    assert "state ==" not in clean_code
    assert "a += 10" in clean_code
    assert "a *= 2" in clean_code
    assert len(logs) == 1

    # Verify execution equivalence
    ns = {}
    exec(clean_code, ns)
    assert ns["process"]() == 22


def test_preserve_non_dispatcher_loop():
    source = """
def normal_loop():
    count = 0
    while count < 5:
        count += 1
    return count
"""
    tree = ast.parse(source)
    deflattener = ControlFlowDeflattener()
    new_tree, logs = deflattener.deflatten_tree(tree)
    clean_code = ast.unparse(new_tree)

    assert "while count < 5:" in clean_code
    assert len(logs) == 0
