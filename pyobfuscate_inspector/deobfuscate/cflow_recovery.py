"""Control Flow De-flattening (CFF) engine for recovering structured control flow.

Transforms state dispatchers (while loop with state variable branching)
back into sequential statements, if/else, and loops when transitions are provable.
"""

import ast
from typing import Any, Dict, List, Optional, Set, Tuple


class BasicBlock:
    """Represents a basic block in a control flow dispatcher."""

    def __init__(self, state_val: Any, statements: List[ast.stmt], next_state: Any, is_terminal: bool = False):
        self.state_val = state_val
        self.statements = statements
        self.next_state = next_state
        self.is_terminal = is_terminal  # True if ends with break or return


class ControlFlowDeflattener(ast.NodeTransformer):
    """De-flattens flattened dispatcher loops while preserving semantic equivalence."""

    def __init__(self):
        self.deflattened_loops = 0
        self.transformation_log: List[str] = []

    def deflatten_tree(self, tree: ast.AST) -> Tuple[ast.AST, List[str]]:
        new_tree = self.visit(tree)
        ast.fix_missing_locations(new_tree)
        return new_tree, self.transformation_log

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.body = self._process_statement_list(node.body)
        self.generic_visit(node)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        node.body = self._process_statement_list(node.body)
        self.generic_visit(node)
        return node

    def visit_Module(self, node: ast.Module) -> ast.AST:
        node.body = self._process_statement_list(node.body)
        self.generic_visit(node)
        return node

    def _process_statement_list(self, statements: List[ast.stmt]) -> List[ast.stmt]:
        new_stmts = []
        for stmt in statements:
            if isinstance(stmt, ast.While):
                # Search backward in new_stmts for candidate state assignment
                found_state = False
                for j in range(len(new_stmts) - 1, max(-1, len(new_stmts) - 10), -1):
                    cand = new_stmts[j]
                    if isinstance(cand, ast.Assign) and len(cand.targets) == 1:
                        target = cand.targets[0]
                        if isinstance(target, ast.Name) and isinstance(cand.value, ast.Constant):
                            state_var = target.id
                            init_val = cand.value.value
                            reconstructed = self._try_deflatten(stmt, state_var, init_val)
                            if reconstructed is not None:
                                line_no = getattr(stmt, "lineno", 0)
                                self.transformation_log.append(
                                    f"De-flattened control flow dispatcher loop for state variable '{state_var}' at line {line_no}"
                                )
                                self.deflattened_loops += 1
                                # Remove the state variable initialization
                                new_stmts.pop(j)
                                new_stmts.extend(reconstructed)
                                found_state = True
                                break
                if found_state:
                    continue

            new_stmts.append(self.visit(stmt))
        return new_stmts

    def _try_deflatten(self, while_node: ast.While, state_var: str, init_val: Any) -> Optional[List[ast.stmt]]:
        """Analyzes dispatcher while loop and attempts to reconstruct linear/structured flow."""
        # Loop test must be True or 1
        is_infinite = False
        if isinstance(while_node.test, ast.Constant) and bool(while_node.test.value) is True:
            is_infinite = True
        elif isinstance(while_node.test, ast.Name) and while_node.test.id == "True":
            is_infinite = True

        if not is_infinite:
            return None

        # Collect all state branches
        blocks: Dict[Any, BasicBlock] = {}
        if not self._extract_blocks(while_node.body, state_var, blocks):
            return None

        if init_val not in blocks:
            return None

        # Trace execution path from init_val
        reconstructed_stmts: List[ast.stmt] = []
        current_state = init_val
        visited_states: Set[Any] = set()

        while current_state is not None:
            if current_state in visited_states:
                # Loop / cycle detected in state transitions
                # If it's a cyclic transition, we cannot safely linearize without constructing a while loop
                return None

            visited_states.add(current_state)
            if current_state not in blocks:
                # State not found in dispatch table
                return None

            block = blocks[current_state]
            reconstructed_stmts.extend(block.statements)

            if block.is_terminal:
                break

            current_state = block.next_state

        return reconstructed_stmts

    def _extract_blocks(self, body: List[ast.stmt], state_var: str, blocks: Dict[Any, BasicBlock]) -> bool:
        """Extracts if-elif-else branches comparing state_var to constants."""
        for stmt in body:
            if isinstance(stmt, ast.If):
                curr = stmt
                while curr:
                    # Check condition: state_var == CONST
                    state_val = self._match_state_cond(curr.test, state_var)
                    if state_val is None:
                        return False

                    # Extract statements and next state from curr.body
                    clean_stmts, next_state, is_term = self._analyze_branch_body(curr.body, state_var)
                    if next_state is None and not is_term:
                        return False

                    blocks[state_val] = BasicBlock(
                        state_val=state_val,
                        statements=clean_stmts,
                        next_state=next_state,
                        is_terminal=is_term,
                    )

                    # Next elif branch
                    if curr.orelse and len(curr.orelse) == 1 and isinstance(curr.orelse[0], ast.If):
                        curr = curr.orelse[0]
                    else:
                        break
            else:
                # Statements outside the if-elif dispatcher inside the while loop
                return False

        return len(blocks) >= 2

    def _match_state_cond(self, test: ast.AST, state_var: str) -> Optional[Any]:
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
            left = test.left
            right = test.comparators[0]
            if isinstance(left, ast.Name) and left.id == state_var and isinstance(right, ast.Constant):
                return right.value
            elif isinstance(right, ast.Name) and right.id == state_var and isinstance(left, ast.Constant):
                return left.value
        return None

    def _analyze_branch_body(self, body: List[ast.stmt], state_var: str) -> Tuple[List[ast.stmt], Optional[Any], bool]:
        """Filters out state transitions and identifies the next state or terminal exit."""
        clean_stmts: List[ast.stmt] = []
        next_state = None
        is_terminal = False

        for s in body:
            if isinstance(s, ast.Break):
                is_terminal = True
                continue
            if isinstance(s, ast.Return):
                is_terminal = True
                clean_stmts.append(s)
                continue
            if isinstance(s, ast.Assign):
                # Check if assigning state_var = CONST
                if len(s.targets) == 1 and isinstance(s.targets[0], ast.Name) and s.targets[0].id == state_var:
                    if isinstance(s.value, ast.Constant):
                        next_state = s.value.value
                        continue
            clean_stmts.append(s)

        return clean_stmts, next_state, is_terminal
