"""Safe AST Evaluator for evaluating expressions in obfuscated Python scripts.

Statically interprets an allowed subset of AST nodes without invoking eval() or exec().
Applies strict limits on recursion depth, step count, loop iterations, memory, and data size.
"""

import ast
import operator
from typing import Any, Callable, Dict, List, Optional, Set, Union

from pyobfuscate_inspector.models import AnalysisLimits
from pyobfuscate_inspector.safe_eval.limits import (
    LimitTracker,
    ResourceLimitExceeded,
    SafeEvalError,
    UnsupportedNodeError,
)
from pyobfuscate_inspector.safe_eval.whitelist import (
    MODULE_WHITELIST,
    SAFE_BUILTINS,
    SAFE_METHODS,
)


class ModuleProxy:
    """Safe proxy representing an allowed standard library module (base64, zlib, etc.)."""

    def __init__(self, name: str, methods: Dict[str, Callable[..., Any]]):
        self.name = name
        self.methods = methods

    def __getattr__(self, item: str) -> Any:
        if item in self.methods:
            return self.methods[item]
        raise UnsupportedNodeError(f"Access to {self.name}.{item} is not permitted")

    def __repr__(self) -> str:
        return f"<SafeModuleProxy {self.name}>"


class BuiltinsProxy:
    """Safe proxy representing __builtins__."""

    def __init__(self, builtins_map: Dict[str, Callable[..., Any]]):
        self._map = builtins_map

    def __getitem__(self, item: str) -> Any:
        if item in self._map:
            return self._map[item]
        raise UnsupportedNodeError(f"Builtin '{item}' is not permitted")

    def __getattr__(self, item: str) -> Any:
        if item == "__dict__":
            return self._map
        if item in self._map:
            return self._map[item]
        raise UnsupportedNodeError(f"Builtin attribute '{item}' is not permitted")

    def get(self, item: str, default: Any = None) -> Any:
        return self._map.get(item, default)


class SafeEvaluator:
    """Evaluates whitelisted AST nodes safely."""

    BIN_OPS = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
        ast.BitOr: operator.or_,
        ast.BitXor: operator.xor,
        ast.BitAnd: operator.and_,
        ast.RShift: operator.rshift,
        ast.LShift: operator.lshift,
    }

    UNARY_OPS = {
        ast.UAdd: operator.pos,
        ast.USub: operator.neg,
        ast.Not: operator.not_,
        ast.Invert: operator.invert,
    }

    COMP_OPS = {
        ast.Eq: operator.eq,
        ast.NotEq: operator.ne,
        ast.Lt: operator.lt,
        ast.LtE: operator.le,
        ast.Gt: operator.gt,
        ast.GtE: operator.ge,
        ast.In: lambda a, b: a in b,
        ast.NotIn: lambda a, b: a not in b,
        ast.Is: operator.is_,
        ast.IsNot: operator.is_not,
    }

    def __init__(
        self,
        env: Optional[Dict[str, Any]] = None,
        limits: Optional[AnalysisLimits] = None,
        tracker: Optional[LimitTracker] = None,
    ):
        self.limits = limits or AnalysisLimits()
        self.tracker = tracker or LimitTracker(self.limits)
        self.env: Dict[str, Any] = env.copy() if env else {}

        # Set up safe module proxies
        self.modules: Dict[str, ModuleProxy] = {
            mod_name: ModuleProxy(mod_name, funcs)
            for mod_name, funcs in MODULE_WHITELIST.items()
        }
        self.builtins_proxy = BuiltinsProxy(SAFE_BUILTINS)

    def evaluate(self, node: ast.AST) -> Any:
        """Evaluate an AST expression node safely."""
        self.tracker.enter_node()
        self.tracker.enter_depth()
        try:
            return self._eval(node)
        finally:
            self.tracker.exit_depth()

    def _eval(self, node: ast.AST) -> Any:
        method_name = f"_eval_{node.__class__.__name__}"
        handler = getattr(self, method_name, None)
        if handler is None:
            raise UnsupportedNodeError(
                f"AST node type '{node.__class__.__name__}' is not supported for safe evaluation"
            )
        res = handler(node)
        self._check_result_size(res)
        return res

    def _check_result_size(self, val: Any) -> None:
        if isinstance(val, (str, bytes, bytearray)):
            self.tracker.check_data_size(len(val))
        elif isinstance(val, int) and not isinstance(val, bool):
            self.tracker.check_int_size(val)
        elif isinstance(val, (list, tuple, set, dict)):
            self.tracker.check_data_size(len(val) * 8)

    def _eval_Constant(self, node: ast.Constant) -> Any:
        return node.value

    def _eval_Name(self, node: ast.Name) -> Any:
        var_id = node.id
        if var_id in self.env:
            return self.env[var_id]
        if var_id in SAFE_BUILTINS:
            return SAFE_BUILTINS[var_id]
        if var_id in self.modules:
            return self.modules[var_id]
        if var_id == "__builtins__":
            return self.builtins_proxy
        if var_id == "True":
            return True
        if var_id == "False":
            return False
        if var_id == "None":
            return None
        raise UnsupportedNodeError(f"Variable or identifier '{var_id}' not found in safe environment")

    def _eval_UnaryOp(self, node: ast.UnaryOp) -> Any:
        operand = self.evaluate(node.operand)
        op_type = type(node.op)
        if op_type not in self.UNARY_OPS:
            raise UnsupportedNodeError(f"Unary operator {op_type.__name__} not supported")
        try:
            res = self.UNARY_OPS[op_type](operand)
            return res
        except Exception as e:
            raise SafeEvalError(f"Unary op error: {e}") from e

    def _eval_BinOp(self, node: ast.BinOp) -> Any:
        left = self.evaluate(node.left)
        right = self.evaluate(node.right)
        op_type = type(node.op)

        # Exponentiation checks
        if op_type is ast.Pow:
            if not isinstance(right, (int, float)) or not isinstance(left, (int, float)):
                raise UnsupportedNodeError("Pow operator only supported for numeric values")
            if isinstance(right, int) and right > 1000:
                raise ResourceLimitExceeded("Power exponent exceeds safety limit (1000)")
            if isinstance(left, int) and isinstance(right, int) and right > 0:
                est_bits = left.bit_length() * right
                if est_bits > self.limits.max_int_bits:
                    raise ResourceLimitExceeded(f"Power result would exceed integer bit limit ({est_bits} bits)")
            return left ** right

        # Shift checks
        if op_type is ast.LShift:
            if not isinstance(right, int) or not isinstance(left, int):
                raise UnsupportedNodeError("LShift requires integers")
            if right < 0 or right > self.limits.max_int_bits:
                raise ResourceLimitExceeded(f"Bit shift {right} exceeds safety limit")
            if left.bit_length() + right > self.limits.max_int_bits:
                raise ResourceLimitExceeded("Bit shift result exceeds integer bit limit")
            return left << right

        if op_type is ast.Mult:
            if isinstance(left, (str, bytes, list, tuple)) and isinstance(right, int):
                if right > 0 and len(left) * right > self.limits.max_data_size:
                    raise ResourceLimitExceeded("Sequence multiplication exceeds maximum data size")
            elif isinstance(right, (str, bytes, list, tuple)) and isinstance(left, int):
                if left > 0 and len(right) * left > self.limits.max_data_size:
                    raise ResourceLimitExceeded("Sequence multiplication exceeds maximum data size")

        if op_type not in self.BIN_OPS:
            raise UnsupportedNodeError(f"Binary operator {op_type.__name__} not supported")

        try:
            return self.BIN_OPS[op_type](left, right)
        except Exception as e:
            raise SafeEvalError(f"Binary op error: {e}") from e

    def _eval_BoolOp(self, node: ast.BoolOp) -> Any:
        if isinstance(node.op, ast.And):
            val: Any = True
            for val_node in node.values:
                val = self.evaluate(val_node)
                if not val:
                    return val
            return val
        elif isinstance(node.op, ast.Or):
            val = False
            for val_node in node.values:
                val = self.evaluate(val_node)
                if val:
                    return val
            return val
        raise UnsupportedNodeError(f"Boolean operator {type(node.op).__name__} not supported")

    def _eval_Compare(self, node: ast.Compare) -> bool:
        left = self.evaluate(node.left)
        for op, comparator in zip(node.ops, node.comparators):
            right = self.evaluate(comparator)
            op_type = type(op)
            if op_type not in self.COMP_OPS:
                raise UnsupportedNodeError(f"Comparison operator {op_type.__name__} not supported")
            if not self.COMP_OPS[op_type](left, right):
                return False
            left = right
        return True

    def _eval_IfExp(self, node: ast.IfExp) -> Any:
        test = self.evaluate(node.test)
        if test:
            return self.evaluate(node.body)
        else:
            return self.evaluate(node.orelse)

    def _eval_Tuple(self, node: ast.Tuple) -> tuple:
        return tuple(self.evaluate(elt) for elt in node.elts)

    def _eval_List(self, node: ast.List) -> list:
        return [self.evaluate(elt) for elt in node.elts]

    def _eval_Set(self, node: ast.Set) -> set:
        return {self.evaluate(elt) for elt in node.elts}

    def _eval_Dict(self, node: ast.Dict) -> dict:
        d = {}
        for k, v in zip(node.keys, node.values):
            if k is None:
                # Dict unpacking {**d}
                unpacked = self.evaluate(v)
                if isinstance(unpacked, dict):
                    d.update(unpacked)
                else:
                    raise UnsupportedNodeError("Dict unpacking non-dict")
            else:
                key_val = self.evaluate(k)
                val_val = self.evaluate(v)
                d[key_val] = val_val
        return d

    def _eval_Slice(self, node: ast.Slice) -> slice:
        lower = self.evaluate(node.lower) if node.lower is not None else None
        upper = self.evaluate(node.upper) if node.upper is not None else None
        step = self.evaluate(node.step) if node.step is not None else None
        return slice(lower, upper, step)

    def _eval_Subscript(self, node: ast.Subscript) -> Any:
        val = self.evaluate(node.value)
        slc = self.evaluate(node.slice)
        try:
            return val[slc]
        except Exception as e:
            raise SafeEvalError(f"Subscript error: {e}") from e

    def _eval_Attribute(self, node: ast.Attribute) -> Any:
        val = self.evaluate(node.value)
        attr = node.attr

        # Safe Module Proxy
        if isinstance(val, ModuleProxy):
            return getattr(val, attr)

        # Builtins Proxy
        if isinstance(val, BuiltinsProxy):
            return getattr(val, attr)

        # Builtin types safe methods
        if isinstance(val, (str, bytes, bytearray, list, dict, set, tuple)):
            if attr in SAFE_METHODS:
                return getattr(val, attr)
            raise UnsupportedNodeError(f"Method '{attr}' on {type(val).__name__} is not in safe whitelist")

        # Type objects (e.g. bytes.fromhex)
        if val is bytes and attr == "fromhex":
            return bytes.fromhex
        if val is bytearray and attr == "fromhex":
            return bytearray.fromhex

        raise UnsupportedNodeError(f"Attribute access '.{attr}' on object {type(val).__name__} is not allowed")

    def _eval_Call(self, node: ast.Call) -> Any:
        # Check for special builtin bypasses like getattr(__builtins__, ...)
        if isinstance(node.func, ast.Name) and node.func.id == "getattr":
            if len(node.args) >= 2:
                target = self.evaluate(node.args[0])
                name = self.evaluate(node.args[1])
                default = self.evaluate(node.args[2]) if len(node.args) > 2 else None
                if isinstance(target, BuiltinsProxy) or target is __builtins__:
                    if name in SAFE_BUILTINS:
                        return SAFE_BUILTINS[name]
                    if default is not None:
                        return default
                    raise UnsupportedNodeError(f"getattr on builtins for '{name}' is not permitted")
                if isinstance(target, ModuleProxy):
                    return getattr(target, name)
                if isinstance(target, (str, bytes, bytearray, list, dict, set)) and name in SAFE_METHODS:
                    return getattr(target, name)
                raise UnsupportedNodeError(f"getattr({target}, '{name}') is not allowed")

        func = self.evaluate(node.func)
        args = [self.evaluate(arg) for arg in node.args]
        kwargs = {kw.arg: self.evaluate(kw.value) for kw in node.keywords if kw.arg}

        # Check call validity
        if not callable(func):
            raise SafeEvalError(f"Attempted to call non-callable object {func}")

        # Check if func is a whitelisted function or method
        func_name = getattr(func, "__name__", "")
        # Whitelisted builtins or module functions or safe methods
        is_safe = (
            func in SAFE_BUILTINS.values()
            or any(func in mod.methods.values() for mod in self.modules.values())
            or func_name in SAFE_METHODS
            or func in (bytes.fromhex, bytearray.fromhex)
        )
        if not is_safe:
            raise UnsupportedNodeError(f"Function call to '{func_name}' is not whitelisted")

        try:
            return func(*args, **kwargs)
        except SafeEvalError:
            raise
        except Exception as e:
            raise SafeEvalError(f"Call to {func_name} failed: {e}") from e

    def _eval_ListComp(self, node: ast.ListComp) -> list:
        res = []
        self._eval_comprehension(node.generators, 0, node.elt, res.append)
        return res

    def _eval_SetComp(self, node: ast.SetComp) -> set:
        res = set()
        self._eval_comprehension(node.generators, 0, node.elt, res.add)
        return res

    def _eval_DictComp(self, node: ast.DictComp) -> dict:
        res = {}

        def collector(key_val: Any) -> None:
            k, v = key_val
            res[k] = v

        # Pair key and value
        elt_pair = ast.Tuple(elts=[node.key, node.value], ctx=ast.Load())
        self._eval_comprehension(node.generators, 0, elt_pair, collector)
        return res

    def _eval_comprehension(
        self,
        generators: List[ast.comprehension],
        gen_idx: int,
        elt_node: ast.AST,
        callback: Callable[[Any], None],
    ) -> None:
        if gen_idx >= len(generators):
            val = self.evaluate(elt_node)
            callback(val)
            return

        gen = generators[gen_idx]
        iter_val = self.evaluate(gen.iter)
        if not hasattr(iter_val, "__iter__"):
            raise SafeEvalError(f"Object {iter_val} is not iterable")

        # Save previous local env bindings for target name(s)
        for item in iter_val:
            self.tracker.tick_loop()
            self._assign_target(gen.target, item)

            # Check if-conditions
            all_ifs = True
            for if_expr in gen.ifs:
                if not self.evaluate(if_expr):
                    all_ifs = False
                    break
            if all_ifs:
                self._eval_comprehension(generators, gen_idx + 1, elt_node, callback)

    def _assign_target(self, target: ast.AST, value: Any) -> None:
        if isinstance(target, ast.Name):
            self.env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            if not isinstance(value, (list, tuple)) or len(target.elts) != len(value):
                raise SafeEvalError("Unpacking target mismatch in comprehension")
            for sub_target, sub_val in zip(target.elts, value):
                self._assign_target(sub_target, sub_val)
        else:
            raise UnsupportedNodeError(f"Comprehension target type {type(target).__name__} unsupported")

    def _eval_JoinedStr(self, node: ast.JoinedStr) -> str:
        parts = []
        for val in node.values:
            parts.append(str(self.evaluate(val)))
        return "".join(parts)

    def _eval_FormattedValue(self, node: ast.FormattedValue) -> Any:
        return self.evaluate(node.value)
