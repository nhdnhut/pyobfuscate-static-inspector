"""Resource limits and safety exceptions for the Safe AST Evaluator."""

from typing import Optional
from pyobfuscate_inspector.models import AnalysisLimits


class SafeEvalError(Exception):
    """Base exception for safe evaluation errors."""
    pass


class ResourceLimitExceeded(SafeEvalError):
    """Raised when an execution or resource limit (depth, nodes, loops, size) is exceeded."""
    pass


class UnsupportedNodeError(SafeEvalError):
    """Raised when encountering an untrusted or non-whitelisted AST node."""
    pass


class MissingKeyError(SafeEvalError):
    """Raised when cryptographic key or parameters are missing."""
    pass


class AuthenticationFailedError(SafeEvalError):
    """Raised when authentication tag verification fails (e.g. AES-GCM)."""
    pass


class LimitTracker:
    """Tracks AST evaluation steps, recursion depth, loops, and generated memory."""

    def __init__(self, limits: Optional[AnalysisLimits] = None):
        self.limits = limits or AnalysisLimits()
        self.step_count = 0
        self.loop_iterations = 0
        self.current_depth = 0

    def enter_node(self) -> None:
        self.step_count += 1
        if self.step_count > self.limits.max_eval_steps:
            raise ResourceLimitExceeded(
                f"Evaluation exceeded maximum step limit ({self.limits.max_eval_steps} steps)"
            )

    def enter_depth(self) -> None:
        self.current_depth += 1
        if self.current_depth > self.limits.max_ast_depth:
            raise ResourceLimitExceeded(
                f"AST traversal exceeded maximum depth ({self.limits.max_ast_depth})"
            )

    def exit_depth(self) -> None:
        if self.current_depth > 0:
            self.current_depth -= 1

    def tick_loop(self) -> None:
        self.loop_iterations += 1
        if self.loop_iterations > self.limits.max_loop_iterations:
            raise ResourceLimitExceeded(
                f"Loop iterations exceeded limit ({self.limits.max_loop_iterations} iterations)"
            )

    def check_int_size(self, val: int) -> None:
        if isinstance(val, int) and not isinstance(val, bool):
            bit_len = val.bit_length()
            if bit_len > self.limits.max_int_bits:
                raise ResourceLimitExceeded(
                    f"Integer bit length ({bit_len}) exceeded limit of {self.limits.max_int_bits} bits"
                )

    def check_data_size(self, size: int) -> None:
        if size > self.limits.max_data_size:
            raise ResourceLimitExceeded(
                f"Data size ({size} bytes) exceeded maximum allowed limit ({self.limits.max_data_size} bytes)"
            )
