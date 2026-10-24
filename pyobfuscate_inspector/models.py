"""Data models and enums for PyObfuscate Inspector."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Status(str, Enum):
    RECOVERED = "recovered"
    PARTIALLY_RECOVERED = "partially_recovered"
    UNSUPPORTED = "unsupported"
    MISSING_KEY = "missing_key"
    LIMIT_EXCEEDED = "limit_exceeded"
    INVALID_INPUT = "invalid_input"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DetectedMechanism:
    name: str
    category: str
    evidence: str
    confidence: float = 1.0
    line: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "name": self.name,
            "category": self.category,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }
        if self.line is not None:
            res["line"] = self.line
        if self.details:
            res["details"] = self.details
        return res


@dataclass
class LayerInfo:
    layer_index: int
    layer_type: str
    size: int
    sha256: str
    filename: str
    transforms: List[str] = field(default_factory=list)
    is_valid_python: bool = False
    content_bytes: Optional[bytes] = None
    content_text: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer_index": self.layer_index,
            "layer_type": self.layer_type,
            "size": self.size,
            "sha256": self.sha256,
            "filename": self.filename,
            "transforms": self.transforms,
            "is_valid_python": self.is_valid_python,
            "notes": self.notes,
        }


@dataclass
class AuditFinding:
    category: str  # imports, file_ops, subprocess, endpoints, exfiltration, anti_debug, etc.
    item: str
    evidence: str
    severity: Severity = Severity.LOW
    line: Optional[int] = None
    redacted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "category": self.category,
            "item": self.item,
            "evidence": self.evidence,
            "severity": self.severity.value,
            "redacted": self.redacted,
        }
        if self.line is not None:
            res["line"] = self.line
        return res


@dataclass
class AnalysisLimits:
    max_file_size: int = 50 * 1024 * 1024       # 50 MB
    max_layers: int = 10                       # Max unpacking iterations
    max_ast_nodes: int = 150_000               # Max AST nodes to traverse
    max_ast_depth: int = 250                   # Max AST depth
    max_eval_steps: int = 100_000              # Max evaluation steps in safe interpreter
    max_loop_iterations: int = 50_000          # Max loop iterations in comprehensions
    max_data_size: int = 25 * 1024 * 1024      # 25 MB max decompressed/evaluated string
    max_int_bits: int = 4096                   # Max integer bit length (prevent 2**99999999)
    timeout_seconds: float = 30.0              # Global timeout in seconds

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_file_size": self.max_file_size,
            "max_layers": self.max_layers,
            "max_ast_nodes": self.max_ast_nodes,
            "max_ast_depth": self.max_ast_depth,
            "max_eval_steps": self.max_eval_steps,
            "max_loop_iterations": self.max_loop_iterations,
            "max_data_size": self.max_data_size,
            "max_int_bits": self.max_int_bits,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass
class AuditReport:
    input_file: str
    hashes: Dict[str, str]
    status: Status
    status_reason: str
    detected_mechanisms: List[DetectedMechanism] = field(default_factory=list)
    layers: List[LayerInfo] = field(default_factory=list)
    audit_findings: List[AuditFinding] = field(default_factory=list)
    missing_parameters: List[str] = field(default_factory=list)
    recovered_code: Optional[str] = None
    limits: AnalysisLimits = field(default_factory=AnalysisLimits)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_file": self.input_file,
            "hashes": self.hashes,
            "status": self.status.value,
            "status_reason": self.status_reason,
            "detected_mechanisms": [m.to_dict() for m in self.detected_mechanisms],
            "layers_summary": [l.to_dict() for l in self.layers],
            "audit": {
                "imports": [f.to_dict() for f in self.audit_findings if f.category == "import"],
                "file_operations": [f.to_dict() for f in self.audit_findings if f.category == "file_op"],
                "subprocess_calls": [f.to_dict() for f in self.audit_findings if f.category == "subprocess"],
                "endpoints": [f.to_dict() for f in self.audit_findings if f.category == "endpoint"],
                "exfiltration_indicators": [f.to_dict() for f in self.audit_findings if f.category == "exfiltration"],
                "anti_analysis": [f.to_dict() for f in self.audit_findings if f.category == "anti_debug"],
                "control_flow_flattening": [f.to_dict() for f in self.audit_findings if f.category == "control_flow_flattening"],
                "all_findings": [f.to_dict() for f in self.audit_findings],
            },
            "missing_parameters": self.missing_parameters,
            "has_recovered_code": self.recovered_code is not None,
            "limits": self.limits.to_dict(),
        }
