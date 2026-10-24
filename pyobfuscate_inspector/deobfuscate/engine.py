"""Multi-layer deobfuscation coordinator.

Safely unpacks nested layers, applies constant folding, extracts exec() payloads,
detects cycles, enforces depth limits, and calls isolated workers for marshal bytecode.
"""

import ast
import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple

from pyobfuscate_inspector.deobfuscate.ast_cleaner import ASTCleaner
from pyobfuscate_inspector.deobfuscate.cflow_recovery import ControlFlowDeflattener
from pyobfuscate_inspector.deobfuscate.constant_fold import ConstantFolder
from pyobfuscate_inspector.deobfuscate.crypto_engine import (
    safe_aes_gcm_decrypt,
    safe_xor_bytes,
)
from pyobfuscate_inspector.deobfuscate.exec_extractor import ExecExtractor
from pyobfuscate_inspector.deobfuscate.marshal_worker import run_isolated_marshal_inspector
from pyobfuscate_inspector.deobfuscate.symbol_renamer import SymbolRenamer
from pyobfuscate_inspector.models import (
    AnalysisLimits,
    LayerInfo,
    Status,
)
from pyobfuscate_inspector.safe_eval.limits import (
    AuthenticationFailedError,
    MissingKeyError,
    ResourceLimitExceeded,
    SafeEvalError,
    UnsupportedNodeError,
)


class DeobfuscationResult:
    """Contains results of multi-layer deobfuscation."""

    def __init__(
        self,
        status: Status,
        status_reason: str,
        layers: List[LayerInfo],
        final_code: Optional[str] = None,
        missing_parameters: Optional[List[str]] = None,
        symbol_map: Optional[List[Dict[str, Any]]] = None,
        transformations: Optional[List[str]] = None,
        unresolved_items: Optional[List[str]] = None,
    ):
        self.status = status
        self.status_reason = status_reason
        self.layers = layers
        self.final_code = final_code
        self.missing_parameters = missing_parameters or []
        self.symbol_map = symbol_map or []
        self.transformations = transformations or []
        self.unresolved_items = unresolved_items or []


class DeobfuscationEngine:
    """Orchestrates layer-by-layer deobfuscation with safety boundaries."""

    def __init__(self, limits: Optional[AnalysisLimits] = None):
        self.limits = limits or AnalysisLimits()

    def deobfuscate(self, initial_source: str) -> DeobfuscationResult:
        layers: List[LayerInfo] = []
        seen_hashes: Set[str] = set()

        current_content = initial_source
        current_layer_idx = 0

        # Layer 0: Raw Input
        raw_bytes = current_content.encode("utf-8", errors="replace")
        sha0 = hashlib.sha256(raw_bytes).hexdigest()
        seen_hashes.add(sha0)

        # Initial syntax check
        try:
            tree = ast.parse(current_content)
            is_valid_py = True
        except SyntaxError as e:
            layers.append(
                LayerInfo(
                    layer_index=0,
                    layer_type="raw_input",
                    size=len(raw_bytes),
                    sha256=sha0,
                    filename="layer_00_raw.py",
                    transforms=[],
                    is_valid_python=False,
                    content_text=current_content,
                    notes=f"SyntaxError in input file: {e}",
                )
            )
            return DeobfuscationResult(
                status=Status.INVALID_INPUT,
                status_reason=f"Input file is not valid Python syntax: {e}",
                layers=layers,
            )

        layers.append(
            LayerInfo(
                layer_index=0,
                layer_type="raw_input",
                size=len(raw_bytes),
                sha256=sha0,
                filename="layer_00_raw.py",
                transforms=[],
                is_valid_python=True,
                content_text=current_content,
            )
        )

        cumulative_transforms: List[str] = []

        while current_layer_idx < self.limits.max_layers:
            current_layer_idx += 1

            # 1. Parse current content
            try:
                tree = ast.parse(current_content)
            except SyntaxError as e:
                # Extracted payload is not valid Python
                return DeobfuscationResult(
                    status=Status.PARTIALLY_RECOVERED,
                    status_reason=f"Extracted payload at layer {current_layer_idx - 1} could not be parsed as Python syntax: {e}",
                    layers=layers,
                    transformations=cumulative_transforms,
                )

            # 2. Constant folding and string resolution
            folder = ConstantFolder(limits=self.limits)
            try:
                folded_tree, transforms = folder.fold_tree(tree)
                folded_code = ast.unparse(folded_tree)
            except ResourceLimitExceeded as e:
                return DeobfuscationResult(
                    status=Status.LIMIT_EXCEEDED,
                    status_reason=str(e),
                    layers=layers,
                    transformations=cumulative_transforms,
                )
            except Exception as e:
                folded_tree = tree
                folded_code = current_content
                transforms = [f"Constant folding skipped due to error: {e}"]

            # If constant folding transformed code meaningfully
            if transforms:
                cumulative_transforms.extend(transforms)
                folded_bytes = folded_code.encode("utf-8", errors="replace")
                sha_folded = hashlib.sha256(folded_bytes).hexdigest()
                if sha_folded not in seen_hashes:
                    seen_hashes.add(sha_folded)
                    layers.append(
                        LayerInfo(
                            layer_index=current_layer_idx,
                            layer_type="constant_folded",
                            size=len(folded_bytes),
                            sha256=sha_folded,
                            filename=f"layer_{current_layer_idx:02d}_folded.py",
                            transforms=transforms,
                            is_valid_python=True,
                            content_text=folded_code,
                            notes=f"Applied {len(transforms)} AST simplifications",
                        )
                    )
                    current_content = folded_code
                    tree = folded_tree
                    current_layer_idx += 1

            # 3. Check for exec(...) payload
            extractor = ExecExtractor(env=folder.known_constants, limits=self.limits)
            extracted_payloads = extractor.find_and_extract(tree)

            if not extracted_payloads:
                # No more exec loaders found.
                # Perform post-unpacking control flow recovery, AST cleaning, and symbol renaming
                all_transforms = list(cumulative_transforms)
                
                # 1. Control flow de-flattening
                deflattener = ControlFlowDeflattener()
                tree, cflow_transforms = deflattener.deflatten_tree(tree)
                all_transforms.extend(cflow_transforms)

                # 2. Builtin unwrapping and dead code cleaning
                cleaner = ASTCleaner()
                tree, clean_transforms = cleaner.clean_tree(tree)
                all_transforms.extend(clean_transforms)

                # 3. Scope-safe symbol renaming
                renamer = SymbolRenamer()
                tree, symbol_map = renamer.rename_symbols(tree)
                for s in symbol_map:
                    all_transforms.append(
                        f"Renamed obfuscated {s['role']} '{s['original_name']}' -> '{s['new_name']}' ({s['scope']})"
                    )

                final_code = ast.unparse(tree)
                return DeobfuscationResult(
                    status=Status.RECOVERED,
                    status_reason=f"Successfully recovered code after {len(layers)} layer(s)",
                    layers=layers,
                    final_code=final_code,
                    symbol_map=symbol_map,
                    transformations=all_transforms,
                    unresolved_items=[],
                )

            # Take the first extracted payload
            payload_item = extracted_payloads[0]
            raw_payload = payload_item.raw_data

            if raw_payload is None and extractor.missing_parameters:
                return DeobfuscationResult(
                    status=Status.MISSING_KEY,
                    status_reason=f"Decryption halted: missing required parameters: {', '.join(extractor.missing_parameters)}",
                    layers=layers,
                    missing_parameters=extractor.missing_parameters,
                )

            # Process payload
            if isinstance(raw_payload, str):
                next_content = raw_payload
                next_bytes = next_content.encode("utf-8", errors="replace")
                payload_type = "exec_str_payload"
                is_py = True
            elif isinstance(raw_payload, (bytes, bytearray)):
                # Test if it's UTF-8 encoded Python source
                try:
                    next_content = raw_payload.decode("utf-8")
                    next_bytes = raw_payload
                    payload_type = "exec_decoded_text"
                    # Validate syntax
                    try:
                        ast.parse(next_content)
                        is_py = True
                    except SyntaxError:
                        is_py = False
                except UnicodeDecodeError:
                    # Binary payload (e.g. marshal bytecode or encrypted blob)
                    next_bytes = bytes(raw_payload)
                    next_content = None
                    payload_type = "marshal_bytecode" if payload_item.is_bytecode else "binary_payload"
                    is_py = False
            else:
                return DeobfuscationResult(
                    status=Status.UNSUPPORTED,
                    status_reason=f"Unsupported payload object type: {type(raw_payload).__name__}",
                    layers=layers,
                )

            payload_sha = hashlib.sha256(next_bytes).hexdigest()

            # Cycle detection
            if payload_sha in seen_hashes:
                return DeobfuscationResult(
                    status=Status.PARTIALLY_RECOVERED,
                    status_reason="Cycle detected: payload hash already seen in previous layer",
                    layers=layers,
                    final_code=current_content if layers[-1].is_valid_python else None,
                )
            seen_hashes.add(payload_sha)

            # Handle binary / marshal payload
            if not is_py or next_content is None:
                # Run isolated worker to safely inspect marshal code object
                worker_res = run_isolated_marshal_inspector(next_bytes)
                notes = ""
                disasm_text = ""
                if worker_res.get("status") == "success" and worker_res.get("is_code_object"):
                    code_info = worker_res.get("code_info", {})
                    disasm_text = code_info.get("disassembly", "")
                    notes = f"Disassembled code object '{code_info.get('co_name')}'; {len(code_info.get('constants', []))} constants"
                else:
                    notes = f"Binary payload ({worker_res.get('message', 'Non-code object')})"

                layers.append(
                    LayerInfo(
                        layer_index=current_layer_idx,
                        layer_type=payload_type,
                        size=len(next_bytes),
                        sha256=payload_sha,
                        filename=f"layer_{current_layer_idx:02d}_payload.bin",
                        transforms=[f"Extracted payload from exec() call at line {payload_item.line}"],
                        is_valid_python=False,
                        content_bytes=next_bytes,
                        content_text=disasm_text if disasm_text else None,
                        notes=notes,
                    )
                )

                # Return partially recovered (we reached bytecode)
                return DeobfuscationResult(
                    status=Status.PARTIALLY_RECOVERED,
                    status_reason="Reached compiled marshal bytecode; disassembled in isolated worker (no full decompilation)",
                    layers=layers,
                    final_code=disasm_text if disasm_text else None,
                )

            # Python text payload
            unpacked_desc = f"Unpacked exec() payload from line {payload_item.line} (expr: {payload_item.source_expr[:50]})"
            cumulative_transforms.append(unpacked_desc)
            layers.append(
                LayerInfo(
                    layer_index=current_layer_idx,
                    layer_type=payload_type,
                    size=len(next_bytes),
                    sha256=payload_sha,
                    filename=f"layer_{current_layer_idx:02d}_unpacked.py",
                    transforms=[unpacked_desc],
                    is_valid_python=True,
                    content_text=next_content,
                )
            )

            current_content = next_content

        # If loop reached max_layers
        return DeobfuscationResult(
            status=Status.LIMIT_EXCEEDED,
            status_reason=f"Exceeded maximum layer unpacking limit ({self.limits.max_layers} layers)",
            layers=layers,
            final_code=current_content if layers[-1].is_valid_python else None,
        )
