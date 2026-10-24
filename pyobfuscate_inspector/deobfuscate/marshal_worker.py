"""Isolated worker to safely inspect and disassemble marshal bytecode in a separate process.

Untrusted marshal payloads are never loaded into the main inspector process.
"""

import dis
import json
import marshal
import os
import subprocess
import sys
import types
from typing import Any, Dict, List, Optional


def _inspect_code_object(code: types.CodeType, depth: int = 0) -> Dict[str, Any]:
    """Recursively extracts metadata and disassembly from a code object."""
    consts_info = []
    nested_codes = []
    candidate_payloads = []

    for i, c in enumerate(code.co_consts):
        c_type = type(c).__name__
        if isinstance(c, types.CodeType):
            if depth < 5:
                nested_codes.append(_inspect_code_object(c, depth + 1))
            consts_info.append({"index": i, "type": "code", "repr": f"<code {c.co_name}>"})
        elif isinstance(c, (bytes, bytearray)):
            # Potential nested payload
            preview = c[:100].hex()
            consts_info.append({"index": i, "type": c_type, "length": len(c), "preview_hex": preview})
            if len(c) > 32:
                candidate_payloads.append({"index": i, "type": "bytes", "length": len(c), "hex": c.hex()})
        elif isinstance(c, str):
            preview = c[:100]
            consts_info.append({"index": i, "type": "str", "length": len(c), "preview": preview})
            if len(c) > 32:
                candidate_payloads.append({"index": i, "type": "str", "length": len(c), "text": c})
        else:
            consts_info.append({"index": i, "type": c_type, "repr": repr(c)})

    # Disassemble instructions (capped at 500 instructions)
    dis_instructions = []
    try:
        bc = dis.Bytecode(code)
        for idx, instr in enumerate(bc):
            if idx > 500:
                dis_instructions.append("... [disassembly truncated for size] ...")
                break
            dis_instructions.append(
                f"{instr.offset:4d} {instr.opname:<20} {instr.argrepr}"
            )
    except Exception as e:
        dis_instructions.append(f"<Disassembly error: {e}>")

    return {
        "co_name": code.co_name,
        "co_filename": code.co_filename,
        "co_names": list(code.co_names),
        "co_varnames": list(code.co_varnames),
        "co_argcount": code.co_argcount,
        "constants": consts_info,
        "nested_codes": nested_codes,
        "disassembly": "\n".join(dis_instructions),
        "candidate_payloads": candidate_payloads,
    }


def worker_main() -> None:
    """Entry point for the isolated subprocess."""
    try:
        # Read raw binary data from stdin
        raw_data = sys.stdin.buffer.read(15 * 1024 * 1024)
        if not raw_data:
            json.dump({"status": "error", "message": "No input data received"}, sys.stdout)
            return

        loaded = marshal.loads(raw_data)
        if isinstance(loaded, types.CodeType):
            info = _inspect_code_object(loaded)
            result = {
                "status": "success",
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                "is_code_object": True,
                "code_info": info,
            }
        else:
            result = {
                "status": "success",
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                "is_code_object": False,
                "data_type": type(loaded).__name__,
                "repr": repr(loaded)[:500],
            }
        json.dump(result, sys.stdout)
    except Exception as e:
        json.dump({"status": "error", "message": f"Marshal parsing failed: {e}"}, sys.stdout)


def run_isolated_marshal_inspector(marshal_bytes: bytes, timeout: float = 6.0) -> Dict[str, Any]:
    """Runs marshal inspection in an isolated child process."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pyobfuscate_inspector.deobfuscate.marshal_worker"],
            input=marshal_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        if proc.returncode != 0:
            err_msg = proc.stderr.decode("utf-8", errors="replace").strip()
            return {
                "status": "error",
                "message": f"Worker process exited with code {proc.returncode}: {err_msg}",
            }
        out_text = proc.stdout.decode("utf-8", errors="replace").strip()
        if not out_text:
            return {"status": "error", "message": "Worker returned empty output"}
        return json.loads(out_text)
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": f"Marshal worker timed out after {timeout}s"}
    except Exception as e:
        return {"status": "error", "message": f"Failed to execute marshal worker: {e}"}


if __name__ == "__main__":
    worker_main()
