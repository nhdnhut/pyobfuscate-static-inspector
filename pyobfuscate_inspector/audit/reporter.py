"""Audit report generator: writes report.json, report.md, layers/, and recovered.py."""

import json
import os
from pathlib import Path
from typing import Optional

from pyobfuscate_inspector.models import AuditReport, Status


class AuditReporter:
    """Exports structured JSON and formatted Markdown reports along with layer artifacts."""

    def __init__(self, report: AuditReport, output_dir: Path):
        self.report = report
        self.output_dir = output_dir

    def write_all(self) -> None:
        """Writes report.json, report.md, layers/, and recovered.py if applicable."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        layers_dir = self.output_dir / "layers"
        layers_dir.mkdir(parents=True, exist_ok=True)

        # 1. Write layer files
        for layer in self.report.layers:
            layer_path = layers_dir / layer.filename
            if layer.content_bytes is not None:
                layer_path.write_bytes(layer.content_bytes)
            elif layer.content_text is not None:
                layer_path.write_text(layer.content_text, encoding="utf-8")

            # Layer metadata
            meta_path = layers_dir / f"{layer.filename}.meta.json"
            meta_path.write_text(json.dumps(layer.to_dict(), indent=2), encoding="utf-8")

        # 2. Write recovered.py ONLY if status is recovered or partially_recovered with valid code
        if self.report.recovered_code:
            recovered_file = self.output_dir / "recovered.py"
            recovered_file.write_text(self.report.recovered_code, encoding="utf-8")

        # 3. Write report.json
        json_file = self.output_dir / "report.json"
        json_file.write_text(json.dumps(self.report.to_dict(), indent=2), encoding="utf-8")

        # 4. Write report.md
        md_file = self.output_dir / "report.md"
        md_file.write_text(self._generate_markdown(), encoding="utf-8")

    def _generate_markdown(self) -> str:
        r = self.report
        status_color = {
            Status.RECOVERED: "🟢 RECOVERED",
            Status.PARTIALLY_RECOVERED: "🟡 PARTIALLY RECOVERED",
            Status.UNSUPPORTED: "🔴 UNSUPPORTED",
            Status.MISSING_KEY: "🟠 MISSING KEY",
            Status.LIMIT_EXCEEDED: "🔴 LIMIT EXCEEDED",
            Status.INVALID_INPUT: "⚫ INVALID INPUT",
        }.get(r.status, r.status.value)

        md = []
        md.append("# PyObfuscate Inspector — Security Audit & Deobfuscation Report\n")
        md.append(f"**Target File:** `{r.input_file}`  \n")
        md.append(f"**Status:** `{status_color}`  \n")
        md.append(f"**Reason:** {r.status_reason}  \n\n")

        md.append("> ⚠️ **AUDIT NOTICE**: The absence of detected suspicious calls does not prove the code is benign.\n")
        md.append("> Static analysis inspects identifiable patterns without executing code, and obfuscators can split or disguise behaviors.\n\n")

        # Hashes Table
        md.append("## 1. File Identification & Hashes\n")
        md.append("| Algorithm | Digest |\n")
        md.append("| :--- | :--- |\n")
        for algo, dig in r.hashes.items():
            md.append(f"| {algo.upper()} | `{dig}` |\n")
        md.append("\n")

        # Detected Mechanisms Table
        md.append("## 2. Detected Protection & Obfuscation Mechanisms\n")
        if r.detected_mechanisms:
            md.append("| Mechanism | Category | Line | Evidence | Confidence |\n")
            md.append("| :--- | :--- | :--- | :--- | :--- |\n")
            for m in r.detected_mechanisms:
                line_str = str(m.line) if m.line is not None else "-"
                ev_clean = m.evidence.replace("|", "\\|")
                md.append(f"| **{m.name}** | `{m.category}` | {line_str} | {ev_clean} | {m.confidence * 100:.0f}% |\n")
        else:
            md.append("_No standard obfuscation mechanisms were detected._\n")
        md.append("\n")

        # Deobfuscation Layers Table
        md.append("## 3. Layer-by-Layer Extraction History\n")
        if r.layers:
            md.append("| Layer # | Type | File | Size | Python Syntax? | Notes / Transforms |\n")
            md.append("| :---: | :--- | :--- | :---: | :---: | :--- |\n")
            for l in r.layers:
                py_valid = "✅ Yes" if l.is_valid_python else "❌ No"
                notes = l.notes or (", ".join(l.transforms) if l.transforms else "-")
                notes_clean = notes.replace("|", "\\|")
                md.append(f"| {l.layer_index} | `{l.layer_type}` | `{l.filename}` | {l.size:,} B | {py_valid} | {notes_clean} |\n")
        else:
            md.append("_No layers extracted._\n")
        md.append("\n")

        # Security Findings
        md.append("## 4. Static Security Audit & Behavioral Indicators\n")
        findings_by_cat = {}
        for f in r.audit_findings:
            findings_by_cat.setdefault(f.category, []).append(f)

        if not findings_by_cat:
            md.append("_No explicit suspicious API calls or indicators found in recovered layers._\n\n")
        else:
            for cat, items in findings_by_cat.items():
                cat_title = {
                    "import": "Suspicious Imports & Dependencies",
                    "subprocess": "Subprocess & Shell Command Execution",
                    "file_op": "File System Operations",
                    "endpoint": "Network Endpoints & IP Addresses",
                    "exfiltration": "Potential Data Exfiltration Indicators",
                    "anti_debug": "Anti-Debugging & Evasion Checks",
                    "card_check": "Financial / Card Verification Indicators",
                }.get(cat, cat.title())

                md.append(f"### {cat_title}\n")
                md.append("| Severity | Item | Line | Evidence |\n")
                md.append("| :--- | :--- | :---: | :--- |\n")
                for item in items:
                    line_str = str(item.line) if item.line is not None else "-"
                    ev_clean = item.evidence.replace("|", "\\|")
                    md.append(f"| `{item.severity.value.upper()}` | **{item.item}** | {line_str} | {ev_clean} |\n")
                md.append("\n")

        # Missing Parameters (if any)
        if r.missing_parameters:
            md.append("## 5. Missing Cryptographic Parameters\n")
            md.append("Decryption could not proceed because the following keys/parameters were missing:\n")
            for p in r.missing_parameters:
                md.append(f"- ⚠️ `{p}`\n")
            md.append("\n")

        # Limits Enforced
        md.append("## 6. Safety & Resource Limits Enforced\n")
        md.append("| Limit Metric | Configured Value |\n")
        md.append("| :--- | :--- |\n")
        md.append(f"| Max Unpacking Layers | {r.limits.max_layers} |\n")
        md.append(f"| Max File Input Size | {r.limits.max_file_size / (1024*1024):.1f} MB |\n")
        md.append(f"| Max Data / Decompression Size | {r.limits.max_data_size / (1024*1024):.1f} MB |\n")
        md.append(f"| Max AST Evaluation Steps | {r.limits.max_eval_steps:,} |\n")
        md.append(f"| Max AST Depth | {r.limits.max_ast_depth} |\n")
        md.append(f"| Max Integer Bits | {r.limits.max_int_bits} bits |\n")
        md.append(f"| Global Timeout | {r.limits.timeout_seconds}s |\n")
        md.append("\n")

        # Recovered Code Status
        md.append("## 7. Recovery Status\n")
        if r.recovered_code:
            md.append(f"Recovered source code has been emitted to `{self.output_dir / 'recovered.py'}`.\n")
        else:
            md.append("No full Python source code could be safely recovered (`recovered.py` not created).\n")

        return "".join(md)
