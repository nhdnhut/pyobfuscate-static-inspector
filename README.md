# PyObfuscate Static Inspector and Deobfuscator

> A static analysis, code recovery, and defensive security audit framework for Python scripts.
> 100% Static Abstract Syntax Tree (AST) Analysis | Zero Dynamic Execution | Sandboxed Bytecode Worker

[![Python](https://img.shields.io/badge/Python-3.10+-brightgreen?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-51%20Passed-brightgreen?style=flat-square)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)

---

## 1. Legal and Educational Disclaimer

This project is developed and published strictly for educational purposes, defensive security auditing, software verification, and reverse engineering research.

Ethical Invariants:
- The tool performs purely static inspection on abstract syntax trees and does not execute untrusted target scripts.
- It is designed to assist software auditors in auditing potentially obfuscated codebases, recovering lost source code, and identifying hidden behavior without detonation.
- Users are solely responsible for ensuring compliance with applicable laws and authorization boundaries before inspecting third-party code.

---

## 2. Technical Principles and Architecture

1. Pure Static Analysis: All transformations, constant unboxing, and string decoding occur on the Python Abstract Syntax Tree (AST) using a constrained visitor (`SafeEvaluator`). Dynamic execution primitives such as `eval()` or `exec()` are strictly forbidden.
2. Zero Network and Zero Side Effects: The engine operates entirely offline without opening sockets, spawning network connections, or importing target code into the runtime environment.
3. Control Flow Flattening (CFF) De-Flattening: Detects dispatcher state machines and reconstructs natural sequential, branching (`if/else`), and looping (`while`) constructs when behavioral equivalence is mathematically provable.
4. Scope-Preserving Safe Renaming: Normalizes random or homoglyph identifier patterns (`_0x...`, `IlII11`) into readable, neutral identifiers (`var_1`, `func_1`, `buffer_1`) while strictly protecting reflection-dependent symbols (`getattr`, `globals()`, `__dict__`).
5. Isolated Bytecode Disassembly: Marshaled code objects and `.pyc` payloads are analyzed in an isolated worker subprocess with hard resource limits and timeouts, protecting the main analysis pipeline against malicious bytecode bombs.
6. Cryptographic Tag Verification: AES-GCM decryption requires valid authentication tags and refuses to brute-force missing credentials, flagging `missing_key` in the audit telemetry.
7. Automated PII and Credential Redaction: Sensitive indicators of compromise (API tokens, Discord webhooks, Telegram tokens, passwords) are automatically redacted in audit reports.

---

## 3. Supported Obfuscation Patterns

| Obfuscation Mechanism | Detection Method | Static Recovery Strategy |
|---|---|---|
| Obfuscator Signatures | Pattern matching on `__obfuscated_by__`, comment banners | Signature identification and loader unwrapping |
| Encoded Strings / Bytes | Base64 (`b64decode`), Hex (`unhexlify`), String slicing (`[::-1]`) | AST Evaluator computation with buffer size limits |
| Data Compression | `zlib`, `gzip`, `bz2`, `lzma` | Chunked decompression with zip-bomb prevention |
| XOR Byte Masking | `b ^ key` loops, XOR comprehensions | Bounded loop unrolling and static byte decoding |
| Dynamic String Joining | `''.join([chr(...) ...])`, `ord()` | AST Constant Folding into static string literals |
| Builtin Aliasing | `getattr(__builtins__, ...)`, `globals()`, `__dict__` | Symbol tracking unaliased to standard builtins |
| Arithmetic Constant Folding | Deeply nested bitwise and arithmetic trees | Bounded integer reduction preventing memory exhaustion |
| Loader Execution Wrappers | `exec(decoded)`, `_exec(...)` | Safe payload extraction without runtime execution |
| AES-GCM Encrypted Payloads | `AESGCM(key).decrypt(...)` | Static tag verification; emits missing_key on missing IV/key |
| Marshaled Bytecode Objects | `marshal.loads(...)`, `.pyc` headers | Sandboxed worker process disassembles opcode sequences |
| Control Flow Flattening | `while True:` dispatcher loops | State variable transition graph re-synthesis |
| Anti-Debugging Calls | `sys.gettrace()`, `IsDebuggerPresent` | Flagged and cataloged in the structured audit report |

---

## 4. Quick Start Guide

### Prerequisites
- Python 3.10 or higher
- Git

### Installation
```bash
# Clone repository
git clone https://github.com/nhdnhut/pyobfuscate-static-inspector.git
cd pyobfuscate-static-inspector

# Install in editable mode
pip install -e .
```

### CLI Commands

```bash
# Display help and available options
pyobf-inspect --help
pyobf-deobf --help

# Audit a script and print a structured security report
pyobf-inspect target_script.py --report audit_report.json

# Deobfuscate and format clean recovered source code
pyobf-deobf target_script.py -o recovered_script.py

# Deobfuscate with specific de-flattening and constant folding passes
pyobf-deobf target_script.py -o recovered_script.py --deflat --fold-constants
```

---

## 5. Verification and Automated Testing

Run the comprehensive unit test suite:

```bash
pytest tests/ -v
```

Test Results Summary:
- Total Tests: 51
- Status: 100% Passed
- Scope: AST cleaner, audit scanner, control-flow recovery, constant folding, cryptographic operations, marshal sandboxing, safety guarantees, and symbol scoping.

---

## 6. Directory Structure

```
pyobfuscate-static-inspector/
├── examples/                   # Synthetic educational test cases
├── pyobfuscate_inspector/      # Core package
│   ├── ast_cleaner.py          # AST transformation and simplification
│   ├── audit_scanner.py        # Threat indicator and telemetry scanner
│   ├── cflow_recovery.py       # Control flow de-flattening engine
│   ├── cli.py                  # Command-line interface driver
│   ├── constant_fold.py        # Safe arithmetic and string folder
│   ├── crypto.py               # Cryptographic unwrapping routines
│   ├── deobfuscator.py         # Main orchestration pipeline
│   ├── detectors.py            # Obfuscation pattern detectors
│   ├── marshal_worker.py       # Sandboxed bytecode disassembler
│   ├── safe_eval.py            # Restricted AST expression evaluator
│   └── symbol_renaming.py      # Identifier normalization and scoping
├── tests/                      # Pytest automated test harness
├── pyproject.toml              # Build configuration and CLI entry points
├── LICENSE                     # MIT License
└── README.md                   # Project documentation
```

---

## 7. Author and License

- Author: Nhut Nguyen (@nhdnhut)
- License: MIT License (see [LICENSE](LICENSE))

