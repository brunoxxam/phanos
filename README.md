# phanos

**Phanos** (from Ancient Greek *φανός*, meaning "lantern" or "torch") is a local DevSecOps security gate designed to illuminate hidden, obfuscated, and malicious logic within third-party open-source dependencies before they compromise your environment. 

By combining **Abstract Syntax Tree (AST) analysis** with **local Large Language Models (LLMs)**, Phanos evaluates the semantic intent of installation scripts (`preinstall`, `postinstall`) completely offline, ensuring zero data leakage and absolute privacy sovereignty.

## The Problem
Supply chain attacks targeting open-source registries (npm, PyPI) have surged. Threat actors bypass perimeter defenses by injecting malicious code directly into lifecycle hooks or heavily obfuscated code blocks. Traditional Software Composition Analysis (SCA) tools fail because they only look for known CVEs. 

Furthermore, modern corporate environments ban sending proprietary code or external manifests to commercial cloud AI APIs due to data privacy regulations.

## Features
- **Local-First / Zero-Data Leakage:** Powered by `Ollama` / `vLLM` running entirely on your local machine or air-gapped infrastructure. No external API calls.
- **AST-Driven Pre-Filtering:** Syntactically parses code using Abstract Syntax Trees to isolate high-risk functions (file system access, network sockets, environment variable exfiltration) before moving to LLM analysis.
- **Semantic Intent Analysis:** Leverages deep reasoning models to detect obfuscation patterns, bypass techniques, and malicious intent rather than relying on brittle, easily bypassed signature hashes.
- **CI/CD Friendly Gate:** Implements a strict CLI architecture that outputs standardized JSON risk metrics and appropriate exit codes (`0` for clean, `1` for blocked) to easily plug into Git hooks or Jenkins/GitHub Actions pipelines.

## Architecture & Flow
1. **Ingestion:** Phanos parses target manifest files (e.g., `package.json`), downloads the package tarballs into an isolated sandbox, and extracts lifecycle execution scripts.
2. **AST Filtering:** Code blocks are reduced to high-risk behavioral tokens (network requests, base64/hex mutations, OS-level interaction). Non-critical code is stripped to optimize LLM context limits.
3. **Local Inferencia:** The suspicious nodes are analyzed using specialized coding/reasoning models (such as `DeepSeek-R1-Distill` or `Qwen2.5-Coder`) utilizing strict structured outputs.
4. **Verdict Generation:** Returns an evaluation schema indicating a `Malice Score`, `Detected Risk Indicators`, and a `Deobfuscated Logic Summary`.

## Tech Stack
- **Language:** Python 3.11+
- **Orchestration & CLI:** Typer, Pydantic (Structured Validation)
- **Local LLM Engine:** Ollama / vLLM
- **Target Inference Models:** `deepseek-r1:8b` / `qwen2.5-coder:7b`
- **Parsing:** Python Native `ast` / `esprima` equivalents

## Getting Started

*(Section to be completed as code is committed)*