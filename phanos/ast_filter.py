"""Static filtering heuristics to reduce risky lifecycle script payloads."""

from __future__ import annotations

import math
import re
import shlex
from collections import Counter

from pydantic import BaseModel, Field

RISKY_BINARIES: tuple[str, ...] = ("curl", "wget", "sh", "bash", "nc", "powershell")
RISKY_ARGUMENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"\|\s*(sh|bash|powershell)\b", re.IGNORECASE),
    re.compile(r"\b(-enc|-encodedcommand)\b", re.IGNORECASE),
    re.compile(r"\b(iwr|invoke-webrequest)\b", re.IGNORECASE),
)
TOKEN_PATTERN = re.compile(
    r"""
    [A-Za-z_][A-Za-z0-9_]*   # identifiers
    | "(?:\\.|[^"\\])*"      # double-quoted strings
    | '(?:\\.|[^'\\])*'      # single-quoted strings
    | `(?:\\.|[^`\\])*`      # template strings
    | [0-9]+                 # integers
    | \.\.\.                 # spread
    | [\[\]\(\)\{\}\.,;:+\-*/%<>=!&|^~?:]  # punctuation/operators
    """,
    re.VERBOSE | re.DOTALL,
)

STRUCTURAL_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "network": (
        re.compile(r"\b(?:fetch|axios|request|socket|net|http|https)\b", re.IGNORECASE),
    ),
    "execution": (
        re.compile(r"\brequire\s*\(\s*['\"]child_process['\"]\s*\)"),
        re.compile(r"\b(?:exec|spawn|execSync|spawnSync)\s*\(", re.IGNORECASE),
        re.compile(r"\[\s*['\"](?:exec|spawn|execSync|spawnSync)['\"]\s*\]\s*\(", re.IGNORECASE),
        re.compile(r"\b(?:eval|Function)\s*\(", re.IGNORECASE),
        re.compile(r"\b(?:os\.system|subprocess|popen)\b", re.IGNORECASE),
    ),
    "filesystem": (
        re.compile(r"\brequire\s*\(\s*['\"]fs['\"]\s*\)"),
        re.compile(r"\b(?:fs|path|Buffer|writeFile|unlink|chmod)\b", re.IGNORECASE),
    ),
    "environment": (
        re.compile(r"\bprocess\s*(?:\.|\[\s*['\"])env\b", re.IGNORECASE),
        re.compile(r"\bos\s*(?:\.|\[\s*['\"])environ\b", re.IGNORECASE),
    ),
}

ASSIGNMENT_PATTERN = re.compile(
    r"""
    (?:
        \b(?:const|let|var)\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*
        |
        [A-Za-z_][A-Za-z0-9_]*\s*=\s*
    )
    (?P<value>[^;\n]+)
    """,
    re.VERBOSE,
)
BASE64_BLOB_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
HEX_BLOB_PATTERN = re.compile(r"\b(?:0x)?[A-Fa-f0-9]{32,}\b")
RANDOMIZED_VAR_PATTERN = re.compile(r"\b[a-zA-Z_][a-zA-Z0-9_]{20,}\b")
ENTROPY_MIN_LENGTH = 24
ENTROPY_THRESHOLD = 4.3


class ASTFilterResult(BaseModel):
    """Structured payload returned by the static filter stage."""

    is_suspicious: bool = False
    matched_triggers: list[str] = Field(default_factory=list)
    condensed_payload: str = ""


class ASTFilter:
    """Token-stream scanner for lifecycle hooks and inline script snippets."""

    def analyze(self, hook_command: str, source_code: str | None = None) -> ASTFilterResult:
        command_findings = self._scan_command(hook_command)
        scan_source = source_code or hook_command
        snippet_findings = self._scan_snippets(scan_source)
        obfuscation_findings = self._scan_obfuscation(scan_source)
        triggers = self._dedupe(
            command_findings["triggers"]
            + snippet_findings["triggers"]
            + obfuscation_findings["triggers"]
        )
        payload = self._build_payload(
            command_findings["payload_lines"],
            snippet_findings["payload_lines"],
            obfuscation_findings["payload_lines"],
        )
        return ASTFilterResult(
            is_suspicious=bool(triggers),
            matched_triggers=triggers,
            condensed_payload=payload,
        )

    def _scan_command(self, command: str) -> dict[str, list[str]]:
        triggers: list[str] = []
        payload_lines: list[str] = []
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()

        for token in tokens:
            if token.lower() in RISKY_BINARIES:
                triggers.append(f"risky_binary:{token.lower()}")
                payload_lines.append(command.strip())
                break

        for pattern in RISKY_ARGUMENT_PATTERNS:
            if pattern.search(command):
                triggers.append(f"risky_argument:{pattern.pattern}")
                payload_lines.append(command.strip())

        return {"triggers": triggers, "payload_lines": payload_lines}

    def _scan_snippets(self, source_code: str) -> dict[str, list[str]]:
        return self._scan_structural_tokens(source_code)

    def _scan_structural_tokens(self, source_code: str) -> dict[str, list[str]]:
        triggers: list[str] = []
        payload_lines: list[str] = []

        normalized_stream = self._normalize_code_stream(source_code)
        for category, patterns in STRUCTURAL_PATTERNS.items():
            for pattern in patterns:
                for match in pattern.finditer(normalized_stream):
                    triggers.append(f"{category}:{pattern.pattern}")
                    payload_lines.append(self._capture_context(normalized_stream, match.start(), 180))

        return {"triggers": triggers, "payload_lines": payload_lines}

    def _scan_obfuscation(self, source_code: str) -> dict[str, list[str]]:
        triggers: list[str] = []
        payload_lines: list[str] = []

        normalized_stream = self._normalize_code_stream(source_code)
        assignment_blocks = [match.group("value") for match in ASSIGNMENT_PATTERN.finditer(source_code)]
        chunks = assignment_blocks if assignment_blocks else [source_code]
        consolidated_chunks = self._build_consolidated_chunks(chunks)

        if BASE64_BLOB_PATTERN.search(normalized_stream):
            triggers.append("obfuscation:base64_blob")
            payload_lines.append(self._capture_match(BASE64_BLOB_PATTERN, normalized_stream))
        if HEX_BLOB_PATTERN.search(normalized_stream):
            triggers.append("obfuscation:hex_blob")
            payload_lines.append(self._capture_match(HEX_BLOB_PATTERN, normalized_stream))
        if RANDOMIZED_VAR_PATTERN.search(normalized_stream):
            triggers.append("obfuscation:randomized_identifier")
            payload_lines.append(self._capture_match(RANDOMIZED_VAR_PATTERN, normalized_stream))

        for chunk in consolidated_chunks:
            token = self._highest_entropy_token(chunk)
            if token is not None and self._shannon_entropy(token) >= ENTROPY_THRESHOLD:
                triggers.append("obfuscation:high_entropy_token")
                payload_lines.append(chunk.strip()[:220])
                break

        return {"triggers": triggers, "payload_lines": payload_lines}

    def _build_payload(
        self,
        command_lines: list[str],
        snippet_lines: list[str],
        obfuscation_lines: list[str],
    ) -> str:
        lines = self._dedupe(
            [line for line in [*command_lines, *snippet_lines, *obfuscation_lines] if line.strip()]
        )
        return "\n".join(lines)

    def _highest_entropy_token(self, line: str) -> str | None:
        token_pattern = re.compile(rf"[A-Za-z0-9+/=]{{{ENTROPY_MIN_LENGTH},}}")
        tokens = token_pattern.findall(line)
        if not tokens:
            return None
        return max(tokens, key=self._shannon_entropy)

    def _build_consolidated_chunks(self, chunks: list[str]) -> list[str]:
        consolidated: list[str] = []
        for chunk in chunks:
            normalized = self._normalize_code_stream(chunk)
            if normalized:
                consolidated.append(normalized)
        if consolidated:
            consolidated.append("".join(consolidated))
        return consolidated

    def _normalize_code_stream(self, source_code: str) -> str:
        tokens = TOKEN_PATTERN.findall(source_code)
        if not tokens:
            return source_code

        stream = " ".join(tokens)
        stream = re.sub(r"\s*([()\[\]{}.,;:+\-*/%<>=!&|^~?:])\s*", r"\1", stream)
        return stream

    def _capture_context(self, stream: str, start: int, width: int) -> str:
        left = max(0, start - width // 2)
        right = min(len(stream), start + width // 2)
        return stream[left:right].strip()

    def _capture_match(self, pattern: re.Pattern[str], stream: str) -> str:
        match = pattern.search(stream)
        if match is None:
            return ""
        return self._capture_context(stream, match.start(), 220)

    def _shannon_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        length = len(text)
        frequencies = Counter(text)
        return -sum((count / length) * math.log2(count / length) for count in frequencies.values())

    @staticmethod
    def _dedupe(values: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            deduped.append(value)
        return deduped
