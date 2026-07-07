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
NETWORK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(fetch|axios|http|https|request|socket|net)\b", re.IGNORECASE),
)
EXECUTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(child_process|exec|spawn|eval|function\s*\(|new\s+Function)\b", re.IGNORECASE),
    re.compile(r"\b(os\.system|subprocess|popen)\b", re.IGNORECASE),
)
FILESYSTEM_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(fs|path|Buffer|open\(|writeFile|unlink|chmod)\b", re.IGNORECASE),
)
ENVIRONMENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(process\.env|os\.environ)\b", re.IGNORECASE),
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
    """Heuristic scanner for lifecycle hooks and inline script snippets."""

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
        triggers: list[str] = []
        payload_lines: list[str] = []
        for line in source_code.splitlines():
            matched = False
            for category, patterns in (
                ("network", NETWORK_PATTERNS),
                ("execution", EXECUTION_PATTERNS),
                ("filesystem", FILESYSTEM_PATTERNS),
                ("environment", ENVIRONMENT_PATTERNS),
            ):
                for pattern in patterns:
                    if pattern.search(line):
                        triggers.append(f"{category}:{pattern.pattern}")
                        matched = True
                        break
                if matched:
                    break
            if matched:
                payload_lines.append(line.rstrip())

        return {"triggers": triggers, "payload_lines": payload_lines}

    def _scan_obfuscation(self, source_code: str) -> dict[str, list[str]]:
        triggers: list[str] = []
        payload_lines: list[str] = []
        for line in source_code.splitlines():
            if BASE64_BLOB_PATTERN.search(line):
                triggers.append("obfuscation:base64_blob")
                payload_lines.append(line.rstrip())
            if HEX_BLOB_PATTERN.search(line):
                triggers.append("obfuscation:hex_blob")
                payload_lines.append(line.rstrip())
            if RANDOMIZED_VAR_PATTERN.search(line):
                triggers.append("obfuscation:randomized_identifier")
                payload_lines.append(line.rstrip())

            token = self._highest_entropy_token(line)
            if token is not None and self._shannon_entropy(token) >= ENTROPY_THRESHOLD:
                triggers.append("obfuscation:high_entropy_token")
                payload_lines.append(line.rstrip())

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
