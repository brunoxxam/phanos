"""Static filtering heuristics to reduce risky lifecycle script payloads."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

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


@dataclass
class FilterScan:
    """Baseline structural scan result before probabilistic heuristics."""

    is_suspicious: bool = False
    matched_triggers: list[str] = field(default_factory=list)
    condensed_payload: str = ""


class ASTFilter:
    """Heuristic scanner for lifecycle hooks and inline script snippets."""

    def analyze(self, hook_command: str, source_code: str | None = None) -> FilterScan:
        command_findings = self._scan_command(hook_command)
        snippet_findings = self._scan_snippets(source_code or hook_command)
        triggers = self._dedupe(command_findings["triggers"] + snippet_findings["triggers"])
        payload = self._build_payload(command_findings["payload_lines"], snippet_findings["payload_lines"])
        return FilterScan(
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

    def _build_payload(self, command_lines: list[str], snippet_lines: list[str]) -> str:
        lines = self._dedupe([line for line in [*command_lines, *snippet_lines] if line.strip()])
        return "\n".join(lines)

    def _dedupe(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            deduped.append(value)
        return deduped
