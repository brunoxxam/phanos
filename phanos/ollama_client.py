"""Local Ollama HTTP client for structured supply-chain verdict inference."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

DEFAULT_OLLAMA_BASE_URL: str = "http://localhost:11434"
DEFAULT_CHAT_PATH: str = "/api/chat"
DEFAULT_MODEL: str = "qwen2.5-coder:7b"
SUPPORTED_MODELS: tuple[str, ...] = ("deepseek-r1:8b", "qwen2.5-coder:7b")
DEFAULT_REQUEST_TIMEOUT_SECONDS: int = 120

VerdictValue = Literal["ALLOW", "REVIEW", "BLOCK"]

SYSTEM_PROMPT: str = """You are Phanos, an offline supply-chain security analyst.
You evaluate condensed installation-script fragments extracted from npm lifecycle hooks.

Your task:
- Ignore benign setup/build boilerplate (logging, version checks, local file copies).
- Strictly penalize data exfiltration (reading process.env / os.environ and sending values outbound).
- Strictly penalize hidden reverse shells, remote code execution, and download-and-execute chains.
- Strictly penalize malicious obfuscation (base64/hex payloads, eval/Function indirection, entropy-packed blobs).

Scoring guidance:
- 0-20: benign or low-risk setup logic.
- 21-60: suspicious but inconclusive; requires human review.
- 61-100: high-confidence malicious behavior.

Verdict mapping:
- ALLOW: malice_score 0-20 and no critical risk indicators.
- REVIEW: malice_score 21-60 or ambiguous indicators.
- BLOCK: malice_score 61-100 or clear malicious intent.

Output rules (critical):
- Respond with ONLY one raw JSON object.
- Do NOT include markdown fences, prose, XML, or reasoning tags.
- JSON schema (exact keys):
{
  "malice_score": <integer 0-100>,
  "detected_risk_indicators": [<string>, ...],
  "is_obfuscated": <boolean>,
  "deobfuscated_logic_summary": <string>,
  "verdict": "ALLOW" | "REVIEW" | "BLOCK"
}
"""


class OllamaVerdict(BaseModel):
    """Structured verdict returned by the local LLM inference stage."""

    malice_score: int = Field(ge=0, le=100)
    detected_risk_indicators: list[str] = Field(default_factory=list)
    is_obfuscated: bool
    deobfuscated_logic_summary: str
    verdict: VerdictValue

    @field_validator("verdict", mode="before")
    @classmethod
    def normalize_verdict(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("verdict must be a string")
        normalized = value.strip().upper()
        if normalized not in {"ALLOW", "REVIEW", "BLOCK"}:
            raise ValueError("verdict must be exactly ALLOW, REVIEW, or BLOCK")
        return normalized
