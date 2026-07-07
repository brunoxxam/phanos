"""Local Ollama HTTP client for structured supply-chain verdict inference."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Literal

import requests
from pydantic import BaseModel, Field, ValidationError, field_validator

from phanos.exceptions import OllamaConnectionError

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_BASE_URL: str = "http://localhost:11434"
DEFAULT_CHAT_PATH: str = "/api/chat"
DEFAULT_MODEL: str = "qwen2.5-coder:7b"
SUPPORTED_MODELS: tuple[str, ...] = ("deepseek-r1:8b", "qwen2.5-coder:7b")
DEFAULT_REQUEST_TIMEOUT_SECONDS: int = 120

THINK_OPEN_TAG = "<" + "think" + ">"
THINK_CLOSE_TAG = "</" + "think" + ">"
THINK_BLOCK_PATTERN = re.compile(
    re.escape(THINK_OPEN_TAG) + r".*?" + re.escape(THINK_CLOSE_TAG),
    flags=re.DOTALL | re.IGNORECASE,
)

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


class OllamaClient:
    """Minimal HTTP client for Ollama chat completions with JSON enforcement."""

    def __init__(
        self,
        base_url: str = DEFAULT_OLLAMA_BASE_URL,
        model: str = DEFAULT_MODEL,
        request_timeout_seconds: int = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        system_prompt: str = SYSTEM_PROMPT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.request_timeout_seconds = request_timeout_seconds
        self.system_prompt = system_prompt

    def analyze_payload(
        self,
        condensed_payload: str,
        system_prompt: str | None = None,
    ) -> OllamaVerdict:
        """Send condensed script evidence to Ollama and return a validated verdict."""
        if not condensed_payload.strip():
            return OllamaVerdict(
                malice_score=0,
                detected_risk_indicators=[],
                is_obfuscated=False,
                deobfuscated_logic_summary="No suspicious payload was provided for analysis.",
                verdict="ALLOW",
            )

        prompt = system_prompt or self.system_prompt
        raw_content = self._invoke_chat(condensed_payload, prompt)
        return self._parse_verdict(raw_content)

    def _invoke_chat(self, user_content: str, system_prompt: str) -> str:
        endpoint = f"{self.base_url}{DEFAULT_CHAT_PATH}"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": (
                        "Analyze the following condensed lifecycle script fragment and "
                        "return ONLY the JSON verdict object:\n\n"
                        f"{user_content}"
                    ),
                },
            ],
            "stream": False,
            "format": "json",
        }

        try:
            response = requests.post(endpoint, json=payload, timeout=self.request_timeout_seconds)
        except requests.ConnectionError as exc:
            raise OllamaConnectionError(
                "Unable to connect to Ollama. Ensure the daemon is running "
                f"(expected at {self.base_url})."
            ) from exc
        except requests.Timeout as exc:
            raise OllamaConnectionError(
                f"Ollama request timed out after {self.request_timeout_seconds}s."
            ) from exc
        except requests.RequestException as exc:
            raise OllamaConnectionError(f"Ollama request failed: {exc}") from exc

        if response.status_code >= 500:
            raise OllamaConnectionError(
                f"Ollama returned server error HTTP {response.status_code}."
            )
        if not response.ok:
            raise OllamaConnectionError(
                f"Ollama returned HTTP {response.status_code}: {response.text[:300]}"
            )

        try:
            body: dict[str, Any] = response.json()
        except ValueError as exc:
            raise OllamaConnectionError("Ollama returned a non-JSON HTTP response.") from exc

        message = body.get("message", {})
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str) or not content.strip():
            raise OllamaConnectionError("Ollama response did not include message content.")

        return content

    def _parse_verdict(self, raw_content: str) -> OllamaVerdict:
        json_blob = self._extract_json_object(raw_content)
        try:
            payload = json.loads(json_blob)
        except json.JSONDecodeError as exc:
            raise OllamaConnectionError(
                f"Ollama returned malformed JSON content: {exc.msg}"
            ) from exc

        try:
            return OllamaVerdict.model_validate(payload)
        except ValidationError as exc:
            raise OllamaConnectionError(
                f"Ollama JSON did not match OllamaVerdict schema: {exc}"
            ) from exc

    def _extract_json_object(self, raw_content: str) -> str:
        cleaned = raw_content.strip()
        cleaned = THINK_BLOCK_PATTERN.sub("", cleaned).strip()
        cleaned = re.sub(r"```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = cleaned.replace("```", "").strip()

        if cleaned.startswith("{") and cleaned.endswith("}"):
            return cleaned

        match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
        if match:
            return match.group(0)

        raise OllamaConnectionError("Unable to locate a JSON object in Ollama response.")
