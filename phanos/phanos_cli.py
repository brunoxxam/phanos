"""Phanos CLI — supply-chain security gate for npm lifecycle scripts."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

import typer

from phanos.ast_filter import ASTFilter, ASTFilterResult
from phanos.exceptions import OllamaConnectionError, PhanosError
from phanos.ingestor import PackageIngestor
from phanos.ollama_client import DEFAULT_MODEL, DEFAULT_OLLAMA_BASE_URL, OllamaClient, OllamaVerdict

app = typer.Typer(
    name="phanos",
    help="Local supply-chain security gate for npm lifecycle scripts.",
    no_args_is_help=True,
    add_completion=False,
)

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


@dataclass(frozen=True)
class ScriptScanResult:
    package_name: str
    hook_name: str
    filter_result: ASTFilterResult


@dataclass(frozen=True)
class ScanReport:
    manifest_path: Path
    sandbox_root: Path
    script_results: list[ScriptScanResult]
    verdict: OllamaVerdict | None = None
    fast_tracked: bool = False


class ScanPipeline:
    """End-to-end orchestration across ingestion, static filtering, and LLM verdict."""

    def __init__(
        self,
        ingestor: PackageIngestor | None = None,
        ast_filter: ASTFilter | None = None,
        ollama_client: OllamaClient | None = None,
    ) -> None:
        self.ingestor = ingestor or PackageIngestor(download_dependencies=False)
        self.ast_filter = ast_filter or ASTFilter()
        self.ollama_client = ollama_client or OllamaClient()

    def run(self, manifest_path: Path, sandbox_root: Path | None = None) -> ScanReport:
        report = self.ingestor.ingest(manifest_path, sandbox_root=sandbox_root)
        script_results: list[ScriptScanResult] = []

        for package in report.all_packages:
            for script in package.extracted_scripts:
                filter_result = self.ast_filter.analyze(script.script_body, script.script_body)
                script_results.append(
                    ScriptScanResult(
                        package_name=package.package_name,
                        hook_name=script.hook_name,
                        filter_result=filter_result,
                    )
                )

        if self._should_fast_track(script_results):
            return ScanReport(
                manifest_path=Path(manifest_path),
                sandbox_root=report.sandbox_root,
                script_results=script_results,
                fast_tracked=True,
            )

        condensed_payload = self._build_condensed_payload(script_results)
        verdict = self.ollama_client.analyze_payload(condensed_payload)
        return ScanReport(
            manifest_path=Path(manifest_path),
            sandbox_root=report.sandbox_root,
            script_results=script_results,
            verdict=verdict,
            fast_tracked=False,
        )

    @staticmethod
    def _should_fast_track(script_results: list[ScriptScanResult]) -> bool:
        if not script_results:
            return True
        return all(
            not result.filter_result.is_suspicious and not result.filter_result.condensed_payload.strip()
            for result in script_results
        )

    @staticmethod
    def _build_condensed_payload(script_results: list[ScriptScanResult]) -> str:
        blocks: list[str] = []
        for result in script_results:
            payload = result.filter_result.condensed_payload.strip()
            if not result.filter_result.is_suspicious and not payload:
                continue
            header = f"# {result.package_name} :: {result.hook_name}"
            body = payload or ", ".join(result.filter_result.matched_triggers)
            blocks.append(f"{header}\n{body}")
        return "\n\n".join(blocks)


def resolve_exit_code(verdict: OllamaVerdict | None, *, fail_on_review: bool) -> int:
    if verdict is None:
        return 0
    if verdict.verdict == "BLOCK":
        return 1
    if verdict.verdict == "REVIEW" and fail_on_review:
        return 1
    return 0


def render_report(report: ScanReport, *, fail_on_review: bool, output: TextIO) -> int:
    if report.fast_tracked:
        _print_clean_report(report, output)
        return 0

    if report.verdict is None:
        raise RuntimeError("Scan report is missing an Ollama verdict.")

    if report.verdict.verdict == "ALLOW":
        _print_allow_report(report, output)
    elif report.verdict.verdict == "REVIEW":
        _print_review_report(report, output)
    else:
        _print_block_report(report, output)

    return resolve_exit_code(report.verdict, fail_on_review=fail_on_review)


def _print_header(output: TextIO) -> None:
    output.write(f"{BOLD}phanos{RESET} - supply-chain scan\n")
    output.write("-" * 40 + "\n")


def _print_clean_report(report: ScanReport, output: TextIO) -> None:
    _print_header(output)
    output.write(f"{GREEN}[CLEAR]{RESET}  No suspicious lifecycle behavior detected.\n")
    output.write(f"  manifest : {report.manifest_path}\n")
    output.write(f"  sandbox  : {report.sandbox_root}\n")
    output.write(f"  scripts  : {len(report.script_results)} scanned, 0 flagged\n")


def _print_allow_report(report: ScanReport, output: TextIO) -> None:
    _print_header(output)
    output.write(f"{GREEN}[ALLOW]{RESET}  LLM assessment: low risk.\n")
    output.write(f"  manifest     : {report.manifest_path}\n")
    output.write(f"  malice score : {report.verdict.malice_score}/100\n")
    if report.verdict.deobfuscated_logic_summary:
        output.write(f"  summary      : {report.verdict.deobfuscated_logic_summary}\n")


def _print_review_report(report: ScanReport, output: TextIO) -> None:
    _print_header(output)
    output.write(f"{YELLOW}[REVIEW]{RESET}  Manual review recommended.\n")
    output.write(f"  manifest     : {report.manifest_path}\n")
    output.write(f"  malice score : {report.verdict.malice_score}/100\n")
    if report.verdict.detected_risk_indicators:
        output.write("  indicators   :\n")
        for indicator in report.verdict.detected_risk_indicators:
            output.write(f"    - {indicator}\n")
    if report.verdict.deobfuscated_logic_summary:
        output.write(f"  summary      : {report.verdict.deobfuscated_logic_summary}\n")


def _print_block_report(report: ScanReport, output: TextIO) -> None:
    _print_header(output)
    output.write(f"{RED}{BOLD}[BLOCK]{RESET}  Malicious behavior detected - pipeline halted.\n")
    output.write(f"  manifest     : {report.manifest_path}\n")
    output.write(f"  malice score : {report.verdict.malice_score}/100\n")
    if report.verdict.detected_risk_indicators:
        output.write("  indicators   :\n")
        for indicator in report.verdict.detected_risk_indicators:
            output.write(f"    - {indicator}\n")
    output.write(f"  analysis     : {report.verdict.deobfuscated_logic_summary}\n")


@app.callback()
def root() -> None:
    """Phanos CLI entrypoint."""


@app.command("scan")
def scan(
    manifest: Path = typer.Argument(..., help="Path to package.json", exists=True, readable=True),
    sandbox_dir: Path | None = typer.Option(None, "--sandbox-dir", help="Sandbox output directory"),
    skip_deps: bool = typer.Option(False, "--skip-deps", help="Skip downloading dependency tarballs"),
    model: str = typer.Option(DEFAULT_MODEL, "--model", help="Ollama model name"),
    ollama_url: str = typer.Option(DEFAULT_OLLAMA_BASE_URL, "--ollama-url", help="Ollama base URL"),
    fail_on_review: bool = typer.Option(False, "--fail-on-review", help="Exit 1 on REVIEW verdicts"),
) -> None:
    """Scan an npm manifest and evaluate lifecycle script risk."""
    try:
        ingestor = PackageIngestor(download_dependencies=not skip_deps)
        ollama_client = OllamaClient(base_url=ollama_url, model=model)
        pipeline = ScanPipeline(ingestor=ingestor, ollama_client=ollama_client)
        report = pipeline.run(manifest, sandbox_root=sandbox_dir)
        exit_code = render_report(report, fail_on_review=fail_on_review, output=sys.stdout)
        raise typer.Exit(code=exit_code)
    except OllamaConnectionError as exc:
        typer.secho(f"Ollama unavailable: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    except PhanosError as exc:
        typer.secho(f"Scan failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc


def main() -> None:
    app()


if __name__ == "__main__":
    main()
