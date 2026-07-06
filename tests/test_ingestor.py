"""Unit tests for phanos.ingestor."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from phanos.exceptions import InvalidManifestError, ManifestNotFoundError
from phanos.ingestor import PackageIngestor

FIXTURES_DIR = Path(__file__).parent / "fixtures"
FIXTURE_MANIFEST = FIXTURES_DIR / "package.json"


def test_load_manifest_parses_dependencies_and_scripts() -> None:
    ingestor = PackageIngestor(download_dependencies=False)
    manifest = ingestor._load_manifest(FIXTURE_MANIFEST)

    assert manifest.name == "phanos-fixture-app"
    assert manifest.version == "1.0.0"
    assert "left-pad" in manifest.dependencies
    assert "is-odd" in manifest.dev_dependencies
    assert manifest.scripts["preinstall"].startswith("node")


def test_ingest_missing_manifest_raises() -> None:
    ingestor = PackageIngestor(download_dependencies=False)

    with pytest.raises(ManifestNotFoundError):
        ingestor.ingest(FIXTURES_DIR / "does-not-exist.json")


def test_ingest_invalid_json_raises(tmp_path: Path) -> None:
    bad_manifest = tmp_path / "package.json"
    bad_manifest.write_text("{ not valid json", encoding="utf-8")
    ingestor = PackageIngestor(download_dependencies=False)

    with pytest.raises(InvalidManifestError):
        ingestor.ingest(bad_manifest)


def test_ingest_extracts_root_scripts_without_downloads(tmp_path: Path) -> None:
    ingestor = PackageIngestor(download_dependencies=False)
    sandbox = tmp_path / "sandbox"

    report = ingestor.ingest(FIXTURE_MANIFEST, sandbox_root=sandbox)

    assert report.sandbox_root == sandbox
    assert report.root_package.package_name == "phanos-fixture-app"
    assert {script.hook_name for script in report.root_package.extracted_scripts} == {
        "preinstall",
        "postinstall",
        "test",
    }

    preinstall_file = report.root_package.scripts_dir / "preinstall.txt"
    assert preinstall_file.is_file()
    assert "root preinstall hook" in preinstall_file.read_text(encoding="utf-8")

    summary = json.loads((sandbox / "manifest_summary.json").read_text(encoding="utf-8"))
    assert summary["dependency_count"] == 2
    assert summary["dependencies"]["left-pad"] == "1.0.0"


@pytest.mark.integration
def test_ingest_downloads_dependency_scripts(tmp_path: Path) -> None:
    """Requires network access to registry.npmjs.org."""
    ingestor = PackageIngestor(include_dev_dependencies=False)
    sandbox = tmp_path / "sandbox"

    report = ingestor.ingest(FIXTURE_MANIFEST, sandbox_root=sandbox)

    assert len(report.dependencies) == 1
    left_pad = report.dependencies[0]
    assert left_pad.package_name == "left-pad"
    assert left_pad.source_dir.exists()
    assert (sandbox / "ingestion_report.json").is_file()
