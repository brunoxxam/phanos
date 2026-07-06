"""Ingest npm package manifests and extract lifecycle scripts into an isolated sandbox."""

from __future__ import annotations

import json
import logging
import shutil
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from phanos.exceptions import (
    InvalidManifestError,
    ManifestNotFoundError,
    PackageDownloadError,
    PhanosError,
    RegistryError,
    SandboxError,
)

logger = logging.getLogger(__name__)

LIFECYCLE_HOOKS: tuple[str, ...] = ("preinstall", "postinstall", "test")
NPM_REGISTRY_BASE_URL: str = "https://registry.npmjs.org"
DEFAULT_REQUEST_TIMEOUT_SECONDS: int = 30


class PackageManifest(BaseModel):
    """Subset of package.json fields required for ingestion."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    name: str
    version: str | None = None
    dependencies: dict[str, str] = Field(default_factory=dict)
    dev_dependencies: dict[str, str] = Field(default_factory=dict, alias="devDependencies")
    optional_dependencies: dict[str, str] = Field(
        default_factory=dict, alias="optionalDependencies"
    )
    peer_dependencies: dict[str, str] = Field(default_factory=dict, alias="peerDependencies")
    scripts: dict[str, str] = Field(default_factory=dict)

    def all_dependencies(self) -> dict[str, str]:
        """Return a de-duplicated map of dependency names to version specifiers."""
        merged: dict[str, str] = {}
        for bucket in (
            self.dependencies,
            self.dev_dependencies,
            self.optional_dependencies,
            self.peer_dependencies,
        ):
            merged.update(bucket)
        return merged


@dataclass(frozen=True)
class ExtractedScript:
    """A lifecycle hook extracted from a package manifest."""

    hook_name: str
    script_body: str
    output_path: Path


@dataclass
class PackageIngestResult:
    """Outcome of ingesting a single package (root or dependency)."""

    package_name: str
    package_version: str | None
    source_dir: Path
    scripts_dir: Path
    extracted_scripts: list[ExtractedScript] = field(default_factory=list)
    skipped_hooks: list[str] = field(default_factory=list)


@dataclass
class IngestionReport:
    """Aggregate result of a full ingestion run."""

    manifest_path: Path
    sandbox_root: Path
    root_package: PackageIngestResult
    dependencies: list[PackageIngestResult] = field(default_factory=list)

    @property
    def all_packages(self) -> list[PackageIngestResult]:
        return [self.root_package, *self.dependencies]

    @property
    def total_extracted_scripts(self) -> int:
        return sum(len(pkg.extracted_scripts) for pkg in self.all_packages)


class PackageIngestor:
    """Parse package.json manifests and materialize lifecycle scripts in a sandbox."""

    def __init__(
        self,
        registry_base_url: str = NPM_REGISTRY_BASE_URL,
        request_timeout_seconds: int = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        lifecycle_hooks: tuple[str, ...] = LIFECYCLE_HOOKS,
        include_dev_dependencies: bool = True,
        download_dependencies: bool = True,
    ) -> None:
        self.registry_base_url = registry_base_url.rstrip("/")
        self.request_timeout_seconds = request_timeout_seconds
        self.lifecycle_hooks = lifecycle_hooks
        self.include_dev_dependencies = include_dev_dependencies
        self.download_dependencies = download_dependencies

    def ingest(
        self,
        manifest_path: Path | str,
        sandbox_root: Path | str | None = None,
    ) -> IngestionReport:
        """Parse *manifest_path* and populate an isolated sandbox with lifecycle scripts."""
        resolved_manifest = Path(manifest_path).expanduser().resolve()

        if not resolved_manifest.is_file():
            raise ManifestNotFoundError(f"Manifest not found: {resolved_manifest}")

        manifest = self._load_manifest(resolved_manifest)
        sandbox_path = self._resolve_sandbox_root(resolved_manifest, sandbox_root)

        try:
            sandbox_path.mkdir(parents=True, exist_ok=True)
            root_result = self._ingest_local_package(
                package_name=manifest.name,
                manifest=manifest,
                destination=sandbox_path / "root",
            )
            self._write_manifest_summary(sandbox_path, manifest, resolved_manifest)

            dependency_results: list[PackageIngestResult] = []
            for dep_name, version_spec in self._select_dependencies(manifest).items():
                dep_result = self._ingest_registry_dependency(
                    package_name=dep_name,
                    version_spec=version_spec,
                    destination=sandbox_path / "dependencies" / self._safe_dirname(dep_name),
                )
                dependency_results.append(dep_result)

            report = IngestionReport(
                manifest_path=resolved_manifest,
                sandbox_root=sandbox_path,
                root_package=root_result,
                dependencies=dependency_results,
            )
            self._write_ingestion_report(sandbox_path, report)
            return report
        except PhanosError:
            raise
        except OSError as exc:
            raise SandboxError(f"Failed to prepare sandbox at {sandbox_path}: {exc}") from exc

    def _load_manifest(self, manifest_path: Path) -> PackageManifest:
        try:
            raw_text = manifest_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise InvalidManifestError(f"Cannot read manifest {manifest_path}: {exc}") from exc

        try:
            payload: dict[str, Any] = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise InvalidManifestError(
                f"Invalid JSON in manifest {manifest_path}: {exc.msg}"
            ) from exc

        if not isinstance(payload, dict):
            raise InvalidManifestError(
                f"Manifest root must be a JSON object, got {type(payload).__name__}"
            )

        try:
            return PackageManifest.model_validate(payload)
        except ValidationError as exc:
            raise InvalidManifestError(
                f"Manifest validation failed for {manifest_path}: {exc}"
            ) from exc

    def _resolve_sandbox_root(
        self,
        manifest_path: Path,
        sandbox_root: Path | str | None,
    ) -> Path:
        if sandbox_root is not None:
            return Path(sandbox_root).expanduser().resolve()
        return Path(tempfile.mkdtemp(prefix="phanos-sandbox-"))

    def _select_dependencies(self, manifest: PackageManifest) -> dict[str, str]:
        selected = dict(manifest.dependencies)
        selected.update(manifest.optional_dependencies)
        selected.update(manifest.peer_dependencies)
        if self.include_dev_dependencies:
            selected.update(manifest.dev_dependencies)
        return selected

    def _ingest_local_package(
        self,
        package_name: str,
        manifest: PackageManifest,
        destination: Path,
    ) -> PackageIngestResult:
        destination.mkdir(parents=True, exist_ok=True)
        source_dir = destination / "source"
        source_dir.mkdir(exist_ok=True)

        manifest_copy = destination / "package.json"
        manifest_copy.write_text(
            manifest.model_dump_json(by_alias=True, indent=2),
            encoding="utf-8",
        )

        return self._extract_lifecycle_scripts(
            package_name=package_name,
            package_version=manifest.version,
            scripts=manifest.scripts,
            destination=destination,
            source_dir=source_dir,
        )

    def _ingest_registry_dependency(
        self,
        package_name: str,
        version_spec: str,
        destination: Path,
    ) -> PackageIngestResult:
        if not self.download_dependencies:
            return PackageIngestResult(
                package_name=package_name,
                package_version=version_spec,
                source_dir=destination / "source",
                scripts_dir=destination / "scripts",
            )

        destination.mkdir(parents=True, exist_ok=True)
        source_dir = destination / "source"
        if source_dir.exists():
            shutil.rmtree(source_dir)
        source_dir.mkdir(parents=True)

        resolved_version, tarball_url = self._resolve_tarball_url(package_name, version_spec)
        tarball_path = destination / "package.tgz"
        self._download_file(tarball_url, tarball_path)
        self._extract_tarball(tarball_path, source_dir)
        tarball_path.unlink(missing_ok=True)

        nested_manifest_path = source_dir / "package" / "package.json"
        if not nested_manifest_path.is_file():
            nested_manifest_path = source_dir / "package.json"

        if not nested_manifest_path.is_file():
            raise PackageDownloadError(
                f"Downloaded package '{package_name}' is missing package.json after extraction"
            )

        nested_manifest = self._load_manifest(nested_manifest_path)
        shutil.copy2(nested_manifest_path, destination / "package.json")

        return self._extract_lifecycle_scripts(
            package_name=package_name,
            package_version=resolved_version,
            scripts=nested_manifest.scripts,
            destination=destination,
            source_dir=source_dir,
        )

    def _extract_lifecycle_scripts(
        self,
        package_name: str,
        package_version: str | None,
        scripts: dict[str, str],
        destination: Path,
        source_dir: Path,
    ) -> PackageIngestResult:
        scripts_dir = destination / "scripts"
        scripts_dir.mkdir(parents=True, exist_ok=True)

        extracted: list[ExtractedScript] = []
        skipped: list[str] = []

        for hook_name in self.lifecycle_hooks:
            script_body = scripts.get(hook_name)
            if not script_body or not script_body.strip():
                skipped.append(hook_name)
                continue

            output_path = scripts_dir / f"{hook_name}.txt"
            header = (
                f"# Package: {package_name}\n"
                f"# Version: {package_version or 'unknown'}\n"
                f"# Hook: {hook_name}\n\n"
            )
            output_path.write_text(header + script_body.strip() + "\n", encoding="utf-8")
            extracted.append(
                ExtractedScript(
                    hook_name=hook_name,
                    script_body=script_body.strip(),
                    output_path=output_path,
                )
            )

        logger.info(
            "Extracted %d lifecycle script(s) for %s",
            len(extracted),
            package_name,
        )
        return PackageIngestResult(
            package_name=package_name,
            package_version=package_version,
            source_dir=source_dir,
            scripts_dir=scripts_dir,
            extracted_scripts=extracted,
            skipped_hooks=skipped,
        )

    def _resolve_tarball_url(self, package_name: str, version_spec: str) -> tuple[str, str]:
        metadata = self._fetch_registry_metadata(package_name)
        versions: dict[str, Any] = metadata.get("versions", {})
        if not versions:
            raise RegistryError(f"No published versions found for '{package_name}'")

        dist_tags: dict[str, str] = metadata.get("dist-tags", {})
        resolved_version = self._resolve_version(version_spec, versions, dist_tags)
        version_entry = versions.get(resolved_version)
        if not version_entry:
            raise RegistryError(
                f"Resolved version '{resolved_version}' missing from registry metadata "
                f"for '{package_name}'"
            )

        tarball_url = version_entry.get("dist", {}).get("tarball")
        if not tarball_url:
            raise RegistryError(
                f"No tarball URL available for '{package_name}@{resolved_version}'"
            )
        return resolved_version, tarball_url

    def _resolve_version(
        self,
        version_spec: str,
        versions: dict[str, Any],
        dist_tags: dict[str, str],
    ) -> str:
        cleaned = version_spec.strip()
        if cleaned in {"*", "latest"}:
            latest = dist_tags.get("latest")
            if latest:
                return latest
            return max(versions.keys())

        if cleaned.startswith("npm:"):
            # Alias dependency, e.g. "npm:foo@^1.0.0"
            alias_target = cleaned.split(":", 1)[1]
            alias_name, _, alias_spec = alias_target.partition("@")
            if alias_name and alias_spec:
                return self._resolve_version(alias_spec, versions, dist_tags)

        for prefix in ("^", "~", ">=", "<=", ">", "<", "v"):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix) :]
                break

        if cleaned in versions:
            return cleaned

        if cleaned in dist_tags:
            return dist_tags[cleaned]

        # Fall back to latest when a range cannot be resolved offline.
        latest = dist_tags.get("latest")
        if latest:
            logger.warning(
                "Could not resolve exact version for spec '%s'; using latest '%s'",
                version_spec,
                latest,
            )
            return latest

        return max(versions.keys())

    def _fetch_registry_metadata(self, package_name: str) -> dict[str, Any]:
        encoded_name = quote(package_name, safe="@/")
        url = f"{self.registry_base_url}/{encoded_name}"
        try:
            response = requests.get(url, timeout=self.request_timeout_seconds)
        except requests.RequestException as exc:
            raise RegistryError(
                f"Failed to reach npm registry for '{package_name}': {exc}"
            ) from exc

        if response.status_code == 404:
            raise RegistryError(f"Package '{package_name}' was not found on the npm registry")
        if not response.ok:
            raise RegistryError(
                f"Registry returned HTTP {response.status_code} for '{package_name}'"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise RegistryError(
                f"Registry returned non-JSON payload for '{package_name}'"
            ) from exc

        if not isinstance(payload, dict):
            raise RegistryError(
                f"Unexpected registry payload type for '{package_name}': {type(payload).__name__}"
            )
        return payload

    def _download_file(self, url: str, destination: Path) -> None:
        try:
            with requests.get(url, stream=True, timeout=self.request_timeout_seconds) as response:
                if not response.ok:
                    raise PackageDownloadError(
                        f"Tarball download failed with HTTP {response.status_code}: {url}"
                    )
                with destination.open("wb") as handle:
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        if chunk:
                            handle.write(chunk)
        except requests.RequestException as exc:
            raise PackageDownloadError(f"Failed to download tarball from {url}: {exc}") from exc
        except OSError as exc:
            raise PackageDownloadError(f"Failed to write tarball to {destination}: {exc}") from exc

    def _extract_tarball(self, tarball_path: Path, destination: Path) -> None:
        if not tarfile.is_tarfile(tarball_path):
            raise PackageDownloadError(f"Downloaded artifact is not a valid tarball: {tarball_path}")

        destination.mkdir(parents=True, exist_ok=True)

        try:
            with tarfile.open(tarball_path, mode="r:gz") as archive:
                if sys.version_info >= (3, 12):
                    archive.extractall(path=destination, filter="data")
                else:
                    self._extract_tarball_safely(archive, destination)
        except (tarfile.TarError, OSError) as exc:
            raise PackageDownloadError(
                f"Failed to extract tarball {tarball_path}: {exc}"
            ) from exc

    def _extract_tarball_safely(self, archive: tarfile.TarFile, destination: Path) -> None:
        """Extract tarball members with path-traversal and symlink guards (Python < 3.12)."""
        destination_resolved = destination.resolve()

        for member in archive.getmembers():
            self._validate_tar_member(member, destination_resolved)
            archive.extract(member, path=destination, set_attrs=False)

    def _validate_tar_member(self, member: tarfile.TarInfo, destination: Path) -> None:
        member_name = member.name
        if not member_name or "\x00" in member_name:
            raise PackageDownloadError(f"Unsafe tarball member name: {member_name!r}")

        if member_name.startswith(("/", "\\")):
            raise PackageDownloadError(
                f"Absolute path not allowed in tarball member: {member_name!r}"
            )

        if len(member_name) > 1 and member_name[1] == ":":
            raise PackageDownloadError(
                f"Drive-relative path not allowed in tarball member: {member_name!r}"
            )

        if member.islnk() or member.issym():
            raise PackageDownloadError(
                f"Link entries not allowed in tarball member: {member_name!r}"
            )

        if member.isdev() or member.isfifo():
            raise PackageDownloadError(
                f"Special file entries not allowed in tarball member: {member_name!r}"
            )

        target_path = (destination / member_name).resolve()
        if not self._is_path_within_directory(destination, target_path):
            raise PackageDownloadError(
                f"Path traversal detected in tarball member: {member_name!r}"
            )

    @staticmethod
    def _is_path_within_directory(directory: Path, target: Path) -> bool:
        directory_resolved = directory.resolve()
        target_resolved = target.resolve()
        try:
            target_resolved.relative_to(directory_resolved)
        except ValueError:
            return False
        return True

    def _write_manifest_summary(
        self,
        sandbox_root: Path,
        manifest: PackageManifest,
        manifest_path: Path,
    ) -> None:
        summary = {
            "source_manifest": str(manifest_path),
            "package_name": manifest.name,
            "package_version": manifest.version,
            "dependency_count": len(manifest.all_dependencies()),
            "dependencies": manifest.all_dependencies(),
            "lifecycle_hooks_tracked": list(self.lifecycle_hooks),
        }
        output_path = sandbox_root / "manifest_summary.json"
        output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    def _write_ingestion_report(self, sandbox_root: Path, report: IngestionReport) -> None:
        payload = {
            "sandbox_root": str(report.sandbox_root),
            "manifest_path": str(report.manifest_path),
            "total_extracted_scripts": report.total_extracted_scripts,
            "packages": [
                {
                    "name": pkg.package_name,
                    "version": pkg.package_version,
                    "scripts_dir": str(pkg.scripts_dir),
                    "extracted_hooks": [script.hook_name for script in pkg.extracted_scripts],
                    "skipped_hooks": pkg.skipped_hooks,
                }
                for pkg in report.all_packages
            ],
        }
        output_path = sandbox_root / "ingestion_report.json"
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @staticmethod
    def _safe_dirname(package_name: str) -> str:
        return package_name.replace("/", "__").replace("@", "")
