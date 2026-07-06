"""Custom exceptions for the Phanos ingestion pipeline."""


class PhanosError(Exception):
    """Base exception for all Phanos errors."""


class ManifestNotFoundError(PhanosError):
    """Raised when a package manifest file cannot be located on disk."""


class InvalidManifestError(PhanosError):
    """Raised when a manifest file exists but cannot be parsed or validated."""


class RegistryError(PhanosError):
    """Raised when the npm registry cannot be reached or returns an unexpected response."""


class PackageDownloadError(PhanosError):
    """Raised when a dependency tarball cannot be downloaded or extracted."""


class SandboxError(PhanosError):
    """Raised when the isolated sandbox directory cannot be created or written."""
