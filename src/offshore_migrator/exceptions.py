"""
Custom exceptions for Offshore Data Migrator.

Provides clear, actionable error types for different failure modes.
"""

from __future__ import annotations


class OffshoreMigratorError(Exception):
    """Base exception for all Offshore Data Migrator errors."""
    pass


class ConfigurationError(OffshoreMigratorError):
    """Raised when configuration is invalid or missing required fields."""
    pass


class ComplianceError(OffshoreMigratorError):
    """Raised when a compliance violation is detected that blocks migration."""
    pass


class PIIError(OffshoreMigratorError):
    """Raised when PII detection or desensitization fails."""
    pass


class CryptoError(OffshoreMigratorError):
    """Raised when encryption/decryption operations fail."""
    pass


class IntegrityError(OffshoreMigratorError):
    """Raised when file integrity checks fail."""
    pass


class MigrationStateError(OffshoreMigratorError):
    """Raised when incremental migration state is corrupted or incompatible."""
    pass


class UnsupportedFileError(OffshoreMigratorError):
    """Raised when a file type is not supported for migration."""
    pass
