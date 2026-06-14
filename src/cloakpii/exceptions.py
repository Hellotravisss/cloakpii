"""
Custom exceptions for CloakPII.

Provides clear, actionable error types for different failure modes.
"""

from __future__ import annotations


class CloakPIIError(Exception):
    """Base exception for all CloakPII errors."""
    pass


class ConfigurationError(CloakPIIError):
    """Raised when configuration is invalid or missing required fields."""
    pass


class ComplianceError(CloakPIIError):
    """Raised when a compliance violation is detected that blocks migration."""
    pass


class PIIError(CloakPIIError):
    """Raised when PII detection or desensitization fails."""
    pass


class CryptoError(CloakPIIError):
    """Raised when encryption/decryption operations fail."""
    pass


class IntegrityError(CloakPIIError):
    """Raised when file integrity checks fail."""
    pass


class MigrationStateError(CloakPIIError):
    """Raised when incremental migration state is corrupted or incompatible."""
    pass


class UnsupportedFileError(CloakPIIError):
    """Raised when a file type is not supported for migration."""
    pass
