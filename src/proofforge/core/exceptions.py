"""Domain exceptions for ProofForge AI.

Keeping these in one place lets the CLI layer translate them into clean,
user-facing messages without leaking tracebacks.
"""

from __future__ import annotations


class BBReportError(Exception):
    """Base class for all ProofForge AI errors."""


class ConfigError(BBReportError):
    """Raised when configuration is missing or invalid."""


class SessionError(BBReportError):
    """Raised for missing/corrupt session state or invalid session operations."""


class EvidenceError(BBReportError):
    """Raised when evidence cannot be ingested or parsed."""


class PathValidationError(EvidenceError):
    """Raised when a file path fails cross-platform safety validation."""


class TemplateError(BBReportError):
    """Raised when a vuln-class template is missing or fails schema validation."""


class RulePackError(BBReportError):
    """Raised when a program rule pack is missing or fails schema validation."""


class LLMError(BBReportError):
    """Raised when an LLM backend fails to produce a usable response."""


class LLMFormatError(LLMError):
    """Raised when the LLM does not return valid structured output after retry."""


class IntegrityError(BBReportError):
    """Raised when a hard integrity check fails and cannot be overridden."""


class SeverityError(BBReportError):
    """Raised when a severity vector cannot be parsed or scored."""
