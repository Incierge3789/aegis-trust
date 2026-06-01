"""Aegis Trust error model — machine-parseable errors for agent retry.

Every error carries ``code`` + ``remediation`` + ``docs_url`` so agents can
route on the code, surface the remediation to a human or a coding model,
and follow the docs_url for canonical guidance. Mirror of the Sentry
archetype error envelope — no free-text guessing required for retry.

Python port of TypeScript :mod:`aegis-trust` ``src/errors.ts``
(introduced in v0.9.0-rc1 productization-ops/sprint_001).
"""

from __future__ import annotations

from typing import Any


# Canonical base URL for the error code documentation index.
_DOCS_BASE = "https://aegis-trust.dev/errors"


def aegis_docs_url(code: str) -> str:
    """Return the canonical documentation URL for an error ``code``."""
    return f"{_DOCS_BASE}/{code}"


class AegisError(Exception):
    """Base class for all Aegis SDK errors.

    Every error carries machine-parseable metadata:

    - ``code``: stable dot-separated identifier (e.g.
      ``aegis.shield.purpose.required``). Switch on this for retry /
      fallback / human escalation.
    - ``remediation``: one-line human/agent guidance.
    - ``docs_url``: canonical URL under ``https://aegis-trust.dev/errors/<code>``.

    Catch this at the agent boundary; switch on ``code`` for retry / fallback.
    """

    code: str
    remediation: str
    docs_url: str

    def __init__(
        self,
        message: str,
        *,
        code: str,
        remediation: str,
        docs_url: str,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.remediation = remediation
        self.docs_url = docs_url
        if cause is not None:
            self.__cause__ = cause

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation (omits ``__cause__`` chain)."""
        return {
            "name": type(self).__name__,
            "message": str(self),
            "code": self.code,
            "remediation": self.remediation,
            "docs_url": self.docs_url,
        }


class AegisValidationError(AegisError, ValueError):
    """Input validation failure — purpose / scope / deny_fields / mode shape.

    Inherits from :class:`ValueError` so existing
    ``except ValueError`` callers continue to catch it (backward-compat
    with pre-v0.9.0-rc1 callers).
    """

    code: str
    remediation: str
    docs_url: str


class AegisConfigError(AegisError, ValueError):
    """aegis.yaml load / parse / shape error.

    Inherits from :class:`ValueError` for backward-compat.
    """

    code: str
    remediation: str
    docs_url: str


class AegisConfigFileNotFoundError(AegisConfigError, FileNotFoundError):
    """Config file not found (no aegis.yaml / explicit path missing).

    S018 D2 catch-compatibility fix: before S018 a missing config file raised a
    raw :class:`FileNotFoundError`, so callers wrote
    ``except FileNotFoundError`` / ``except OSError``. The S018 rich-envelope
    work briefly broke those catches by raising only ``AegisConfigError``
    (a :class:`ValueError`). This subtype restores the natural builtin contract
    — it **is** a ``FileNotFoundError`` (hence also an :class:`OSError`) — while
    still carrying the machine-parseable ``.code`` / ``.remediation`` /
    ``.docs_url`` / ``.to_dict()`` envelope and remaining catchable as
    ``AegisConfigError`` / ``ValueError`` (additive, for callers who adopted the
    S018 advice). No layout conflict: see tests/test_error_catch_compat_S018.py.
    """

    code: str
    remediation: str
    docs_url: str


class AegisConfigImportError(AegisConfigError, ImportError):
    """Optional ``yaml`` dependency missing.

    S018 D2 catch-compatibility fix: before S018 a missing ``yaml`` dependency
    raised a raw :class:`ImportError`, so callers wrote ``except ImportError``.
    This subtype restores that contract — it **is** an ``ImportError`` — while
    still carrying the rich envelope and remaining catchable as
    ``AegisConfigError`` / ``ValueError``.
    """

    code: str
    remediation: str
    docs_url: str


class AegisIngestError(AegisError, ValueError):
    """shield/ingest response parse error — server contract violation."""

    code: str
    remediation: str
    docs_url: str


class AegisAuditError(AegisError, ValueError):
    """audit/verify response parse error — chain invariant violation."""

    code: str
    remediation: str
    docs_url: str


class AegisHttpError(AegisError):
    """HTTP-level failure — non-2xx response from aegis-core REST.

    Carries ``status`` (HTTP status code).
    """

    code: str
    remediation: str
    docs_url: str
    status: int

    def __init__(
        self,
        message: str,
        *,
        code: str,
        remediation: str,
        docs_url: str,
        status: int,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(
            message,
            code=code,
            remediation=remediation,
            docs_url=docs_url,
            cause=cause,
        )
        self.status = status
