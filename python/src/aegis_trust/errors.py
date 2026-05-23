"""Aegis Trust error model — machine-parseable errors for agent retry.

Every error carries ``code`` + ``remediation`` + ``docs_url`` so agents can
route on the code, surface the remediation to a human or a coding model,
and follow the docs_url for canonical guidance. Mirror of the Sentry
archetype error envelope — no free-text guessing required for retry.

Python port of TypeScript :mod:`aegis-trust` ``src/errors.ts``
(introduced in v0.9.0-rc1 internal-ops/sprint_001).
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
