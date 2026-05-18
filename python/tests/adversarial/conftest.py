"""Shared fixtures for the adversarial (red-team) test suite.

The ``_clean`` autouse fixture resets the shield module cache and forces
``AEGIS_MODE=lite`` so each adversarial scenario runs against the local
filter path without bleeding state between cases. Individual test files
can still override this by defining a fixture with the same name — that
preserves the pre-existing S018 test-specific resets.
"""

from __future__ import annotations

import pytest

from aegis_trust.shield import reset


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset()
    monkeypatch.setenv("AEGIS_MODE", "lite")
    yield
    reset()
