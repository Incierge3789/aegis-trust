"""Back-compat shim — `import aegis` was renamed to `import aegis_trust` (v0.9.0-rc2+).

This shim re-exports the public surface from `aegis_trust` so existing v0.8.x
client code continues to work. Emits DeprecationWarning. Slated for removal in
v2.0.0 (per api_versioning_policy.yaml).
"""

from __future__ import annotations

import warnings as _warnings

_warnings.warn(
    "Module 'aegis' was renamed to 'aegis_trust' (v0.9.0-rc2+). "
    "Please migrate: `from aegis import shield` -> `from aegis_trust import shield`. "
    "This back-compat shim will be removed in v2.0.0.",
    DeprecationWarning,
    stacklevel=2,
)

from aegis_trust import *  # noqa: F401,F403,E402
from aegis_trust import __all__ as _public  # noqa: E402

__all__ = list(_public)
