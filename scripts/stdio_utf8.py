"""UTF-8 stdio for Netie KB CLI scripts - required on Windows (cp1252 default)."""

from __future__ import annotations

import sys


def ensure_utf8_stdio(*, errors: str = "replace") -> None:
    """Reconfigure stdout/stderr to UTF-8 before printing corpus text."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors=errors)
        except (ValueError, OSError):
            # Piped, closed, or non-reconfigurable stream - leave as-is.
            pass
