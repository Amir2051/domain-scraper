"""safenest — shared infrastructure for the OSINT engine.

Phase 0 of the SAFENESTT 2099 roadmap. This package collects the
cross-cutting concerns that the tools_*.py modules used to re-implement
locally (HTTP client, headers, soon-to-come logging / retry / cache).

Plugin modules import from here; nothing in safenest imports tools_*.
"""
__version__ = "0.1.0"
