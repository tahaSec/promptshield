"""promptshield - detect prompt injection and hidden text in LLM inputs."""

__version__ = "0.1.0"

from .scanner import Finding, Report, sanitize, scan  # noqa: E402

__all__ = ["scan", "sanitize", "Report", "Finding", "__version__"]
