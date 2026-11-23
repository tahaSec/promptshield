"""Command line interface: ``promptshield [paths...]``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterator, List, Tuple

from . import __version__
from .scanner import SEVERITY_ORDER, Report, sanitize, scan

DEFAULT_EXTS = {".txt", ".md", ".markdown", ".html", ".htm", ".json", ".csv", ".xml",
                ".yaml", ".yml", ".rst", ".log", ".py", ".js", ".ts", ".prompt"}

COLORS = {
    "critical": "\033[1;97;41m",
    "high": "\033[1;31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[37m",
    "reset": "\033[0m",
    "dim": "\033[2m",
    "bold": "\033[1m",
}


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.name == "nt":
        # Enable ANSI on Windows 10+ terminals.
        os.system("")
    return True


def _iter_inputs(paths: List[str], exts: set) -> Iterator[Tuple[str, str]]:
    for p in paths:
        if p == "-":
            data = sys.stdin.buffer.read()
            yield "<stdin>", data.decode("utf-8", errors="replace")
            continue
        path = Path(p)
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix.lower() in exts and ".git" not in child.parts:
                    yield str(child), child.read_text(encoding="utf-8", errors="replace")
        elif path.is_file():
            yield str(path), path.read_text(encoding="utf-8", errors="replace")
        else:
            print("promptshield: no such file or directory: %s" % p, file=sys.stderr)


def _print_text(reports: List[Report], color: bool) -> None:
    c = COLORS if color else {k: "" for k in COLORS}
    total = 0
    for report in reports:
        if not report.findings:
            continue
        print("%s%s%s  (risk score %d/100)" % (c["bold"], report.source, c["reset"], report.risk_score))
        for f in report.findings:
            total += 1
            sev = "%s%-8s%s" % (c[f.severity], f.severity.upper(), c["reset"])
            print("  %s %s  %d:%d  %s" % (sev, f.rule_id, f.line, f.column, f.message))
            print("           %s%s%s" % (c["dim"], f.excerpt, c["reset"]))
            if f.decoded:
                print("           hidden text -> %r" % f.decoded)
        print()
    scanned = len(reports)
    if total == 0:
        print("No prompt injection indicators found in %d input(s)." % scanned)
    else:
        print("%d finding(s) in %d of %d input(s)." % (
            total, sum(1 for r in reports if r.findings), scanned))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="promptshield",
        description="Detect prompt injection and hidden text before it reaches your LLM.",
    )
    parser.add_argument("paths", nargs="*", default=["-"],
                        help="files or directories to scan, '-' for stdin (default)")
    parser.add_argument("-f", "--format", choices=["text", "json"], default="text")
    parser.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low",
                        help="hide findings below this level (default: low)")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER) + ["never"], default="high",
                        help="exit with code 1 if a finding at or above this level exists (default: high)")
    parser.add_argument("--sanitize", action="store_true",
                        help="print the input with invisible/control characters removed instead of a report")
    parser.add_argument("--ext", action="append", default=None,
                        help="file extension to include when scanning directories (repeatable)")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    # Old Windows consoles use legacy code pages; never crash on output.
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except (ValueError, OSError):
            pass
    exts = {e if e.startswith(".") else "." + e for e in args.ext} if args.ext else DEFAULT_EXTS

    if args.sanitize:
        for _, text in _iter_inputs(args.paths, exts):
            sys.stdout.write(sanitize(text))
        return 0

    reports = [scan(text, source=name, min_severity=args.min_severity)
               for name, text in _iter_inputs(args.paths, exts)]

    if args.format == "json":
        json.dump([r.to_dict() for r in reports], sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        _print_text(reports, _use_color(sys.stdout))

    if args.fail_on == "never":
        return 0
    limit = SEVERITY_ORDER[args.fail_on]
    failed = any(SEVERITY_ORDER[f.severity] >= limit for r in reports for f in r.findings)
    return 1 if failed else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
