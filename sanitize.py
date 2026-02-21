#! /usr/bin/env python3
"""CLI entrypoint for the sanitizer tool."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from sanitizer_core import (
    DEFAULT_EXTS,
    DEFAULT_MAX_SIZE_MB,
    FileReport,
    RedactionConfig,
    has_io_errors,
    parse_exts,
    run_self_tests,
    sanitize_directory,
)


def format_status(report: FileReport) -> str:
    if report.modified:
        return "modified"
    if report.skipped:
        return f"skipped:{report.skipped}"
    return "unchanged"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sanitize YAML/text configuration files without rewriting formatting")
    parser.add_argument("source_dir", nargs="?", help="Source directory to scan recursively")
    parser.add_argument("--ext", default=",".join(sorted(DEFAULT_EXTS)), help="Comma-separated extensions")
    parser.add_argument("--out", default=None, help="Output directory (default: <source>_sanitized)")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Analyze only; do not write sanitized files (JSON report is still written)",
    )
    parser.add_argument("--redact-certs", action="store_true", help="Also redact certificate blocks")
    parser.add_argument("--redact-public-keys", action="store_true", help="Also redact SSH public keys")
    parser.add_argument(
        "--domain",
        action="append",
        default=[],
        help="Domain to redact. Repeat this flag or pass multiple values with --domains.",
    )
    parser.add_argument(
        "--domains",
        default="",
        help="Comma-separated list of domains to redact (example: company.com,internal.local).",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--max-size-mb", type=float, default=DEFAULT_MAX_SIZE_MB, help="Skip files larger than this size")
    parser.add_argument("--self-test", action="store_true", help="Run built-in minimal tests")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_tests()

    if not args.source_dir:
        parser.error("source_dir is required unless --self-test is used")

    source_dir = Path(args.source_dir).resolve()
    output_dir = Path(args.out).resolve() if args.out else None
    extensions = parse_exts(args.ext)

    domain_inputs = list(args.domain)
    if args.domains:
        domain_inputs.append(args.domains)

    try:
        config = RedactionConfig(
            domains=domain_inputs,
            redact_certs=args.redact_certs,
            redact_public_keys=args.redact_public_keys,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    def progress_callback(relative_path: Path, report: FileReport) -> None:
        if args.verbose:
            print(f"[{format_status(report)}] {relative_path}")

    try:
        result = sanitize_directory(
            source_dir=source_dir,
            out_dir=output_dir,
            config=config,
            exts=extensions,
            dry_run=args.dry_run,
            max_size_mb=args.max_size_mb,
            progress_callback=progress_callback,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3

    print(f"Files processed: {result.stats.files_processed}")
    print(f"Files modified:  {result.stats.files_modified}")
    print(f"Replacements:    {result.stats.replacements}")
    print(f"Domains:         {', '.join(config.domains) if config.domains else '(none)'}")
    print(f"Report:          {result.report_path}")

    return 1 if has_io_errors(result.results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
