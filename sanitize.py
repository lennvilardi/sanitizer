#! /usr/bin/env python3
"""CLI entrypoint for the sanitizer tool."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from sanitizer_core import (
    FileReport,
    RedactionConfig,
    has_io_errors,
    run_self_tests,
    sanitize_single_file,
    suggested_output_file,
)


def format_status(report: FileReport) -> str:
    if report.modified:
        return "modified"
    if report.skipped:
        return f"skipped:{report.skipped}"
    return "unchanged"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sanitize one YAML/text configuration file without rewriting formatting")
    parser.add_argument("source_file", nargs="?", help="Source file to sanitize")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Analyze only; do not write sanitized file",
    )
    parser.add_argument("--no-redact-certs", action="store_true", help="Do not redact certificate blocks")
    parser.add_argument("--no-redact-public-keys", action="store_true", help="Do not redact SSH public keys")
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
    parser.add_argument("--force-overwrite", action="store_true", help="Overwrite output file without confirmation")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--self-test", action="store_true", help="Run built-in minimal tests")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_tests()

    if not args.source_file:
        parser.error("source_file is required unless --self-test is used")

    source_file = Path(args.source_file).resolve()
    output_file = suggested_output_file(source_file)

    domain_inputs = list(args.domain)
    if args.domains:
        domain_inputs.append(args.domains)

    try:
        config = RedactionConfig(
            domains=domain_inputs,
            redact_certs=not args.no_redact_certs,
            redact_public_keys=not args.no_redact_public_keys,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    def progress_callback(relative_path: Path, report: FileReport) -> None:
        if args.verbose:
            print(f"[{format_status(report)}] {relative_path}")

    if output_file.exists() and not args.dry_run and not args.force_overwrite:
        answer = input(f"Output file exists: {output_file}\nOverwrite? [y/N]: ").strip().lower()
        if answer not in {"y", "yes"}:
            print("Aborted: output file not overwritten.", file=sys.stderr)
            return 4

    try:
        result = sanitize_single_file(
            source_file=source_file,
            config=config,
            dry_run=args.dry_run,
        )
        progress_callback(result.source_file, result.report)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3

    if result.report.skipped:
        print(f"Status:          skipped:{result.report.skipped}")
    else:
        print(f"Status:          {'dry-run' if args.dry_run else 'completed'}")
    print(f"Domains:         {', '.join(config.domains) if config.domains else '(none)'}")
    print(f"Replacements:    {result.report.replacements}")
    print(f"Output file:     {result.output_file}")

    if result.report.logs:
        print("Replacement log:")
        for entry in result.report.logs:
            print(f"  L{entry.line} [{entry.rule}]")
            print(f"    before: {entry.before}")
            print(f"    after : {entry.after}")

    return 1 if has_io_errors(result.report) else 0


if __name__ == "__main__":
    raise SystemExit(main())
