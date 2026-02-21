"""Core sanitization logic for YAML/text configuration files.

This module exposes a reusable API used by both CLI and GUI entrypoints.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Pattern, Sequence, Tuple

DEFAULT_EXTS = {".yml", ".yaml", ".conf", ".ini", ".env", ".txt"}
DEFAULT_MAX_SIZE_MB = 10.0
DEFAULT_REDACTED_TOKEN = "<REDACTED>"
DEFAULT_REDACTED_BLOCK_TOKEN = "<REDACTED_BLOCK>"

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pass",
    "passphrase",
    "secret",
    "secret_key",
    "client_secret",
    "jwt_secret",
    "hmac_secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "bearer",
    "private_key",
    "ssh_key",
    "rsa_key",
    "encryption_key",
    "cookie_secret",
    "session_secret",
    "redis_password",
    "db_password",
    "smtp_password",
}

CONTEXT_SENSITIVE_PARENTS = {"tls", "jwks", "oidc"}
DOMAIN_CANDIDATE_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")

RE_KEY_VALUE = re.compile(
    r"^(?P<prefix>\s*(?:-\s*)?)(?P<key>[A-Za-z0-9_.-]+)(?P<sep>\s*:\s*)(?P<rest>.*?)(?P<eol>\r?\n?)$"
)
RE_BLOCK_MARKER = re.compile(r"^[>|][+-]?\d?\s*(?:#.*)?$")

RE_JWT = re.compile(r"\b[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
RE_LONG_HEX = re.compile(r"\b[a-fA-F0-9]{24,}\b")
RE_LONG_B64 = re.compile(r"\b[A-Za-z0-9+/=_-]{24,}\b")
RE_BEARER = re.compile(r"^Bearer\s+\S+", re.IGNORECASE)
RE_URL_CREDS = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:[^\s@/]+@")
RE_PEM_PRIVATE_BEGIN = re.compile(r"-----BEGIN\s+.*PRIVATE KEY-----")
RE_PEM_PRIVATE_END = re.compile(r"-----END\s+.*PRIVATE KEY-----")
RE_PEM_CERT_BEGIN = re.compile(r"-----BEGIN CERTIFICATE-----")
RE_PEM_CERT_END = re.compile(r"-----END CERTIFICATE-----")
RE_SSH_PUBLIC = re.compile(r"\b(?:ssh-rsa|ssh-ed25519)\s+[A-Za-z0-9+/=]+")


@dataclass
class MatchEvent:
    line: int
    rule: str
    length: int


@dataclass
class FileReport:
    replacements: int = 0
    rules: Dict[str, int] = field(default_factory=dict)
    matches: List[MatchEvent] = field(default_factory=list)
    modified: bool = False
    skipped: Optional[str] = None

    def add(self, rule: str, line_num: int, original_length: int) -> None:
        self.replacements += 1
        self.modified = True
        self.rules[rule] = self.rules.get(rule, 0) + 1
        self.matches.append(MatchEvent(line=line_num, rule=rule, length=original_length))


@dataclass
class Stats:
    files_processed: int = 0
    files_modified: int = 0
    replacements: int = 0


@dataclass
class RedactionConfig:
    domains: Sequence[str] = field(default_factory=list)
    redact_certs: bool = False
    redact_public_keys: bool = False
    redacted_token: str = DEFAULT_REDACTED_TOKEN
    redacted_block_token: str = DEFAULT_REDACTED_BLOCK_TOKEN
    domain_patterns: List[Tuple[str, Pattern[str]]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        normalized_domains = parse_domain_list(self.domains)
        self.domains = normalized_domains
        self.domain_patterns = compile_domain_patterns(normalized_domains)


@dataclass
class RunResult:
    source_dir: Path
    out_dir: Path
    report_path: Path
    stats: Stats
    results: Dict[str, FileReport]


ProgressCallback = Callable[[Path, FileReport], None]


def normalize_domain(raw: str) -> str:
    text = raw.strip().lower()
    if not text:
        return ""
    text = re.sub(r"^https?://", "", text)
    text = text.strip("/")
    text = text.split("/", maxsplit=1)[0]
    text = text.split("?", maxsplit=1)[0]
    text = text.split("#", maxsplit=1)[0]
    text = text.split(":", maxsplit=1)[0]
    return text.strip(".")


def parse_domain_list(raw_domains: Sequence[str]) -> List[str]:
    unique: List[str] = []
    seen = set()
    for raw in raw_domains:
        if not raw:
            continue
        parts = [part.strip() for part in raw.split(",") if part.strip()]
        for part in parts:
            normalized = normalize_domain(part)
            if not normalized:
                continue
            if not DOMAIN_CANDIDATE_RE.fullmatch(normalized):
                raise ValueError(f"Invalid domain value: {part}")
            if normalized not in seen:
                seen.add(normalized)
                unique.append(normalized)
    return unique


def compile_domain_patterns(domains: Sequence[str]) -> List[Tuple[str, Pattern[str]]]:
    patterns: List[Tuple[str, Pattern[str]]] = []
    for domain in domains:
        escaped = re.escape(domain)
        pattern = re.compile(rf"\b(?:[A-Za-z0-9-]+\.)*{escaped}\b", re.IGNORECASE)
        patterns.append((domain, pattern))
    return patterns


def detect_binary(path: Path, sample_size: int = 4096) -> bool:
    with path.open("rb") as file_obj:
        chunk = file_obj.read(sample_size)
    return b"\x00" in chunk


def split_value_and_comment(text: str) -> Tuple[str, str]:
    in_single = False
    in_double = False
    escaped = False

    for idx, char in enumerate(text):
        if in_double and char == "\\" and not escaped:
            escaped = True
            continue
        if char == "\"" and not in_single and not escaped:
            in_double = not in_double
        elif char == "'" and not in_double:
            in_single = not in_single
        elif char == "#" and not in_single and not in_double:
            if idx == 0 or text[idx - 1].isspace():
                return text[:idx], text[idx:]
        escaped = False
    return text, ""


def preserve_quotes(original_core: str, redacted_token: str) -> str:
    core = original_core.strip()
    if len(core) >= 2 and core[0] == core[-1] and core[0] in {"'", "\""}:
        return f"{core[0]}{redacted_token}{core[0]}"
    return redacted_token


def replace_value_keep_spacing(value_part: str, replacement_core: str) -> str:
    leading = len(value_part) - len(value_part.lstrip(" "))
    trailing = len(value_part) - len(value_part.rstrip(" "))
    return (" " * leading) + replacement_core + (" " * trailing)


def is_sensitive_key(key: str, parent_context: Sequence[str], value_core: str, config: RedactionConfig) -> bool:
    low = key.lower()
    if low in SENSITIVE_KEYS:
        return True
    if low != "key":
        return False

    if any(ctx in CONTEXT_SENSITIVE_PARENTS for ctx in parent_context):
        return True
    return value_looks_sensitive(
        value_core,
        config=config,
        redact_certs=False,
        redact_public_keys=True,
    )


def value_looks_sensitive(
    value: str,
    config: RedactionConfig,
    redact_certs: Optional[bool] = None,
    redact_public_keys: Optional[bool] = None,
) -> bool:
    stripped = value.strip().strip("'\"")
    if not stripped:
        return False
    with_certs = config.redact_certs if redact_certs is None else redact_certs
    with_public = config.redact_public_keys if redact_public_keys is None else redact_public_keys
    if RE_BEARER.match(stripped):
        return True
    if RE_URL_CREDS.search(stripped):
        return True
    if RE_JWT.search(stripped):
        return True
    if RE_LONG_HEX.search(stripped) or RE_LONG_B64.search(stripped):
        return True
    if RE_PEM_PRIVATE_BEGIN.search(stripped) or RE_PEM_PRIVATE_END.search(stripped):
        return True
    if with_certs and (RE_PEM_CERT_BEGIN.search(stripped) or RE_PEM_CERT_END.search(stripped)):
        return True
    if with_public and RE_SSH_PUBLIC.search(stripped):
        return True
    return False


def redact_configured_domains(text: str, config: RedactionConfig) -> Tuple[str, int, int]:
    if not config.domain_patterns:
        return text, 0, 0

    redacted = text
    match_count = 0
    match_length = 0

    for _, pattern in config.domain_patterns:
        hits = list(pattern.finditer(redacted))
        if not hits:
            continue
        match_count += len(hits)
        match_length += sum(len(hit.group(0)) for hit in hits)
        redacted = pattern.sub(config.redacted_token, redacted)
    return redacted, match_count, match_length


def sanitize_plain_line(line: str, line_num: int, report: FileReport, config: RedactionConfig) -> str:
    if line.endswith("\r\n"):
        eol = "\r\n"
        body = line[:-2]
    elif line.endswith("\n"):
        eol = "\n"
        body = line[:-1]
    else:
        eol = ""
        body = line

    if RE_PEM_PRIVATE_BEGIN.search(body) or RE_PEM_PRIVATE_END.search(body):
        report.add("value:pem_private", line_num, len(body))
        return f"{config.redacted_token}{eol}"
    if config.redact_certs and (RE_PEM_CERT_BEGIN.search(body) or RE_PEM_CERT_END.search(body)):
        report.add("value:pem_cert", line_num, len(body))
        return f"{config.redacted_token}{eol}"
    if config.redact_public_keys and RE_SSH_PUBLIC.search(body):
        report.add("value:ssh_public", line_num, len(body))
        return f"{config.redacted_token}{eol}"

    redacted, count, length = redact_configured_domains(body, config)
    if count:
        report.add("value:configured_domain", line_num, length)
        return redacted + eol
    return line


def sanitize_lines(lines: List[str], config: RedactionConfig) -> Tuple[List[str], FileReport]:
    report = FileReport()
    out: List[str] = []
    context_stack: List[Tuple[int, str]] = []

    index = 0
    while index < len(lines):
        line_num = index + 1
        line = lines[index]
        match = RE_KEY_VALUE.match(line)
        if not match:
            out.append(sanitize_plain_line(line, line_num, report, config))
            index += 1
            continue

        prefix = match.group("prefix")
        key = match.group("key")
        sep = match.group("sep")
        rest = match.group("rest")
        eol = match.group("eol")

        key_indent = len(prefix) - len(prefix.lstrip(" "))
        while context_stack and context_stack[-1][0] >= key_indent:
            context_stack.pop()
        parent_context = [ctx_key for _, ctx_key in context_stack]

        value_part, comment_part = split_value_and_comment(rest)
        value_core = value_part.strip()

        key_sensitive = is_sensitive_key(key, parent_context, value_core, config)
        is_block = bool(RE_BLOCK_MARKER.match(value_core))

        if key_sensitive and is_block:
            new_line = f"{prefix}{key}{sep}\"{config.redacted_block_token}\""
            if comment_part:
                new_line += comment_part
            out.append(new_line + eol)
            report.add(f"key_block:{key.lower()}", line_num, len(value_core))

            next_index = index + 1
            while next_index < len(lines):
                next_line = lines[next_index]
                stripped = next_line.strip()
                if stripped == "":
                    next_index += 1
                    continue
                next_indent = len(next_line) - len(next_line.lstrip(" "))
                if next_indent <= key_indent:
                    break
                next_index += 1
            index = next_index
            context_stack.append((key_indent, key.lower()))
            continue

        replacement_token: Optional[str] = None
        rule: Optional[str] = None

        if key_sensitive and value_core:
            replacement_token = preserve_quotes(value_core, config.redacted_token)
            rule = f"key:{key.lower()}"
        elif value_looks_sensitive(value_core, config):
            replacement_token = preserve_quotes(value_core, config.redacted_token)
            rule = "value:pattern"

        if replacement_token is not None:
            new_value = replace_value_keep_spacing(value_part, replacement_token)
            out.append(f"{prefix}{key}{sep}{new_value}{comment_part}{eol}")
            report.add(rule or "unknown", line_num, len(value_core))
        else:
            redacted_value, count, length = redact_configured_domains(value_part, config)
            if count:
                out.append(f"{prefix}{key}{sep}{redacted_value}{comment_part}{eol}")
                report.add("value:configured_domain", line_num, length)
            else:
                out.append(line)

        if value_core == "" or is_block:
            context_stack.append((key_indent, key.lower()))
        index += 1

    return out, report


def parse_exts(exts: str) -> set[str]:
    parsed = {
        ext.strip().lower() if ext.strip().startswith(".") else "." + ext.strip().lower()
        for ext in exts.split(",")
        if ext.strip()
    }
    return parsed or set(DEFAULT_EXTS)


def iter_target_files(source_dir: Path, exts: set[str]) -> List[Path]:
    files: List[Path] = []
    for path in source_dir.rglob("*"):
        if path.is_file() and path.suffix.lower() in exts:
            files.append(path)
    return files


def sanitize_file(
    src: Path,
    dst: Path,
    config: RedactionConfig,
    dry_run: bool,
    max_size_bytes: int,
) -> FileReport:
    report = FileReport()

    try:
        file_size = src.stat().st_size
    except OSError:
        report.skipped = "stat_error"
        return report

    if file_size > max_size_bytes:
        report.skipped = "too_large"
        return report

    try:
        if detect_binary(src):
            report.skipped = "binary"
            return report
    except OSError:
        report.skipped = "read_error"
        return report

    try:
        with src.open("r", encoding="utf-8", errors="surrogateescape", newline="") as file_obj:
            lines = file_obj.readlines()
    except OSError:
        report.skipped = "read_error"
        return report

    sanitized_lines, internal_report = sanitize_lines(lines, config)
    report = internal_report

    if not dry_run:
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            with dst.open("w", encoding="utf-8", errors="surrogateescape", newline="") as file_obj:
                file_obj.writelines(sanitized_lines)
        except OSError:
            report.skipped = "write_error"
            return report

    return report


def build_json_report(results: Dict[str, FileReport], stats: Stats, config: RedactionConfig) -> dict:
    files_payload = {}
    for rel, report in results.items():
        files_payload[rel] = {
            "modified": report.modified,
            "replacements": report.replacements,
            "rules": report.rules,
            "matches": [{"line": m.line, "rule": m.rule, "length": m.length} for m in report.matches],
            "skipped": report.skipped,
        }
    return {
        "summary": {
            "files_processed": stats.files_processed,
            "files_modified": stats.files_modified,
            "replacements": stats.replacements,
            "domains_redacted": list(config.domains),
        },
        "files": files_payload,
    }


def sanitize_directory(
    source_dir: Path,
    out_dir: Optional[Path],
    config: RedactionConfig,
    *,
    exts: set[str],
    dry_run: bool,
    max_size_mb: float,
    progress_callback: Optional[ProgressCallback] = None,
) -> RunResult:
    resolved_source = source_dir.resolve()
    if not resolved_source.exists() or not resolved_source.is_dir():
        raise ValueError(f"source_dir is not a directory: {resolved_source}")

    target_dir = out_dir.resolve() if out_dir else resolved_source.with_name(resolved_source.name + "_sanitized")
    max_size_bytes = int(max_size_mb * 1024 * 1024)

    targets = iter_target_files(resolved_source, exts)
    stats = Stats()
    results: Dict[str, FileReport] = {}

    if not dry_run:
        target_dir.mkdir(parents=True, exist_ok=True)

    for src in targets:
        relative = src.relative_to(resolved_source)
        dst = target_dir / relative
        report = sanitize_file(src, dst, config, dry_run, max_size_bytes)
        stats.files_processed += 1
        if report.modified:
            stats.files_modified += 1
        stats.replacements += report.replacements
        relative_key = str(relative)
        results[relative_key] = report
        if progress_callback is not None:
            progress_callback(relative, report)

    if dry_run:
        target_dir.mkdir(parents=True, exist_ok=True)

    report_payload = build_json_report(results, stats, config)
    report_path = target_dir / "sanitizer_report.json"
    with report_path.open("w", encoding="utf-8") as file_obj:
        json.dump(report_payload, file_obj, indent=2)

    return RunResult(
        source_dir=resolved_source,
        out_dir=target_dir,
        report_path=report_path,
        stats=stats,
        results=results,
    )


def has_io_errors(results: Dict[str, FileReport]) -> bool:
    return any(report.skipped in {"read_error", "write_error", "stat_error"} for report in results.values())


def run_self_tests() -> int:
    config = RedactionConfig(domains=["example.com"])

    sample = ["jwt_secret: 'a_very_important_secret'\n"]
    out, report = sanitize_lines(sample, config)
    assert out[0] == "jwt_secret: '<REDACTED>'\n", out[0]
    assert report.replacements == 1

    sample = ["secret: insecure_session_secret\n"]
    out, report = sanitize_lines(sample, config)
    assert out[0] == "secret: <REDACTED>\n", out[0]
    assert report.replacements == 1

    sample = [
        "jwks:\n",
        "  - key: |\n",
        "      -----BEGIN PRIVATE KEY-----\n",
        "      abc\n",
        "      -----END PRIVATE KEY-----\n",
        "  enabled: true\n",
    ]
    out, report = sanitize_lines(sample, config)
    assert "  - key: \"<REDACTED_BLOCK>\"\n" in out, out
    assert all("PRIVATE KEY" not in line for line in out)
    assert report.replacements == 1

    sample = ["site: example.com\n"]
    out, report = sanitize_lines(sample, config)
    assert out[0] == "site: <REDACTED>\n", out[0]
    assert report.replacements == 1

    sample = ["site: not-configured.example\n"]
    out, report = sanitize_lines(sample, config)
    assert out[0] == "site: not-configured.example\n", out[0]
    assert report.replacements == 0

    sample = ["homepage: https://api.example.com/docs\n"]
    out, report = sanitize_lines(sample, config)
    assert out[0] == "homepage: https://<REDACTED>/docs\n", out[0]
    assert report.replacements == 1

    print("Self-tests passed")
    return 0
