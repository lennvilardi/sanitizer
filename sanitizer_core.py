"""Core sanitization logic for YAML/text configuration files.

This module exposes a reusable API used by both CLI and GUI entrypoints.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Callable, Dict, List, Optional, Pattern, Sequence, Tuple

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
    "gpg_passphrase",
    "pgp_passphrase",
    "gpg_private_key",
    "pgp_private_key",
    "keystore_password",
}
NORMALIZED_SENSITIVE_KEYS = {re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_") for key in SENSITIVE_KEYS}

CONTEXT_SENSITIVE_PARENTS = {"tls", "jwks", "oidc"}
DOMAIN_CANDIDATE_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")

RE_KEY_VALUE = re.compile(
    r"^(?P<prefix>\s*(?:-\s*)?)(?P<key>[A-Za-z0-9_.-]+)(?P<sep>\s*:\s*)(?P<rest>.*?)(?P<eol>\r?\n?)$"
)
RE_ASSIGNMENT = re.compile(
    r"^(?P<prefix>\s*(?:export\s+)?)"
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P<sep>\s*=\s*)"
    r"(?P<rest>.*?)(?P<eol>\r?\n?)$"
)
RE_BLOCK_MARKER = re.compile(r"^[>|][+-]?\d?\s*(?:#.*)?$")
RE_JSON_INLINE_PAIR = re.compile(
    r'(?P<prefix>["\'](?P<key>[^"\']+)["\']\s*:\s*)'
    r'(?P<value>"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^,\}\]\s][^,\}\]\r\n]*)'
)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")

RE_JWT = re.compile(r"\b[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
RE_LONG_HEX = re.compile(r"\b[a-fA-F0-9]{24,}\b")
RE_LONG_B64 = re.compile(r"\b[A-Za-z0-9+/=_-]{24,}\b")
RE_BEARER = re.compile(r"^Bearer\s+\S+", re.IGNORECASE)
RE_URL_CREDS = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:[^\s@/]+@")
RE_PEM_PRIVATE_BEGIN = re.compile(r"-----BEGIN\s+.*PRIVATE KEY-----")
RE_PEM_PRIVATE_END = re.compile(r"-----END\s+.*PRIVATE KEY-----")
RE_PGP_PRIVATE_BEGIN = re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----")
RE_PGP_PRIVATE_END = re.compile(r"-----END PGP PRIVATE KEY BLOCK-----")
RE_PEM_CERT_BEGIN = re.compile(r"-----BEGIN CERTIFICATE-----")
RE_PEM_CERT_END = re.compile(r"-----END CERTIFICATE-----")
RE_SSH_PUBLIC = re.compile(r"\b(?:ssh-rsa|ssh-ed25519)\s+[A-Za-z0-9+/=]+")
MASKABLE_CHUNK_RE = re.compile(r"[A-Za-z0-9+/=_-]{4,}")


@dataclass
class MatchEvent:
    line: int
    rule: str
    length: int


@dataclass
class ReplacementLog:
    line: int
    rule: str
    before: str
    after: str


@dataclass
class FileReport:
    replacements: int = 0
    rules: Dict[str, int] = field(default_factory=dict)
    matches: List[MatchEvent] = field(default_factory=list)
    logs: List[ReplacementLog] = field(default_factory=list)
    modified: bool = False
    skipped: Optional[str] = None

    def add(self, rule: str, line_num: int, original_length: int, *, before: Optional[str] = None, after: Optional[str] = None) -> None:
        self.replacements += 1
        self.modified = True
        self.rules[rule] = self.rules.get(rule, 0) + 1
        self.matches.append(MatchEvent(line=line_num, rule=rule, length=original_length))
        if before is not None and after is not None:
            self.logs.append(ReplacementLog(line=line_num, rule=rule, before=before, after=after))


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
    source_file: Path
    output_file: Path
    dry_run: bool
    report: FileReport


ProgressRatioCallback = Callable[[float], None]
LineProgressCallback = Callable[[int, int], None]


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


def normalize_key_name(key: str) -> str:
    camel_split = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)
    return re.sub(r"[^A-Za-z0-9]+", "_", camel_split).lower().strip("_")


def key_looks_password_related(key: str) -> bool:
    low = key.lower()
    if "password" in low or "passwd" in low or "passphrase" in low:
        return True
    normalized = normalize_key_name(key)
    parts = [part for part in normalized.split("_") if part]
    return any(part in {"pass", "pwd", "passcode"} for part in parts)


def is_sensitive_key(key: str, parent_context: Sequence[str], value_core: str, config: RedactionConfig) -> bool:
    low = key.lower()
    normalized = normalize_key_name(key)
    if low in SENSITIVE_KEYS or normalized in NORMALIZED_SENSITIVE_KEYS:
        return True
    if key_looks_password_related(key):
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
    if (
        RE_PEM_PRIVATE_BEGIN.search(stripped)
        or RE_PEM_PRIVATE_END.search(stripped)
        or RE_PGP_PRIVATE_BEGIN.search(stripped)
        or RE_PGP_PRIVATE_END.search(stripped)
    ):
        return True
    if with_certs and (RE_PEM_CERT_BEGIN.search(stripped) or RE_PEM_CERT_END.search(stripped)):
        return True
    if with_public and RE_SSH_PUBLIC.search(stripped):
        return True
    return False


def block_looks_sensitive(
    lines: Sequence[str],
    start_index: int,
    key_indent: int,
    config: RedactionConfig,
) -> bool:
    probe = start_index + 1
    while probe < len(lines):
        probe_line = lines[probe]
        stripped = probe_line.strip()
        if not stripped:
            probe += 1
            continue
        probe_indent = len(probe_line) - len(probe_line.lstrip(" "))
        if probe_indent <= key_indent:
            return False
        return value_looks_sensitive(stripped, config)
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


def redact_emails(text: str, config: RedactionConfig) -> Tuple[str, int, int]:
    hits = list(RE_EMAIL.finditer(text))
    if not hits:
        return text, 0, 0
    redacted = RE_EMAIL.sub(config.redacted_token, text)
    return redacted, len(hits), sum(len(hit.group(0)) for hit in hits)


def mask_token(token: str, keep_start: int = 4, keep_end: int = 3) -> str:
    if len(token) <= (keep_start + keep_end):
        return "*" * len(token)
    return token[:keep_start] + ("*" * (len(token) - keep_start - keep_end)) + token[-keep_end:]


def mask_fragment(fragment: str) -> str:
    masked = MASKABLE_CHUNK_RE.sub(lambda m: mask_token(m.group(0)), fragment)
    if masked == fragment:
        masked = "".join("*" if not ch.isspace() else ch for ch in fragment)
    return masked


def shorten_for_log(text: str, limit: int = 150) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def build_replacement_preview(original_line: str, sanitized_line: str) -> Tuple[str, str]:
    before = original_line.rstrip("\r\n")
    after = sanitized_line.rstrip("\r\n")
    matcher = SequenceMatcher(a=before, b=after)

    masked_before_parts: List[str] = []
    for opcode, i1, i2, _, _ in matcher.get_opcodes():
        part = before[i1:i2]
        if opcode == "equal":
            masked_before_parts.append(part)
        else:
            masked_before_parts.append(mask_fragment(part))

    masked_before = shorten_for_log("".join(masked_before_parts))
    masked_after = shorten_for_log(after)
    return masked_before, masked_after


def record_replacement(
    report: FileReport,
    *,
    rule: str,
    line_num: int,
    original_length: int,
    original_line: str,
    sanitized_line: str,
) -> None:
    before, after = build_replacement_preview(original_line, sanitized_line)
    report.add(rule, line_num, original_length, before=before, after=after)


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

    if (
        RE_PEM_PRIVATE_BEGIN.search(body)
        or RE_PEM_PRIVATE_END.search(body)
        or RE_PGP_PRIVATE_BEGIN.search(body)
        or RE_PGP_PRIVATE_END.search(body)
    ):
        sanitized = f"{config.redacted_token}{eol}"
        record_replacement(
            report,
            rule="value:pem_private",
            line_num=line_num,
            original_length=len(body),
            original_line=line,
            sanitized_line=sanitized,
        )
        return sanitized

    json_changed = False
    json_match_length = 0

    def redact_json_pair(match: re.Match[str]) -> str:
        nonlocal json_changed, json_match_length
        key = match.group("key")
        value = match.group("value")
        value_core = value.strip()
        if not is_sensitive_key(key, [], value_core, config):
            return match.group(0)
        replacement_core = preserve_quotes(value_core, config.redacted_token)
        json_changed = True
        json_match_length += len(value_core)
        return f"{match.group('prefix')}{replacement_core}"

    redacted_json = RE_JSON_INLINE_PAIR.sub(redact_json_pair, body)
    if json_changed:
        sanitized = redacted_json + eol
        record_replacement(
            report,
            rule="key:json_sensitive",
            line_num=line_num,
            original_length=json_match_length,
            original_line=line,
            sanitized_line=sanitized,
        )
        return sanitized
    if config.redact_certs and (RE_PEM_CERT_BEGIN.search(body) or RE_PEM_CERT_END.search(body)):
        sanitized = f"{config.redacted_token}{eol}"
        record_replacement(
            report,
            rule="value:pem_cert",
            line_num=line_num,
            original_length=len(body),
            original_line=line,
            sanitized_line=sanitized,
        )
        return sanitized
    if config.redact_public_keys and RE_SSH_PUBLIC.search(body):
        sanitized = f"{config.redacted_token}{eol}"
        record_replacement(
            report,
            rule="value:ssh_public",
            line_num=line_num,
            original_length=len(body),
            original_line=line,
            sanitized_line=sanitized,
        )
        return sanitized

    redacted_email, email_count, email_length = redact_emails(body, config)
    if email_count:
        sanitized = redacted_email + eol
        record_replacement(
            report,
            rule="value:email",
            line_num=line_num,
            original_length=email_length,
            original_line=line,
            sanitized_line=sanitized,
        )
        return sanitized

    redacted, count, length = redact_configured_domains(body, config)
    if count:
        sanitized = redacted + eol
        record_replacement(
            report,
            rule="value:configured_domain",
            line_num=line_num,
            original_length=length,
            original_line=line,
            sanitized_line=sanitized,
        )
        return sanitized
    return line


def sanitize_lines(
    lines: List[str],
    config: RedactionConfig,
    progress_callback: Optional[LineProgressCallback] = None,
) -> Tuple[List[str], FileReport]:
    report = FileReport()
    out: List[str] = []
    context_stack: List[Tuple[int, str]] = []

    total_lines = len(lines)
    if progress_callback is not None:
        progress_callback(0, total_lines)

    index = 0
    while index < len(lines):
        line_num = index + 1
        line = lines[index]
        line_mode = "yaml"
        match = RE_KEY_VALUE.match(line)
        if not match:
            match = RE_ASSIGNMENT.match(line)
            if match:
                line_mode = "assignment"
        if not match:
            out.append(sanitize_plain_line(line, line_num, report, config))
            index += 1
            if progress_callback is not None:
                progress_callback(index, total_lines)
            continue

        prefix = match.group("prefix")
        key = match.group("key")
        sep = match.group("sep")
        rest = match.group("rest")
        eol = match.group("eol")

        key_indent = 0
        parent_context: List[str] = []
        if line_mode == "yaml":
            key_indent = len(prefix) - len(prefix.lstrip(" "))
            while context_stack and context_stack[-1][0] >= key_indent:
                context_stack.pop()
            parent_context = [ctx_key for _, ctx_key in context_stack]

        value_part, comment_part = split_value_and_comment(rest)
        value_core = value_part.strip()

        key_sensitive = is_sensitive_key(key, parent_context, value_core, config)
        is_block = line_mode == "yaml" and bool(RE_BLOCK_MARKER.match(value_core))

        block_sensitive = key_sensitive
        if is_block and not block_sensitive:
            block_sensitive = block_looks_sensitive(lines, index, key_indent, config)

        if block_sensitive and is_block:
            new_line = f"{prefix}{key}{sep}\"{config.redacted_block_token}\""
            if comment_part:
                new_line += comment_part
            sanitized_line = new_line + eol
            out.append(sanitized_line)
            record_replacement(
                report,
                rule=(f"key_block:{key.lower()}" if key_sensitive else "value:block_pattern"),
                line_num=line_num,
                original_length=len(value_core),
                original_line=line,
                sanitized_line=sanitized_line,
            )

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
            if line_mode == "yaml":
                context_stack.append((key_indent, key.lower()))
            if progress_callback is not None:
                progress_callback(index, total_lines)
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
            sanitized_line = f"{prefix}{key}{sep}{new_value}{comment_part}{eol}"
            out.append(sanitized_line)
            record_replacement(
                report,
                rule=rule or "unknown",
                line_num=line_num,
                original_length=len(value_core),
                original_line=line,
                sanitized_line=sanitized_line,
            )
        else:
            redacted_value = value_part
            total_length = 0
            applied_rule: Optional[str] = None

            redacted_value, email_count, email_length = redact_emails(redacted_value, config)
            if email_count:
                total_length += email_length
                applied_rule = "value:email"

            redacted_value, count, length = redact_configured_domains(redacted_value, config)
            if count:
                total_length += length
                applied_rule = applied_rule or "value:configured_domain"

            if total_length > 0:
                sanitized_line = f"{prefix}{key}{sep}{redacted_value}{comment_part}{eol}"
                out.append(sanitized_line)
                record_replacement(
                    report,
                    rule=applied_rule or "value:pattern",
                    line_num=line_num,
                    original_length=total_length,
                    original_line=line,
                    sanitized_line=sanitized_line,
                )
            else:
                out.append(line)

        if line_mode == "yaml" and (value_core == "" or is_block):
            context_stack.append((key_indent, key.lower()))
        index += 1
        if progress_callback is not None:
            progress_callback(index, total_lines)

    if progress_callback is not None:
        progress_callback(total_lines, total_lines)

    return out, report


def sanitize_file(
    src: Path,
    dst: Path,
    config: RedactionConfig,
    dry_run: bool,
    progress_callback: Optional[ProgressRatioCallback] = None,
) -> FileReport:
    report = FileReport()

    if progress_callback is not None:
        progress_callback(0.0)

    try:
        if detect_binary(src):
            report.skipped = "binary"
            if progress_callback is not None:
                progress_callback(1.0)
            return report
    except OSError:
        report.skipped = "read_error"
        if progress_callback is not None:
            progress_callback(1.0)
        return report

    try:
        with src.open("r", encoding="utf-8", errors="surrogateescape", newline="") as file_obj:
            lines = file_obj.readlines()
    except OSError:
        report.skipped = "read_error"
        if progress_callback is not None:
            progress_callback(1.0)
        return report

    if progress_callback is not None:
        progress_callback(0.2)

    def line_progress(processed: int, total: int) -> None:
        if progress_callback is None:
            return
        if total <= 0:
            progress_callback(0.85)
            return
        ratio = 0.2 + (0.65 * (processed / total))
        progress_callback(max(0.2, min(0.85, ratio)))

    sanitized_lines, internal_report = sanitize_lines(lines, config, progress_callback=line_progress)
    report = internal_report

    if not dry_run:
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            with dst.open("w", encoding="utf-8", errors="surrogateescape", newline="") as file_obj:
                file_obj.writelines(sanitized_lines)
        except OSError:
            report.skipped = "write_error"
            if progress_callback is not None:
                progress_callback(1.0)
            return report

    if progress_callback is not None:
        progress_callback(1.0)
    return report


def suggested_output_file(source_file: Path) -> Path:
    return source_file.with_name(f"{source_file.stem}_sanitized{source_file.suffix}")


def sanitize_single_file(
    source_file: Path,
    config: RedactionConfig,
    *,
    dry_run: bool,
    output_file: Optional[Path] = None,
    progress_callback: Optional[ProgressRatioCallback] = None,
) -> RunResult:
    resolved_source = source_file.resolve()
    if not resolved_source.exists() or not resolved_source.is_file():
        raise ValueError(f"source_file is not a file: {resolved_source}")

    target = output_file.resolve() if output_file else suggested_output_file(resolved_source)
    report = sanitize_file(resolved_source, target, config, dry_run=dry_run, progress_callback=progress_callback)
    return RunResult(
        source_file=resolved_source,
        output_file=target,
        dry_run=dry_run,
        report=report,
    )


def has_io_errors(report: FileReport) -> bool:
    return report.skipped in {"read_error", "write_error", "stat_error"}


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

    sample = ["MY_PASSWORD=supersecret\n"]
    out, report = sanitize_lines(sample, config)
    assert out[0] == "MY_PASSWORD=<REDACTED>\n", out[0]
    assert report.replacements == 1

    sample = ['{"user":"alice","password":"supersecret"}\n']
    out, report = sanitize_lines(sample, config)
    assert out[0] == '{"user":"alice","password":"<REDACTED>"}\n', out[0]
    assert report.replacements == 1

    sample = ["email: user@example.com\n"]
    out, report = sanitize_lines(sample, config)
    assert out[0] == "email: <REDACTED>\n", out[0]
    assert report.replacements == 1

    print("Self-tests passed")
    return 0
