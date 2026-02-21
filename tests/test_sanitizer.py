from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sanitizer_core import RedactionConfig, parse_exts, run_self_tests, sanitize_directory, sanitize_lines


class SanitizerTests(unittest.TestCase):
    def test_sensitive_key_redaction(self) -> None:
        config = RedactionConfig(domains=["example.com"])
        out, report = sanitize_lines(["secret: super_secret\n"], config)
        self.assertEqual(out[0], "secret: <REDACTED>\n")
        self.assertEqual(report.replacements, 1)

    def test_configured_domain_redaction(self) -> None:
        config = RedactionConfig(domains=["example.com"])
        out, report = sanitize_lines(["site: api.example.com\n"], config)
        self.assertEqual(out[0], "site: <REDACTED>\n")
        self.assertEqual(report.replacements, 1)

    def test_unconfigured_domain_is_untouched(self) -> None:
        config = RedactionConfig(domains=["example.com"])
        out, report = sanitize_lines(["site: not-configured.example\n"], config)
        self.assertEqual(out[0], "site: not-configured.example\n")
        self.assertEqual(report.replacements, 0)

    def test_block_redaction(self) -> None:
        config = RedactionConfig(domains=[])
        lines = [
            "jwks:\n",
            "  - key: |\n",
            "      -----BEGIN PRIVATE KEY-----\n",
            "      content\n",
            "      -----END PRIVATE KEY-----\n",
            "  enabled: true\n",
        ]
        out, report = sanitize_lines(lines, config)
        self.assertIn("  - key: \"<REDACTED_BLOCK>\"\n", out)
        self.assertTrue(all("PRIVATE KEY" not in line for line in out))
        self.assertEqual(report.replacements, 1)

    def test_sanitize_directory_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "src"
            src.mkdir()
            (src / "app.yaml").write_text("site: example.com\nsecret: abc\n", encoding="utf-8")
            config = RedactionConfig(domains=["example.com"])
            result = sanitize_directory(
                source_dir=src,
                out_dir=None,
                config=config,
                exts=parse_exts(".yaml"),
                dry_run=False,
                max_size_mb=1.0,
            )
            sanitized_file = result.out_dir / "app.yaml"
            self.assertTrue(sanitized_file.exists())
            content = sanitized_file.read_text(encoding="utf-8")
            self.assertIn("site: <REDACTED>", content)
            self.assertIn("secret: <REDACTED>", content)
            self.assertTrue(result.report_path.exists())

    def test_self_test(self) -> None:
        self.assertEqual(run_self_tests(), 0)


if __name__ == "__main__":
    unittest.main()
