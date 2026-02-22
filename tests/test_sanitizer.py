from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sanitizer_core import RedactionConfig, run_self_tests, sanitize_lines, sanitize_single_file, suggested_output_file


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

    def test_replacement_logs_are_masked(self) -> None:
        config = RedactionConfig(domains=[])
        out, report = sanitize_lines(["secret: very_sensitive_value_123\n"], config)
        self.assertEqual(out[0], "secret: <REDACTED>\n")
        self.assertEqual(report.replacements, 1)
        self.assertTrue(report.logs)
        self.assertIn("*", report.logs[0].before)

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

    def test_env_style_password_assignment(self) -> None:
        config = RedactionConfig(domains=[])
        out, report = sanitize_lines(["MY_PASSWORD=supersecret\n"], config)
        self.assertEqual(out[0], "MY_PASSWORD=<REDACTED>\n")
        self.assertEqual(report.replacements, 1)

    def test_ini_style_password_assignment(self) -> None:
        config = RedactionConfig(domains=[])
        out, report = sanitize_lines(["db.password = ultra_secret\n"], config)
        self.assertEqual(out[0], "db.password = <REDACTED>\n")
        self.assertEqual(report.replacements, 1)

    def test_camel_case_password_key(self) -> None:
        config = RedactionConfig(domains=[])
        out, report = sanitize_lines(["dbPassword: supersecret\n"], config)
        self.assertEqual(out[0], "dbPassword: <REDACTED>\n")
        self.assertEqual(report.replacements, 1)

    def test_json_password_redaction(self) -> None:
        config = RedactionConfig(domains=[])
        out, report = sanitize_lines(['{"user":"alice","password":"supersecret"}\n'], config)
        self.assertEqual(out[0], '{"user":"alice","password":"<REDACTED>"}\n')
        self.assertEqual(report.replacements, 1)

    def test_email_value_redaction(self) -> None:
        config = RedactionConfig(domains=[])
        out, report = sanitize_lines(["email: user@example.com\n"], config)
        self.assertEqual(out[0], "email: <REDACTED>\n")
        self.assertEqual(report.replacements, 1)

    def test_email_in_plain_text_redaction(self) -> None:
        config = RedactionConfig(domains=[])
        out, report = sanitize_lines(["Contact: user@example.com for support\n"], config)
        self.assertEqual(out[0], "Contact: <REDACTED> for support\n")
        self.assertEqual(report.replacements, 1)

    def test_email_in_json_redaction(self) -> None:
        config = RedactionConfig(domains=[])
        out, report = sanitize_lines(['{"owner":"user@example.com","env":"prod"}\n'], config)
        self.assertEqual(out[0], '{"owner":"<REDACTED>","env":"prod"}\n')
        self.assertEqual(report.replacements, 1)

    def test_gpg_passphrase_key_redaction(self) -> None:
        config = RedactionConfig(domains=[])
        out, report = sanitize_lines(["gpg_passphrase: topsecret\n"], config)
        self.assertEqual(out[0], "gpg_passphrase: <REDACTED>\n")
        self.assertEqual(report.replacements, 1)

    def test_pgp_private_block_redaction(self) -> None:
        config = RedactionConfig(domains=[])
        lines = [
            "credentials:\n",
            "  key: |\n",
            "    -----BEGIN PGP PRIVATE KEY BLOCK-----\n",
            "    abcdef\n",
            "    -----END PGP PRIVATE KEY BLOCK-----\n",
            "  enabled: true\n",
        ]
        out, report = sanitize_lines(lines, config)
        self.assertIn('  key: "<REDACTED_BLOCK>"\n', out)
        self.assertTrue(all("PGP PRIVATE KEY BLOCK" not in line for line in out))
        self.assertEqual(report.replacements, 1)

    def test_sanitize_single_file_writes_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = Path(tmpdir) / "app.yaml"
            source_file.write_text("site: example.com\nsecret: abc\n", encoding="utf-8")
            config = RedactionConfig(domains=["example.com"])
            result = sanitize_single_file(
                source_file=source_file,
                config=config,
                dry_run=False,
            )
            sanitized_file = result.output_file
            self.assertTrue(sanitized_file.exists())
            content = sanitized_file.read_text(encoding="utf-8")
            self.assertIn("site: <REDACTED>", content)
            self.assertIn("secret: <REDACTED>", content)
            self.assertEqual(result.report.replacements, 2)

    def test_sanitize_single_file_reports_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = Path(tmpdir) / "app.yaml"
            source_file.write_text("site: example.com\nsecret: abc\n", encoding="utf-8")
            config = RedactionConfig(domains=["example.com"])
            progress_values: list[float] = []

            sanitize_single_file(
                source_file=source_file,
                config=config,
                dry_run=True,
                progress_callback=progress_values.append,
            )

            self.assertTrue(progress_values)
            self.assertAlmostEqual(progress_values[0], 0.0, places=2)
            self.assertAlmostEqual(progress_values[-1], 1.0, places=2)

    def test_suggested_output_file(self) -> None:
        source_file = Path("/tmp/config.yaml")
        self.assertEqual(suggested_output_file(source_file), Path("/tmp/config_sanitized.yaml"))

    def test_self_test(self) -> None:
        self.assertEqual(run_self_tests(), 0)


if __name__ == "__main__":
    unittest.main()
