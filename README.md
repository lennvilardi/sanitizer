# Config Sanitizer

![Sanitize Logo](assets/sanitize-logo.svg)

Sanitize YAML/text configuration files while keeping the original formatting as much as possible.

## Features

- Redacts sensitive keys (`password`, `secret`, `token`, `api_key`, etc.)
- Redacts token-like values (JWT, long hex/base64, bearer tokens, URL credentials)
- Redacts private key material and optional certificate/public key data
- Redacts user-defined domain names (no hardcoded company domain)
- Provides:
  - CLI (`sanitizer-cli` / `python sanitize.py`)
  - GUI (`sanitizer-gui` / `python sanitize_gui.py`)
- Generates `sanitizer_report.json` with all replacements

## Install

```bash
python -m pip install .
```

## Usage (CLI)

```bash
python sanitize.py /path/to/source \
  --domain example.com \
  --domain internal.example.com \
  --out /path/to/output \
  --verbose
```

You can also pass domains in one argument:

```bash
python sanitize.py /path/to/source --domains "example.com,internal.example.com"
```

Useful flags:

- `--dry-run`: do not write sanitized files, only JSON report
- `--redact-certs`: redact certificate blocks
- `--redact-public-keys`: redact SSH public keys
- `--ext`: custom extensions, example `.yaml,.yml,.env`
- `--max-size-mb`: skip files larger than the threshold

## Usage (GUI)

```bash
python sanitize_gui.py
```

1. Select source directory
1. Optionally set output directory
1. Enter domains to redact (`domain1.com,domain2.com`)
1. Click `Run sanitizer`

The GUI works on macOS, Windows, and Linux with Python + Tk installed.

## Build Desktop Executables

This project includes a PyInstaller builder for GUI executables.

## Logo Variants and Exports

Generate flat-design logo variants and exports:

```bash
python scripts/generate_logo_assets.py
```

Generated files:

- SVG variants: `assets/logo/variants/`
- PNG exports: `assets/logo/png/<variant>/`
- ICO exports: `assets/logo/ico/`
- Windows installer icon: `packaging/assets/config-sanitizer.ico`

Install build dependencies:

```bash
python -m pip install .[packaging]
```

Build for your current OS:

```bash
python scripts/build_executable.py
```

Output files:

- Built app/binary: `dist/`
- Distributable archive: `release/`

Expected artifacts by platform:

- Windows: `ConfigSanitizer.exe` inside `.zip`
- macOS: `ConfigSanitizer.app` inside `.tar.gz`
- Linux: `ConfigSanitizer` inside `.tar.gz`

End users can extract and double-click the app/binary, no terminal needed.

## Auto-Build for Windows/macOS/Linux (GitHub Actions)

Workflow file:

- `.github/workflows/build-executables.yml`

Trigger options:

- Manual run (`workflow_dispatch`)
- Automatic on git tag push (`v*`, for example `v0.1.0`)

Each run uploads three artifacts (Windows/macOS/Linux) in GitHub Actions.

## Self-test

```bash
python sanitize.py --self-test
```

## Publish to PyPI

```bash
python -m pip install build twine
python -m build
python -m twine check dist/*
python -m twine upload dist/*
```

## Notes for Distribution

- macOS: unsigned apps can show Gatekeeper warnings until code-signed/notarized.
- Windows: unsigned `.exe` can trigger SmartScreen warnings.
- Linux: ensure executable bit is preserved after extraction (`chmod +x ConfigSanitizer` if needed).

## Security Note

Before publishing:

1. Run tests and self-tests
1. Scan repository content for accidental secrets
1. Confirm no private data in sample files or report artifacts
