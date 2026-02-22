#! /usr/bin/env python3
"""Build desktop GUI executables with PyInstaller for the current OS."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

APP_NAME = "ConfigSanitizer"


def run(cmd: list[str], cwd: Path) -> None:
    print(f"+ {' '.join(cmd)}")
    subprocess.run(cmd, cwd=str(cwd), check=True)


def clean(paths: list[Path]) -> None:
    for path in paths:
        if path.exists():
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()


def get_binary_target(dist_dir: Path, system_name: str) -> Path:
    if system_name == "Windows":
        return dist_dir / f"{APP_NAME}.exe"
    if system_name == "Darwin":
        return dist_dir / f"{APP_NAME}.app"
    return dist_dir / APP_NAME


def archive_target(target: Path, release_dir: Path) -> Path:
    system_name = platform.system()
    machine = platform.machine() or "unknown"
    archive_base = f"{APP_NAME}-{system_name.lower()}-{machine.lower()}"

    if system_name == "Windows":
        archive_path = release_dir / f"{archive_base}.zip"
        with zipfile.ZipFile(archive_path, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(target, arcname=target.name)
        return archive_path

    if system_name == "Darwin":
        archive_path = release_dir / f"{archive_base}.tar.gz"
        with tarfile.open(archive_path, mode="w:gz") as archive:
            archive.add(target, arcname=target.name)
        return archive_path

    archive_path = release_dir / f"{archive_base}.tar.gz"
    with tarfile.open(archive_path, mode="w:gz") as archive:
        archive.add(target, arcname=target.name)
    return archive_path


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    dist_dir = root / "dist"
    build_dir = root / "build"
    release_dir = root / "release"
    entrypoint = root / "sanitize_gui.py"

    if not entrypoint.exists():
        print(f"ERROR: entrypoint not found: {entrypoint}", file=sys.stderr)
        return 2

    clean([dist_dir, build_dir, root / f"{APP_NAME}.spec"])
    release_dir.mkdir(parents=True, exist_ok=True)

    system_name = platform.system()
    pyinstaller_cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--name",
        APP_NAME,
        "--windowed",
    ]

    # macOS users generally expect an .app bundle; Linux/Windows are simpler as single binaries.
    if system_name in {"Windows", "Linux"}:
        pyinstaller_cmd.append("--onefile")

    data_separator = ";" if system_name == "Windows" else ":"
    assets_dir = root / "assets"
    if assets_dir.exists():
        pyinstaller_cmd.extend(["--add-data", f"{assets_dir}{data_separator}assets"])

    pyinstaller_cmd.append(str(entrypoint))
    run(pyinstaller_cmd, cwd=root)

    binary_target = get_binary_target(dist_dir, system_name)
    if not binary_target.exists():
        print(f"ERROR: build output missing: {binary_target}", file=sys.stderr)
        return 3

    archive_path = archive_target(binary_target, release_dir)

    print(f"OS:            {system_name}")
    print(f"Built target:  {binary_target}")
    print(f"Release file:  {archive_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
