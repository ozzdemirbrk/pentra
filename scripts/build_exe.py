"""Package Pentra as a single-file Windows .exe with PyInstaller.

Usage:
    python scripts/build_exe.py              # Normal build
    python scripts/build_exe.py --clean      # Clean build/ + dist/ first

Output:
    dist/Pentra.exe   (~150-200 MB, single file)

Bundled data:
    - src/pentra/i18n/locales/*.json       -> pentra/i18n/locales/
    - src/pentra/reporting/templates/*.j2  -> pentra/reporting/templates/
    - public/logo/Pentra.png (report logo) -> public/logo/
    - resources/icons/pentra.ico           -> embedded as the .exe icon
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).parent.parent.resolve()
ENTRY_POINT: Path = PROJECT_ROOT / "src" / "pentra" / "__main__.py"
ICON_PATH: Path = PROJECT_ROOT / "resources" / "icons" / "pentra.ico"
BUILD_DIR: Path = PROJECT_ROOT / "build"
DIST_DIR: Path = PROJECT_ROOT / "dist"
SPEC_FILE: Path = PROJECT_ROOT / "Pentra.spec"

APP_NAME: str = "Pentra"


def _ensure_icon() -> None:
    """Run create_icon.py if the icon doesn't exist yet."""
    if ICON_PATH.exists():
        return
    print(f"[INFO] {ICON_PATH} missing — running create_icon.py...")
    subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "create_icon.py")],
        check=True,
        cwd=PROJECT_ROOT,
    )


def _clean() -> None:
    for path in (BUILD_DIR, DIST_DIR, SPEC_FILE):
        if path.is_dir():
            shutil.rmtree(path)
            print(f"[CLEAN] {path} removed")
        elif path.is_file():
            path.unlink()
            print(f"[CLEAN] {path} removed")


def _build_pyinstaller_args() -> list[str]:
    """Build the PyInstaller command-line arguments."""
    sep = ";"  # PyInstaller data separator on Windows (Linux/macOS uses ':')
    if sys.platform != "win32":
        sep = ":"

    # --add-data "SRC<sep>DEST" — destination is the relative path inside the bundle
    data_pairs: list[tuple[Path, str]] = [
        (PROJECT_ROOT / "src" / "pentra" / "i18n" / "locales", "pentra/i18n/locales"),
        (PROJECT_ROOT / "src" / "pentra" / "reporting" / "templates", "pentra/reporting/templates"),
        (PROJECT_ROOT / "public" / "logo" / "Pentra.png", "public/logo"),
    ]

    add_data_args: list[str] = []
    for src, dest in data_pairs:
        add_data_args.extend(["--add-data", f"{src}{sep}{dest}"])

    args: list[str] = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name", APP_NAME,
        "--icon", str(ICON_PATH),
        "--clean",
        # Explicit hints for lazily imported modules PyInstaller can miss
        "--hidden-import", "pentra.knowledge.remediations_tr",
        "--hidden-import", "pentra.knowledge.remediations_en",
        # PySide6 SVG / image format plugins
        "--collect-submodules", "PySide6",
        *add_data_args,
        str(ENTRY_POINT),
    ]
    return args


def main() -> int:
    clean = "--clean" in sys.argv[1:]

    if clean:
        _clean()

    _ensure_icon()

    args = _build_pyinstaller_args()
    print(f"[BUILD] Running PyInstaller...")
    print(f"        {' '.join(args)}")
    print()

    result = subprocess.run(args, cwd=PROJECT_ROOT, check=False)
    if result.returncode != 0:
        print(f"[ERROR] PyInstaller failed (exit code: {result.returncode})", file=sys.stderr)
        return result.returncode

    exe_path = DIST_DIR / f"{APP_NAME}.exe"
    if not exe_path.exists():
        print(f"[ERROR] Expected .exe was not produced: {exe_path}", file=sys.stderr)
        return 1

    size_mb = exe_path.stat().st_size / 1024 / 1024
    print()
    print(f"[OK] {exe_path} created ({size_mb:.1f} MB)")
    print(f"     Run with: {exe_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
