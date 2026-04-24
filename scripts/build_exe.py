"""Pentra'yı PyInstaller ile tek dosyalık Windows .exe olarak paketler.

Kullanım:
    python scripts/build_exe.py              # Normal build
    python scripts/build_exe.py --clean      # build/ + dist/ temizleyip başla

Çıktı:
    dist/Pentra.exe   (~150-200 MB, tek dosya)

Bundle edilen datalar:
    - src/pentra/i18n/locales/*.json       → pentra/i18n/locales/
    - src/pentra/reporting/templates/*.j2  → pentra/reporting/templates/
    - public/logo/Pentra.png (rapor logosu) → public/logo/
    - resources/icons/pentra.ico           → .exe ikonu olarak
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------
# Yollar
# ---------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).parent.parent.resolve()
ENTRY_POINT: Path = PROJECT_ROOT / "src" / "pentra" / "__main__.py"
ICON_PATH: Path = PROJECT_ROOT / "resources" / "icons" / "pentra.ico"
BUILD_DIR: Path = PROJECT_ROOT / "build"
DIST_DIR: Path = PROJECT_ROOT / "dist"
SPEC_FILE: Path = PROJECT_ROOT / "Pentra.spec"

APP_NAME: str = "Pentra"


def _ensure_icon() -> None:
    """Icon yoksa create_icon.py'yi çalıştır."""
    if ICON_PATH.exists():
        return
    print(f"[INFO] {ICON_PATH} yok — create_icon.py çalıştırılıyor...")
    subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "create_icon.py")],
        check=True,
        cwd=PROJECT_ROOT,
    )


def _clean() -> None:
    for path in (BUILD_DIR, DIST_DIR, SPEC_FILE):
        if path.is_dir():
            shutil.rmtree(path)
            print(f"[CLEAN] {path} silindi")
        elif path.is_file():
            path.unlink()
            print(f"[CLEAN] {path} silindi")


def _build_pyinstaller_args() -> list[str]:
    """PyInstaller komut satırı argümanlarını hazırlar."""
    sep = ";"  # Windows PyInstaller data ayracı (Linux/macOS ':')
    if sys.platform != "win32":
        sep = ":"

    # --add-data "SRC<sep>DEST" — destination bundle içindeki göreceli yol
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
        # Lazy import'larla bulunmayan modüller için explicit hint
        "--hidden-import", "pentra.knowledge.remediations_tr",
        "--hidden-import", "pentra.knowledge.remediations_en",
        # PySide6 SVG / image formatları için
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
    print(f"[BUILD] PyInstaller çalıştırılıyor...")
    print(f"        {' '.join(args)}")
    print()

    result = subprocess.run(args, cwd=PROJECT_ROOT, check=False)
    if result.returncode != 0:
        print(f"[HATA] PyInstaller başarısız (exit code: {result.returncode})", file=sys.stderr)
        return result.returncode

    exe_path = DIST_DIR / f"{APP_NAME}.exe"
    if not exe_path.exists():
        print(f"[HATA] Beklenen .exe oluşmadı: {exe_path}", file=sys.stderr)
        return 1

    size_mb = exe_path.stat().st_size / 1024 / 1024
    print()
    print(f"[OK] {exe_path} oluşturuldu ({size_mb:.1f} MB)")
    print(f"     Çalıştırmak için: {exe_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
