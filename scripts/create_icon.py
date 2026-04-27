"""Convert the Pentra logo (PNG) into a Windows .ico file.

Uses Pillow. Produces a single .ico containing multiple sizes
(16, 32, 48, 64, 128, 256) — suitable for Windows Explorer, the taskbar,
and .exe metadata.

Usage:
    python scripts/create_icon.py

Output:
    resources/icons/pentra.ico
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("[ERROR] Pillow is not installed. Install with: pip install Pillow", file=sys.stderr)
    sys.exit(1)


SOURCE_PNG: Path = Path("public") / "logo" / "Pentra.png"
OUTPUT_ICO: Path = Path("resources") / "icons" / "pentra.ico"
SIZES: list[tuple[int, int]] = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]


def main() -> int:
    if not SOURCE_PNG.exists():
        print(f"[ERROR] Source PNG not found: {SOURCE_PNG}", file=sys.stderr)
        return 1

    OUTPUT_ICO.parent.mkdir(parents=True, exist_ok=True)

    image = Image.open(SOURCE_PNG).convert("RGBA")
    # A single save() call produces a multi-size .ico
    image.save(
        OUTPUT_ICO,
        format="ICO",
        sizes=SIZES,
    )

    out_size_kb = OUTPUT_ICO.stat().st_size / 1024
    print(f"[OK] {OUTPUT_ICO} created ({out_size_kb:.1f} KB, {len(SIZES)} sizes).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
