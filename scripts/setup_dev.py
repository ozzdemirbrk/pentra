"""Pentra dev ortamı kurulum otomasyonu.

Kullanım (proje kök dizininden):
    python scripts/setup_dev.py

Yaptıkları (sırasıyla):
    1. Python sürüm kontrolü (>= 3.11 olmalı)
    2. .venv sanal ortamını oluşturur (yoksa)
    3. pip'i günceller
    4. requirements-dev.txt kurulumunu yapar (üretim + geliştirme)
    5. pre-commit hook'larını kurar
    6. Sistem bağımlılıklarını (Nmap, Npcap) kontrol eder
    7. Bir sonraki adımları ekrana yazdırır

Not: Script yönetici yetkisi istemez; Npcap kurulumu elle yapılır.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path

MIN_PYTHON = (3, 11)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
VENV_DIR = PROJECT_ROOT / ".venv"
REQS_DEV = PROJECT_ROOT / "requirements-dev.txt"

# ANSI renkler (Windows Terminal ve modern cmd destekler)
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def ok(msg: str) -> None:
    print(f"{GREEN}✔{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}⚠{RESET} {msg}")


def fail(msg: str) -> None:
    print(f"{RED}✘{RESET} {msg}")


def header(msg: str) -> None:
    print(f"\n{BOLD}── {msg} ──{RESET}")


def check_python_version() -> None:
    """Python >= 3.11 kontrolü."""
    header("1/6 Python sürümü kontrol ediliyor")
    if sys.version_info < MIN_PYTHON:
        fail(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ gerekli, "
            f"bulunan: {sys.version_info.major}.{sys.version_info.minor}",
        )
        fail("Lütfen python.org'dan güncel sürümü kurun.")
        sys.exit(1)
    ok(f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")


def create_venv() -> None:
    """Sanal ortam oluştur (yoksa)."""
    header("2/6 Sanal ortam (.venv)")
    if VENV_DIR.exists():
        ok(f".venv mevcut: {VENV_DIR}")
        return
    try:
        subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
        ok(f".venv oluşturuldu: {VENV_DIR}")
    except subprocess.CalledProcessError as e:
        fail(f"venv oluşturma başarısız: {e}")
        sys.exit(1)


def venv_python() -> Path:
    """Venv içindeki python executable yolu."""
    if platform.system() == "Windows":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def upgrade_pip() -> None:
    """Venv içindeki pip'i günceller."""
    header("3/6 pip güncelleniyor")
    try:
        subprocess.run(
            [str(venv_python()), "-m", "pip", "install", "--upgrade", "pip"],
            check=True,
        )
        ok("pip güncel")
    except subprocess.CalledProcessError as e:
        fail(f"pip güncelleme başarısız: {e}")
        sys.exit(1)


def install_requirements() -> None:
    """requirements-dev.txt kur."""
    header("4/6 Bağımlılıklar kuruluyor (bu birkaç dakika sürebilir)")
    if not REQS_DEV.exists():
        fail(f"requirements-dev.txt bulunamadı: {REQS_DEV}")
        sys.exit(1)
    try:
        subprocess.run(
            [str(venv_python()), "-m", "pip", "install", "-r", str(REQS_DEV)],
            check=True,
        )
        ok("Tüm bağımlılıklar kuruldu")
    except subprocess.CalledProcessError as e:
        fail(f"Bağımlılık kurulumu başarısız: {e}")
        sys.exit(1)


def install_precommit() -> None:
    """pre-commit hook'larını kur."""
    header("5/6 pre-commit hook'ları")
    if not (PROJECT_ROOT / ".git").exists():
        warn("Git repo'su henüz başlatılmamış — pre-commit hook'ları atlanıyor.")
        warn("Git init yaptıktan sonra bu adımı elle çalıştırın:")
        warn("    .venv\\Scripts\\pre-commit install")
        return
    try:
        subprocess.run(
            [str(venv_python()), "-m", "pre_commit", "install"],
            check=True,
            cwd=PROJECT_ROOT,
        )
        ok("pre-commit hook'ları kuruldu")
    except subprocess.CalledProcessError as e:
        warn(f"pre-commit kurulumu başarısız: {e}")


def check_system_deps() -> None:
    """Sistem bağımlılıklarını kontrol et (sadece uyarı)."""
    header("6/6 Sistem bağımlılıkları kontrol ediliyor")

    if platform.system() != "Windows":
        warn("Pentra v1 yalnızca Windows üzerinde desteklenir. Diğer OS'larda")
        warn("geliştirme yapabilirsin ama kurulum-testler çalışmayabilir.")

    if shutil.which("nmap"):
        ok("Nmap kurulu")
    else:
        warn("Nmap bulunamadı. https://nmap.org/download.html adresinden kurun.")
        warn("Kurulum sonrası PATH'e eklendiğinden emin olun.")

    npcap_paths = [
        Path("C:/Windows/System32/Npcap"),
        Path("C:/Program Files/Npcap"),
    ]
    if any(p.exists() for p in npcap_paths):
        ok("Npcap kurulu görünüyor")
    else:
        warn("Npcap tespit edilemedi. https://npcap.com/ adresinden kurun.")
        warn("Scapy ham paket fonksiyonları Npcap olmadan çalışmaz.")


def print_next_steps() -> None:
    """Kurulum sonrası kullanıcı yönergeleri."""
    print()
    print(f"{BOLD}{'═' * 60}{RESET}")
    print(f"{BOLD}Kurulum tamamlandı! Sonraki adımlar:{RESET}")
    print(f"{BOLD}{'═' * 60}{RESET}")
    print()
    print("1. Sanal ortamı aktifleştir:")
    print(f"   {GREEN}.venv\\Scripts\\activate{RESET}")
    print()
    print("2. Smoke testi çalıştır (paket import edilebiliyor mu?):")
    print(f"   {GREEN}pytest tests/unit/test_smoke.py -v{RESET}")
    print()
    print("3. Uygulamayı çalıştır (şu an placeholder):")
    print(f"   {GREEN}python -m pentra{RESET}")
    print()


def main() -> int:
    print(f"{BOLD}Pentra — Geliştirme Ortamı Kurulumu{RESET}")
    print(f"Proje dizini: {PROJECT_ROOT}")

    check_python_version()
    create_venv()
    upgrade_pip()
    install_requirements()
    install_precommit()
    check_system_deps()
    print_next_steps()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
