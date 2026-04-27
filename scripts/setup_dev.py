"""Pentra dev environment setup automation.

Usage (from the project root):
    python scripts/setup_dev.py

What it does (in order):
    1. Python version check (must be >= 3.11)
    2. Creates the .venv virtual environment (if missing)
    3. Upgrades pip
    4. Installs requirements-dev.txt (production + development)
    5. Installs pre-commit hooks
    6. Checks system dependencies (Nmap, Npcap)
    7. Prints next steps to the screen

Note: the script does not require admin rights; Npcap must be installed manually.
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

# ANSI colours (Windows Terminal and modern cmd support these)
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def ok(msg: str) -> None:
    print(f"{GREEN}\u2714{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}\u26a0{RESET} {msg}")


def fail(msg: str) -> None:
    print(f"{RED}\u2718{RESET} {msg}")


def header(msg: str) -> None:
    print(f"\n{BOLD}\u2500\u2500 {msg} \u2500\u2500{RESET}")


def check_python_version() -> None:
    """Check Python >= 3.11."""
    header("1/6 Checking Python version")
    if sys.version_info < MIN_PYTHON:
        fail(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ required, "
            f"found: {sys.version_info.major}.{sys.version_info.minor}",
        )
        fail("Please install a current version from python.org.")
        sys.exit(1)
    ok(f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")


def create_venv() -> None:
    """Create the virtual environment (if missing)."""
    header("2/6 Virtual environment (.venv)")
    if VENV_DIR.exists():
        ok(f".venv already exists: {VENV_DIR}")
        return
    try:
        subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
        ok(f".venv created: {VENV_DIR}")
    except subprocess.CalledProcessError as e:
        fail(f"venv creation failed: {e}")
        sys.exit(1)


def venv_python() -> Path:
    """Path to the python executable inside the venv."""
    if platform.system() == "Windows":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def upgrade_pip() -> None:
    """Upgrade pip inside the venv."""
    header("3/6 Upgrading pip")
    try:
        subprocess.run(
            [str(venv_python()), "-m", "pip", "install", "--upgrade", "pip"],
            check=True,
        )
        ok("pip is up to date")
    except subprocess.CalledProcessError as e:
        fail(f"pip upgrade failed: {e}")
        sys.exit(1)


def install_requirements() -> None:
    """Install requirements-dev.txt."""
    header("4/6 Installing dependencies (this may take a few minutes)")
    if not REQS_DEV.exists():
        fail(f"requirements-dev.txt not found: {REQS_DEV}")
        sys.exit(1)
    try:
        subprocess.run(
            [str(venv_python()), "-m", "pip", "install", "-r", str(REQS_DEV)],
            check=True,
        )
        ok("All dependencies installed")
    except subprocess.CalledProcessError as e:
        fail(f"Dependency installation failed: {e}")
        sys.exit(1)


def install_precommit() -> None:
    """Install pre-commit hooks."""
    header("5/6 pre-commit hooks")
    if not (PROJECT_ROOT / ".git").exists():
        warn("Git repository not yet initialized — skipping pre-commit hooks.")
        warn("After running git init, run this step manually:")
        warn("    .venv\\Scripts\\pre-commit install")
        return
    try:
        subprocess.run(
            [str(venv_python()), "-m", "pre_commit", "install"],
            check=True,
            cwd=PROJECT_ROOT,
        )
        ok("pre-commit hooks installed")
    except subprocess.CalledProcessError as e:
        warn(f"pre-commit installation failed: {e}")


def check_system_deps() -> None:
    """Check system dependencies (warning only)."""
    header("6/6 Checking system dependencies")

    if platform.system() != "Windows":
        warn("Pentra v1 only supports Windows. You can develop on other OSes")
        warn("but installation tests may not work.")

    if shutil.which("nmap"):
        ok("Nmap is installed")
    else:
        warn("Nmap not found. Install from https://nmap.org/download.html.")
        warn("Make sure it is added to PATH after installation.")

    npcap_paths = [
        Path("C:/Windows/System32/Npcap"),
        Path("C:/Program Files/Npcap"),
    ]
    if any(p.exists() for p in npcap_paths):
        ok("Npcap appears to be installed")
    else:
        warn("Npcap not detected. Install from https://npcap.com/.")
        warn("Scapy raw-packet features won't work without Npcap.")


def print_next_steps() -> None:
    """Post-install user guidance."""
    print()
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}Setup complete! Next steps:{RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}")
    print()
    print("1. Activate the virtual environment:")
    print(f"   {GREEN}.venv\\Scripts\\activate{RESET}")
    print()
    print("2. Run the smoke test (can the package be imported?):")
    print(f"   {GREEN}pytest tests/unit/test_smoke.py -v{RESET}")
    print()
    print("3. Run the application:")
    print(f"   {GREEN}python -m pentra{RESET}")
    print()


def main() -> int:
    print(f"{BOLD}Pentra \u2014 Development Environment Setup{RESET}")
    print(f"Project directory: {PROJECT_ROOT}")

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
