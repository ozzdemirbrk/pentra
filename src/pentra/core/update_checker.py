"""Check for a new release on GitHub Releases.

Runs on a background QThread. If a new version exists it emits the
`update_available` signal; the UI connects to it and shows a small notice.

Design decisions:
    - Silently skipped when offline (keeps the app's offline-friendly principle)
    - 5-second timeout — doesn't delay the user
    - Pre-release versions are excluded (only stable releases count)
    - Defensive parsing against malformed responses
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QThread, Signal

from pentra import __github_repo__, __version__

_GITHUB_API_URL: str = f"https://api.github.com/repos/{__github_repo__}/releases/latest"
_TIMEOUT_SEC: float = 5.0
_USER_AGENT: str = f"Pentra/{__version__} (update-check)"


class UpdateChecker(QThread):
    """Queries the GitHub Releases API in the background.

    Usage::

        checker = UpdateChecker()
        checker.update_available.connect(on_update)
        checker.start()
    """

    #: Emitted with (new_version, release_url)
    update_available = Signal(str, str)

    #: Emitted on error (for logging — the UI does not show this)
    check_failed = Signal(str)

    def run(self) -> None:  # Qt's expected name
        # Lazy import — keeps the thread quiet when requests isn't available
        try:
            import requests
        except ImportError:
            self.check_failed.emit("requests library not available")
            return

        try:
            response = requests.get(
                _GITHUB_API_URL,
                timeout=_TIMEOUT_SEC,
                headers={"User-Agent": _USER_AGENT, "Accept": "application/vnd.github+json"},
            )
        except requests.RequestException as e:
            # Offline / DNS failure / timeout — skip silently
            self.check_failed.emit(f"Network error: {e}")
            return

        if response.status_code != 200:
            self.check_failed.emit(f"HTTP {response.status_code}")
            return

        try:
            data: dict[str, Any] = response.json()
        except ValueError:
            self.check_failed.emit("Invalid JSON")
            return

        latest_tag: str = str(data.get("tag_name", "")).lstrip("vV")
        html_url: str = str(data.get("html_url", ""))
        prerelease: bool = bool(data.get("prerelease", False))

        if not latest_tag or not html_url:
            self.check_failed.emit("tag_name or html_url missing")
            return

        if _is_newer(latest_tag, __version__, allow_prerelease=prerelease):
            self.update_available.emit(latest_tag, html_url)


def _is_newer(
    remote: str, local: str, *, allow_prerelease: bool = False,
) -> bool:
    """Return True if remote > local.

    - Uses `packaging.version.Version` (PEP 440 compliant)
    - If versions can't be compared (exotic tag), the safe default is False
    - With `allow_prerelease=False`, pre-release remotes don't count as updates
    """
    try:
        from packaging.version import InvalidVersion, Version
    except ImportError:
        return False

    try:
        remote_ver = Version(remote)
        local_ver = Version(local)
    except InvalidVersion:
        return False

    if remote_ver.is_prerelease and not allow_prerelease:
        # Remote is a pre-release; don't suggest to users on stable
        if not local_ver.is_prerelease:
            return False

    return remote_ver > local_ver
