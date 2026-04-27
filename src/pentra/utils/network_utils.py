"""Network helper functions — local subnet detection and the like."""

from __future__ import annotations

import ipaddress
import socket


def get_local_ip() -> str | None:
    """Detect this computer's IP on the local network.

    Points a UDP socket at a public address (without sending data) and reads
    back the local endpoint IP. This is a standard trick; it doesn't really
    connect, it just asks the OS for its routing decision.

    Returns:
        Local IPv4 address (e.g. "192.168.1.42") or None when undetectable.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No packet is actually sent — only the OS routing table is consulted
        sock.settimeout(2.0)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        return str(ip)
    except (TimeoutError, OSError):
        return None
    finally:
        sock.close()


def guess_local_cidr(prefix_length: int = 24) -> str | None:
    """Guess the local network in CIDR notation using a `/24` assumption.

    Args:
        prefix_length: Default /24 (254 hosts). A reasonable assumption for
            small offices. Enterprise /16 networks are rare at home.

    Returns:
        CIDR string like "192.168.1.0/24", or None.
    """
    if not 8 <= prefix_length <= 30:
        raise ValueError(f"prefix_length must be in range 8-30, got: {prefix_length}")

    local_ip = get_local_ip()
    if local_ip is None:
        return None

    try:
        # Zero the host bits to get the network address
        interface = ipaddress.IPv4Interface(f"{local_ip}/{prefix_length}")
        return str(interface.network)
    except (ValueError, ipaddress.AddressValueError):
        return None


def is_valid_cidr(cidr: str) -> bool:
    """Check whether a CIDR string parses as a valid IPv4 network."""
    try:
        ipaddress.ip_network(cidr.strip(), strict=False)
        return True
    except ValueError:
        return False
