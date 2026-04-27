"""Scope validator — decides whether a target may be scanned.

Rules (from CLAUDE.md section 2):
    - Loopback (127.0.0.0/8) -> ALLOWED_PRIVATE
    - RFC1918 (10/8, 172.16/12, 192.168/16) -> ALLOWED_PRIVATE
    - Multicast, link-local, reserved, unspecified -> DENIED (scanning forbidden)
    - External (public) unicast -> REQUIRES_CONFIRMATION (extra consent required)
    - IPv6 -> DENIED (will arrive in v2)

For URL targets the hostname is resolved via DNS and the **strictest** category wins.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from typing import TypeAlias
from urllib.parse import urlparse

from pentra.models import ScopeDecision, ScopeDecisionType, Target, TargetType

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------
_RFC1918_NETS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_LOOPBACK_NET: ipaddress.IPv4Network = ipaddress.IPv4Network("127.0.0.0/8")

# Very large networks are not allowed (DoS risk + time constraints)
_MIN_PUBLIC_PREFIX: int = 24

# DNS resolution timeout (seconds)
_DNS_TIMEOUT_SEC: float = 5.0

DnsResolver: TypeAlias = Callable[[str], list[str]]


# ---------------------------------------------------------------------
# Default DNS resolver
# ---------------------------------------------------------------------
def _default_dns_resolver(hostname: str) -> list[str]:
    """Resolve hostname to IP list via socket.getaddrinfo (IPv4 only)."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(_DNS_TIMEOUT_SEC)
    try:
        infos = socket.getaddrinfo(hostname, None, family=socket.AF_INET)
        # Keep unique IPs only
        return sorted({info[4][0] for info in infos})
    finally:
        socket.setdefaulttimeout(old_timeout)


# ---------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------
class ScopeValidator:
    """Target scope validator.

    A `dns_resolver` parameter can be injected to mock DNS in tests.
    """

    def __init__(self, dns_resolver: DnsResolver | None = None) -> None:
        self._resolve = dns_resolver if dns_resolver is not None else _default_dns_resolver

    # -----------------------------------------------------------------
    # Main entry point
    # -----------------------------------------------------------------
    def validate(self, target: Target) -> ScopeDecision:
        """Classify the target and return a decision.

        Decision chain: valid format? -> classify by target type.
        """
        match target.target_type:
            case TargetType.LOCALHOST:
                return self._validate_localhost(target)
            case TargetType.WIFI:
                return self._validate_wifi(target)
            case TargetType.IP_SINGLE:
                return self._validate_single_ip(target)
            case TargetType.IP_RANGE | TargetType.LOCAL_NETWORK:
                return self._validate_cidr(target)
            case TargetType.URL:
                return self._validate_url(target)

    # -----------------------------------------------------------------
    # Per-type validators
    # -----------------------------------------------------------------
    def _validate_localhost(self, target: Target) -> ScopeDecision:
        # For the localhost type the value must lie inside 127.0.0.0/8;
        # passing an RFC1918 or external IP yields DENIED.
        try:
            ip = ipaddress.ip_address(target.value)
        except ValueError:
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                f"Invalid IP for localhost target: {target.value}",
                (target.value,),
            )
        if not isinstance(ip, ipaddress.IPv4Address) or ip not in _LOOPBACK_NET:
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                "Localhost target must be within 127.0.0.0/8",
                (target.value,),
            )
        return ScopeDecision(
            ScopeDecisionType.ALLOWED_PRIVATE,
            target,
            "Loopback (this computer)",
            (target.value,),
        )

    def _validate_wifi(self, target: Target) -> ScopeDecision:
        # Passive Wi-Fi listing — no packets are sent, only the environment is observed.
        # Always allowed; no extra consent needed.
        return ScopeDecision(
            ScopeDecisionType.ALLOWED_PRIVATE,
            target,
            "Passive Wi-Fi scan — no packets are transmitted",
        )

    def _validate_single_ip(self, target: Target) -> ScopeDecision:
        decision, reason = _classify_ipv4(target.value)
        return ScopeDecision(decision, target, reason, (target.value,))

    def _validate_cidr(self, target: Target) -> ScopeDecision:
        try:
            net = ipaddress.ip_network(target.value, strict=False)
        except ValueError as e:
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                f"Invalid CIDR format: {e}",
            )

        if isinstance(net, ipaddress.IPv6Network):
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                "IPv6 networks are not yet supported (planned for v2)",
            )

        # Is the whole network inside RFC1918 or loopback?
        if _is_entirely_private(net):
            return ScopeDecision(
                ScopeDecisionType.ALLOWED_PRIVATE,
                target,
                f"Private network range ({net})",
                (str(net.network_address),),
            )

        # No very large external networks allowed (e.g. /8 public -> millions of IPs)
        if net.prefixlen < _MIN_PUBLIC_PREFIX:
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                f"Network too large (/{net.prefixlen}) — external targets are capped at /{_MIN_PUBLIC_PREFIX}",
                (str(net.network_address),),
            )

        # Does the network touch reserved/multicast ranges? -> DENIED
        first_decision, first_reason = _classify_ipv4(str(net.network_address))
        if first_decision == ScopeDecisionType.DENIED:
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                f"Network falls into a reserved/multicast range: {first_reason}",
                (str(net.network_address),),
            )

        return ScopeDecision(
            ScopeDecisionType.REQUIRES_CONFIRMATION,
            target,
            "External (public) IP range — ownership or written authorization required",
            (str(net.network_address),),
        )

    def _validate_url(self, target: Target) -> ScopeDecision:
        parsed = urlparse(target.value)

        # Scheme is required and only http/https are accepted
        if parsed.scheme not in ("http", "https"):
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                "URL scheme must be http or https",
            )

        hostname = parsed.hostname
        if not hostname:
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                "Could not extract hostname from URL",
            )

        # Hostname may already be an IP
        try:
            ipaddress.ip_address(hostname)
            resolved: list[str] = [hostname]
        except ValueError:
            try:
                resolved = self._resolve(hostname)
            except (OSError, socket.gaierror) as e:
                return ScopeDecision(
                    ScopeDecisionType.DENIED,
                    target,
                    f"Hostname could not be resolved ({hostname}): {e}",
                )

        if not resolved:
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                f"Hostname did not resolve to any IP: {hostname}",
            )

        # Classify every resolved IP and apply the strictest category
        decisions = [_classify_ipv4(ip) for ip in resolved]
        any_denied = any(d == ScopeDecisionType.DENIED for d, _ in decisions)
        any_external = any(d == ScopeDecisionType.REQUIRES_CONFIRMATION for d, _ in decisions)

        if any_denied:
            denied_reason = next(r for d, r in decisions if d == ScopeDecisionType.DENIED)
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                f"At least one resolved IP is in a forbidden range: {denied_reason}",
                tuple(resolved),
            )

        if any_external:
            return ScopeDecision(
                ScopeDecisionType.REQUIRES_CONFIRMATION,
                target,
                f"URL resolves to an external (public) IP ({', '.join(resolved)}) — authorization required",
                tuple(resolved),
            )

        return ScopeDecision(
            ScopeDecisionType.ALLOWED_PRIVATE,
            target,
            f"URL resolves to a private-network IP ({', '.join(resolved)})",
            tuple(resolved),
        )


# ---------------------------------------------------------------------
# Helper: IPv4 classification
# ---------------------------------------------------------------------
def _classify_ipv4(ip_str: str) -> tuple[ScopeDecisionType, str]:
    """Classify a single IP (string) into a category."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return (ScopeDecisionType.DENIED, f"Invalid IP address: {ip_str}")

    if isinstance(ip, ipaddress.IPv6Address):
        return (ScopeDecisionType.DENIED, "IPv6 not yet supported (planned for v2)")

    if ip in _LOOPBACK_NET:
        return (ScopeDecisionType.ALLOWED_PRIVATE, "Loopback (this computer)")

    if any(ip in net for net in _RFC1918_NETS):
        return (ScopeDecisionType.ALLOWED_PRIVATE, "Private network (RFC1918)")

    if ip.is_multicast:
        return (ScopeDecisionType.DENIED, "Multicast address — scanning forbidden")

    if ip.is_link_local:
        return (ScopeDecisionType.DENIED, "Link-local address (169.254/16)")

    if ip.is_unspecified:
        return (ScopeDecisionType.DENIED, "0.0.0.0 is not a valid target")

    # Limited broadcast — check this BEFORE is_reserved (255.255.255.255 is_reserved=True)
    if str(ip) == "255.255.255.255":
        return (ScopeDecisionType.DENIED, "Limited broadcast address")

    if ip.is_reserved:
        return (ScopeDecisionType.DENIED, "Reserved IP range")

    return (
        ScopeDecisionType.REQUIRES_CONFIRMATION,
        "External (public) IP — ownership/authorization required",
    )


def _is_entirely_private(net: ipaddress.IPv4Network) -> bool:
    """Check whether an IPv4 network is entirely inside RFC1918 or loopback."""
    if net.subnet_of(_LOOPBACK_NET):
        return True
    return any(net.subnet_of(private) for private in _RFC1918_NETS)
