"""Kapsam doğrulayıcı — bir hedefin taranabilir olup olmadığını karar verir.

Kurallar (CLAUDE.md § 2'den):
    - Loopback (127.0.0.0/8) → ALLOWED_PRIVATE
    - RFC1918 (10/8, 172.16/12, 192.168/16) → ALLOWED_PRIVATE
    - Multicast, link-local, rezerve, unspecified → DENIED (tarama yasak)
    - Dış (public) unicast → REQUIRES_CONFIRMATION (ek onay şart)
    - IPv6 → DENIED (v2'de desteklenecek)

URL hedeflerinde hostname DNS ile çözülür ve **en katı** kategori uygulanır.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from typing import TypeAlias
from urllib.parse import urlparse

from pentra.models import ScopeDecision, ScopeDecisionType, Target, TargetType

# ---------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------
_RFC1918_NETS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_LOOPBACK_NET: ipaddress.IPv4Network = ipaddress.IPv4Network("127.0.0.0/8")

# Çok büyük ağlar taranmaya izin verilmez (DoS + zaman kısıtı)
_MIN_PUBLIC_PREFIX: int = 24

# DNS çözümleme zaman aşımı (saniye)
_DNS_TIMEOUT_SEC: float = 5.0

DnsResolver: TypeAlias = Callable[[str], list[str]]


# ---------------------------------------------------------------------
# Varsayılan DNS çözümleyici
# ---------------------------------------------------------------------
def _default_dns_resolver(hostname: str) -> list[str]:
    """socket.getaddrinfo ile hostname → IP listesi (yalnızca IPv4)."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(_DNS_TIMEOUT_SEC)
    try:
        infos = socket.getaddrinfo(hostname, None, family=socket.AF_INET)
        # Eşsiz IP'leri koru
        return sorted({info[4][0] for info in infos})
    finally:
        socket.setdefaulttimeout(old_timeout)


# ---------------------------------------------------------------------
# Asıl sınıf
# ---------------------------------------------------------------------
class ScopeValidator:
    """Hedef kapsam doğrulayıcı.

    Testte DNS'i mock'lamak için `dns_resolver` parametresi enjekte edilebilir.
    """

    def __init__(self, dns_resolver: DnsResolver | None = None) -> None:
        self._resolve = dns_resolver if dns_resolver is not None else _default_dns_resolver

    # -----------------------------------------------------------------
    # Ana giriş noktası
    # -----------------------------------------------------------------
    def validate(self, target: Target) -> ScopeDecision:
        """Hedefi sınıflandır ve karar döndür.

        Karar zinciri: geçerli format? → hedef tipine göre sınıflandır.
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
    # Tek tek doğrulayıcılar
    # -----------------------------------------------------------------
    def _validate_localhost(self, target: Target) -> ScopeDecision:
        # Localhost tipi için değerin 127.0.0.0/8 içinde olması şart;
        # RFC1918 veya dış IP geçirilmişse DENIED.
        try:
            ip = ipaddress.ip_address(target.value)
        except ValueError:
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                f"Localhost hedefi için geçersiz IP: {target.value}",
                (target.value,),
            )
        if not isinstance(ip, ipaddress.IPv4Address) or ip not in _LOOPBACK_NET:
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                "Localhost hedefi 127.0.0.0/8 aralığında olmalı",
                (target.value,),
            )
        return ScopeDecision(
            ScopeDecisionType.ALLOWED_PRIVATE,
            target,
            "Loopback (bu bilgisayar)",
            (target.value,),
        )

    def _validate_wifi(self, target: Target) -> ScopeDecision:
        # Wi-Fi pasif listeleme — paket gönderilmez, sadece çevre dinlenir.
        # Her durumda izinli; ek onay gerekmez.
        return ScopeDecision(
            ScopeDecisionType.ALLOWED_PRIVATE,
            target,
            "Wi-Fi pasif taraması — dışarıya paket gönderilmez",
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
                f"Geçersiz CIDR formatı: {e}",
            )

        if isinstance(net, ipaddress.IPv6Network):
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                "IPv6 ağları henüz desteklenmiyor (v2'de gelecek)",
            )

        # Tamamen RFC1918 veya loopback içinde mi?
        if _is_entirely_private(net):
            return ScopeDecision(
                ScopeDecisionType.ALLOWED_PRIVATE,
                target,
                f"Özel ağ aralığı ({net})",
                (str(net.network_address),),
            )

        # Çok büyük dış ağlara izin yok (ör. /8 public → milyonlarca IP)
        if net.prefixlen < _MIN_PUBLIC_PREFIX:
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                f"Ağ çok büyük (/{net.prefixlen}) — dış hedef için en fazla /{_MIN_PUBLIC_PREFIX}",
                (str(net.network_address),),
            )

        # Ağ rezerve/multicast aralıklarına değiyor mu? → DENIED
        first_decision, first_reason = _classify_ipv4(str(net.network_address))
        if first_decision == ScopeDecisionType.DENIED:
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                f"Ağ rezerve/multicast alanına düşüyor: {first_reason}",
                (str(net.network_address),),
            )

        return ScopeDecision(
            ScopeDecisionType.REQUIRES_CONFIRMATION,
            target,
            "Dış (public) IP aralığı — sahiplik veya yazılı yetki gerekir",
            (str(net.network_address),),
        )

    def _validate_url(self, target: Target) -> ScopeDecision:
        parsed = urlparse(target.value)

        # Şema zorunlu + sadece http/https kabul ediliyor
        if parsed.scheme not in ("http", "https"):
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                "URL şeması http veya https olmalı",
            )

        hostname = parsed.hostname
        if not hostname:
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                "URL'den hostname çıkarılamadı",
            )

        # Hostname zaten IP olabilir
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
                    f"Hostname çözümlenemedi ({hostname}): {e}",
                )

        if not resolved:
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                f"Hostname hiçbir IP'ye çözümlenmedi: {hostname}",
            )

        # Tüm çözülen IP'leri sınıflandır, en katı kategoriyi uygula
        decisions = [_classify_ipv4(ip) for ip in resolved]
        any_denied = any(d == ScopeDecisionType.DENIED for d, _ in decisions)
        any_external = any(d == ScopeDecisionType.REQUIRES_CONFIRMATION for d, _ in decisions)

        if any_denied:
            denied_reason = next(r for d, r in decisions if d == ScopeDecisionType.DENIED)
            return ScopeDecision(
                ScopeDecisionType.DENIED,
                target,
                f"Çözülen IP'lerden en az biri yasak aralıkta: {denied_reason}",
                tuple(resolved),
            )

        if any_external:
            return ScopeDecision(
                ScopeDecisionType.REQUIRES_CONFIRMATION,
                target,
                f"URL dış (public) IP'ye çözümleniyor ({', '.join(resolved)}) — yetki gerekir",
                tuple(resolved),
            )

        return ScopeDecision(
            ScopeDecisionType.ALLOWED_PRIVATE,
            target,
            f"URL özel ağdaki IP'ye çözümleniyor ({', '.join(resolved)})",
            tuple(resolved),
        )


# ---------------------------------------------------------------------
# Yardımcı: IPv4 sınıflandırma
# ---------------------------------------------------------------------
def _classify_ipv4(ip_str: str) -> tuple[ScopeDecisionType, str]:
    """Tek bir IP'yi (string) kategoriye ayırır."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return (ScopeDecisionType.DENIED, f"Geçersiz IP adresi: {ip_str}")

    if isinstance(ip, ipaddress.IPv6Address):
        return (ScopeDecisionType.DENIED, "IPv6 henüz desteklenmiyor (v2'de gelecek)")

    if ip in _LOOPBACK_NET:
        return (ScopeDecisionType.ALLOWED_PRIVATE, "Loopback (bu bilgisayar)")

    if any(ip in net for net in _RFC1918_NETS):
        return (ScopeDecisionType.ALLOWED_PRIVATE, "Özel ağ (RFC1918)")

    if ip.is_multicast:
        return (ScopeDecisionType.DENIED, "Multicast adresi — tarama yapılamaz")

    if ip.is_link_local:
        return (ScopeDecisionType.DENIED, "Link-local adresi (169.254/16)")

    if ip.is_unspecified:
        return (ScopeDecisionType.DENIED, "0.0.0.0 geçerli bir hedef değil")

    # Limited broadcast — is_reserved'den ÖNCE kontrol et (255.255.255.255 is_reserved=True)
    if str(ip) == "255.255.255.255":
        return (ScopeDecisionType.DENIED, "Sınırlı broadcast adresi")

    if ip.is_reserved:
        return (ScopeDecisionType.DENIED, "Rezerve IP aralığı")

    return (
        ScopeDecisionType.REQUIRES_CONFIRMATION,
        "Dış (public) IP — sahiplik/yetki onayı gerekir",
    )


def _is_entirely_private(net: ipaddress.IPv4Network) -> bool:
    """Bir IPv4 ağının tamamı RFC1918 veya loopback içinde mi."""
    if net.subnet_of(_LOOPBACK_NET):
        return True
    return any(net.subnet_of(private) for private in _RFC1918_NETS)
