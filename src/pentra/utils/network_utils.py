"""Ağ yardımcı fonksiyonları — yerel subnet tespiti vb."""

from __future__ import annotations

import ipaddress
import socket


def get_local_ip() -> str | None:
    """Bu bilgisayarın yerel ağdaki IP'sini tespit eder.

    UDP socket'i kamuya yönlendirip (veri göndermeden) yerel uç IP'yi okur.
    Bu bir standart yöntem; gerçekten bağlanmaz, sadece OS'nin routing
    kararını sorar.

    Returns:
        Yerel IPv4 adresi (ör. "192.168.1.42") veya tespit edilemezse None.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Gerçekten bir paket gönderilmiyor — sadece OS routing tablosu kullanılıyor
        sock.settimeout(2.0)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        return str(ip)
    except (OSError, socket.timeout):
        return None
    finally:
        sock.close()


def guess_local_cidr(prefix_length: int = 24) -> str | None:
    """Yerel ağı `/24` varsayımıyla CIDR notasyonunda tahmin eder.

    Args:
        prefix_length: Varsayılan /24 (254 host). Küçük ofisler için
            doğru bir varsayım. Kurumsal /16 ağlar nadir evde.

    Returns:
        "192.168.1.0/24" gibi CIDR string'i veya None.
    """
    if not 8 <= prefix_length <= 30:
        raise ValueError(f"prefix_length 8-30 aralığında olmalı, verilen: {prefix_length}")

    local_ip = get_local_ip()
    if local_ip is None:
        return None

    try:
        # Host bit'lerini sıfırlayarak network adresini elde et
        interface = ipaddress.IPv4Interface(f"{local_ip}/{prefix_length}")
        return str(interface.network)
    except (ValueError, ipaddress.AddressValueError):
        return None


def is_valid_cidr(cidr: str) -> bool:
    """CIDR string'i geçerli IPv4 ağ mı kontrol eder (parse etmeden önce)."""
    try:
        ipaddress.ip_network(cidr.strip(), strict=False)
        return True
    except ValueError:
        return False
