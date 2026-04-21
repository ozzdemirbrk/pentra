"""Yetki yöneticisi — tarama başlamadan önceki son bariyer.

Kullanıcı sihirbazda onay verdikten sonra `AuthorizationRequest` oluşturulur.
`AuthorizationManager.grant()` bu isteği doğrulayıp HMAC imzalı bir
`AuthorizationToken` döndürür. Her `Scanner` paket göndermeden önce
bu token'ın `verify()` kontrolünden geçmesini sağlar.

Token özellikleri:
    - HMAC-SHA256 imzalı (sahtecilik koruması)
    - Hedefe bağlı (hash eşleşmesi zorunlu — A token'ı B hedefine geçmez)
    - TTL'li (varsayılan 30 dk)
    - Tek oturumluk session secret ile imzalı (uygulama yeniden başlarsa
      eski token'lar otomatik geçersiz)
    - İptal edilebilir (scan bitince revoke edilir)
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from collections.abc import Callable

from pentra.models import (
    AuthorizationRequest,
    AuthorizationToken,
    ScopeDecision,
    Target,
)


# ---------------------------------------------------------------------
# Hata sınıfları
# ---------------------------------------------------------------------
class AuthorizationError(Exception):
    """Yetkilendirme sürecindeki genel hata sınıfı."""


class AuthorizationDenied(AuthorizationError):
    """Kullanıcı onayı veya kapsam kontrolü reddedildi."""


class InvalidToken(AuthorizationError):
    """Token sahte, bozuk veya süresi dolmuş."""


# ---------------------------------------------------------------------
# Dahili meta
# ---------------------------------------------------------------------
@dataclasses.dataclass
class _IssuedTokenInfo:
    """Verilmiş token için tutulan bilgiler (iptal + inceleme için)."""

    target_hash: str
    granted_at: int
    ttl_sec: int


# ---------------------------------------------------------------------
# AuthorizationManager
# ---------------------------------------------------------------------
class AuthorizationManager:
    """Tarama yetki belgeleri (token) üreten ve doğrulayan merkezi sınıf.

    Secret parametresi `None` ise her uygulama başlangıcında rastgele üretilir
    (os.urandom). Böylece önceki oturumun token'ları tekrar kullanılamaz.
    """

    def __init__(
        self,
        secret: bytes | None = None,
        ttl_sec: int = 30 * 60,
        time_func: Callable[[], float] | None = None,
    ) -> None:
        if secret is not None and len(secret) < 16:
            raise ValueError("secret en az 16 bayt olmalı")
        if ttl_sec <= 0:
            raise ValueError(f"ttl_sec pozitif olmalı, verilen: {ttl_sec}")

        self._secret: bytes = secret if secret is not None else os.urandom(32)
        self._ttl: int = ttl_sec
        self._time: Callable[[], float] = time_func if time_func is not None else time.time

        self._issued: dict[str, _IssuedTokenInfo] = {}
        self._revoked: set[str] = set()
        self._lock = threading.Lock()

    # -----------------------------------------------------------------
    # Ana API
    # -----------------------------------------------------------------
    def grant(
        self,
        request: AuthorizationRequest,
        scope_decision: ScopeDecision,
    ) -> AuthorizationToken:
        """İstek geçerliyse yetki token'ı döndürür; aksi halde hata atar.

        Kontroller:
            1. Kullanıcı ana onay kutusunu işaretledi mi
            2. ScopeValidator hedefi reddetmedi mi
            3. Ek onay gereken hedefte kullanıcı ekstra onay verdi mi
            4. Hedef eşleşiyor mu (istek hedefi = scope kararının hedefi)
        """
        if not request.user_accepted_terms:
            raise AuthorizationDenied(
                "Kullanıcı yetki onay ekranını doğrulamadı — tarama başlatılamaz",
            )

        if scope_decision.target != request.target:
            raise AuthorizationDenied(
                "Scope kararı ile yetki isteği farklı hedeflere işaret ediyor",
            )

        if scope_decision.is_denied:
            raise AuthorizationDenied(
                f"Hedef tarama için uygun değil: {scope_decision.reason}",
            )

        if scope_decision.needs_confirmation and not request.external_target_confirmed:
            raise AuthorizationDenied(
                "Dış (public) hedef için ek kullanıcı onayı gereklidir",
            )

        # Geçerli istek — token üret
        return self._issue_token(request.target)

    def verify(self, token: AuthorizationToken, target: Target) -> bool:
        """Token geçerli ve belirtilen hedefe ait mi."""
        try:
            payload = self._decode_payload(token)
        except (InvalidToken, ValueError):
            return False

        # İmza kontrol (constant-time)
        expected_sig = self._sign(self._payload_bytes(token))
        if not hmac.compare_digest(expected_sig, token.signature):
            return False

        # TTL
        now = int(self._time())
        if now > payload["granted_at"] + payload["ttl_sec"]:
            return False

        # Hedef hash eşleşmesi
        if payload["target_hash"] != hash_target(target):
            return False

        # İptal kontrolü
        with self._lock:
            if payload["token_id"] in self._revoked:
                return False

        return True

    def revoke(self, token: AuthorizationToken | str) -> None:
        """Token'ı iptal et. Parametre ya AuthorizationToken ya token_id string."""
        token_id = token.token_id if isinstance(token, AuthorizationToken) else token
        with self._lock:
            self._revoked.add(token_id)

    # -----------------------------------------------------------------
    # İç
    # -----------------------------------------------------------------
    def _issue_token(self, target: Target) -> AuthorizationToken:
        token_id = str(uuid.uuid4())
        target_hash = hash_target(target)
        granted_at = int(self._time())

        payload = {
            "token_id": token_id,
            "target_hash": target_hash,
            "granted_at": granted_at,
            "ttl_sec": self._ttl,
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii")
        signature = self._sign(payload_bytes)

        with self._lock:
            self._issued[token_id] = _IssuedTokenInfo(
                target_hash=target_hash,
                granted_at=granted_at,
                ttl_sec=self._ttl,
            )

        return AuthorizationToken(
            token_id=token_id,
            payload=payload_b64,
            signature=signature,
        )

    def _sign(self, payload_bytes: bytes) -> str:
        return hmac.new(self._secret, payload_bytes, hashlib.sha256).hexdigest()

    @staticmethod
    def _payload_bytes(token: AuthorizationToken) -> bytes:
        try:
            return base64.urlsafe_b64decode(token.payload.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as e:
            raise InvalidToken(f"Token payload çözümlenemedi: {e}") from e

    def _decode_payload(self, token: AuthorizationToken) -> dict[str, object]:
        raw = self._payload_bytes(token)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise InvalidToken(f"Token JSON geçersiz: {e}") from e

        required_keys = {"token_id", "target_hash", "granted_at", "ttl_sec"}
        if not required_keys.issubset(data.keys()):
            raise InvalidToken("Token payload eksik alanlar içeriyor")

        return data


# ---------------------------------------------------------------------
# Yardımcı: Target hash
# ---------------------------------------------------------------------
def hash_target(target: Target) -> str:
    """Bir Target'ın kanonik SHA256 kısa özeti.

    Token payload'unda tam IP/URL saklamak yerine hash tutarız — denetim
    logları insan gözüyle okunurken rastgele veriler görünmez.
    """
    data = f"{target.target_type.value}|{target.value}".encode("utf-8")
    return hashlib.sha256(data).hexdigest()[:32]
