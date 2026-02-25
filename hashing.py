#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

PASSLIB_AVAILABLE = False
try:
    from passlib.context import CryptContext  # type: ignore
    from passlib.registry import get_crypt_handler  # type: ignore
    PASSLIB_AVAILABLE = True
except Exception:
    PASSLIB_AVAILABLE = False

CRYPT_AVAILABLE = False
try:
    import crypt  # type: ignore
    CRYPT_AVAILABLE = True
except Exception:
    CRYPT_AVAILABLE = False


class HashVerifier(Protocol):
    def verify(self, candidate: str) -> bool: ...


@dataclass
class PasslibVerifier:
    ctx: "CryptContext"
    full_hash: str

    def verify(self, candidate: str) -> bool:
        try:
            candidate_bytes = candidate.encode("utf-8")

            # bcrypt hard limit
            if len(candidate_bytes) > 72:
                return False

            return self.ctx.verify(candidate, self.full_hash)

        except Exception:
            return False


@dataclass
class CryptVerifier:
    full_hash: str

    def verify(self, candidate: str) -> bool:
        return crypt.crypt(candidate, self.full_hash) == self.full_hash  # type: ignore


def detect_algorithm_name(full_hash: str) -> str:
    if full_hash.startswith("$1$"):
        return "md5_crypt"
    if full_hash.startswith("$5$"):
        return "sha256_crypt"
    if full_hash.startswith("$6$"):
        return "sha512_crypt"
    if full_hash.startswith("$2a$") or full_hash.startswith("$2b$") or full_hash.startswith("$2y$"):
        return "bcrypt"
    if full_hash.startswith("$y$"):
        return "yescrypt"
    return "unknown"


def _passlib_has_scheme(name: str) -> bool:
    if not PASSLIB_AVAILABLE:
        return False
    try:
        get_crypt_handler(name)
        return True
    except KeyError:
        return False


def build_verifier(full_hash: str) -> HashVerifier:
    algo = detect_algorithm_name(full_hash)

    if PASSLIB_AVAILABLE:

        candidates = ["bcrypt", "sha512_crypt", "sha256_crypt", "md5_crypt", "yescrypt"]
        schemes = [s for s in candidates if _passlib_has_scheme(s)]

        if algo in schemes or algo in ("md5_crypt", "sha256_crypt", "sha512_crypt", "bcrypt"):
            ctx = CryptContext(schemes=schemes, deprecated="auto")
            return PasslibVerifier(ctx=ctx, full_hash=full_hash)

        if algo == "yescrypt" and CRYPT_AVAILABLE:
            return CryptVerifier(full_hash=full_hash)

    if CRYPT_AVAILABLE:
        return CryptVerifier(full_hash=full_hash)

    raise RuntimeError(
        f"No supported verifier available for algorithm '{algo}'. "
        "Install/enable passlib handlers or use a platform with crypt() support."
    )
