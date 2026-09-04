"""Password hashing and session-token primitives.

Passwords: Argon2id via argon2-cffi (a strong modern KDF; NFR security).
Session tokens: 256-bit random, stored only as a SHA-256 hash so a DB read
does not yield a usable credential.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_hasher = PasswordHasher()

# Minimum password policy for the single operator account.
MIN_PASSWORD_LENGTH = 12


class WeakPasswordError(ValueError):
    pass


def validate_password_strength(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
    classes = [
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ]
    if sum(classes) < 3:
        raise WeakPasswordError(
            "Password must include at least three of: lowercase, uppercase, digit, symbol."
        )


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> tuple[bool, str | None]:
    """Returns (ok, new_hash_if_rehash_needed)."""
    try:
        _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False, None
    if _hasher.check_needs_rehash(password_hash):
        return True, _hasher.hash(password)
    return True, None


def generate_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
