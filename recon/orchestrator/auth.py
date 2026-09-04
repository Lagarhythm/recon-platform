"""Authentication service - single operator account, server-side sessions."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from recon.core.security import (
    generate_session_token,
    hash_password,
    hash_token,
    validate_password_strength,
    verify_password,
)
from recon.models.base import utcnow
from recon.models.user import Session, User


class AuthError(Exception):
    pass


class SetupAlreadyComplete(AuthError):
    pass


class AuthService:
    def __init__(self, idle_timeout_minutes: int = 60) -> None:
        self.idle_timeout = timedelta(minutes=idle_timeout_minutes)

    # --- First-run setup ------------------------------------------------
    async def needs_setup(self, session: AsyncSession) -> bool:
        count = (await session.execute(select(func.count()).select_from(User))).scalar_one()
        return int(count) == 0

    async def create_initial_admin(
        self, session: AsyncSession, username: str, password: str
    ) -> User:
        if not await self.needs_setup(session):
            raise SetupAlreadyComplete("an operator account already exists")
        username = username.strip().lower()
        if not username or len(username) > 64:
            raise AuthError("username must be 1-64 characters")
        validate_password_strength(password)
        user = User(username=username, password_hash=hash_password(password))
        session.add(user)
        await session.flush()
        return user

    # --- Login / sessions --------------------------------------------
    async def authenticate(
        self, session: AsyncSession, username: str, password: str
    ) -> User | None:
        username = username.strip().lower()
        user = (
            await session.execute(select(User).where(User.username == username))
        ).scalar_one_or_none()
        if user is None:
            # Uniform work factor even when the user does not exist.
            hash_password(password)
            return None
        ok, new_hash = verify_password(password, user.password_hash)
        if not ok:
            return None
        if new_hash:
            user.password_hash = new_hash
        user.last_login = utcnow()
        return user

    async def start_session(
        self,
        session: AsyncSession,
        user: User,
        *,
        user_agent: str | None = None,
        ip_address: str | None = None,
    ) -> str:
        raw = generate_session_token()
        now = utcnow()
        session.add(
            Session(
                user_id=user.id,
                token_hash=hash_token(raw),
                last_activity=now,
                expires_at=now + self.idle_timeout,
                user_agent=(user_agent or "")[:255] or None,
                ip_address=ip_address,
            )
        )
        await session.flush()
        return raw

    async def resolve_session(self, session: AsyncSession, raw_token: str) -> User | None:
        if not raw_token:
            return None
        row = (
            await session.execute(
                select(Session, User)
                .join(User, User.id == Session.user_id)
                .where(Session.token_hash == hash_token(raw_token))
            )
        ).first()
        if row is None:
            return None
        sess, user = row
        now = utcnow()
        if sess.revoked or sess.expires_at < now:
            return None
        # Sliding idle expiry.
        sess.last_activity = now
        sess.expires_at = now + self.idle_timeout
        return user

    async def end_session(self, session: AsyncSession, raw_token: str) -> None:
        if not raw_token:
            return
        sess = (
            await session.execute(
                select(Session).where(Session.token_hash == hash_token(raw_token))
            )
        ).scalar_one_or_none()
        if sess is not None:
            sess.revoked = True

    async def change_password(
        self, session: AsyncSession, user: User, old_password: str, new_password: str
    ) -> None:
        ok, _ = verify_password(old_password, user.password_hash)
        if not ok:
            raise AuthError("current password is incorrect")
        validate_password_strength(new_password)
        user.password_hash = hash_password(new_password)
        # Invalidate all other sessions for this user.
        for sess in (
            await session.execute(select(Session).where(Session.user_id == user.id))
        ).scalars():
            sess.revoked = True
