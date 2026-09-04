"""API token service - bearer credentials for the CLI / REST client (PRD 8.4).

The dashboard could expose these too (an "API tokens" settings page); the logic
lives here, not in the CLI, so both clients share one implementation.
"""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from recon.core.security import generate_api_token, hash_token
from recon.models.apitoken import ApiToken
from recon.models.base import utcnow
from recon.models.user import User


class TokenError(Exception):
    pass


class TokenNotFound(TokenError):
    pass


class TokenService:
    async def create(
        self, session: AsyncSession, user: User, name: str
    ) -> tuple[ApiToken, str]:
        """Mint a token for ``user``. Returns (row, raw_token); the raw token is
        the only time the secret is available."""
        name = (name or "").strip()
        if not name or len(name) > 100:
            raise TokenError("token name must be 1-100 characters")
        raw = generate_api_token()
        token = ApiToken(user_id=user.id, name=name, token_hash=hash_token(raw))
        session.add(token)
        await session.flush()
        return token, raw

    async def list(self, session: AsyncSession, user: User) -> Sequence[ApiToken]:
        return (
            await session.execute(
                select(ApiToken)
                .where(ApiToken.user_id == user.id)
                .order_by(ApiToken.created_at.desc())
            )
        ).scalars().all()

    async def revoke(self, session: AsyncSession, user: User, token_id: str) -> ApiToken:
        token = await session.get(ApiToken, token_id)
        if token is None or token.user_id != user.id:
            raise TokenNotFound(token_id)
        if token.revoked_at is None:
            token.revoked_at = utcnow()
        return token

    async def authenticate(self, session: AsyncSession, raw_token: str) -> User | None:
        """Resolve a bearer token to its owner, or None. Bumps ``last_used``."""
        if not raw_token:
            return None
        row = (
            await session.execute(
                select(ApiToken, User)
                .join(User, User.id == ApiToken.user_id)
                .where(ApiToken.token_hash == hash_token(raw_token))
            )
        ).first()
        if row is None:
            return None
        token, user = row
        if token.revoked_at is not None:
            return None
        token.last_used = utcnow()
        return user


token_service = TokenService()
