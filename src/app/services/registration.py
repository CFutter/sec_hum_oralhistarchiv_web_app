"""Commit a new account, verification capability and durable email together."""

from typing import Any

from psycopg import AsyncCursor
from psycopg.errors import UniqueViolation
from psycopg_pool import AsyncConnectionPool

from config import settings

from .crypto import password_hasher
from .db import get_db_cursor
from .db_constraints import is_users_email_collision
from .email import build_verification_email
from .email_outbox import enqueue_outbound_email_cur
from .email_verification import (
    generate_verification_token,
    store_verification_token_hash_cur,
    verification_token_email_metadata,
)
from .password_validation import validate_password_strength
from .password_work import run_password_work
from .users import User, UserAlreadyExistsError, insert_unverified_local_user_cur


async def queue_verification_email_cur(cur: AsyncCursor[Any], user: User) -> None:
    """Store a fresh verification-token hash and queue its email transactionally.

    The caller owns the transaction. Existing verification mail is cancelled;
    ValueError means the account is absent, verified, or its email changed.
    """
    token = generate_verification_token(user.id, user.email)
    action = verification_token_email_metadata(token)
    message = build_verification_email(
        user.email,
        f"{settings.public_base_url}/verify-email/{token}",
        expires_at=action.expires_at,
    )
    await store_verification_token_hash_cur(
        cur,
        user.id,
        action.token_hash,
        expected_email=user.email,
    )
    await enqueue_outbound_email_cur(cur, user_id=user.id, email=message, action=action)


async def register_local_user(
    pool: AsyncConnectionPool,
    *,
    email: str,
    display_name: str,
    password: str,
    affiliation: str | None = None,
    country: str | None = None,
) -> User:
    """Commit an unverified local user and queued verification email together.

    Validate password strength, hash off-thread, and normalize email/display
    name through insert_unverified_local_user_cur. Raise ValueError for invalid
    profile/password values or UserAlreadyExistsError for an email collision;
    other database/outbox failures propagate and roll back account creation.
    """
    if error := validate_password_strength(password, email=email, display_name=display_name):
        raise ValueError(error)
    password_hash = await run_password_work(password_hasher.hash, password)
    try:
        async with get_db_cursor(pool) as cur:
            user = await insert_unverified_local_user_cur(
                cur,
                email=email,
                display_name=display_name,
                password_hash=password_hash,
                affiliation=affiliation,
                country=country,
            )
            await queue_verification_email_cur(cur, user)
        return user
    except UniqueViolation as exc:
        if is_users_email_collision(exc):
            raise UserAlreadyExistsError(email) from exc
        raise
