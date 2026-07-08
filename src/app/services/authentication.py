"""Authentication: password verification, re-authentication, and account lockout.

Three concerns, all about proving a local user is who they claim to be:

- verify_password() is the login path — looks up by email, verifies the
  argon2 hash. On success, rehashes the password if the argon2 parameters 
  are outdated. Returns the User on success, None on any failure. Failure 
  paths run a dummy verify to equalize timing and close the user-enumeration 
  side channel.

- verify_current_password() is the re-auth path — verifies by user ID,
  for sensitive in-session actions (e.g. email change). No timing
  defense needed because the actor's identity is already known.

- record_login_failure() / clear_login_failures()
  implement the failed-login counter with auto-lockout after N attempts.
  Threshold and duration come from settings.

Shibboleth accounts have no password_hash. All verification paths reject
them — those users authenticate against the IdP, not here.
"""
from datetime import datetime, timedelta, timezone
import logging

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from psycopg import sql
from psycopg_pool import AsyncConnectionPool
from starlette.concurrency import run_in_threadpool

from config import settings
from .db import get_db_cursor
from .users import User, parse_user, USER_COLUMNS_SQL

logger = logging.getLogger(__name__)

_ph = PasswordHasher()
_DUMMY_HASH = _ph.hash("this-is-a-dummy-password-for-constant-time-verification")

async def verify_password(
    pool: AsyncConnectionPool, email: str, password: str
) -> tuple[User | None, bool, datetime | None]:
    """Look up a user by email (single query) and verify a local password.

    Returns (user, password_ok, locked_until):
      - user:         the User if ANY account exists for this email (local or
                      Shibboleth, active or not), so the caller can log accurately
                      and decide whether lockout applies; None only if no account
                      has this email.
      - password_ok:  True only if the account is local, active, not locked, and
                      the password matches.
      - locked_until: lock expiry if a local account is currently locked, else None.

    Timing: every non-success path runs an equivalent dummy Argon2 verify, so wrong
    password / missing user / inactive / locked / non-local all take the same time
    (no user-enumeration oracle). The caller gates record_login_failure on
    `user.auth_method == "local"`.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL(
                "SELECT {}, password_hash, locked_until "
                "FROM users WHERE LOWER(email) = LOWER(%s)"
            ).format(USER_COLUMNS_SQL),
            (email,),
        )
        row = await cur.fetchone()

    if not row:
        await verify_dummy(password)
        return None, False, None

    user = parse_user(row)

    # Non-local (e.g. Shibboleth) or inactive → no local password login.
    if row["auth_method"] != "local" or not row["is_active"]:
        await verify_dummy(password)
        return user, False, None

    now = datetime.now(timezone.utc)
    locked_until = (
        row["locked_until"]
        if row["locked_until"] is not None and row["locked_until"] > now
        else None
    )

    if locked_until is not None:
        await verify_dummy(password)
        return user, False, locked_until

    if not row["password_hash"]:
        await verify_dummy(password)
        return user, False, None

    try:
        await run_in_threadpool(_ph.verify, row["password_hash"], password)
        password_ok = True
    except VerifyMismatchError:
        password_ok = False
    except (InvalidHashError, VerificationError):
        logger.error("Unverifiable password hash for user id=%s", row["id"])
        await verify_dummy(password)
        return user, False, None

    if password_ok and _ph.check_needs_rehash(row["password_hash"]):
        new_hash = await run_in_threadpool(_ph.hash, password)
        async with get_db_cursor(pool) as cur:
            await cur.execute(
                "UPDATE users SET password_hash = %s WHERE id = %s",
                (new_hash, row["id"]),
            )

    return user, password_ok, locked_until


async def verify_current_password(pool: AsyncConnectionPool, user_id: int, password: str) -> bool:
    """Verify a password against a user's stored hash, by user ID.

    Used to re-authenticate an already-logged-in user before a sensitive
    self-service action (e.g. changing their email). Distinct from
    verify_password(), which looks up by email and is the login path —
    here we already know who the user is and only need to confirm they
    can supply the current password.

    Returns False for non-local users, missing users, accounts with no
    password hash, or a wrong password. Returns True only on a match.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "SELECT password_hash, auth_method FROM users WHERE id = %s",
            (user_id,),
        )
        row = await cur.fetchone()

    if not row or row["auth_method"] != "local" or not row["password_hash"]:
        return False

    try:
        await run_in_threadpool(_ph.verify, row["password_hash"], password)
        return True
    except VerifyMismatchError:
        return False


async def verify_dummy(password: str) -> None:
    """Run argon2 verify against a dummy hash to equalize timing.

    Called on failure paths (user not found, wrong auth method, inactive)
    so the total time spent on a failed lookup matches the time spent
    on a real verify. This closes the timing side channel that would
    otherwise reveal whether an email belongs to an account.
    """
    try:
        await run_in_threadpool(_ph.verify, _DUMMY_HASH, password)
    except VerifyMismatchError:
        pass


async def record_login_failure(pool: AsyncConnectionPool, user_id: int) -> tuple[int, bool]:
    """Increment failure counter; lock account if threshold reached.
    
    Returns (new_count, was_locked_this_call). The boolean is True only
    when this specific call crossed the threshold — useful for audit
    log differentiation between "another failure" and "account just
    locked."
    """
    threshold = settings.login_failure_threshold
    lockout_duration = timedelta(minutes=settings.login_lockout_minutes)
    
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            UPDATE users
            SET failed_login_count = failed_login_count + 1,
                locked_until = CASE
                    WHEN failed_login_count + 1 >= %s
                    THEN CURRENT_TIMESTAMP + %s
                    ELSE locked_until
                END
            WHERE id = %s
            RETURNING failed_login_count, locked_until
            """,
            (threshold, lockout_duration, user_id),
        )
        row = await cur.fetchone()
        if not row:
            return 0, False
        new_count = row["failed_login_count"]
        was_locked_this_call = (new_count == threshold)
        return new_count, was_locked_this_call


async def clear_login_failures(pool: AsyncConnectionPool, user_id: int) -> None:
    """Reset failure counter and lock state.
    
    Called on successful login and on password reset completion.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            UPDATE users
            SET failed_login_count = 0, locked_until = NULL
            WHERE id = %s
            """,
            (user_id,),
        )


