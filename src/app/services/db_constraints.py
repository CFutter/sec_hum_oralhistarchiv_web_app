"""Identify the case-insensitive users-email uniqueness constraint."""

from psycopg.errors import UniqueViolation

USERS_EMAIL_UNIQUE_CONSTRAINT = "idx_users_email_lower"


def is_users_email_collision(exc: UniqueViolation) -> bool:
    """Return whether the violation names the users-email unique index."""
    return exc.diag.constraint_name == USERS_EMAIL_UNIQUE_CONSTRAINT
