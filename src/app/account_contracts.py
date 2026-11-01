"""Code-owned eligibility predicates shared by account mutation boundaries.

These fragments contain no runtime input; callers bind identity/capability
values and retain their own transaction and post-lock checks.
"""

from typing import Final

PENDING_ACCOUNT_PREDICATE: Final = """
    auth_method = 'local' AND password_hash IS NULL
    AND NOT is_active AND NOT email_verified AND NOT is_admin
    AND totp_secret IS NULL AND totp_recovery_code_generation = 0
    AND NOT totp_recovery_required
"""
