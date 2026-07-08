"""Service layer — re-exports database, sync, user, and session operations."""
from .access_tiers import AccessTier

from .cache import FacetCache

from .datasets import (
    Dataset,
    Author,
    search_datasets,
    get_recent_datasets,
    get_dataset_by_id,
    get_facets,
    get_last_full_rebuild_date,
    get_keyword_count,
    can_view_full,
    filter_for_tier,
    validate_dataset_schema,
    validate_dataset_insert_schema,
    assert_redaction_total
)

from .db import (
    get_db_cursor, 
    create_pool
)

from .db_drift import validate_schema_against_db

from .sync import (
    run_sync, 
    run_full_rebuild, 
)

from .sessions import (
    SessionPurpose,
    create_session, 
    delete_session,
    delete_user_sessions,
    get_session_user,
    cleanup_expired_sessions,
    upgrade_session_purpose,
    set_flash,
    consume_flash
)

from .scheduler import create_scheduler


from .users import (
    UserAlreadyExistsError,
    DISPLAY_NAME_MAX_LENGTH,
    get_user_by_id, 
    get_user_by_email,
    create_local_user, 
    create_shibboleth_user,
    update_last_login, 
    update_access_tier, 
    update_display_name,
    get_all_users, 
    set_user_active, 
    set_user_admin,
    validate_user_schema,
    normalize_display_name
)

from .authentication import (
    verify_password, 
    clear_login_failures,
    record_login_failure,
    verify_current_password,
    verify_dummy
)

from .totp import (
    TotpDecryptionError,
    get_totp_secret, 
    update_totp_secret,
    store_pending_totp_secret, 
    get_pending_totp_secret,
    generate_totp_secret,
    verify_and_consume_totp,
    matched_step
)

from .password_reset import (
    generate_reset_token, 
    validate_reset_token,
    update_password_with_token,
    store_reset_token_hash, 
    verify_reset_token_hash
)

from .password_validation import validate_password_strength

from .email_verification import (
    generate_verification_token, 
    store_verification_token_hash, 
    validate_verification_token, 
    confirm_email_verification
)

from .seed_admin import seed_admin_user

from .email import (
    send_email, 
    send_password_reset_email, 
    send_verification_email,
    send_email_change_verification,
    send_email_change_notice,
    send_duplicate_registration_notice,
    verify_smtp_tls,
    send_account_locked_notice
)

from .email_change import (
    generate_email_change_token,
    validate_email_change_token,
    store_pending_email,
    confirm_email_change,
    pending_email_change_matches,
    normalize_email
)

from .tokens import hash_token

from .audit import audit_admin_action, audit_user_event
from .crypto import audit_email_hash 


__all__ = [
    "SessionPurpose",
    "AccessTier",
    "UserAlreadyExistsError",
    "DISPLAY_NAME_MAX_LENGTH",
    "Author",
    "Dataset",
    "FacetCache",
    "TotpDecryptionError",
    "assert_redaction_total",
    "audit_admin_action",
    "audit_email_hash",
    "audit_user_event",
    "can_view_full",
    "cleanup_expired_sessions",
    "clear_login_failures",
    "confirm_email_change",
    "confirm_email_verification",
    "consume_flash",
    "create_local_user",
    "create_pool",
    "create_scheduler",
    "create_session",
    "create_shibboleth_user",
    "delete_session",
    "delete_user_sessions",
    "filter_for_tier",
    "generate_email_change_token",
    "generate_reset_token",
    "generate_totp_secret",
    "generate_verification_token",
    "get_all_users",
    "get_dataset_by_id",
    "get_db_cursor",
    "get_facets",
    "verify_password", 
    "get_last_full_rebuild_date",
    "get_keyword_count",
    "get_pending_totp_secret",
    "get_recent_datasets",
    "get_session_user",
    "get_totp_secret",
    "get_user_by_email",
    "get_user_by_id",
    "hash_token",
    "matched_step",
    "normalize_display_name",
    "normalize_email",
    "pending_email_change_matches",
    "record_login_failure",
    "run_full_rebuild",
    "run_sync",
    "search_datasets",
    "seed_admin_user",
    "send_account_locked_notice",
    "send_duplicate_registration_notice",
    "send_email",
    "send_email_change_notice",
    "send_email_change_verification",
    "send_password_reset_email",
    "send_verification_email",
    "set_flash",
    "set_user_active",
    "set_user_admin",
    "store_pending_email",
    "store_pending_totp_secret",
    "store_reset_token_hash",
    "store_verification_token_hash",
    "update_access_tier",
    "update_display_name",
    "update_last_login",
    "update_password_with_token",
    "update_totp_secret",
    "upgrade_session_purpose",
    "validate_dataset_insert_schema",
    "validate_dataset_schema",
    "validate_email_change_token",
    "validate_password_strength",
    "validate_reset_token",
    "validate_schema_against_db",
    "validate_user_schema",
    "validate_verification_token",
    "verify_and_consume_totp",
    "verify_current_password",
    "verify_dummy",
    "verify_password",
    "verify_reset_token_hash",
    "verify_smtp_tls"
]