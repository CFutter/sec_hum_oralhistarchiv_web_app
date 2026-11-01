"""Public service facade with lazy, identity-preserving exports.

Other application layers import supported service operations and types here.
Implementations use explicit sibling imports for their internal dependencies;
tests may import those internals directly. This convention documents the public
boundary without attempting to enforce Python privacy.
Importing this package does not initialize settings or unrelated services. An
export loads its owning module on first access and retains the original object.
"""

from importlib import import_module as _import_module
from typing import TYPE_CHECKING

# Keep runtime lookup and static aliases in sync; the boundary regression checks
# every public name and its owning module. Order preserves the established API.
_EXPORT_MODULES: dict[str, str] = {
    "AuditDeliveryError": ".audit_outbox",
    "append_security_event_cur": ".audit_outbox",
    "export_security_audit_events": ".audit_outbox",
    "audit_facet_disclosures": ".disclosure_audit",
    "audit_metadata_disclosures": ".disclosure_audit",
    "request_password_reset": ".password_reset",
    "unlock_account_with_token": ".password_reset",
    "ADMIN_DATASET_MAX_ID": ".dataset_admin_queries",
    "ADMIN_DATASET_PAGE_SIZE": ".dataset_admin_queries",
    "ADMIN_DATASET_UUID_MAX_CHARS": ".dataset_admin_queries",
    "ADMIN_PROMOTION_MAX_AGE_SECONDS": ".admin_promotion",
    "ADMIN_PROMOTION_PREPARED_MAX_AGE_SECONDS": ".admin_promotion",
    "CREDENTIAL_INTEGRITY_FAULTS": ".authentication",
    "DISPLAY_NAME_MAX_LENGTH": ".users",
    "FEDERATED_SESSION_POLICY_VERSION": ".federated_session_policy",
    "FIELD_VISIBILITY": "..",
    "NUMBERED_SEARCH_PAGES": ".search_cursor",
    "PUBLIC_DISCOVERY_FIELDS": "..",
    "PUBLIC_SEARCH_FIELDS": ".datasets",
    "REGISTRATION_AFFILIATION_MAX_CHARS": ".registration_setup",
    "REGISTRATION_COUNTRY_MAX_CHARS": ".registration_setup",
    "REGISTRATION_TOKEN_MAX_CHARS": ".registration_setup",
    "REQUIRED_SHIBBOLETH_AUTHN_CONTEXT": ".federated_session_policy",
    "SEARCH_CURSOR_MAX_LENGTH": ".search_cursor",
    "SHIBBOLETH_AFFILIATION_HEADER": ".federated_authentication",
    "SHIBBOLETH_AUTHN_CONTEXT_HEADER": ".federated_authentication",
    "SHIBBOLETH_COUNTRY_HEADER": ".federated_authentication",
    "SHIBBOLETH_DISPLAY_NAME_HEADER": ".federated_authentication",
    "SHIBBOLETH_ENTITLEMENT_HEADER": ".federated_authentication",
    "SHIBBOLETH_INTERNAL_AUTH_HEADER": ".federated_authentication",
    "SHIBBOLETH_ISSUER_HEADER": ".federated_authentication",
    "SHIBBOLETH_MAIL_HEADER": ".federated_authentication",
    "SHIBBOLETH_SUBJECT_HEADER": ".federated_authentication",
    "TOTP_RECOVERY_AUTHORIZATION_MAX_AGE_SECONDS": ".totp_recover",
    "TOTP_RECOVERY_CODE_MAX_CHARS": ".totp_recovery_codes",
    "TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT": ".totp_recovery_codes",
    "TOTP_RECOVERY_SESSION_MAX_AGE_SECONDS": ".totp_recover",
    "AcceptedAdminPromotion": ".admin_promotion",
    "AccountDeletionReason": ".account_deletion",
    "AccountDeletionRejected": ".account_deletion",
    "AccountDeletionResult": ".account_deletion",
    "AdminActionRejected": ".users",
    "AdminEmailChangeRejected": ".email_change",
    "AdminEmailChangeResult": ".email_change",
    "AdminPromotion": ".admin_promotion",
    "AdminPromotionRejected": ".admin_promotion",
    "AdminPromotionRequestResult": ".admin_promotion",
    "Author": ".datasets",
    "CataloguePolicy": ".datasets",
    "CatalogueStatsCache": ".cache",
    "ClaimedEmail": ".email_outbox",
    "Dataset": ".datasets",
    "FacetDisclosure": ".datasets",
    "DatasetAdminAction": ".dataset_admin",
    "DatasetAdminChange": ".dataset_admin",
    "DatasetAdminContext": ".dataset_admin",
    "DatasetAdminReason": ".dataset_admin",
    "DatasetAdminPage": ".dataset_admin_queries",
    "DatasetAdminRecord": ".dataset_admin_queries",
    "DatasetAdminRejected": ".dataset_admin",
    "DatasetAdminState": ".dataset_admin",
    "FederatedApproval": ".users",
    "FederatedLoginFailure": ".federated_authentication",
    "FederatedPrincipal": ".federated_authentication",
    "FederatedReview": ".federated_review",
    "FederatedStatus": ".users",
    "HarvestResult": ".harvest",
    "HarvestResultSizeError": ".harvest",
    "InvalidFederatedPrincipal": ".federated_authentication",
    "LocalLoginFailure": ".authentication",
    "OutboundEmail": ".email_outbox",
    "OutboxBodyDecryptionError": ".email_outbox",
    "OutboxLeaseLostError": ".email_outbox",
    "PasswordChangeReason": ".password_change",
    "PasswordChangeRejected": ".password_change",
    "PendingTotpOutcome": ".totp",
    "PendingTotpPurpose": ".totp",
    "PreparedAdminPromotion": ".admin_promotion",
    "RegistrationSetup": ".registration_setup",
    "RunningJobTracker": ".scheduler",
    "SearchCursorInvalid": ".search_cursor",
    "SearchPage": ".datasets",
    "SearchUnavailable": ".search_work",
    "SearchWork": ".search_work",
    "SelfEmailChangeRejected": ".email_change",
    "SelfEmailChangeResult": ".email_change",
    "SessionNotFoundError": ".sessions",
    "SessionPurpose": ".sessions",
    "SessionStepUpAttemptOutcome": ".credential_attempts",
    "SignedActionToken": ".tokens",
    "SourceStatus": ".source_status",
    "TotpDecryptionError": ".totp",
    "TotpEnrollmentOutcome": ".totp",
    "TotpRecoveryAuthorization": ".totp_recover",
    "TotpRecoveryRedemption": ".totp_recover",
    "TotpRecoveryRedemptionRejected": ".totp_recover",
    "TotpRecoveryRejected": ".totp_recover",
    "TotpRecoveryTarget": ".totp_recover",
    "TotpRotationOutcome": ".totp",
    "TotpRotationStartOutcome": ".totp",
    "TotpRotationStartResult": ".totp",
    "User": ".users",
    "accept_admin_promotion": ".admin_promotion",
    "action_token_public_id": ".tokens",
    "action_token_url": ".tokens",
    "approve_federated_user": ".users",
    "assert_field_visibility_total": ".datasets",
    "assert_tier_rank_complete": ".access_tiers",
    "audit_admin_action": ".audit",
    "audit_email_hash": ".crypto",
    "audit_user_event": ".audit",
    "authorize_totp_recovery": ".totp_recover",
    "begin_local_registration": ".registration_setup",
    "begin_totp_rotation": ".totp",
    "build_account_credential_fault_notice": ".email",
    "build_account_locked_notice": ".email",
    "build_catalogue_policy": ".datasets",
    "compile_default_catalogue_policy": ".catalogue_policy",
    "build_duplicate_registration_notice": ".email",
    "build_email_change_notice": ".email",
    "build_email_change_verification": ".email",
    "build_federated_principal": ".federated_authentication",
    "build_password_reset_email": ".email",
    "build_verification_email": ".email",
    "can_access": ".access_tiers",
    "can_view_field": ".datasets",
    "can_view_full": ".datasets",
    "cancel_admin_promotion": ".admin_promotion",
    "change_password": ".password_change",
    "change_dataset_admin_state": ".dataset_admin",
    "claim_due_emails": ".email_outbox",
    "cleanup_expired_sessions": ".sessions",
    "complete_local_registration": ".registration_setup",
    "confirm_email_change": ".email_change",
    "confirm_totp_rotation": ".totp",
    "consume_flash": ".sessions",
    "count_search_datasets": ".datasets",
    "create_pool": ".db",
    "create_search_pool": ".db",
    "create_scheduler": ".scheduler",
    "create_session": ".sessions",
    "create_shibboleth_user": ".users",
    "decline_admin_promotion": ".admin_promotion",
    "decrypt_claimed_email_body": ".email_outbox",
    "delete_account_as_admin": ".account_deletion",
    "delete_own_account": ".account_deletion",
    "delete_session": ".sessions",
    "delete_user_sessions": ".session_revocation",
    "delete_user_sessions_cur": ".session_revocation",
    "deliver_email_outbox_batch": ".email_delivery",
    "email_change_token_email_metadata": ".email_change",
    "encode_harvest_result": ".harvest",
    "enqueue_email_cur": ".email_outbox",
    "enqueue_outbound_email_cur": ".email_outbox",
    "ensure_source_status_rows": ".sync_state",
    "federated_session_policy_fingerprint": ".federated_session_policy",
    "field_required_tier": ".datasets",
    "filter_for_tier": ".datasets",
    "finalize_local_login": ".authentication",
    "finalize_shibboleth_login": ".federated_authentication",
    "full_required_tier": ".datasets",
    "generate_email_change_token": ".email_change",
    "generate_reset_token": ".password_reset",
    "generate_totp_secret": ".totp",
    "generate_verification_token": ".email_verification",
    "get_admin_dataset_by_id": ".dataset_admin_queries",
    "get_admin_promotion": ".admin_promotion",
    "get_catalogue_cursor": ".db",
    "get_dataset_by_id": ".datasets",
    "get_db_cursor": ".db",
    "get_facets": ".datasets",
    "get_global_catalogue_stats": ".datasets",
    "get_last_full_rebuild_date": ".datasets",
    "guard_catalogue_policy_cur": ".search_projection",
    "get_or_create_pending_totp_secret": ".totp",
    "get_outbox_metrics_cur": ".outbox_maintenance",
    "get_pending_totp_secret": ".totp",
    "get_primary_totp_decryptor": ".totp_crypto",
    "rotate_totp_value": ".totp_crypto",
    "get_recent_datasets": ".datasets",
    "get_session_user": ".sessions",
    "get_source_statuses": ".source_status",
    "get_totp_recovery_target": ".totp_recover",
    "get_totp_secret": ".totp",
    "get_user_by_email": ".users",
    "get_user_by_id": ".users",
    "harvest_result_from_document": ".harvest",
    "harvest_result_to_json": ".harvest",
    "hash_session_id": ".session_ids",
    "hash_token": ".tokens",
    "inspect_local_registration": ".registration_setup",
    "invalidate_pending_authentication_state_cur": ".session_revocation",
    "is_trusted_federated_principal": ".federated_authentication",
    "list_admin_promotion_states": ".admin_promotion",
    "list_federated_reviews": ".federated_review",
    "list_users": ".users",
    "load_runtime_sources": ".runtime_sources",
    "load_runtime_catalogue_sources": ".runtime_sources",
    "mark_email_dead": ".email_outbox",
    "mark_email_sent": ".email_outbox",
    "matched_step": ".totp",
    "normalize_display_name": ".users",
    "normalize_email": ".email_utils",
    "outbox_is_degraded": ".outbox_maintenance",
    "pending_email_change_matches": ".email_change",
    "prepare_admin_promotion": ".admin_promotion",
    "reconcile_federated_session_policy": ".federated_session_policy",
    "record_login_failure": ".authentication",
    "record_login_failure_cur": ".authentication",
    "redeem_totp_recovery": ".totp_recover",
    "request_admin_promotion": ".admin_promotion",
    "resend_local_registration": ".registration_setup",
    "reserve_session_step_up_attempt": ".credential_attempts",
    "reset_token_email_metadata": ".password_reset",
    "restore_flash_if_empty": ".sessions",
    "retry_email_later": ".email_outbox",
    "run_full_rebuild": ".ingestion",
    "run_sync": ".ingestion",
    "search_admin_datasets": ".dataset_admin_queries",
    "replace_search_policy": ".search_projection",
    "search_catalogue_page": ".datasets",
    "search_datasets": ".datasets",
    "seed_admin_user": ".seed_admin",
    "send_email": ".email",
    "set_flash": ".sessions",
    "set_flash_if_exists": ".sessions",
    "set_user_active": ".users",
    "set_user_admin": ".users",
    "stage_admin_email_change": ".email_change",
    "stage_self_email_change": ".email_change",
    "store_pending_email": ".email_change",
    "store_pending_email_cur": ".email_change",
    "store_reset_token_hash": ".password_reset",
    "store_reset_token_hash_cur": ".password_reset",
    "store_verification_token_hash": ".email_verification",
    "store_verification_token_hash_cur": ".email_verification",
    "synchronize_search_policy": ".search_projection",
    "update_access_tier": ".users",
    "update_display_name": ".users",
    "update_last_login": ".users",
    "update_password_with_token": ".password_reset",
    "valid_action_public_id": ".tokens",
    "validate_dataset_insert_schema": ".datasets",
    "validate_dataset_schema": ".datasets",
    "validate_email_change_token": ".email_change",
    "validate_parsed_record": ".parsed_record",
    "validate_password_strength": ".password_validation",
    "validate_reset_token": ".password_reset",
    "validate_schema_against_db": ".db_drift",
    "validate_search_string": ".search_query",
    "validate_user_schema": ".users",
    "validate_verification_token": ".email_verification",
    "verification_token_email_metadata": ".email_verification",
    "verify_and_consume_totp": ".totp",
    "verify_and_enroll_totp": ".totp",
    "verify_dummy": ".password_verification",
    "verify_password": ".authentication",
    "verify_reset_token_hash": ".password_reset",
    "warm_password_blocklist": ".password_validation",
}

__all__ = list(_EXPORT_MODULES)

if TYPE_CHECKING:
    from .. import FIELD_VISIBILITY as FIELD_VISIBILITY
    from .. import PUBLIC_DISCOVERY_FIELDS as PUBLIC_DISCOVERY_FIELDS
    from .access_tiers import assert_tier_rank_complete as assert_tier_rank_complete
    from .access_tiers import can_access as can_access
    from .account_deletion import AccountDeletionReason as AccountDeletionReason
    from .account_deletion import AccountDeletionRejected as AccountDeletionRejected
    from .account_deletion import AccountDeletionResult as AccountDeletionResult
    from .account_deletion import delete_account_as_admin as delete_account_as_admin
    from .account_deletion import delete_own_account as delete_own_account
    from .admin_promotion import ADMIN_PROMOTION_MAX_AGE_SECONDS as ADMIN_PROMOTION_MAX_AGE_SECONDS
    from .admin_promotion import (
        ADMIN_PROMOTION_PREPARED_MAX_AGE_SECONDS as ADMIN_PROMOTION_PREPARED_MAX_AGE_SECONDS,
    )
    from .admin_promotion import AcceptedAdminPromotion as AcceptedAdminPromotion
    from .admin_promotion import AdminPromotion as AdminPromotion
    from .admin_promotion import AdminPromotionRejected as AdminPromotionRejected
    from .admin_promotion import AdminPromotionRequestResult as AdminPromotionRequestResult
    from .admin_promotion import PreparedAdminPromotion as PreparedAdminPromotion
    from .admin_promotion import accept_admin_promotion as accept_admin_promotion
    from .admin_promotion import cancel_admin_promotion as cancel_admin_promotion
    from .admin_promotion import decline_admin_promotion as decline_admin_promotion
    from .admin_promotion import get_admin_promotion as get_admin_promotion
    from .admin_promotion import list_admin_promotion_states as list_admin_promotion_states
    from .admin_promotion import prepare_admin_promotion as prepare_admin_promotion
    from .admin_promotion import request_admin_promotion as request_admin_promotion
    from .audit import audit_admin_action as audit_admin_action
    from .audit import audit_user_event as audit_user_event
    from .audit_outbox import AuditDeliveryError as AuditDeliveryError
    from .audit_outbox import append_security_event_cur as append_security_event_cur
    from .audit_outbox import export_security_audit_events as export_security_audit_events
    from .authentication import CREDENTIAL_INTEGRITY_FAULTS as CREDENTIAL_INTEGRITY_FAULTS
    from .authentication import LocalLoginFailure as LocalLoginFailure
    from .authentication import finalize_local_login as finalize_local_login
    from .authentication import record_login_failure as record_login_failure
    from .authentication import record_login_failure_cur as record_login_failure_cur
    from .authentication import verify_password as verify_password
    from .cache import CatalogueStatsCache as CatalogueStatsCache
    from .catalogue_policy import (
        compile_default_catalogue_policy as compile_default_catalogue_policy,
    )
    from .credential_attempts import SessionStepUpAttemptOutcome as SessionStepUpAttemptOutcome
    from .credential_attempts import (
        reserve_session_step_up_attempt as reserve_session_step_up_attempt,
    )
    from .crypto import audit_email_hash as audit_email_hash
    from .dataset_admin import DatasetAdminAction as DatasetAdminAction
    from .dataset_admin import DatasetAdminChange as DatasetAdminChange
    from .dataset_admin import DatasetAdminContext as DatasetAdminContext
    from .dataset_admin import DatasetAdminReason as DatasetAdminReason
    from .dataset_admin import DatasetAdminRejected as DatasetAdminRejected
    from .dataset_admin import DatasetAdminState as DatasetAdminState
    from .dataset_admin import change_dataset_admin_state as change_dataset_admin_state
    from .dataset_admin_queries import ADMIN_DATASET_MAX_ID as ADMIN_DATASET_MAX_ID
    from .dataset_admin_queries import ADMIN_DATASET_PAGE_SIZE as ADMIN_DATASET_PAGE_SIZE
    from .dataset_admin_queries import ADMIN_DATASET_UUID_MAX_CHARS as ADMIN_DATASET_UUID_MAX_CHARS
    from .dataset_admin_queries import DatasetAdminPage as DatasetAdminPage
    from .dataset_admin_queries import DatasetAdminRecord as DatasetAdminRecord
    from .dataset_admin_queries import get_admin_dataset_by_id as get_admin_dataset_by_id
    from .dataset_admin_queries import search_admin_datasets as search_admin_datasets
    from .datasets import PUBLIC_SEARCH_FIELDS as PUBLIC_SEARCH_FIELDS
    from .datasets import Author as Author
    from .datasets import CataloguePolicy as CataloguePolicy
    from .datasets import Dataset as Dataset
    from .datasets import FacetDisclosure as FacetDisclosure
    from .datasets import SearchPage as SearchPage
    from .datasets import assert_field_visibility_total as assert_field_visibility_total
    from .datasets import build_catalogue_policy as build_catalogue_policy
    from .datasets import can_view_field as can_view_field
    from .datasets import can_view_full as can_view_full
    from .datasets import count_search_datasets as count_search_datasets
    from .datasets import field_required_tier as field_required_tier
    from .datasets import filter_for_tier as filter_for_tier
    from .datasets import full_required_tier as full_required_tier
    from .datasets import get_dataset_by_id as get_dataset_by_id
    from .datasets import get_facets as get_facets
    from .datasets import get_global_catalogue_stats as get_global_catalogue_stats
    from .datasets import get_last_full_rebuild_date as get_last_full_rebuild_date
    from .datasets import get_recent_datasets as get_recent_datasets
    from .datasets import search_catalogue_page as search_catalogue_page
    from .datasets import search_datasets as search_datasets
    from .datasets import validate_dataset_insert_schema as validate_dataset_insert_schema
    from .datasets import validate_dataset_schema as validate_dataset_schema
    from .db import create_pool as create_pool
    from .db import create_search_pool as create_search_pool
    from .db import get_catalogue_cursor as get_catalogue_cursor
    from .db import get_db_cursor as get_db_cursor
    from .db_drift import validate_schema_against_db as validate_schema_against_db
    from .disclosure_audit import audit_facet_disclosures as audit_facet_disclosures
    from .disclosure_audit import audit_metadata_disclosures as audit_metadata_disclosures
    from .email import (
        build_account_credential_fault_notice as build_account_credential_fault_notice,
    )
    from .email import build_account_locked_notice as build_account_locked_notice
    from .email import build_duplicate_registration_notice as build_duplicate_registration_notice
    from .email import build_email_change_notice as build_email_change_notice
    from .email import build_email_change_verification as build_email_change_verification
    from .email import build_password_reset_email as build_password_reset_email
    from .email import build_verification_email as build_verification_email
    from .email import send_email as send_email
    from .email_change import AdminEmailChangeRejected as AdminEmailChangeRejected
    from .email_change import AdminEmailChangeResult as AdminEmailChangeResult
    from .email_change import SelfEmailChangeRejected as SelfEmailChangeRejected
    from .email_change import SelfEmailChangeResult as SelfEmailChangeResult
    from .email_change import confirm_email_change as confirm_email_change
    from .email_change import email_change_token_email_metadata as email_change_token_email_metadata
    from .email_change import generate_email_change_token as generate_email_change_token
    from .email_change import pending_email_change_matches as pending_email_change_matches
    from .email_change import stage_admin_email_change as stage_admin_email_change
    from .email_change import stage_self_email_change as stage_self_email_change
    from .email_change import store_pending_email as store_pending_email
    from .email_change import store_pending_email_cur as store_pending_email_cur
    from .email_change import validate_email_change_token as validate_email_change_token
    from .email_delivery import deliver_email_outbox_batch as deliver_email_outbox_batch
    from .email_outbox import ClaimedEmail as ClaimedEmail
    from .email_outbox import OutboundEmail as OutboundEmail
    from .email_outbox import OutboxBodyDecryptionError as OutboxBodyDecryptionError
    from .email_outbox import OutboxLeaseLostError as OutboxLeaseLostError
    from .email_outbox import claim_due_emails as claim_due_emails
    from .email_outbox import decrypt_claimed_email_body as decrypt_claimed_email_body
    from .email_outbox import enqueue_email_cur as enqueue_email_cur
    from .email_outbox import enqueue_outbound_email_cur as enqueue_outbound_email_cur
    from .email_outbox import mark_email_dead as mark_email_dead
    from .email_outbox import mark_email_sent as mark_email_sent
    from .email_outbox import retry_email_later as retry_email_later
    from .email_utils import normalize_email as normalize_email
    from .email_verification import generate_verification_token as generate_verification_token
    from .email_verification import store_verification_token_hash as store_verification_token_hash
    from .email_verification import (
        store_verification_token_hash_cur as store_verification_token_hash_cur,
    )
    from .email_verification import validate_verification_token as validate_verification_token
    from .email_verification import (
        verification_token_email_metadata as verification_token_email_metadata,
    )
    from .federated_authentication import (
        SHIBBOLETH_AFFILIATION_HEADER as SHIBBOLETH_AFFILIATION_HEADER,
    )
    from .federated_authentication import (
        SHIBBOLETH_AUTHN_CONTEXT_HEADER as SHIBBOLETH_AUTHN_CONTEXT_HEADER,
    )
    from .federated_authentication import SHIBBOLETH_COUNTRY_HEADER as SHIBBOLETH_COUNTRY_HEADER
    from .federated_authentication import (
        SHIBBOLETH_DISPLAY_NAME_HEADER as SHIBBOLETH_DISPLAY_NAME_HEADER,
    )
    from .federated_authentication import (
        SHIBBOLETH_ENTITLEMENT_HEADER as SHIBBOLETH_ENTITLEMENT_HEADER,
    )
    from .federated_authentication import (
        SHIBBOLETH_INTERNAL_AUTH_HEADER as SHIBBOLETH_INTERNAL_AUTH_HEADER,
    )
    from .federated_authentication import SHIBBOLETH_ISSUER_HEADER as SHIBBOLETH_ISSUER_HEADER
    from .federated_authentication import SHIBBOLETH_MAIL_HEADER as SHIBBOLETH_MAIL_HEADER
    from .federated_authentication import SHIBBOLETH_SUBJECT_HEADER as SHIBBOLETH_SUBJECT_HEADER
    from .federated_authentication import FederatedLoginFailure as FederatedLoginFailure
    from .federated_authentication import FederatedPrincipal as FederatedPrincipal
    from .federated_authentication import InvalidFederatedPrincipal as InvalidFederatedPrincipal
    from .federated_authentication import build_federated_principal as build_federated_principal
    from .federated_authentication import finalize_shibboleth_login as finalize_shibboleth_login
    from .federated_authentication import (
        is_trusted_federated_principal as is_trusted_federated_principal,
    )
    from .federated_review import FederatedReview as FederatedReview
    from .federated_review import list_federated_reviews as list_federated_reviews
    from .federated_session_policy import (
        FEDERATED_SESSION_POLICY_VERSION as FEDERATED_SESSION_POLICY_VERSION,
    )
    from .federated_session_policy import (
        REQUIRED_SHIBBOLETH_AUTHN_CONTEXT as REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
    )
    from .federated_session_policy import (
        federated_session_policy_fingerprint as federated_session_policy_fingerprint,
    )
    from .federated_session_policy import (
        reconcile_federated_session_policy as reconcile_federated_session_policy,
    )
    from .harvest import HarvestResult as HarvestResult
    from .harvest import HarvestResultSizeError as HarvestResultSizeError
    from .harvest import encode_harvest_result as encode_harvest_result
    from .harvest import harvest_result_from_document as harvest_result_from_document
    from .harvest import harvest_result_to_json as harvest_result_to_json
    from .ingestion import run_full_rebuild as run_full_rebuild
    from .ingestion import run_sync as run_sync
    from .outbox_maintenance import get_outbox_metrics_cur as get_outbox_metrics_cur
    from .outbox_maintenance import outbox_is_degraded as outbox_is_degraded
    from .parsed_record import validate_parsed_record as validate_parsed_record
    from .password_change import PasswordChangeReason as PasswordChangeReason
    from .password_change import PasswordChangeRejected as PasswordChangeRejected
    from .password_change import change_password as change_password
    from .password_reset import generate_reset_token as generate_reset_token
    from .password_reset import request_password_reset as request_password_reset
    from .password_reset import reset_token_email_metadata as reset_token_email_metadata
    from .password_reset import store_reset_token_hash as store_reset_token_hash
    from .password_reset import store_reset_token_hash_cur as store_reset_token_hash_cur
    from .password_reset import unlock_account_with_token as unlock_account_with_token
    from .password_reset import update_password_with_token as update_password_with_token
    from .password_reset import validate_reset_token as validate_reset_token
    from .password_reset import verify_reset_token_hash as verify_reset_token_hash
    from .password_validation import validate_password_strength as validate_password_strength
    from .password_validation import warm_password_blocklist as warm_password_blocklist
    from .password_verification import verify_dummy as verify_dummy
    from .registration_setup import (
        REGISTRATION_AFFILIATION_MAX_CHARS as REGISTRATION_AFFILIATION_MAX_CHARS,
    )
    from .registration_setup import REGISTRATION_COUNTRY_MAX_CHARS as REGISTRATION_COUNTRY_MAX_CHARS
    from .registration_setup import REGISTRATION_TOKEN_MAX_CHARS as REGISTRATION_TOKEN_MAX_CHARS
    from .registration_setup import RegistrationSetup as RegistrationSetup
    from .registration_setup import begin_local_registration as begin_local_registration
    from .registration_setup import complete_local_registration as complete_local_registration
    from .registration_setup import inspect_local_registration as inspect_local_registration
    from .registration_setup import resend_local_registration as resend_local_registration
    from .runtime_sources import load_runtime_catalogue_sources as load_runtime_catalogue_sources
    from .runtime_sources import load_runtime_sources as load_runtime_sources
    from .scheduler import RunningJobTracker as RunningJobTracker
    from .scheduler import create_scheduler as create_scheduler
    from .search_cursor import NUMBERED_SEARCH_PAGES as NUMBERED_SEARCH_PAGES
    from .search_cursor import SEARCH_CURSOR_MAX_LENGTH as SEARCH_CURSOR_MAX_LENGTH
    from .search_cursor import SearchCursorInvalid as SearchCursorInvalid
    from .search_projection import guard_catalogue_policy_cur as guard_catalogue_policy_cur
    from .search_projection import replace_search_policy as replace_search_policy
    from .search_projection import synchronize_search_policy as synchronize_search_policy
    from .search_query import validate_search_string as validate_search_string
    from .search_work import SearchUnavailable as SearchUnavailable
    from .search_work import SearchWork as SearchWork
    from .seed_admin import seed_admin_user as seed_admin_user
    from .session_ids import hash_session_id as hash_session_id
    from .session_revocation import delete_user_sessions as delete_user_sessions
    from .session_revocation import delete_user_sessions_cur as delete_user_sessions_cur
    from .session_revocation import (
        invalidate_pending_authentication_state_cur as invalidate_pending_authentication_state_cur,
    )
    from .sessions import SessionNotFoundError as SessionNotFoundError
    from .sessions import SessionPurpose as SessionPurpose
    from .sessions import cleanup_expired_sessions as cleanup_expired_sessions
    from .sessions import consume_flash as consume_flash
    from .sessions import create_session as create_session
    from .sessions import delete_session as delete_session
    from .sessions import get_session_user as get_session_user
    from .sessions import restore_flash_if_empty as restore_flash_if_empty
    from .sessions import set_flash as set_flash
    from .sessions import set_flash_if_exists as set_flash_if_exists
    from .source_status import SourceStatus as SourceStatus
    from .source_status import get_source_statuses as get_source_statuses
    from .sync_state import ensure_source_status_rows as ensure_source_status_rows
    from .tokens import SignedActionToken as SignedActionToken
    from .tokens import action_token_public_id as action_token_public_id
    from .tokens import action_token_url as action_token_url
    from .tokens import hash_token as hash_token
    from .tokens import valid_action_public_id as valid_action_public_id
    from .totp import PendingTotpOutcome as PendingTotpOutcome
    from .totp import PendingTotpPurpose as PendingTotpPurpose
    from .totp import TotpDecryptionError as TotpDecryptionError
    from .totp import TotpEnrollmentOutcome as TotpEnrollmentOutcome
    from .totp import TotpRotationOutcome as TotpRotationOutcome
    from .totp import TotpRotationStartOutcome as TotpRotationStartOutcome
    from .totp import TotpRotationStartResult as TotpRotationStartResult
    from .totp import begin_totp_rotation as begin_totp_rotation
    from .totp import confirm_totp_rotation as confirm_totp_rotation
    from .totp import generate_totp_secret as generate_totp_secret
    from .totp import get_or_create_pending_totp_secret as get_or_create_pending_totp_secret
    from .totp import get_pending_totp_secret as get_pending_totp_secret
    from .totp import get_totp_secret as get_totp_secret
    from .totp import matched_step as matched_step
    from .totp import verify_and_consume_totp as verify_and_consume_totp
    from .totp import verify_and_enroll_totp as verify_and_enroll_totp
    from .totp_crypto import get_primary_totp_decryptor as get_primary_totp_decryptor
    from .totp_crypto import rotate_totp_value as rotate_totp_value
    from .totp_recover import (
        TOTP_RECOVERY_AUTHORIZATION_MAX_AGE_SECONDS as TOTP_RECOVERY_AUTHORIZATION_MAX_AGE_SECONDS,
    )
    from .totp_recover import (
        TOTP_RECOVERY_SESSION_MAX_AGE_SECONDS as TOTP_RECOVERY_SESSION_MAX_AGE_SECONDS,
    )
    from .totp_recover import TotpRecoveryAuthorization as TotpRecoveryAuthorization
    from .totp_recover import TotpRecoveryRedemption as TotpRecoveryRedemption
    from .totp_recover import TotpRecoveryRedemptionRejected as TotpRecoveryRedemptionRejected
    from .totp_recover import TotpRecoveryRejected as TotpRecoveryRejected
    from .totp_recover import TotpRecoveryTarget as TotpRecoveryTarget
    from .totp_recover import authorize_totp_recovery as authorize_totp_recovery
    from .totp_recover import get_totp_recovery_target as get_totp_recovery_target
    from .totp_recover import redeem_totp_recovery as redeem_totp_recovery
    from .totp_recovery_codes import TOTP_RECOVERY_CODE_MAX_CHARS as TOTP_RECOVERY_CODE_MAX_CHARS
    from .totp_recovery_codes import (
        TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT as TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT,
    )
    from .users import DISPLAY_NAME_MAX_LENGTH as DISPLAY_NAME_MAX_LENGTH
    from .users import AdminActionRejected as AdminActionRejected
    from .users import FederatedApproval as FederatedApproval
    from .users import FederatedStatus as FederatedStatus
    from .users import User as User
    from .users import approve_federated_user as approve_federated_user
    from .users import create_shibboleth_user as create_shibboleth_user
    from .users import get_user_by_email as get_user_by_email
    from .users import get_user_by_id as get_user_by_id
    from .users import list_users as list_users
    from .users import normalize_display_name as normalize_display_name
    from .users import set_user_active as set_user_active
    from .users import set_user_admin as set_user_admin
    from .users import update_access_tier as update_access_tier
    from .users import update_display_name as update_display_name
    from .users import update_last_login as update_last_login
    from .users import validate_user_schema as validate_user_schema
else:
    # Static callers see only the explicit aliases above. A dynamic fallback in
    # the type-checking branch would allow misspelled public names to escape it.
    def __getattr__(name: str) -> object:
        """Load and cache a declared export; raise AttributeError for unknown names."""
        try:
            module_name = _EXPORT_MODULES[name]
        except KeyError:
            raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
        value = getattr(_import_module(module_name, __name__), name)
        globals()[name] = value
        return value


def __dir__() -> list[str]:
    """Expose public names to discovery without importing their implementations."""
    return sorted(set(globals()) | set(__all__))
