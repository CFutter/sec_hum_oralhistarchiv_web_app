"""Token signing/validation and salt domain separation across action-email flows.

Pins the itsdangerous token layer shared by three flows:

- app.services.tokens.hash_token          — SHA-256 storage hashing
- app.services.email_verification         — salt "email-verification", 24h max age
- app.services.password_reset             — salt "password-reset", 30min max age
- app.services.email_change               — salt "email-change", 1h max age

and the delivery-lifetime policy each action email is enqueued under
(app.services.email_outbox, app.services.email).

All tests are pure unit tests: no DB, no client, no Argon2. Expiry is tested
by patching itsdangerous.timed.TimestampSigner.get_timestamp during GENERATION
only (the token is signed "in the past"), then validating normally.
"""

import hashlib
import logging
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
import time_machine
from itsdangerous import (
    BadSignature,
    SignatureExpired,
    TimestampSigner,
    URLSafeTimedSerializer,
)

from app.services import (
    email,
    email_change,
    email_outbox,
    email_verification,
    password_reset,
)
from app.services.tokens import ActionEmailMetadata, hash_token
from config import settings

EMAIL = "alice@uzh.ch"
USER_ID = 42
AUTH_REVISION = 6

_NOW = datetime(2030, 1, 1, tzinfo=UTC)


def _tamper(token: str) -> str:
    """Flip a character in the PAYLOAD segment deterministically.

    Deliberately not the token's final character: base64's last char carries
    unused trailing bits, so two different final chars can decode to the same
    signature bytes and the tampered token would still verify (a real flake
    observed in full-suite runs). Changing a payload character always
    invalidates the HMAC computed over the payload.
    """
    payload, sep, rest = token.partition(".")
    ch = payload[0]
    replacement = "A" if ch != "A" else "B"
    return replacement + payload[1:] + sep + rest


# ---------------------------------------------------------------------------
# Minting and hashing
# ---------------------------------------------------------------------------


class TestHashToken:
    def test_hash_token_is_sha256_hexdigest(self):
        """hash_token must be exactly sha256(token).hexdigest().

        Pins the storage-hash algorithm: the DB stores this digest for
        single-use enforcement, so silently changing the algorithm would
        invalidate every outstanding verification/reset/email-change link.
        """
        token = "some-raw-token-value"
        assert hash_token(token) == hashlib.sha256(token.encode()).hexdigest()
        # 64 lowercase hex chars — the shape the DB columns expect.
        digest = hash_token("x")
        assert len(digest) == 64
        assert digest == digest.lower()


class TestEmailChangeTokenPayload:
    """Roundtrip and validation contracts specific to the email-change token."""

    def test_email_change_token_self_service_binds_auth_revision(self):
        token = email_change.generate_email_change_token(
            USER_ID,
            "new@uzh.ch",
            auth_revision=AUTH_REVISION,
        )
        data = email_change.validate_email_change_token(token)
        assert data == {
            "user_id": USER_ID,
            "new_email": "new@uzh.ch",
            "auth_revision": AUTH_REVISION,
        }
        assert "acting_admin_id" not in data

    def test_email_change_token_carries_admin_and_auth_revision(self):
        token = email_change.generate_email_change_token(
            USER_ID,
            "new@uzh.ch",
            auth_revision=AUTH_REVISION,
            acting_admin_id=99,
        )
        assert email_change.validate_email_change_token(token) == {
            "user_id": USER_ID,
            "new_email": "new@uzh.ch",
            "auth_revision": AUTH_REVISION,
            "acting_admin_id": 99,
        }

    def test_email_change_token_without_revision_fails_closed(self):
        signer = email_change.URLSafeTimedSerializer(settings.secret_key.get_secret_value())
        legacy = signer.dumps(
            {
                "user_id": USER_ID,
                "new_email": "new@uzh.ch",
                "nonce": "legacy-token-without-revision",
            },
            salt=email_change._SALT,
        )
        assert email_change.validate_email_change_token(legacy) is None

    @pytest.mark.parametrize(
        "bad_revision",
        [True, -1, "6", None],
        ids=["boolean-true", "negative-integer", "numeric-string", "null"],
    )
    def test_email_change_token_rejects_invalid_revision_payload(self, bad_revision):
        signer = email_change.URLSafeTimedSerializer(settings.secret_key.get_secret_value())
        token = signer.dumps(
            {
                "user_id": USER_ID,
                "new_email": "new@uzh.ch",
                "auth_revision": bad_revision,
                "nonce": "malformed-revision",
            },
            salt=email_change._SALT,
        )
        assert email_change.validate_email_change_token(token) is None

    def test_email_change_token_validates_as_neither_verification_nor_reset(self):
        token = email_change.generate_email_change_token(
            USER_ID,
            "new@uzh.ch",
            auth_revision=AUTH_REVISION,
        )
        assert email_verification.validate_verification_token(token) is None
        assert password_reset.validate_reset_token(token) is None

    def test_email_change_token_expires_after_max_age(self):
        assert email_change.EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS == 3600
        # Mint the token two hours in the past (twice the max age), then
        # return to the real clock for validation.
        with time_machine.travel(datetime.now(UTC) - timedelta(seconds=7200)):
            token = email_change.generate_email_change_token(
                USER_ID,
                "new@uzh.ch",
                auth_revision=AUTH_REVISION,
            )
        assert email_change.validate_email_change_token(token) is None


class TestTamperedTokensAreRejected:
    @pytest.mark.parametrize(
        ("generate", "validate", "logger_name"),
        [
            pytest.param(
                lambda: email_verification.generate_verification_token(
                    USER_ID,
                    EMAIL,
                ),
                email_verification.validate_verification_token,
                "app.services.email_verification",
                id="verification",
            ),
            pytest.param(
                lambda: password_reset.generate_reset_token(USER_ID, EMAIL),
                password_reset.validate_reset_token,
                "app.services.password_reset",
                id="reset",
            ),
            pytest.param(
                lambda: email_change.generate_email_change_token(
                    USER_ID,
                    "new@uzh.ch",
                    auth_revision=AUTH_REVISION,
                ),
                email_change.validate_email_change_token,
                "app.services.email_change",
                id="email-change",
            ),
        ],
    )
    def test_tampered_token_returns_none_and_logs_warning(
        self,
        generate,
        validate,
        logger_name,
        caplog,
    ):
        token = generate()
        tampered = _tamper(token)
        assert tampered != token
        with caplog.at_level(logging.WARNING, logger=logger_name):
            assert validate(tampered) is None
        warnings = [
            record
            for record in caplog.records
            if record.name == logger_name and record.levelno == logging.WARNING
        ]
        assert warnings, "expected a WARNING log for the tampered token"


# ---------------------------------------------------------------------------
# Nonce uniqueness
# ---------------------------------------------------------------------------


class TestNonceUniqueness:
    """Every issuance is distinct even when the signer clock has not ticked."""

    @pytest.fixture
    def frozen_signer(self, monkeypatch):
        frozen_at = datetime(2031, 6, 1, tzinfo=UTC)
        instant = int(frozen_at.timestamp())
        with time_machine.travel(frozen_at, tick=False):
            monkeypatch.setattr(TimestampSigner, "get_timestamp", lambda _self: instant)
            yield instant

    @pytest.mark.parametrize(
        ("module", "generate", "validate", "metadata", "email_key", "kwargs"),
        [
            (
                password_reset,
                "generate_reset_token",
                "validate_reset_token",
                "reset_token_email_metadata",
                "email",
                {},
            ),
            (
                email_verification,
                "generate_verification_token",
                "validate_verification_token",
                "verification_token_email_metadata",
                "email",
                {},
            ),
            (
                email_change,
                "generate_email_change_token",
                "validate_email_change_token",
                "email_change_token_email_metadata",
                "new_email",
                {"auth_revision": 4},
            ),
        ],
        ids=["password_reset", "email_verification", "email_change"],
    )
    def test_same_second_tokens_are_distinct_and_keep_payload_and_expiry(
        self,
        module,
        generate,
        validate,
        metadata,
        email_key,
        kwargs,
        frozen_signer,
    ):
        first = getattr(module, generate)(7, "person@example.org", **kwargs)
        second = getattr(module, generate)(7, "person@example.org", **kwargs)
        assert first != second
        expected = {"user_id": 7, email_key: "person@example.org", **kwargs}
        assert getattr(module, validate)(first) == expected
        assert getattr(module, validate)(second) == expected
        old = getattr(module, metadata)(first)
        new = getattr(module, metadata)(second)
        assert old.token_hash != new.token_hash
        assert old.expires_at == new.expires_at
        signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
        payload, issued = signer.loads(first, salt=module._SALT, return_timestamp=True)
        assert issued == datetime.fromtimestamp(frozen_signer, UTC)
        assert isinstance(payload["nonce"], str) and len(payload["nonce"]) >= 22

        legacy = signer.dumps(expected, salt=module._SALT)
        if module is email_change:
            # Revision is mandatory, but nonce remains optional for validation.
            assert getattr(module, validate)(legacy) == expected
            without_revision = dict(expected)
            without_revision.pop("auth_revision")
            assert (
                getattr(module, validate)(signer.dumps(without_revision, salt=module._SALT)) is None
            )
        else:
            assert getattr(module, validate)(legacy) == expected

    @pytest.mark.usefixtures("frozen_signer")
    def test_admin_identity_is_preserved_alongside_revision_and_nonce(self):
        kwargs = {"auth_revision": 4, "acting_admin_id": 99}
        first = email_change.generate_email_change_token(7, "new@example.org", **kwargs)
        second = email_change.generate_email_change_token(7, "new@example.org", **kwargs)
        assert first != second
        assert email_change.validate_email_change_token(first) == {
            "user_id": 7,
            "new_email": "new@example.org",
            **kwargs,
        }


# ---------------------------------------------------------------------------
# Action-email lifetimes and delivery policy
# ---------------------------------------------------------------------------


class TestActionEmailMetadataDeadlines:
    @pytest.mark.parametrize(
        ("generate", "metadata", "lifetime"),
        [
            (
                password_reset.generate_reset_token,
                password_reset.reset_token_email_metadata,
                1800,
            ),
            (
                email_verification.generate_verification_token,
                email_verification.verification_token_email_metadata,
                86400,
            ),
            (
                lambda user_id, email: email_change.generate_email_change_token(
                    user_id,
                    email,
                    auth_revision=3,
                ),
                email_change.email_change_token_email_metadata,
                3600,
            ),
        ],
        ids=["password_reset", "email_verification", "email_change"],
    )
    def test_metadata_keeps_original_signed_deadline(
        self,
        monkeypatch,
        generate,
        metadata,
        lifetime,
    ):
        signed_at = int(_NOW.timestamp())
        monkeypatch.setattr(
            TimestampSigner,
            "get_timestamp",
            lambda _self: signed_at,
        )
        token = generate(7, "person@example.test")

        monkeypatch.setattr(
            TimestampSigner,
            "get_timestamp",
            lambda _self: signed_at + 120,
        )
        action = metadata(token)

        assert action.token_hash == hash_token(token)
        assert action.expires_at == _NOW + timedelta(seconds=lifetime)
        assert action.expires_at.utcoffset() == timedelta(0)
        assert action.token_hash not in repr(action)

        with pytest.raises(BadSignature):
            metadata("invalid." + token)

        monkeypatch.setattr(
            TimestampSigner,
            "get_timestamp",
            lambda _self: signed_at + lifetime + 1,
        )
        with pytest.raises(SignatureExpired):
            metadata(token)


class TestActionEmailRendering:
    @pytest.mark.parametrize(
        "builder",
        [
            email.build_password_reset_email,
            email.build_verification_email,
            email.build_email_change_verification,
        ],
    )
    def test_action_builders_render_absolute_utc_expiry(self, builder):
        expiry = datetime(
            2030,
            1,
            1,
            14,
            0,
            tzinfo=timezone(timedelta(hours=2)),
        )
        link = "https://example.test/action/token"

        message = builder(
            "person@example.test",
            link,
            expires_at=expiry,
        )

        assert "expires at 2030-01-01 12:00:00 UTC" in message.body
        assert "expires in" not in message.body
        assert link in message.body

        with pytest.raises(ValueError, match="timezone-aware"):
            builder(
                "person@example.test",
                link,
                expires_at=expiry.replace(tzinfo=None),
            )


class TestDeliveryLifetimeGuards:
    @pytest.mark.parametrize(
        ("seconds", "required", "expected"),
        [
            (0, 120, "expired"),
            (119, 120, "insufficient_lifetime"),
            (120, 120, "insufficient_lifetime"),
            (121, 120, None),
            (150, 150, "insufficient_lifetime"),
            (151, 150, None),
        ],
    )
    @pytest.mark.parametrize("limiting_deadline", ["signed", "database"])
    def test_earlier_deadline_controls_send_and_retry(
        self,
        seconds,
        required,
        expected,
        limiting_deadline,
    ):
        row = {
            "message_type": "password_reset",
            "action_token_hash": "hash",
            "expires_at": _NOW + timedelta(hours=2),
        }
        user = {
            "password_reset_token_hash": "hash",
            "password_reset_created_at": _NOW,
            "is_active": True,
            "auth_method": "local",
            "recipient_matches": True,
        }

        if limiting_deadline == "signed":
            row["expires_at"] = _NOW + timedelta(seconds=seconds)
        else:
            user["password_reset_created_at"] = _NOW + timedelta(seconds=seconds - 1800)

        assert (
            email_outbox._delivery_block_reason(
                row,
                user,
                now=_NOW,
                required_remaining=timedelta(seconds=required),
            )
            == expected
        )


class TestEnqueuePolicyValidation:
    """Every rejection here has its acceptance path covered elsewhere.

    ``TestActionEmailMetadataDeadlines`` and ``TestDeliveryLifetimeGuards``
    exercise the accepted shapes (a real ``ActionEmailMetadata`` paired with
    the matching message type); this class proves the mismatched and missing
    shapes are rejected before any SQL runs.
    """

    @pytest.mark.parametrize(
        ("kind", "user_id", "action"),
        [
            pytest.param(
                "password_reset",
                7,
                None,
                id="password_reset_without_metadata",
            ),
            pytest.param(
                "email_verification",
                7,
                None,
                id="email_verification_without_metadata",
            ),
            pytest.param(
                "email_change_verification",
                7,
                None,
                id="email_change_verification_without_metadata",
            ),
            pytest.param(
                "password_reset",
                None,
                ActionEmailMetadata("hash", _NOW),
                id="password_reset_metadata_without_user_id",
            ),
            pytest.param(
                "account_locked_notice",
                7,
                ActionEmailMetadata("hash", _NOW),
                id="account_locked_notice_disallows_metadata",
            ),
            pytest.param(
                "unknown",
                7,
                None,
                id="unknown_message_type",
            ),
            pytest.param(
                "password_reset",
                7,
                ActionEmailMetadata("hash", _NOW.replace(tzinfo=None)),
                id="password_reset_metadata_missing_tzinfo",
            ),
        ],
    )
    async def test_invalid_enqueue_policy_never_reaches_sql(
        self,
        kind,
        user_id,
        action,
    ):
        cur = AsyncMock()

        with pytest.raises(ValueError):
            await email_outbox.enqueue_email_cur(
                cur,
                user_id=user_id,
                message_type=kind,
                recipient="person@example.test",
                subject="Subject",
                body="Body",
                action=action,
            )

        cur.execute.assert_not_awaited()

    async def test_omitted_policy_is_an_error(self):
        cur = AsyncMock()

        with pytest.raises(TypeError, match="action"):
            await email_outbox.enqueue_outbound_email_cur(
                cur,
                user_id=None,
                email=email_outbox.OutboundEmail(
                    "account_locked_notice",
                    "a@b.test",
                    "Subject",
                    "Body",
                ),
            )

        cur.execute.assert_not_awaited()
