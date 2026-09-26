"""Unit tests for app.services.totp_recovery_codes: the staging, activation,
nonlocking lookup, and reservation-gated consumption of durable one-time
TOTP recovery codes.

Each cursor-taking helper here is exercised directly against a scripted mock
cursor (no DB) — this is the module TOTP callers rely on to keep an unknown
or already-used code from spending real Argon2 work or a real database
write. Every test proving a code/state is rejected has a positive control
in the same class proving the matching valid code/state still succeeds.
"""

from unittest.mock import AsyncMock

import pytest

from app.services.tokens import hash_token
from app.services.totp_recovery_codes import (
    MatchedRecoveryCodeCandidate,
    ReservedRecoveryCodePasswordAttempt,
    activate_pending_recovery_code_set_cur,
    consume_reserved_recovery_code_cur,
    discard_pending_recovery_code_set_cur,
    find_active_recovery_code_candidate_cur,
    generate_recovery_codes,
    has_unused_active_recovery_code_cur,
    reserve_recovery_code_password_attempt_cur,
    stage_recovery_code_set_cur,
)
from tests.fixtures import make_async_cursor

USER_ID = 630
GENERATION = 4
POSITION = 7
CODE_HASH = hash_token("AAAAAAAAAAAAAAAAAAAA")


def _candidate(**overrides) -> MatchedRecoveryCodeCandidate:
    fields = {
        "user_id": USER_ID,
        "generation": GENERATION,
        "position": POSITION,
        "code_hash": CODE_HASH,
    }
    fields.update(overrides)
    return MatchedRecoveryCodeCandidate(**fields)


def _reservation(**overrides) -> ReservedRecoveryCodePasswordAttempt:
    fields = {
        "user_id": USER_ID,
        "generation": GENERATION,
        "position": POSITION,
        "code_hash": CODE_HASH,
    }
    fields.update(overrides)
    return ReservedRecoveryCodePasswordAttempt(**fields)


class TestStageRecoveryCodeSet:
    """stage_recovery_code_set_cur: the write path that displays a new pending set."""

    async def test_wrong_cardinality_is_rejected_before_touching_the_database(self):
        cur = make_async_cursor()
        with pytest.raises(ValueError, match="wrong cardinality"):
            await stage_recovery_code_set_cur(cur, user_id=USER_ID, codes=("ONLY-ONE-CODE",))
        cur.execute.assert_not_awaited()

    async def test_duplicate_raw_codes_are_rejected_as_the_wrong_cardinality(self):
        codes = (*generate_recovery_codes()[:9], generate_recovery_codes()[0])
        # Force an exact raw-string duplicate (independent of hashing).
        codes = (codes[0], codes[0], *codes[2:])
        cur = make_async_cursor()
        with pytest.raises(ValueError, match="wrong cardinality"):
            await stage_recovery_code_set_cur(cur, user_id=USER_ID, codes=codes)

    async def test_a_malformed_generated_code_raises_before_any_write(self):
        """Defends _code_hash's own invariant: every code this function hashes must
        already be a normalizable canonical value; a caller-supplied garbage code
        is a programming error, not a silent rejection.
        """
        codes = (*generate_recovery_codes()[:9], "not-a-valid-recovery-code")
        cur = make_async_cursor()
        with pytest.raises(ValueError, match="Generated recovery code is invalid"):
            await stage_recovery_code_set_cur(cur, user_id=USER_ID, codes=codes)
        cur.execute.assert_not_awaited()

    async def test_two_codes_normalizing_to_the_same_canonical_value_is_a_runtime_error(self):
        """Two raw strings can differ (one dash-grouped, one not) yet normalize to the
        same canonical code — the cardinality check alone would miss this collision.
        """
        base = generate_recovery_codes()
        canonical_first = "".join(character for character in base[0] if character != "-")
        codes = (base[0], canonical_first, *base[2:])
        cur = make_async_cursor()
        with pytest.raises(RuntimeError, match="duplicate values"):
            await stage_recovery_code_set_cur(cur, user_id=USER_ID, codes=codes)

    async def test_unknown_user_id_is_rejected(self):
        cur = make_async_cursor(fetchone=None)
        with pytest.raises(ValueError, match=f"User {USER_ID} not found"):
            await stage_recovery_code_set_cur(cur, user_id=USER_ID, codes=generate_recovery_codes())

    async def test_valid_code_set_is_staged_as_the_next_generation(self):
        """Positive control for every rejection above."""
        cur = make_async_cursor(fetchone={"totp_recovery_code_generation": 6})
        cur.executemany = AsyncMock()
        codes = generate_recovery_codes()

        staged = await stage_recovery_code_set_cur(cur, user_id=USER_ID, codes=codes)

        assert staged.generation == 7
        assert staged.codes == codes
        cur.executemany.assert_awaited_once()
        rows = cur.executemany.await_args.args[1]
        assert len(rows) == 10
        assert {row[1] for row in rows} == {7}
        assert {row[2] for row in rows} == set(range(1, 11))
        update_statement, update_params = cur.execute.await_args_list[-1].args
        assert "pending_totp_recovery_code_generation" in update_statement
        assert update_params == (7, USER_ID)


class TestActivatePendingRecoveryCodeSet:
    """activate_pending_recovery_code_set_cur: the one-time confirmation that
    promotes a pending set to active."""

    async def test_malformed_confirmation_code_is_rejected_without_touching_the_database(self):
        cur = make_async_cursor()
        confirmed = await activate_pending_recovery_code_set_cur(
            cur, user_id=USER_ID, candidate_code="not-a-recovery-code"
        )
        assert confirmed is False
        cur.execute.assert_not_awaited()

    @pytest.mark.parametrize(
        "row",
        [None, {"totp_recovery_code_generation": 3, "pending_totp_recovery_code_generation": None}],
        ids=["no_such_user", "no_pending_generation_staged"],
    )
    async def test_missing_pending_generation_is_rejected(self, row):
        cur = make_async_cursor(fetchone=row)
        confirmed = await activate_pending_recovery_code_set_cur(
            cur, user_id=USER_ID, candidate_code="AAAAA-BBBBB-CCCCC-DDDDD"
        )
        assert confirmed is False
        assert cur.execute.await_count == 1

    async def test_pending_generation_not_newer_than_active_is_a_runtime_error(self):
        cur = make_async_cursor(
            fetchone={
                "totp_recovery_code_generation": 5,
                "pending_totp_recovery_code_generation": 5,
            }
        )
        with pytest.raises(RuntimeError, match="not newer than active set"):
            await activate_pending_recovery_code_set_cur(
                cur, user_id=USER_ID, candidate_code="AAAAA-BBBBB-CCCCC-DDDDD"
            )

    async def test_wrong_or_already_used_confirmation_code_is_rejected(self):
        cur = make_async_cursor(
            fetchone=[
                {"totp_recovery_code_generation": 5, "pending_totp_recovery_code_generation": 6},
                {"code_count": 10, "unused_count": 10, "candidate_count": 0},
            ]
        )
        confirmed = await activate_pending_recovery_code_set_cur(
            cur, user_id=USER_ID, candidate_code="AAAAA-BBBBB-CCCCC-DDDDD"
        )
        assert confirmed is False
        statements = [str(call.args[0]).strip().upper() for call in cur.execute.await_args_list]
        assert not any(statement.startswith("UPDATE") for statement in statements)

    async def test_matching_unused_confirmation_code_activates_the_pending_set(self):
        """Positive control for every rejection above."""
        cur = make_async_cursor(
            fetchone=[
                {"totp_recovery_code_generation": 5, "pending_totp_recovery_code_generation": 6},
                {"code_count": 10, "unused_count": 10, "candidate_count": 1},
            ]
        )
        confirmed = await activate_pending_recovery_code_set_cur(
            cur, user_id=USER_ID, candidate_code="AAAAA-BBBBB-CCCCC-DDDDD"
        )
        assert confirmed is True
        update_statement, update_params = cur.execute.await_args_list[-1].args
        assert "totp_recovery_code_generation" in update_statement
        assert "pending_totp_recovery_code_generation" in update_statement
        assert update_params == (6, USER_ID)


class TestFindActiveRecoveryCodeCandidate:
    """find_active_recovery_code_candidate_cur: the nonlocking public lookup."""

    async def test_malformed_code_returns_none_without_touching_the_database(self):
        cur = make_async_cursor()
        candidate = await find_active_recovery_code_candidate_cur(
            cur, user_id=USER_ID, active_generation=GENERATION, candidate_code="garbage"
        )
        assert candidate is None
        cur.execute.assert_not_awaited()

    async def test_non_positive_active_generation_returns_none_without_touching_the_database(self):
        cur = make_async_cursor()
        candidate = await find_active_recovery_code_candidate_cur(
            cur, user_id=USER_ID, active_generation=0, candidate_code="AAAAA-BBBBB-CCCCC-DDDDD"
        )
        assert candidate is None
        cur.execute.assert_not_awaited()

    async def test_unmatched_code_returns_none(self):
        cur = make_async_cursor(fetchone=None)
        candidate = await find_active_recovery_code_candidate_cur(
            cur,
            user_id=USER_ID,
            active_generation=GENERATION,
            candidate_code="AAAAA-BBBBB-CCCCC-DDDDD",
        )
        assert candidate is None

    async def test_matched_code_returns_the_exact_row_candidate(self):
        """Positive control above: an unknown code at the same generation returns None."""
        cur = make_async_cursor(fetchone={"position": POSITION})
        candidate = await find_active_recovery_code_candidate_cur(
            cur,
            user_id=USER_ID,
            active_generation=GENERATION,
            candidate_code="AAAAA-BBBBB-CCCCC-DDDDD",
        )
        assert candidate == MatchedRecoveryCodeCandidate(
            user_id=USER_ID,
            generation=GENERATION,
            position=POSITION,
            code_hash=hash_token("AAAAABBBBBCCCCCDDDDD"),
        )


class TestReserveRecoveryCodePasswordAttempt:
    """reserve_recovery_code_password_attempt_cur: the locking write that spends
    one password-attempt slot for an already-matched candidate."""

    async def test_stale_generation_returns_none_without_reserving(self):
        cur = make_async_cursor(fetchone={"totp_recovery_code_generation": GENERATION + 1})
        reserved = await reserve_recovery_code_password_attempt_cur(cur, candidate=_candidate())
        assert reserved is None
        assert cur.execute.await_count == 1

    async def test_missing_user_returns_none_without_reserving(self):
        cur = make_async_cursor(fetchone=None)
        reserved = await reserve_recovery_code_password_attempt_cur(cur, candidate=_candidate())
        assert reserved is None
        assert cur.execute.await_count == 1

    async def test_exhausted_or_already_used_row_returns_none(self):
        cur = make_async_cursor(fetchone=[{"totp_recovery_code_generation": GENERATION}, None])
        reserved = await reserve_recovery_code_password_attempt_cur(cur, candidate=_candidate())
        assert reserved is None

    async def test_matching_current_generation_reserves_the_exact_row(self):
        """Positive control above: a stale generation snapshot reserves nothing."""
        cur = make_async_cursor(
            fetchone=[{"totp_recovery_code_generation": GENERATION}, {"position": POSITION}]
        )
        reserved = await reserve_recovery_code_password_attempt_cur(cur, candidate=_candidate())
        assert reserved == ReservedRecoveryCodePasswordAttempt(
            user_id=USER_ID, generation=GENERATION, position=POSITION, code_hash=CODE_HASH
        )


class TestConsumeReservedRecoveryCode:
    """consume_reserved_recovery_code_cur: the final, single-use write."""

    async def test_stale_generation_leaves_the_code_unconsumed(self):
        cur = make_async_cursor(fetchone={"totp_recovery_code_generation": GENERATION + 1})
        consumed = await consume_reserved_recovery_code_cur(cur, reservation=_reservation())
        assert consumed is False
        assert cur.execute.await_count == 1

    async def test_matching_reservation_marks_the_row_used(self):
        """Positive control above: a stale generation snapshot never consumes the row."""
        cur = make_async_cursor(
            fetchone=[{"totp_recovery_code_generation": GENERATION}, {"position": POSITION}]
        )
        consumed = await consume_reserved_recovery_code_cur(cur, reservation=_reservation())
        assert consumed is True
        update_statement = str(cur.execute.await_args_list[-1].args[0])
        assert "used_at = clock_timestamp()" in update_statement


class TestHasUnusedActiveRecoveryCode:
    """has_unused_active_recovery_code_cur: the account-level "any codes left?" check."""

    async def test_non_positive_generation_returns_false_without_touching_the_database(self):
        cur = make_async_cursor()
        assert (
            await has_unused_active_recovery_code_cur(cur, user_id=USER_ID, active_generation=0)
            is False
        )
        cur.execute.assert_not_awaited()

    async def test_exhausted_generation_returns_false(self):
        cur = make_async_cursor(fetchone=None)
        assert (
            await has_unused_active_recovery_code_cur(
                cur, user_id=USER_ID, active_generation=GENERATION
            )
            is False
        )

    async def test_generation_with_an_unused_code_returns_true(self):
        """Positive control above: a generation with no unused rows returns False."""
        cur = make_async_cursor(fetchone={"?column?": 1})
        assert (
            await has_unused_active_recovery_code_cur(
                cur, user_id=USER_ID, active_generation=GENERATION
            )
            is True
        )


class TestDiscardPendingRecoveryCodeSet:
    """discard_pending_recovery_code_set_cur: clears a displayed-but-unconfirmed set."""

    async def test_discard_deletes_the_pending_generation_and_clears_the_pointer(self):
        cur = make_async_cursor()
        await discard_pending_recovery_code_set_cur(cur, user_id=USER_ID)
        assert cur.execute.await_count == 2
        delete_statement = str(cur.execute.await_args_list[0].args[0])
        update_statement, update_params = cur.execute.await_args_list[1].args
        assert "DELETE FROM totp_recovery_codes" in delete_statement
        assert "pending_totp_recovery_code_generation = NULL" in update_statement
        assert update_params == (USER_ID,)
