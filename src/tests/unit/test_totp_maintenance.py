"""Unit tests for `app.services.totp_maintenance`: the bounded, writers-stopped
reads used by the TOTP key-rotation maintenance procedure (`scripts/reencrypt_totp.py`).

`secret_pages` is an async generator that pages through users with a TOTP
secret set, ordered by id, without holding a database connection open while
the caller processes a batch — each page acquires and releases its own
`get_db_cursor` context, so a long-running re-encryption pass never pins a
pool connection between batches. `rotation_secret_pages` is the same
contract for the session-bound replacement credentials in
`pending_totp_rotations`, paged by `user_id` instead of `id`.

Pure unit tests: no DB, `get_db_cursor` is patched with an async context
manager over a mock cursor.
"""

from contextlib import asynccontextmanager
from unittest.mock import create_autospec, patch

import pytest

import app.services.totp_maintenance as totp_maintenance_module
from app.services.totp_maintenance import (
    _MAX_BATCH_SIZE,
    rotation_secret_pages,
    secret_pages,
)
from tests.fixtures import make_async_cursor


class TestSecretPagesBatching:
    """`secret_pages` yields bounded pages and never holds a connection across batches."""

    async def test_pages_release_the_connection_and_advance_by_last_id_between_batches(self):
        """Each page is read under its own `get_db_cursor` context (released
        before the caller sees the page), and the next page's query starts
        strictly after the last id already yielded — a rotation over a large
        user table must not pin a connection for its whole duration nor
        re-read rows it already processed."""
        cursor = make_async_cursor()
        cursor.fetchall.side_effect = [[{"id": 2}, {"id": 7}], [{"id": 11}], []]
        held = False

        @asynccontextmanager
        async def page_cursor(_pool):
            nonlocal held
            assert not held
            held = True
            try:
                yield cursor
            finally:
                held = False

        ids = []
        with patch.object(
            totp_maintenance_module,
            "get_db_cursor",
            create_autospec(
                totp_maintenance_module.get_db_cursor,
                side_effect=page_cursor,
                spec_set=True,
            ),
        ):
            async for rows in secret_pages(object(), 2):
                assert not held  # No read connection is held while processing a batch.
                assert len(rows) <= 2
                ids.extend(row["id"] for row in rows)
        assert ids == [2, 7, 11]
        assert [call.args[1] for call in cursor.execute.await_args_list] == [
            (0, 2),
            (7, 2),
            (11, 2),
        ]

    async def test_no_matching_rows_yields_no_pages(self):
        """Positive control above: rows do accumulate across pages when present."""
        cursor = make_async_cursor(fetchall=[])
        acquire = create_autospec(
            totp_maintenance_module.get_db_cursor,
            side_effect=lambda _pool: _single_use_cursor(cursor),
            spec_set=True,
        )
        with patch.object(totp_maintenance_module, "get_db_cursor", acquire):
            pages = [rows async for rows in secret_pages(object(), 2)]
        assert pages == []


class TestSecretPagesValidation:
    """`secret_pages` rejects a batch size outside its supported range."""

    @pytest.mark.parametrize(
        "batch_size",
        [0, -1, _MAX_BATCH_SIZE + 1],
        ids=["zero_is_too_small", "negative_is_too_small", "one_past_the_maximum"],
    )
    async def test_out_of_range_batch_size_is_rejected(self, batch_size):
        with pytest.raises(ValueError, match="batch_size must be between 1"):
            async for _ in secret_pages(object(), batch_size):
                pass

    @pytest.mark.parametrize(
        "batch_size", [1, _MAX_BATCH_SIZE], ids=["minimum_batch_size", "maximum_batch_size"]
    )
    async def test_boundary_batch_sizes_are_accepted(self, batch_size):
        """Positive control above: the values immediately outside the range are rejected."""
        cursor = make_async_cursor(fetchall=[])
        acquire = create_autospec(
            totp_maintenance_module.get_db_cursor,
            side_effect=lambda _pool: _single_use_cursor(cursor),
            spec_set=True,
        )
        with patch.object(totp_maintenance_module, "get_db_cursor", acquire):
            pages = [rows async for rows in secret_pages(object(), batch_size)]
        assert pages == []


@asynccontextmanager
async def _single_use_cursor(cursor):
    yield cursor


class TestRotationSecretPagesValidation:
    """`rotation_secret_pages` shares the same batch-size contract as `secret_pages`."""

    @pytest.mark.parametrize(
        "batch_size",
        [0, -5, _MAX_BATCH_SIZE + 1],
        ids=["zero_is_too_small", "negative_is_too_small", "one_past_the_maximum"],
    )
    async def test_out_of_range_batch_size_is_rejected(self, batch_size):
        with pytest.raises(ValueError, match="batch_size must be between 1"):
            async for _ in rotation_secret_pages(object(), batch_size):
                pass

    async def test_in_range_batch_size_is_accepted(self):
        """Positive control above: values outside the range are rejected before any query."""
        cursor = make_async_cursor(fetchall=[])
        acquire = create_autospec(
            totp_maintenance_module.get_db_cursor,
            side_effect=lambda _pool: _single_use_cursor(cursor),
            spec_set=True,
        )
        with patch.object(totp_maintenance_module, "get_db_cursor", acquire):
            pages = [rows async for rows in rotation_secret_pages(object(), 500)]
        assert pages == []


class TestRotationSecretPagesBatching:
    """`rotation_secret_pages` pages session-bound replacement credentials by user_id,
    releasing its connection between batches exactly like `secret_pages`.
    """

    async def test_pages_release_the_connection_and_advance_by_last_user_id_between_batches(self):
        cursor = make_async_cursor()
        cursor.fetchall.side_effect = [
            [
                {"user_id": 3, "encrypted_secret": "cipher-a"},
                {"user_id": 9, "encrypted_secret": "cipher-b"},
            ],
            [{"user_id": 15, "encrypted_secret": "cipher-c"}],
            [],
        ]
        held = False

        @asynccontextmanager
        async def page_cursor(_pool):
            nonlocal held
            assert not held
            held = True
            try:
                yield cursor
            finally:
                held = False

        user_ids = []
        with patch.object(
            totp_maintenance_module,
            "get_db_cursor",
            create_autospec(
                totp_maintenance_module.get_db_cursor,
                side_effect=page_cursor,
                spec_set=True,
            ),
        ):
            async for rows in rotation_secret_pages(object(), 2):
                assert not held
                assert len(rows) <= 2
                user_ids.extend(row["user_id"] for row in rows)
        assert user_ids == [3, 9, 15]
        assert [call.args[1] for call in cursor.execute.await_args_list] == [
            (0, 2),
            (9, 2),
            (15, 2),
        ]
