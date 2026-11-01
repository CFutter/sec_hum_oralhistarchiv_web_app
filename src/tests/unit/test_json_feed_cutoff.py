"""JSON-feed cutoff rollback is fenced before staging or catalogue mutation."""

import base64
import hashlib
import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec, patch

import pytest

from app import services
from app.paths import PROJECT_ROOT
from app.services import ingestion
from app.services.stored_harvest import decode_stored_harvest, encode_stored_harvest
from app.sources import (
    AuthenticatedFeedPage,
    FeedRequest,
    JsonFeedConfig,
    JsonFeedHarvestBuilder,
    configure_sources,
    prepare_json_feed_startup,
)
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool
from tests.ingestion_doubles import add_dataset_returning
from tests.source_fixtures import legacy_source

_NOW = datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)
_MESSAGE = "JSON feed snapshot predates the committed source cursor"
_CANARY = "private-committed-cursor-canary"


def _source():
    """Configure a synthetic public JSON feed with development credentials."""
    config = JsonFeedConfig.model_validate(
        {
            "name": "feed_archive",
            "display": {"label": "Feed archive"},
            "endpoint": "https://archive.example.org/feed",
            "max_visibility": "public",
            "credential_env": "FEED_TOKEN",
            "signing_key_env": "FEED_KEY",
        }
    )
    credentials = prepare_json_feed_startup(
        (config,),
        environment="dev",
        environ={
            "FEED_TOKEN": "kR9vT2xW7pL4qN8mZ3cB6fH1jD5gS0aY4eU9iO2wQ7rM5tK8",
            "FEED_KEY": base64.urlsafe_b64encode(hashlib.sha256(b"cutoff signing fixture").digest())
            .decode()
            .rstrip("="),
        },
    )
    return configure_sources((config,), credentials=credentials)[0]


def _harvest(source, *, cutoff=_NOW, matching=True, uncertain=False):
    """Build and classify an example-based harvest at cutoff with optional matching/uncertain
    records.
    """
    document = json.loads(
        (PROJECT_ROOT / "docs/sources/examples/feed-v1-full-page-1.json").read_text()
    )
    records = document["records"][:1] if matching else []
    if uncertain:
        records.append({**document["records"][1], "title": [_CANARY]})
    request = FeedRequest("a" * 64, None, None)
    document.update(
        generated_at=cutoff.isoformat().replace("+00:00", "Z"),
        records=records,
        withdrawn=["44444444-4444-4444-8444-444444444444"],
        complete=True,
        next_cursor=None,
    )
    builder = JsonFeedHarvestBuilder(source.config, since=None)
    builder.accept(AuthenticatedFeedPage(request, json.dumps(document).encode()), now=cutoff)
    return services.harvest_result_from_document(json.loads(builder.finish()))


def _row(source, committed, pending=None):
    """Return committed/pending ingestion state using the source configuration fingerprint."""
    return {
        "source_cursor": committed,
        "source_fingerprint": source.adapter.config_fingerprint(),
        "incremental_harvest": pending,
        "incremental_started_at": _NOW if pending else None,
        "incremental_position": 0,
        "incremental_affected": 0,
        "existing_count": 10,
        "inferred_delete_count": 0,
        "had_failures": False,
    }


def _cursor(row):
    """Return a dataset-writing fake cursor with nested transaction support."""
    cur = add_dataset_returning(make_async_cursor(fetchone=row, rowcount=1))
    cur.connection.transaction.return_value = FakeCursorCtx(cur)
    return cur


@contextmanager
def _db(cur):
    """Temporarily route ingestion queries to cur and hide prior tier state."""
    real_read = ingestion.read_tier_state_cur
    with (
        patch.object(
            ingestion, "get_db_cursor", autospec=True, side_effect=lambda _pool: FakeCursorCtx(cur)
        ),
        patch.object(
            ingestion,
            "read_tier_state_cur",
            new=create_autospec(real_read, spec_set=True, return_value=None),
        ),
    ):
        yield


def _fetch(source, harvest):
    """Return a signature-checked patch supplying harvest from the adapter fetch."""
    real = type(source.adapter).fetch
    return patch.object(
        type(source.adapter),
        "fetch",
        new=create_autospec(real, spec_set=True, return_value=harvest),
    )


def _mutations(cur):
    """Return captured statements that change catalogue, failure or ingestion-progress state."""
    return [
        call
        for call in cur.execute.await_args_list
        if any(
            token in str(call.args[0])
            for token in (
                "oral_history_datasets",
                "ingestion_failures",
                "incremental_harvest =",
                "incremental_position =",
                "source_cursor =",
                "source_fetch_cursor =",
            )
        )
    ]


@pytest.mark.parametrize("entry", ["new", "replay", "apply", "rebuild", "empty_rebuild"])
@pytest.mark.parametrize(
    "committed", [_NOW + timedelta(seconds=1), _NOW.replace(tzinfo=None), _CANARY]
)
@pytest.mark.parametrize("cursor_column", ["source_cursor", "source_fetch_cursor"])
async def test_stale_or_invalid_committed_cutoff_blocks_all_catalogue_and_staging_work(
    entry, committed, cursor_column
):
    """Stale or invalid committed cutoff blocks all catalogue and staging work."""
    source = _source()
    harvest = _harvest(source, matching=entry != "empty_rebuild", uncertain=True)
    payload = encode_stored_harvest(harvest, source_fingerprint=source.adapter.config_fingerprint())
    row = _row(source, _NOW - timedelta(days=1), payload if entry == "replay" else None)
    row[cursor_column] = committed
    cur = _cursor(row)
    real_encode = ingestion.encode_stored_harvest_parts
    encode = create_autospec(real_encode, spec_set=True, side_effect=real_encode)
    with (
        _db(cur),
        _fetch(source, harvest) as fetch,
        patch.object(ingestion, "encode_stored_harvest_parts", new=encode),
    ):
        if entry == "new":
            outcome = await ingestion._sync_source(make_mock_pool(), configured_source=source)
            assert outcome.status == "failed" and _CANARY not in outcome.reason
            if committed == _NOW + timedelta(seconds=1):
                assert outcome.reason == "ValueError: " + _MESSAGE
                fetch.assert_called_once()
            else:
                fetch.assert_not_called()
        else:
            error_type = ValueError if "rebuild" in entry else ingestion._FullReharvestRequired
            with pytest.raises(error_type, match=_MESSAGE):
                if entry == "replay":
                    await ingestion._sync_source(make_mock_pool(), configured_source=source)
                elif entry == "apply":
                    await ingestion._apply_incremental_harvest(
                        make_mock_pool(), harvest, _NOW, configured_source=source
                    )
                else:
                    await ingestion._apply_full_harvest(
                        make_mock_pool(),
                        harvest,
                        _NOW,
                        configured_source=source,
                        source_fingerprint=source.adapter.config_fingerprint(),
                        staged_payload_to_clear=payload,
                    )
            fetch.assert_not_called()
    encode.assert_not_called()
    assert not _mutations(cur)


@pytest.mark.parametrize("entry", ["new", "rebuild"])
@pytest.mark.parametrize("committed", [None, _NOW, _NOW - timedelta(seconds=1)])
async def test_missing_equal_or_older_commitment_allows_real_engine_writes(entry, committed):
    """Missing equal or older commitment allows real engine writes."""
    source = _source()
    harvest = _harvest(source)
    cur = _cursor(_row(source, committed))
    real_upsert = ingestion._upsert_public_catalogue_record
    upsert = create_autospec(real_upsert, spec_set=True, side_effect=real_upsert)
    with (
        _db(cur),
        _fetch(source, harvest) as fetch,
        patch.object(ingestion, "_upsert_public_catalogue_record", new=upsert),
    ):
        operation = ingestion._sync_source if entry == "new" else ingestion._full_rebuild_source
        outcome = await operation(make_mock_pool(), configured_source=source)
    assert outcome.status == "success"
    upsert.assert_awaited_once()
    fetch.assert_called_once()
    expected_since = committed - timedelta(days=2) if entry == "new" and committed else None
    assert fetch.call_args.kwargs["since"] == expected_since
    publications = [
        call for call in cur.execute.await_args_list if "source_cursor =" in str(call.args[0])
    ]
    assert len(publications) == 1 and _NOW in publications[0].args[1]
    stages = [call for call in cur.execute.await_args_list if "%s::bytea" in str(call.args[0])]
    assert len(stages) == (1 if entry == "new" else 0)
    if stages:
        prefix, body, suffix, *_ = stages[0].args[1]
        assert (
            decode_stored_harvest(
                prefix + body + suffix,
                expected_source_fingerprint=source.adapter.config_fingerprint(),
            )
            == harvest
        )


async def test_full_rebuild_rereads_cutoff_after_pending_replay_advances_it():
    """Full rebuild rereads cutoff after pending replay advances it."""
    source = _source()
    pending = _harvest(source, cutoff=_NOW + timedelta(days=1))
    payload = encode_stored_harvest(pending, source_fingerprint=source.adapter.config_fingerprint())
    before = _row(source, _NOW, payload)
    cur = _cursor([before, before, before, {"source_cursor": pending.source_cursor}])
    real_stamp, real_publish = (
        ingestion._update_sync_timestamp,
        ingestion._update_full_rebuild_timestamp,
    )
    stamp = create_autospec(real_stamp, spec_set=True, side_effect=real_stamp)
    publish = create_autospec(real_publish, spec_set=True, side_effect=real_publish)
    real_stale = ingestion._delete_stale_source_records
    stale = create_autospec(real_stale, spec_set=True, side_effect=real_stale)
    with (
        _db(cur),
        _fetch(source, _harvest(source)),
        patch.object(ingestion, "_update_sync_timestamp", new=stamp),
        patch.object(ingestion, "_update_full_rebuild_timestamp", new=publish),
        patch.object(ingestion, "_delete_stale_source_records", new=stale),
        pytest.raises(ValueError, match=_MESSAGE),
    ):
        await ingestion._full_rebuild_source(make_mock_pool(), configured_source=source)
    stamp.assert_awaited_once()
    assert stamp.call_args.kwargs["source_cursor"] == pending.source_cursor
    publish.assert_not_awaited()
    stale.assert_not_awaited()
    texts = [str(call.args[0]) for call in cur.execute.await_args_list]
    last_read = next(
        index
        for index, text in enumerate(texts)
        if text == "SELECT source_cursor, source_fetch_cursor FROM sync_status WHERE source = %s"
    )
    assert not any(
        "oral_history_datasets" in text or "incremental_harvest =" in text
        for text in texts[last_read + 1 :]
    )


@pytest.mark.parametrize("entry", ["new", "rebuild"])
async def test_legacy_source_retains_its_existing_cursor_semantics(entry):
    """Legacy source retains its existing cursor semantics."""
    source = legacy_source(max_visibility="public")
    harvest = _harvest(_source())
    cur = _cursor(_row(source, _NOW + timedelta(days=1)))
    with _db(cur), _fetch(source, harvest):
        operation = ingestion._sync_source if entry == "new" else ingestion._full_rebuild_source
        outcome = await operation(make_mock_pool(), configured_source=source)
    assert outcome.status == "success"
    assert not any(
        "SELECT source_cursor FROM" in str(call.args[0]) for call in cur.execute.await_args_list
    )
