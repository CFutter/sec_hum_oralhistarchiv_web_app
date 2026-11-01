"""Fatal native feed failures preserve the committed source and its neighbours."""

import copy
from datetime import timedelta

import pytest

from app.services import ingestion
from tests.json_feed_fixtures import (
    DEFAULT_CUTOFF,
    SignedFeed,
    feed_uuid,
    provision_feed_source,
    snapshot_feed_source,
)

_PRIVATE = "fatalfeedprivatecanary"
_BUDGETS = {
    "page_bytes": "max_page_bytes",
    "total_bytes": "max_total_bytes",
    "record_bytes": "max_record_bytes",
    "record_count": "max_records",
    "page_count": "max_pages",
    "result_bytes": "max_result_bytes",
}


def _without_error(snapshot, channel):
    """Copy a snapshot, removing only the selected error channel and timestamp."""
    result = copy.deepcopy(snapshot)
    result["state"].pop(f"last_{channel}_error")
    result["state"].pop(f"last_{channel}_error_at")
    return result


@pytest.mark.parametrize("runner", [ingestion.run_sync, ingestion.run_full_rebuild])
@pytest.mark.parametrize(
    "failure",
    ["redirect", "signature", "utf8", "identity", *_BUDGETS, "deadline"],
)
async def test_fatal_native_fetch_preserves_all_committed_state_except_its_error(
    db_pool, sync_conn, monkeypatch, caplog, runner, failure
):
    """A failed complete fetch publishes no partial input.

    SB-VIS-007, SB-TRANS-001, SB-TRANS-002, SB-TRANS-003, SB-TRANS-004.
    """
    feed = SignedFeed(monkeypatch)
    source = feed.source()
    foreign = feed.source(name="retained_archive")
    records = [feed.record(feed_uuid(number)) for number in range(1, 4)]
    for selected in (source, foreign):
        await provision_feed_source(db_pool, selected)
        feed.set_snapshot(records)
        outcome = await ingestion.run_full_rebuild(db_pool, configured_source=selected)
        assert outcome.status == "success"
    before = snapshot_feed_source(sync_conn, source.name)
    other_before = snapshot_feed_source(sync_conn, foreign.name)
    incoming = [
        feed.record(feed_uuid(number), marker=_PRIVATE, title=f"Pending replacement {number}")
        for number in range(1, 4)
    ]
    if failure == "utf8":
        incoming[1] = b'"\xff"'
    elif failure == "identity":
        incoming[1] = feed.duplicate_field(incoming[1], "uuid", feed_uuid(2))
    feed.set_snapshot(
        incoming,
        withdrawn=(feed_uuid(99),),
        cutoff=DEFAULT_CUTOFF + timedelta(hours=1),
        page_size=1,
    )
    if failure in _BUDGETS:
        budget = 2 if failure == "record_count" else 1
        source = feed.source(**{_BUDGETS[failure]: budget})
        assert source.adapter.config_fingerprint() == before["state"]["source_fingerprint"]
    elif failure == "redirect":
        feed.status_code = 302
    elif failure == "signature":
        feed.signature_mode = "wrong"
    elif failure == "deadline":
        # The synthetic process boundary supplies an already-expired deadline;
        # the production collector and its deadline check remain real.
        feed.expired_deadline = True

    feed.clear_calls()
    caplog.clear()
    outcome = await runner(db_pool, configured_source=source)
    assert outcome.status == "failed" and not outcome.requires_full_rebuild
    after = snapshot_feed_source(sync_conn, source.name)
    channel = "sync" if runner is ingestion.run_sync else "rebuild"
    assert _without_error(after, channel) == _without_error(before, channel)
    assert after["state"][f"last_{channel}_error"]
    assert after["state"][f"last_{channel}_error_at"]
    assert snapshot_feed_source(sync_conn, foreign.name) == other_before
    assert _PRIVATE not in repr(after)
    assert _PRIVATE not in (outcome.reason or "")
    assert _PRIVATE not in caplog.text
    if failure in {"utf8", "identity", "record_count"}:
        assert len(feed.requests) >= 2, "the first valid page must precede rejection"
    if failure == "page_count":
        assert len(feed.requests) == 1, "the next page must be refused before HTTP"
    if failure == "deadline":
        assert feed.requests == []
