"""Real signed native pages through the feed adapter, parser and serializer.

Only HTTP session construction and the complete-fetch process boundary are
replaced. Requests methods retain their real signatures; body streams and
exact-byte HMAC authentication remain real. No accepted harvest is fabricated.
"""

import base64
import hashlib
import hmac
import io
import json
import time
from datetime import UTC, datetime
from unittest.mock import create_autospec

import pytest
import requests
from urllib3._collections import HTTPHeaderDict
from urllib3.response import HTTPResponse

from app.ingestion_contracts.cancellation import check_harvest_cancellation
from app.paths import PROJECT_ROOT
from app.services import harvest_result_from_document
from app.sources import (
    FeedTransportError,
    JsonFeedAdapter,
    JsonFeedConfig,
    prepare_json_feed_startup,
)
from app.sources import json_feed_fetch as fetch_module
from tests.sources.contracts import Case

_ENDPOINT = "https://feed.example.edu/catalogue"
_CURSOR = datetime(2020, 1, 4, tzinfo=UTC)
_BOUNDARY = datetime(2020, 1, 2, 12, tzinfo=UTC)
_KEY = hashlib.sha256(b"synthetic conformance feed signing key").digest()
_ENVIRON = {
    "CONTRACT_FEED_BEARER": base64.urlsafe_b64encode(
        hashlib.sha256(b"separate synthetic conformance bearer credential").digest()
    )
    .decode()
    .rstrip("="),
    "CONTRACT_FEED_KEY": base64.urlsafe_b64encode(_KEY).decode().rstrip("="),
}
_VALUES = {
    "name": "contract_archive",
    "adapter": "json_feed",
    "display": {"label": "Contract archive"},
    "max_visibility": "public",
    "requires_record_tier": True,
    "endpoint": _ENDPOINT,
    "credential_env": "CONTRACT_FEED_BEARER",
    "signing_key_env": "CONTRACT_FEED_KEY",
    "max_pages": 7,
}


def _records():
    """Read the two example feed pages and assign ordered modification timestamps."""
    directory = PROJECT_ROOT / "docs/sources/examples"
    first = json.loads((directory / "feed-v1-full-page-1.json").read_text())
    second = json.loads((directory / "feed-v1-full-page-2.json").read_text())
    records = first["records"] + second["records"]
    for index, record in enumerate(records, start=1):
        record["modified_at"] = f"2020-01-0{index}T12:00:00Z"
    return records


def make_case(monkeypatch: pytest.MonkeyPatch) -> Case:
    """Install signed-page HTTP and in-process worker doubles; return the adapter conformance case."""
    io_calls: list[dict[str, object]] = []
    records = _records()
    config = JsonFeedConfig.model_validate(_VALUES)
    credentials = prepare_json_feed_startup((config,), environment="dev", environ=_ENVIRON)[0]
    original_session = requests.Session
    original_fetch = fetch_module.fetch_json_feed_isolated
    original_collect = fetch_module.collect_feed_payload
    original_now = fetch_module._utc_now

    def recorded_get(url, *, params, headers, timeout, allow_redirects, stream, verify):
        """Validate feed request options and return the matching signed synthetic page."""
        assert url == _ENDPOINT
        assert allow_redirects is False and stream is True and verify is True
        assert all(0 < value <= 10 for value in timeout)
        assert headers == {
            "Authorization": f"Bearer {credentials.bearer_token.get_secret_value()}",
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        }
        io_calls.append({"url": url, "params": dict(params)})
        assert set(params) <= {"nonce", "since", "cursor"} and "nonce" in params
        since = params.get("since")
        selected = [record for record in records if since is None or record["modified_at"] >= since]
        cursor = params.get("cursor")
        assert cursor in (None, "contract-page-2")
        page_records = selected[:1] if cursor is None else selected[1:]
        next_cursor = "contract-page-2" if cursor is None and len(selected) > 1 else None
        document = {
            "feed_version": 1,
            "snapshot_id": "00000000-0000-4000-8000-000000000001",
            "generated_at": "2020-01-04T00:00:00Z",
            "request": {"nonce": params["nonce"], "since": since, "cursor": cursor},
            "records": page_records,
            "withdrawn": [],
            "next_cursor": next_cursor,
            "complete": next_cursor is None,
        }
        body = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()
        signature = hmac.new(_KEY, body, hashlib.sha256).hexdigest()
        response = requests.Response()
        response.status_code = 200
        response.raw = HTTPResponse(
            body=io.BytesIO(body),
            preload_content=False,
            enforce_content_length=False,
            headers=HTTPHeaderDict(
                {
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    "X-Feed-Signature": f"v1={signature}",
                }
            ),
        )
        return response

    def recorded_session():
        """Create a real session with its GET method replaced by the recorded-response double."""
        session = original_session()
        session.get = create_autospec(session.get, spec_set=True, side_effect=recorded_get)
        return session

    def direct_fetch(config, credentials, *, since, cancel_event=None):
        """Run the real feed collector in-process after cancellation checks and decode its harvest."""
        check_harvest_cancellation(cancel_event)
        payload = original_collect(
            config,
            credentials,
            since=since,
            deadline=time.monotonic() + config.fetch_deadline_seconds,
        )
        return harvest_result_from_document(json.loads(payload))

    monkeypatch.setattr(
        requests,
        "Session",
        create_autospec(original_session, spec_set=True, side_effect=recorded_session),
    )
    monkeypatch.setattr(
        fetch_module,
        "fetch_json_feed_isolated",
        create_autospec(original_fetch, spec_set=True, side_effect=direct_fetch),
    )
    monkeypatch.setattr(
        fetch_module,
        "_utc_now",
        create_autospec(original_now, spec_set=True, return_value=_CURSOR),
    )
    return Case(
        adapter_id="json_feed",
        adapter_type=JsonFeedAdapter,
        values=_VALUES,
        document="""[[sources]]
name = "contract_archive"
adapter = "json_feed"
label = "Contract archive"
max_visibility = "public"
requires_record_tier = true
endpoint = "https://feed.example.edu/catalogue"
credential_env = "CONTRACT_FEED_BEARER"
signing_key_env = "CONTRACT_FEED_KEY"
max_pages = 7
""",
        cursor=_CURSOR,
        boundary=_BOUNDARY,
        full_ids=tuple(record["uuid"] for record in records),
        boundary_ids=tuple(record["uuid"] for record in records[1:]),
        raw_tiers=("public", "registered", "vetted"),
        expected_registered_tiers=("registered", "registered", "vetted"),
        operational_overrides={
            "display": {"label": "Renamed archive", "sensitivity_badge": "Examples"},
            "schedule": {
                "incremental_interval_seconds": 900,
                "rebuild_interval_seconds": 43200,
                "write_timeout_seconds": 240,
            },
            "max_pages": 11,
            "fetch_deadline_seconds": 60,
        },
        insufficient_budget={"max_pages": 1},
        budget_error=FeedTransportError,
        budget_match="resource budget was exceeded",
        io_calls=io_calls,
        environ=_ENVIRON,
        mandatory_record_tier=True,
    )
