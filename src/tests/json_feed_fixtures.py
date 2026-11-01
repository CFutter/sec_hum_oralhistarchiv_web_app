"""Signed native feed scenarios; only HTTP and the worker boundary are isolated."""

import base64
import copy
import hashlib
import hmac
import io
import json
import time
from datetime import UTC, datetime
from unittest.mock import create_autospec

import requests
from urllib3._collections import HTTPHeaderDict
from urllib3.response import HTTPResponse

from app.ingestion_contracts.cancellation import check_harvest_cancellation
from app.services import ensure_source_status_rows, harvest_result_from_document
from app.sources import JsonFeedConfig, configure_sources, prepare_json_feed_startup
from app.sources import json_feed_fetch as fetch_module

DEFAULT_CUTOFF = datetime(2030, 1, 4, tzinfo=UTC)


def feed_uuid(number):
    """Format a synthetic UUIDv4; number must be an unsigned 32-bit integer."""
    return f"{number:08x}-0000-4000-8000-{number:012x}"


class SignedFeed:
    """Mutable upstream scenarios exercising real adapter/authentication/parser code.

    ConfiguredSource, adapter.fetch, exact HMAC verification, decoding, record
    classification, candidate serialization and ingestion remain real. The
    direct collector replaces process isolation so its HTTP fixture is visible.
    It is not evidence for process termination; those unit tests remain separate.
    """

    def __init__(self, monkeypatch):
        """Initialize a mutable feed scenario and patch HTTP, collection and source time through
        monkeypatch.
        """
        self.requests = []
        self.worker_calls = []
        self.cutoff = DEFAULT_CUTOFF
        self.records = []
        self.withdrawn = []
        self.page_size = 2
        self.signature_mode = "valid"
        self.status_code = 200
        self.expired_deadline = False
        self._sources = {}
        real_session = requests.Session
        real_fetch = fetch_module.fetch_json_feed_isolated
        real_collect = fetch_module.collect_feed_payload
        real_now = fetch_module._utc_now

        def session():
            """Create a real session with its GET method replaced by the recorded-response double."""
            instance = real_session()
            instance.get = create_autospec(instance.get, spec_set=True, side_effect=self._get)
            return instance

        def direct_fetch(config, credentials, *, since, cancel_event=None):
            """Run the real feed collector in-process after cancellation checks and decode its
            harvest.
            """
            check_harvest_cancellation(cancel_event)
            self.worker_calls.append((config.name, since))
            payload = real_collect(
                config,
                credentials,
                since=since,
                deadline=time.monotonic()
                + (-1 if self.expired_deadline else config.fetch_deadline_seconds),
            )
            return harvest_result_from_document(json.loads(payload))

        monkeypatch.setattr(
            requests, "Session", create_autospec(real_session, spec_set=True, side_effect=session)
        )
        monkeypatch.setattr(
            fetch_module,
            "fetch_json_feed_isolated",
            create_autospec(real_fetch, spec_set=True, side_effect=direct_fetch),
        )
        monkeypatch.setattr(
            fetch_module,
            "_utc_now",
            create_autospec(real_now, spec_set=True, side_effect=lambda: self.cutoff),
        )

    def source(self, name="sensitive_archive", floor="public", **changes):
        """Construct a real registered adapter from explicit synthetic credentials."""
        config = JsonFeedConfig.model_validate(
            {
                "name": name,
                "display": {"label": "Synthetic sensitive archive"},
                "endpoint": f"https://feed.example.edu/{name}",
                "credential_env": f"{name.upper()}_BEARER",
                "signing_key_env": f"{name.upper()}_KEY",
                "max_visibility": floor,
                **changes,
            }
        )
        key = hashlib.sha256(f"synthetic feed key {name}".encode()).digest()
        bearer = (
            base64.urlsafe_b64encode(
                hashlib.sha256(f"synthetic bearer independent {name}".encode()).digest()
            )
            .decode()
            .rstrip("=")
        )
        credentials = prepare_json_feed_startup(
            (config,),
            environment="dev",
            environ={
                config.credential_env: bearer,
                config.signing_key_env: base64.urlsafe_b64encode(key).decode().rstrip("="),
            },
        )
        self._sources[config.endpoint] = (credentials[0], key)
        return configure_sources((config,), credentials=credentials)[0]

    @staticmethod
    def record(uuid, *, marker="privatefeedcanary", **changes):
        """Return complete wire metadata whose public fields contain no private marker."""
        return {
            "uuid": uuid,
            "title": f"Discovery record {uuid[:8]}",
            "project_title": f"{marker} project",
            "description": f"{marker} description",
            "resource_description": f"{marker} resource",
            "languages": [f"{marker}language"],
            "project_description": f"{marker} project description",
            "authors": [f"{marker} author"],
            "keywords": [f"{marker}keyword"],
            "resource_proxies": [
                {"type": "Resource", "ref": f"https://archive.example.org/{marker}/resource"},
                {"type": "LandingPage", "ref": f"https://archive.example.org/{marker}/landing"},
            ],
            "license_val": "Restricted access",
            "license_url": f"https://archive.example.org/{marker}/license",
            "version": "1.0",
            "doi": f"10.99999/{uuid}",
            "resource_type": f"{marker} audio",
            "institutions": [f"{marker} institution"],
            "main_disciplines": [f"{marker} discipline"],
            "bibliographical_citation": f"{marker} citation",
            "modified_at": "2030-01-03T12:00:00Z",
            "visibility_tier": "public",
            **changes,
        }

    @staticmethod
    def duplicate_field(record, field, value):
        """Return raw JSON preserving duplicate-key evidence for the real decoder."""
        original = json.dumps(record, separators=(",", ":")).encode()
        addition = json.dumps({field: value}, separators=(",", ":")).encode()[1:]
        return original[:-1] + b"," + addition

    def set_snapshot(self, records, *, withdrawn=(), cutoff=DEFAULT_CUTOFF, page_size=2):
        """Select a stable snapshot; dictionaries and raw duplicate-key bytes are accepted."""
        self.records = copy.deepcopy(list(records))
        self.withdrawn = list(withdrawn)
        self.cutoff = cutoff
        self.page_size = page_size
        self.signature_mode = "valid"
        self.status_code = 200
        self.expired_deadline = False

    def clear_calls(self):
        """Clear recorded HTTP requests and worker invocations."""
        self.requests.clear()
        self.worker_calls.clear()

    def _get(self, url, *, params, headers, timeout, allow_redirects, stream, verify):
        """Validate request options and return a paginated, signed synthetic HTTP response."""
        credentials, key = self._sources[url]
        assert allow_redirects is False and stream is True and verify is True
        assert headers == {
            "Authorization": f"Bearer {credentials.bearer_token.get_secret_value()}",
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        }
        assert all(0 < value <= 10 for value in timeout)
        self.requests.append(dict(params))
        cursor = params.get("cursor")
        page = int(cursor.removeprefix("synthetic-page-")) if cursor else 0
        start = page * self.page_size
        selected = self.records[start : start + self.page_size]
        next_cursor = (
            f"synthetic-page-{page + 1}" if start + self.page_size < len(self.records) else None
        )
        document = {
            "feed_version": 1,
            "snapshot_id": feed_uuid(999),
            "generated_at": self.cutoff.isoformat().replace("+00:00", "Z"),
            "request": {"nonce": params["nonce"], "since": params.get("since"), "cursor": cursor},
            "records": [],
            "withdrawn": self.withdrawn if page == 0 else [],
            "next_cursor": next_cursor,
            "complete": next_cursor is None,
        }
        raw_records = b",".join(
            record
            if isinstance(record, bytes)
            else json.dumps(record, separators=(",", ":")).encode()
            for record in selected
        )
        body = (
            json.dumps(document, separators=(",", ":"))
            .encode()
            .replace(b'"records":[]', b'"records":[' + raw_records + b"]")
        )
        digest = hmac.new(key, body, hashlib.sha256).hexdigest()
        response_headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }
        if self.signature_mode != "missing":
            response_headers["X-Feed-Signature"] = (
                f"v1={digest}" if self.signature_mode == "valid" else "v1=" + "0" * 64
            )
        response = requests.Response()
        response.status_code = self.status_code
        response.raw = HTTPResponse(
            body=io.BytesIO(body),
            preload_content=False,
            enforce_content_length=False,
            headers=HTTPHeaderDict(response_headers),
        )
        return response


async def provision_feed_source(pool, source):
    """Create only its unbound status row; the real rebuild must establish binding."""
    await ensure_source_status_rows(pool, (source.name,))


def snapshot_feed_source(conn, source):
    """Read cursor, raw records, failures and admin state; close the observer transaction.

    Quarantine and search projections need separate assertions: rejected corrections
    can preserve raw records while deliberately changing serving eligibility."""
    state = conn.execute(
        "SELECT to_jsonb(status) FROM sync_status AS status WHERE source = %s", (source,)
    ).fetchone()
    rows = conn.execute(
        "SELECT to_jsonb(dataset) FROM oral_history_datasets AS dataset WHERE source = %s ORDER BY uuid",
        (source,),
    ).fetchall()
    failures = conn.execute(
        "SELECT to_jsonb(failure) FROM ingestion_failures AS failure WHERE source = %s ORDER BY uuid",
        (source,),
    ).fetchall()
    admin = conn.execute(
        "SELECT to_jsonb(state) FROM dataset_admin_state AS state WHERE source = %s ORDER BY uuid",
        (source,),
    ).fetchall()
    conn.commit()
    return {
        "state": state[0] if state else None,
        "rows": [row[0] for row in rows],
        "failures": [row[0] for row in failures],
        "admin": [row[0] for row in admin],
    }
