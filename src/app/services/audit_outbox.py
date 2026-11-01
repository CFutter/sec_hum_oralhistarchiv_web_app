"""Transaction-bound security events and acknowledged, idempotent delivery.

Producers append identities and restriction state with their mutation cursor.
An owner-operated exporter sends committed events to an independent HTTPS sink.
The sink must durably store and deduplicate an event before acknowledging its ID.
"""

import json
import re
from collections.abc import Iterable, Mapping
from http import HTTPStatus
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import psycopg
import requests
from psycopg import AsyncCursor
from psycopg.pq import TransactionStatus
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from requests.adapters import HTTPAdapter

_EVENT_TYPE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_PAYLOAD_FIELDS = frozenset(
    {
        "actor_admin_id",
        "dataset_id",
        "dataset_source",
        "dataset_uuid",
        "source",
        "uuid",
        "before",
        "after",
        "old_tier",
        "new_tier",
        "reason",
        "request_id",
        "client_ip",
    }
)
_STATE_FIELDS = frozenset({"stored_tier", "admin_tier", "effective_tier", "hidden_at"})
_MAX_PAYLOAD_BYTES = 16_384
_MAX_ACK_BYTES = 4_096
_MAX_FIELD_CHARS = 512
_MAX_TOKEN_CHARS = 4_096
_MAX_EXPORT_EVENTS = 100
_EXPORT_LOCK = 0x41554449544F5554


class AuditDeliveryError(RuntimeError):
    """The sink did not return the required durable-storage acknowledgement."""


def _checked_payload(event_type: str, payload: Mapping[str, object]) -> dict[str, object]:
    """Copy a bounded identity/restriction payload; raise ValueError for invalid fields."""
    if not isinstance(event_type, str) or _EVENT_TYPE.fullmatch(event_type) is None:
        raise ValueError("Security event type must be bounded lowercase snake case")
    if set(payload) - _PAYLOAD_FIELDS:
        raise ValueError("Security events may contain only identity and restriction fields")
    result = dict(payload)
    for name, value in result.items():
        values: Iterable[object]
        if name in {"before", "after"}:
            if not isinstance(value, dict) or set(value) - _STATE_FIELDS:
                raise ValueError("Security event restriction state is invalid")
            values = value.values()
        else:
            values = (value,)
        for item in values:
            if item is not None and (type(item) not in {str, int} or isinstance(item, bool)):
                raise ValueError("Security event fields must be bounded scalar values")
            if isinstance(item, str) and len(item) > _MAX_FIELD_CHARS:
                raise ValueError("Security event text exceeds its bound")
    encoded = json.dumps(result, ensure_ascii=False, allow_nan=False).encode()
    if len(encoded) > _MAX_PAYLOAD_BYTES:
        raise ValueError("Security event payload exceeds its bound")
    return result


async def append_security_event_cur(
    cur: AsyncCursor[Any],
    event_type: str,
    payload: Mapping[str, object],
    *,
    event_id: UUID | None = None,
) -> UUID:
    """Append a validated event to the caller's transaction and return its UUID.

    None generates a UUID; other IDs must be UUID instances. Payload validation
    raises ValueError and invalid IDs raise TypeError. Database errors propagate
    to prevent committing a mutation without its event; producers need INSERT only.
    """
    checked = _checked_payload(event_type, payload)
    identifier = uuid4() if event_id is None else event_id
    if not isinstance(identifier, UUID):
        raise TypeError("Security event identifier must be a UUID")
    await cur.execute(
        "INSERT INTO public.security_audit_events (event_id, event_type, payload) "
        "VALUES (%s, %s, %s)",
        (identifier, event_type, Jsonb(checked)),
    )
    return identifier


def _checked_sink(sink_url: str, bearer_token: str) -> None:
    """Raise ValueError unless the HTTPS sink and printable ASCII token meet their bounds."""
    try:
        parsed = urlsplit(sink_url)
        valid = (
            sink_url == sink_url.strip()
            and sink_url.isprintable()
            and not any(char.isspace() for char in sink_url)
            and parsed.scheme == "https"
            and bool(parsed.hostname)
            and parsed.port != 0
            and parsed.username is None
            and parsed.password is None
            and "?" not in sink_url
            and "#" not in sink_url
            and "\\" not in sink_url
        )
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("Security audit sink must be an HTTPS URL without embedded credentials")
    if (
        not isinstance(bearer_token, str)
        or not bearer_token
        or len(bearer_token) > _MAX_TOKEN_CHARS
        or not bearer_token.isascii()
        or not bearer_token.isprintable()
        or any(char.isspace() for char in bearer_token)
    ):
        raise ValueError("Security audit sink token must be bounded printable ASCII")


def _send_event(session: requests.Session, sink_url: str, event: dict[str, Any]) -> None:
    """POST one event and require its durable-storage receipt.

    Use 2-second connect and 5-second read timeouts, verified TLS and no
    redirects. Raise AuditDeliveryError for transport, JSON or receipt failure;
    reject acknowledgement bodies over 4,096 bytes.
    """
    try:
        with session.post(
            sink_url,
            json=event,
            timeout=(2, 5),
            allow_redirects=False,
            stream=True,
            verify=True,
        ) as response:
            if response.status_code != HTTPStatus.OK:
                raise AuditDeliveryError("Security audit sink did not acknowledge the event")
            body = bytearray()
            for chunk in response.iter_content(chunk_size=1_024):
                body.extend(chunk)
                if len(body) > _MAX_ACK_BYTES:
                    raise AuditDeliveryError(
                        "Security audit sink acknowledgement exceeds its bound"
                    )
            receipt = json.loads(body)
            if not isinstance(receipt, dict) or receipt.get("event_id") != event["event_id"]:
                raise AuditDeliveryError("Security audit sink acknowledged a different event")
            if receipt.get("stored") is not True:
                raise AuditDeliveryError("Security audit sink did not confirm durable storage")
    except (requests.RequestException, ValueError, RecursionError):
        raise AuditDeliveryError("Security audit sink delivery failed") from None


def export_security_audit_events(
    connection: psycopg.Connection[Any],
    *,
    sink_url: str,
    bearer_token: str,
    limit: int = 100,
) -> int:
    """POST up to limit undelivered events and commit matching sink receipts.

    Return the count, or zero if another exporter holds the advisory lock. Require
    an idle owner connection, limit 1-100, an HTTPS sink without credentials,
    query or fragment, and a nonempty printable ASCII bearer token; invalid inputs
    raise ValueError. Transport/receipt failure raises AuditDeliveryError; database
    errors propagate. Rollback removes all batch receipts, so the sink must
    durably deduplicate event IDs before acknowledging them. Environment proxies
    and redirects are disabled; SQL timeouts belong to the caller.
    """
    if type(limit) is not int or not 1 <= limit <= _MAX_EXPORT_EVENTS:
        raise ValueError("Security audit export limit must be between 1 and 100")
    _checked_sink(sink_url, bearer_token)
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise ValueError("Security audit export requires an idle owner connection")
    with connection.transaction(), connection.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT pg_try_advisory_xact_lock(%s) AS acquired", (_EXPORT_LOCK,))
        lock = cur.fetchone()
        if lock is None or not lock["acquired"]:
            return 0
        cur.execute(
            "SELECT event.event_id, event.created_at, event.event_type, event.payload "
            "FROM public.security_audit_events AS event "
            "LEFT JOIN public.security_audit_receipts AS receipt USING (event_id) "
            "WHERE receipt.event_id IS NULL "
            "ORDER BY event.created_at, event.event_id LIMIT %s",
            (limit,),
        )
        events = cur.fetchall()
        with requests.Session() as session:
            session.trust_env = False
            session.mount("https://", HTTPAdapter(max_retries=0))
            session.headers["Authorization"] = f"Bearer {bearer_token}"
            for row in events:
                event = {
                    "event_id": str(row["event_id"]),
                    "created_at": row["created_at"].isoformat(),
                    "event_type": row["event_type"],
                    "payload": row["payload"],
                }
                _send_event(session, sink_url, event)
                cur.execute(
                    "INSERT INTO public.security_audit_receipts (event_id) VALUES (%s)",
                    (row["event_id"],),
                )
    return len(events)
