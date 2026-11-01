#!/usr/bin/env python3
"""Approve one reviewed source-configuration rebinding using the database owner."""

import argparse
import os
import re
import sys

import psycopg

from app import SOURCE_NAME_PATTERN, resolve_environment


def acknowledge(source: str, previous_fingerprint: str, new_fingerprint: str) -> None:
    """Commit a source-binding acknowledgement and security event through DATABASE_URL.

    Require canonical ENV_STATE, valid source and distinct lowercase SHA-256 hex
    fingerprints. Lock sync_status and compare the committed binding before writing;
    ValueError rejects invalid/stale input, libpq/I/O errors propagate. This approves
    a rebuild; it does not change the active binding or perform the rebuild.
    """
    resolve_environment()
    if SOURCE_NAME_PATTERN.fullmatch(source) is None:
        raise ValueError("Source name is invalid")
    if any(
        re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in (previous_fingerprint, new_fingerprint)
    ):
        raise ValueError("Fingerprints must contain 64 lowercase hexadecimal characters")
    if previous_fingerprint == new_fingerprint:
        raise ValueError("A new source binding must differ from the previous binding")
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise ValueError("DATABASE_URL is required")
    with psycopg.connect(
        database_url,
        connect_timeout=10,
        application_name="oralhistarchiv-source-binding-maintenance",
        options="-c statement_timeout=10000 -c lock_timeout=5000",
    ) as connection:
        row = connection.execute(
            "SELECT COALESCE(source_fetch_fingerprint, source_fingerprint) "
            "FROM public.sync_status WHERE source = %s FOR UPDATE",
            (source,),
        ).fetchone()
        if row is None or row[0] != previous_fingerprint:
            raise ValueError("The committed source binding no longer matches the reviewed value")
        connection.execute(
            """INSERT INTO public.source_binding_acknowledgements
                (source, previous_fingerprint, source_fingerprint)
            VALUES (%s, %s, %s)
            ON CONFLICT (source) DO UPDATE SET
                previous_fingerprint = EXCLUDED.previous_fingerprint,
                source_fingerprint = EXCLUDED.source_fingerprint,
                acknowledged_at = clock_timestamp()""",
            (source, previous_fingerprint, new_fingerprint),
        )
        connection.execute(
            """INSERT INTO public.security_audit_events (event_id, event_type, payload)
            VALUES (pg_catalog.gen_random_uuid(), 'source_binding_acknowledged',
                pg_catalog.jsonb_build_object(
                    'source', %s::text,
                    'previous_fingerprint', %s::text,
                    'target_fingerprint', %s::text))""",
            (source, previous_fingerprint, new_fingerprint),
        )


def main() -> int:
    """Parse a reviewed binding pair, commit its acknowledgement and print status; return 0 or 1."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--expected-fingerprint", required=True)
    parser.add_argument("--new-fingerprint", required=True)
    args = parser.parse_args()
    try:
        acknowledge(args.source, args.expected_fingerprint, args.new_fingerprint)
    except (ValueError, OSError, psycopg.Error):
        print(
            "Source acknowledgement failed; verify the canonical environment, owner connection "
            "and reviewed binding pair.",
            file=sys.stderr,
        )
        return 1
    print("Source binding acknowledged; run a full rebuild and inspect its result.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
