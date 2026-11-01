#!/usr/bin/env python3
"""Atomically replace a reviewed search policy using the database owner identity."""

import argparse
import os
import re
import sys

import psycopg
from psycopg.types.json import Jsonb

from app import resolve_environment
from app.services import compile_default_catalogue_policy
from app.sources import load_catalogue_sources_for_startup


def replace(expected_fingerprint: str) -> str:
    """Atomically rebuild audience projections and return the new policy fingerprint.

    Read canonical ENV_STATE, DATABASE_URL and SOURCES_CONFIG_FILE, without loading
    Settings or feed secrets. Require a reviewed lowercase SHA-256 expected binding
    and owner permissions. Read/validate source TOML, then commit one compare-and-swap
    SQL call (600-second statement and 10-second lock timeouts); errors propagate.
    """
    if re.fullmatch(r"[0-9a-f]{64}", expected_fingerprint) is None:
        raise ValueError("Expected fingerprint must contain 64 lowercase hexadecimal characters")
    environment = resolve_environment()
    values = {
        name: os.environ.get(name, "")
        for name in ("DATABASE_URL", "SOURCES_CONFIG_FILE", "ENV_STATE")
    }
    if not all(values.values()):
        raise ValueError("DATABASE_URL, SOURCES_CONFIG_FILE and ENV_STATE are required")
    sources = load_catalogue_sources_for_startup(
        values["SOURCES_CONFIG_FILE"], environment=environment
    )
    policy = compile_default_catalogue_policy(sources)
    # The context commits only the single owner-only compare-and-swap call.
    # Its failure rolls back the binding and every rebuilt projection together.
    with psycopg.connect(
        values["DATABASE_URL"],
        connect_timeout=10,
        application_name="oralhistarchiv-policy-maintenance",
        options="-c statement_timeout=600000 -c lock_timeout=10000",
    ) as connection:
        connection.execute(
            "SELECT public.catalogue_replace_search_policy(%s, %s, %s)",
            (
                expected_fingerprint,
                policy.fingerprint,
                Jsonb({str(rank): dict(masks) for rank, masks in policy.page_masks.items()}),
            ),
        )
    return policy.fingerprint


def main() -> int:
    """Replace the reviewed policy and print its fingerprint; classified failures return 1,
    success 0.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--expected-fingerprint",
        required=True,
        help="Reviewed catalogue_search_policy.fingerprint (64 lowercase hex characters)",
    )
    args = parser.parse_args()
    try:
        fingerprint = replace(args.expected_fingerprint)
    except (ValueError, OSError, psycopg.Error):
        # libpq and configuration exceptions may include connection/source text.
        print(
            "Search policy replacement failed; verify the protected configuration, "
            "owner connection and expected fingerprint.",
            file=sys.stderr,
        )
        return 1
    print(f"Search policy installed: {fingerprint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
