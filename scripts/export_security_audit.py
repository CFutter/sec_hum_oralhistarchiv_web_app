#!/usr/bin/env python3
"""Export committed security events using an owner connection and a durable HTTPS sink."""

import argparse
import os
import sys

import psycopg

from app.services import AuditDeliveryError, export_security_audit_events


def _configuration() -> dict[str, str]:
    """Read required DATABASE_URL/AUDIT_SINK_URL/AUDIT_SINK_TOKEN; missing values raise
    ValueError.
    """
    values = {
        name: os.environ.get(name, "")
        for name in ("DATABASE_URL", "AUDIT_SINK_URL", "AUDIT_SINK_TOKEN")
    }
    if not all(values.values()):
        raise ValueError("Security audit export configuration is incomplete")
    return values


def main() -> int:
    """Export at most --limit committed audit events to HTTPS, acknowledge them and print a
    count.

    Read DATABASE_URL/AUDIT_SINK_URL/AUDIT_SINK_TOKEN, open an owner connection
    and commit receipts; return 0 on success or 1 for classified configuration, I/O,
    database or delivery failures. Argument parsing may exit before the operation.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--limit", type=int, default=100, help="Events per batch, between 1 and 100"
    )
    args = parser.parse_args()
    try:
        values = _configuration()
        with psycopg.connect(
            values["DATABASE_URL"],
            connect_timeout=10,
            application_name="oralhistarchiv-audit-export",
            options="-c statement_timeout=10000 -c lock_timeout=1000",
        ) as connection:
            count = export_security_audit_events(
                connection,
                sink_url=values["AUDIT_SINK_URL"],
                bearer_token=values["AUDIT_SINK_TOKEN"],
                limit=args.limit,
            )
    except (ValueError, OSError, psycopg.Error, AuditDeliveryError):
        print(
            "Security audit export failed; inspect the protected configuration and sink.",
            file=sys.stderr,
        )
        return 1
    print(f"Acknowledged security events: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
