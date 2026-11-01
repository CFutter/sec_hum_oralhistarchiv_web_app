#!/usr/bin/env python3
"""Create the first administrator once, reading its password from a terminal."""

import argparse
import asyncio
import getpass
import sys

from app import resolve_environment, validate_seed_credentials
from app.services import create_pool, seed_admin_user, warm_password_blocklist


async def bootstrap(email: str, password: str) -> None:
    """Validate credentials, warm the blocklist and seed through an owned database pool.

    Require canonical ENV_STATE and configured database/settings; service guards
    control whether creation is allowed. Errors propagate; close an opened pool.
    """
    resolve_environment()
    normalized = validate_seed_credentials(email, password)
    warm_password_blocklist()
    pool = create_pool(application_name="oralhistarchiv-bootstrap")
    await pool.open()
    try:
        await seed_admin_user(pool, normalized, password)
    finally:
        await pool.close()


def main() -> int:
    """Read matching passwords from a terminal, bootstrap the admin and print status; return 0 or
    1.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True, help="A fresh initial administrator address")
    args = parser.parse_args()
    if not sys.stdin.isatty():
        print("Run bootstrap from a protected interactive terminal.", file=sys.stderr)
        return 1
    try:
        password = getpass.getpass("New administrator password: ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            print("Passwords do not match.", file=sys.stderr)
            return 1
        asyncio.run(bootstrap(args.email, password))
    except (EOFError, KeyboardInterrupt):
        print("Bootstrap cancelled.", file=sys.stderr)
        return 1
    except Exception:
        # Database and configuration exceptions can contain connection details.
        print(
            "Bootstrap failed. Check the protected configuration, password policy "
            "and whether an account already uses that address.",
            file=sys.stderr,
        )
        return 1
    print("Bootstrap completed. Enroll the initial authenticator before opening public access.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
