#!/usr/bin/env python3
"""Verify active, pending and rotation-challenge TOTP secrets with the first key only.

After reencrypt_totp.py, keep writers stopped and run this before retiring old
keys. Exit 0 means all selected ciphertexts decrypt and decode as UTF-8; exit 1
reports failures. See docs/runbooks/key-rotation.md.
"""

import argparse
import asyncio
import sys

from cryptography.fernet import InvalidToken

from app.services import create_pool, get_primary_totp_decryptor
from app.services.totp_maintenance import (
    DEFAULT_BATCH_SIZE,
    MAINTENANCE_STATEMENT_TIMEOUT,
    rotation_secret_pages,
    secret_pages,
)


async def main(batch_size: int = DEFAULT_BATCH_SIZE) -> int:
    """Read TOTP secrets in pages; return 1 for decryption/UTF-8 failures, otherwise 0.

    Requires stopped writers. batch_size is 1..5000 rows; invalid sizes raise
    ValueError. Opens/closes a database pool and prints progress without changing
    secrets. Other errors propagate.
    """
    primary = get_primary_totp_decryptor()

    pool = create_pool("oralhistarchiv-verify", statement_timeout=MAINTENANCE_STATEMENT_TIMEOUT)
    await pool.open()
    failures = 0
    checked = 0
    try:
        async for rows in secret_pages(pool, batch_size):
            for row in rows:
                for column in ("totp_secret", "pending_totp_secret"):
                    ciphertext = row[column]
                    if ciphertext is None:
                        continue
                    checked += 1
                    try:
                        primary.decrypt(ciphertext.encode()).decode()
                    except (InvalidToken, UnicodeDecodeError):
                        failures += 1
                        print(
                            f"  user {row['id']}: {column} (not decryptable under the primary key)"
                        )
            print(
                f"processed through user {rows[-1]['id']}; checked={checked}; failures={failures}"
            )
        async for rows in rotation_secret_pages(pool, batch_size):
            for row in rows:
                checked += 1
                try:
                    primary.decrypt(row["encrypted_secret"].encode()).decode()
                except (InvalidToken, UnicodeDecodeError):
                    failures += 1
                    print(
                        f"  user {row['user_id']}: rotation challenge "
                        "(not decryptable under the primary key)"
                    )
            print(
                f"processed rotation challenges through user {rows[-1]['user_id']}; "
                f"checked={checked}; failures={failures}"
            )
    finally:
        await pool.close()

    if failures:
        print(f"FAIL — {failures} values not decryptable under the primary TOTP key")
        return 1

    print(f"OK — {checked} stored TOTP value(s) decrypt under the primary key")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    sys.exit(asyncio.run(main(parser.parse_args().batch_size)))
