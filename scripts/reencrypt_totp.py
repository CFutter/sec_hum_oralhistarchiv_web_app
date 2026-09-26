"""Re-encrypt active, pending and rotation-challenge TOTP secrets with the first key.

Stop writers and follow docs/runbooks/key-rotation.md; configure
TOTP_ENCRYPTION_KEYS with the new key first and every needed old key retained.
Run verify_totp_reencryption.py before retiring keys. Re-running is safe but
changes ciphertext. Exit 1 reports undecryptable or concurrently changed values.
"""

import argparse
import asyncio
import sys

from cryptography.fernet import InvalidToken
from psycopg import sql
from psycopg.rows import dict_row

from app.services.crypto import _fernet_instance  # MultiFernet over [new, old]
from app.services.db import create_pool, get_db_cursor
from app.services.totp_maintenance import (
    DEFAULT_BATCH_SIZE,
    MAINTENANCE_STATEMENT_TIMEOUT,
    rotation_secret_pages,
    secret_pages,
)


async def main(batch_size: int = DEFAULT_BATCH_SIZE) -> int:
    """Rotate stored TOTP ciphertext in committed pages and return 0, or 1 for skips.

    Requires stopped writers and all decryption keys. batch_size is 1..5000 rows;
    invalid sizes raise ValueError. Opens/closes a database pool, prints progress,
    and commits compare-and-swap updates per page. Database and unexpected crypto
    errors propagate; earlier pages stay committed.
    """
    pool = create_pool("oralhistarchiv-reencrypt", statement_timeout=MAINTENANCE_STATEMENT_TIMEOUT)
    await pool.open()
    rotated_users = 0
    rotated_challenges = 0
    skipped = 0
    try:
        async for rows in secret_pages(pool, batch_size):
            # One bounded transaction per page; compare-and-swap preserves a
            # value even if the documented writers-stopped precondition is violated.
            async with get_db_cursor(pool, row_factory=dict_row) as cur:
                for row in rows:
                    row_rotated = False
                    for col in ("totp_secret", "pending_totp_secret"):
                        ct = row[col]
                        if ct is None:
                            continue
                        try:
                            rotated = _fernet_instance.rotate(ct.encode()).decode()
                        except InvalidToken:
                            skipped += 1
                            print(
                                f"  user {row['id']}: {col} (undecryptable under configured keys)"
                            )
                            continue
                        await cur.execute(
                            sql.SQL("UPDATE users SET {c} = %s WHERE id = %s AND {c} = %s").format(
                                c=sql.Identifier(col)
                            ),
                            (rotated, row["id"], ct),
                        )
                        if cur.rowcount == 1:
                            row_rotated = True
                        else:
                            skipped += 1
                            print(f"  user {row['id']}: {col} (changed mid-run (CAS miss))")
                    if row_rotated:
                        rotated_users += 1
            print(
                f"processed through user {rows[-1]['id']}; "
                f"rotated={rotated_users}; skipped={skipped}"
            )

        async for rows in rotation_secret_pages(pool, batch_size):
            async with get_db_cursor(pool, row_factory=dict_row) as cur:
                for row in rows:
                    ct = row["encrypted_secret"]
                    try:
                        rotated = _fernet_instance.rotate(ct.encode()).decode()
                    except InvalidToken:
                        skipped += 1
                        print(f"  user {row['user_id']}: rotation challenge (undecryptable)")
                        continue
                    await cur.execute(
                        """UPDATE pending_totp_rotations SET encrypted_secret = %s
                        WHERE user_id = %s AND encrypted_secret = %s""",
                        (rotated, row["user_id"], ct),
                    )
                    if cur.rowcount == 1:
                        rotated_challenges += 1
                    else:
                        skipped += 1
                        print(f"  user {row['user_id']}: rotation challenge (CAS miss)")

    finally:
        await pool.close()

    print(f"re-encrypted secrets for {rotated_users} user(s)")
    print(f"re-encrypted rotation challenges for {rotated_challenges} user(s)")
    if skipped:
        print(f"SKIPPED {skipped} column(s) — rerun Phase B2 until clean")
        return 1
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    sys.exit(asyncio.run(main(parser.parse_args().batch_size)))
