"""Shared v1 lexical primitives; each caller owns rejection policy.

Lexical acceptance alone does not establish a real calendar date. Both page
and record validators retain their datetime parsing and distinct error codes.
"""

import re
from typing import Final

FEED_UUID_PATTERN: Final = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
FEED_UTC_SECOND_PATTERN: Final = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-5][0-9]:[0-5][0-9]Z\Z"
)

FEED_CURSOR_PATTERN: Final = re.compile(r"[A-Za-z0-9_-]{1,512}\Z")
