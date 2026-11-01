"""Canonical source identity syntax shared by Python and current SQL.

Historical migrations keep literal snapshots; changing this contract requires
reviewing their successors and the corresponding runtime SQL contracts.
"""

import re
from typing import Final

SOURCE_NAME_MAX_CHARS: Final = 32
SOURCE_NAME_BODY: Final = rf"[a-z0-9_]{{1,{SOURCE_NAME_MAX_CHARS}}}"
SOURCE_NAME_SQL_PATTERN: Final = rf"^{SOURCE_NAME_BODY}$"
SOURCE_NAME_OPTIONAL_PATTERN: Final = rf"^(?:{SOURCE_NAME_BODY})?$"
SOURCE_NAME_PATTERN: Final = re.compile(SOURCE_NAME_BODY)
