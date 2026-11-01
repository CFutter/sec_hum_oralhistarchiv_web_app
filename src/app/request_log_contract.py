"""Internal request-state names shared by admission and request logging.

Admission writes its route template or coarse label to request.state. This is
server-owned state, never a value read from a request header or query parameter.
Keep this module free of settings and middleware imports.
"""

from typing import Final

RATE_LIMIT_LOG_PATH_STATE: Final = "rate_limit_log_path"
