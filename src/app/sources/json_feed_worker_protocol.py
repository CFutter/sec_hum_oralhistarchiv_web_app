"""Shared fixed transport diagnostics for page and complete-fetch IPC.

Workers keep their existing frame prefixes (E for a page transport error and T
for a complete-fetch transport error). Their code vocabulary and safe encoding
are shared; full-fetch protocol refusals remain a separate P frame.
"""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from .json_feed_http import FeedErrorCode, FeedTransportError

TRANSPORT_ERROR_FRAMES: Final[Mapping[bytes, FeedErrorCode]] = MappingProxyType(
    {
        b"transport": "transport",
        b"http_status": "http_status",
        b"headers": "headers",
        b"signature": "signature",
        b"resource_limit": "resource_limit",
        b"worker": "worker",
    }
)


def encode_transport_error(error: BaseException) -> bytes:
    """Encode only a declared transport code, replacing all other faults safely."""
    if isinstance(error, FeedTransportError):
        for encoded, code in TRANSPORT_ERROR_FRAMES.items():
            if error.error_code == code:
                return encoded
    return b"worker"
