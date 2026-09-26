"""Form Content-Type validation installed on every mutation route.

``SecureAPIRouter`` applies this dependency to every method except GET, HEAD,
and OPTIONS. It rejects non-form bodies before FastAPI parses handler fields.
"""

import logging

from fastapi import HTTPException, Request, status

from ..request_utils import safe_request_path

logger = logging.getLogger(__name__)
_ALLOWED_FORM_CONTENT_TYPES = frozenset(
    {
        "application/x-www-form-urlencoded",
        "multipart/form-data",
    }
)


async def validate_form_content_type(request: Request) -> None:
    """Raise HTTPException(415) unless Content-Type is URL-encoded or multipart form data.

    Ignore parameters and case; log only header presence on rejection.
    """
    raw_content_type = request.headers.get("Content-Type", "")
    media_type = raw_content_type.partition(";")[0].strip().lower()

    if media_type not in _ALLOWED_FORM_CONTENT_TYPES:
        logger.warning(
            "Rejected form Content-Type",
            extra={
                "request_id": getattr(request.state, "request_id", "unknown"),
                "path": safe_request_path(request),
                # Record only whether it existed—not the attacker-controlled value.
                "content_type_present": bool(raw_content_type),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported Media Type",
        )
