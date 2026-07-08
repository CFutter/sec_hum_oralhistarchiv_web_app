"""Content-Type validation for POST requests.

Rejects requests with unexpected Content-Type headers as defense
in depth — FastAPI's form parsing already provides partial protection,
but explicit validation prevents content-type confusion attacks.
"""

import logging

from fastapi import Request, HTTPException, status

logger = logging.getLogger(__name__)


async def validate_form_content_type(request: Request) -> None:
    """FastAPI dependency that rejects unexpected Content-Type headers.

    Usage:
        @router.post("/submit", dependencies=[Depends(validate_form_content_type)])
    """
    content_type = request.headers.get("Content-Type", "")
    if not content_type.lower().startswith((
        "application/x-www-form-urlencoded",
        "multipart/form-data",
    )):
        logger.warning(
            "Rejected Content-Type: %s on %s",
            content_type, request.url.path,
            extra={"request_id": getattr(request.state, "request_id", "unknown")},
        )
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported Media Type",
        )