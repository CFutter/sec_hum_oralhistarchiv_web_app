"""HTTP exceptions whose messages may be rendered to users."""

from fastapi import HTTPException


class UserFacingForbidden(HTTPException):
    """A 403 carrying a user-visible detail and title for the branded error handler."""

    def __init__(self, detail: str, title: str = "Access denied") -> None:
        """Store the display title and initialize HTTP status 403 with the supplied detail."""
        super().__init__(status_code=403, detail=detail)
        self.title = title
