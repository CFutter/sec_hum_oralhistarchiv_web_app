"""Public test helpers for public action links and separately emailed codes."""

import re
from urllib.parse import urlsplit

from app.services.tokens import action_token_public_id, action_token_url


def token_from_action_email(body: str, url: str) -> str:
    """Read the manually copied email code and bind its entirely public URL.

    The URL itself contains no secret and cannot supply one. Tests using this
    helper model a user copying the separately printed code into the form POST.
    """
    lines = body.splitlines()
    labels = [index for index, line in enumerate(lines) if line == "Security code:"]
    assert len(labels) == 1
    token = next(line for line in lines[labels[0] + 1 :] if line)
    assert re.fullmatch(r"[A-Za-z0-9_.-]{1,2000}", token, flags=re.ASCII)
    parsed = urlsplit(url)
    assert not parsed.query and not parsed.fragment and token not in url
    assert parsed.path.rsplit("/", 1)[1] == action_token_public_id(token)
    return token


def action_path(flow: str, token: str) -> str:
    """Return the public HTTP path for a manually submitted email code."""
    return action_token_url(flow, token)
