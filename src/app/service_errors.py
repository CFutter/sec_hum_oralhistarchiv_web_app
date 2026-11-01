"""Domain failures shared by services and their presentation boundaries."""


class UserNotFound(LookupError):
    """The target account disappeared or never existed; not an input-validation error."""


class UserInputRejected(ValueError):
    """An intentional validation refusal whose message is suitable for display."""


class UserStateChanged(ValueError):
    """An account no longer qualifies for a pending operation; do not render its detail."""
