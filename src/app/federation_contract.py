"""Shared federation scalar contracts; no settings, HTTP, or database dependencies."""

# Private app-facing headers.  nginx must clear these on ordinary proxy
# locations and overwrite them exclusively from Shibboleth SP variables on the
# callback.  They are deliberately not configurable.
SHIBBOLETH_INTERNAL_AUTH_HEADER = "X-OHA-Internal-Auth"
SHIBBOLETH_SUBJECT_HEADER = "X-OHA-Shib-Subject"
SHIBBOLETH_ISSUER_HEADER = "X-OHA-Shib-Issuer"
SHIBBOLETH_MAIL_HEADER = "X-OHA-Shib-Mail"
SHIBBOLETH_DISPLAY_NAME_HEADER = "X-OHA-Shib-Display-Name"
SHIBBOLETH_AFFILIATION_HEADER = "X-OHA-Shib-Affiliation"
SHIBBOLETH_COUNTRY_HEADER = "X-OHA-Shib-Country"
SHIBBOLETH_AUTHN_CONTEXT_HEADER = "X-OHA-Shib-Authn-Context"

ISSUER_MAX_LENGTH = 2048
SUBJECT_MAX_LENGTH = 512
EMAIL_MAX_LENGTH = 320
AUTHN_CONTEXT_MAX_LENGTH = 1024
DISPLAY_NAME_MAX_LENGTH = 200
AFFILIATION_MAX_LENGTH = 512
COUNTRY_MAX_LENGTH = 128


class InvalidFederatedPrincipal(ValueError):
    """Raised when asserted attributes cannot form one canonical principal."""

    def __init__(self, reason: str):
        """Store reason as both the reason attribute and exception message."""
        self.reason = reason
        super().__init__(reason)


def exact_security_value(value: str, *, name: str, max_length: int) -> str:
    """Return value unchanged if nonempty, printable, bounded and unambiguous.

    Reject nonstrings, surrounding whitespace and commas with
    InvalidFederatedPrincipal; name prefixes the reason and max_length counts characters.
    """
    if not isinstance(value, str) or not value:
        raise InvalidFederatedPrincipal(f"{name}:missing")
    if len(value) > max_length:
        raise InvalidFederatedPrincipal(f"{name}:oversized")
    if not value.isprintable():
        raise InvalidFederatedPrincipal(f"{name}:nonprintable")
    if value != value.strip():
        raise InvalidFederatedPrincipal(f"{name}:surrounding_whitespace")
    # Some HTTP stacks coalesce duplicate fields into one comma-separated
    # value. These fields are scalar identity/security claims, so accepting a
    # comma would make duplicate interpretation proxy-dependent.
    if "," in value:
        raise InvalidFederatedPrincipal(f"{name}:ambiguous")
    return value


def valid_federated_identity(issuer: str, subject_id: str) -> bool:
    """Return whether issuer/subject meet scalar bounds; this does not validate issuer URLs."""
    try:
        exact_security_value(issuer, name="issuer", max_length=ISSUER_MAX_LENGTH)
        exact_security_value(subject_id, name="subject", max_length=SUBJECT_MAX_LENGTH)
    except InvalidFederatedPrincipal:
        return False
    return True
