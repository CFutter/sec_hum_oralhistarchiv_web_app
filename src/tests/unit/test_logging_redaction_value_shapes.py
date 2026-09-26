"""Unit tests for the shape-recursive value handling in src/config/logging.py:
`_iter_secret_values` (the runtime mirror that flattens a Settings field value
down to its raw string leaves) and `AuditEmailAutoHash._sanitize` (the audit
channel's non-string extra-value walk).

Pins, against src/config/logging.py:
- `_iter_secret_values` walks not just list/tuple/set/frozenset (already
  exercised by the SecretStr-list Settings fields) but also dict VALUES, and
  stringifies a plain leaf — the shape a
  `json_schema_extra={"sensitive": True}` field without SecretStr typing
  would take. `None` yields nothing at every level.
- `AuditEmailAutoHash._sanitize` recurses into dict values, list/tuple
  elements, and stringifies an arbitrary object, applying the SAME
  hash-preserving email rewrite at every leaf — a raw address nested inside a
  structured `extra` cannot bypass the audit channel's guarantee by hiding a
  level deeper than the message string.

No database is touched anywhere in this file.
"""

import logging

from app.services.crypto import audit_email_hash
from config.logging import AuditEmailAutoHash, _iter_secret_values


class _StringsAs:
    """An object whose __str__ is the only way to read its payload — the
    shape `_sanitize`'s final `self._apply(str(value))` branch exists for."""

    def __init__(self, text: str) -> None:
        self._text = text

    def __str__(self) -> str:
        return self._text


def _audit_record(msg: str = "event", **extra) -> logging.LogRecord:
    return logging.getLogger("audit").makeRecord(
        "audit", logging.INFO, __file__, 1, msg, (), None, extra=extra
    )


class TestIterSecretValuesWalksDictsAndStringifiesScalars:
    """`_iter_secret_values` covers the two leaf shapes list-shaped Settings
    fields never exercise: a dict container and a bare scalar."""

    def test_dict_values_are_yielded_but_not_dict_keys(self):
        """Documented as walking dict VALUES — a secret hidden in a key
        rather than a value is out of scope, and that asymmetry must hold."""
        values = list(_iter_secret_values({"label": "rotation-1", "value": "s3cr3t-payload"}))

        assert values == ["rotation-1", "s3cr3t-payload"]

    def test_a_nested_dict_inside_a_list_is_still_flattened(self):
        """The two container shapes compose: a list of dicts (the MultiFernet
        rotation-state shape, generalised) still reaches every leaf."""
        values = list(_iter_secret_values([{"key": "one"}, {"key": "two"}]))

        assert values == ["one", "two"]

    def test_a_plain_non_container_leaf_is_stringified(self):
        """The `json_schema_extra={"sensitive": True}` plain-field shape: no
        SecretStr wrapper, no container, just a value that must still become
        a string leaf the caller can build a redaction pattern from."""
        assert list(_iter_secret_values(12345678)) == ["12345678"]

    def test_none_at_a_dict_value_position_yields_nothing(self):
        """Positive control: an unset optional secret nested in a dict value
        still contributes no pattern, matching the documented top-level
        `None` behaviour."""
        assert list(_iter_secret_values({"key": None})) == []


class TestAuditEmailAutoHashSanitizesNestedExtraShapes:
    """A raw email address reaches the same [email:<hash>] rewrite no matter
    how deep it sits inside a dict/list-shaped `extra` value."""

    def test_an_email_nested_in_a_dict_extra_is_hashed(self):
        expected = audit_email_hash("alice@example.org")
        record = _audit_record("profile_updated", changes={"contact": "alice@example.org"})

        AuditEmailAutoHash().filter(record)

        assert record.changes == {"contact": f"[email:{expected}]"}

    def test_an_email_nested_in_a_list_extra_is_hashed(self):
        expected = audit_email_hash("bob@example.org")
        record = _audit_record("recipients_notified", recipients=["bob@example.org"])

        AuditEmailAutoHash().filter(record)

        assert record.recipients == [f"[email:{expected}]"]

    def test_a_custom_objects_string_form_is_hashed(self):
        """The `default=str` bypass shape: an object with no dict/list/str
        type still gets its __str__ scrubbed, so a lazily-stringified value
        cannot smuggle a raw address past the filter."""
        expected = audit_email_hash("carol@example.org")
        record = _audit_record("actor_identified", actor=_StringsAs("actor=carol@example.org"))

        AuditEmailAutoHash().filter(record)

        assert record.actor == f"actor=[email:{expected}]"

    def test_non_email_content_in_the_same_nested_shapes_survives_untouched(self):
        """Positive control: the recursive walk rewrites ONLY email-shaped
        text — everything else nested alongside it is unaffected."""
        record = _audit_record(
            "profile_updated",
            changes={"tier": "vetted", "count": 3, "active": True, "note": None},
            recipients=["ops-team", 42],
        )

        AuditEmailAutoHash().filter(record)

        assert record.changes == {"tier": "vetted", "count": 3, "active": True, "note": None}
        assert record.recipients == ["ops-team", 42]
