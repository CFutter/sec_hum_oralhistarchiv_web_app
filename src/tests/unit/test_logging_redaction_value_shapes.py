"""Recursive Settings-secret extraction and audit-email hashing of structured values."""

import logging

from app.services.crypto import audit_email_hash
from config.logging import AuditEmailAutoHash, _iter_secret_values


class _StringsAs:
    """An object whose __str__ is the only way to read its payload — the
    shape `_sanitize`'s final `self._apply(str(value))` branch exists for."""

    def __init__(self, text: str) -> None:
        """Retain the supplied value for text conversion."""
        self._text = text

    def __str__(self) -> str:
        """Return the retained text unchanged."""
        return self._text


def _audit_record(msg: str = "event", **extra) -> logging.LogRecord:
    """Build an unhandled INFO audit record with the supplied extra attributes."""
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
        """Stringify unwrapped sensitive scalar values into pattern-building leaves."""
        assert list(_iter_secret_values(12345678)) == ["12345678"]

    def test_none_at_a_dict_value_position_yields_nothing(self):
        """An unset optional secret nested in a dict value still contributes no pattern, matching
        the documented top-level `None` behaviour.
        """
        assert list(_iter_secret_values({"key": None})) == []


class TestAuditEmailAutoHashSanitizesNestedExtraShapes:
    """A raw email address reaches the same [email:<hash>] rewrite no matter
    how deep it sits inside a dict/list-shaped `extra` value."""

    def test_an_email_nested_in_a_dict_extra_is_hashed(self):
        """An email nested in a dict extra is hashed."""
        expected = audit_email_hash("alice@example.org")
        record = _audit_record("profile_updated", changes={"contact": "alice@example.org"})

        AuditEmailAutoHash().filter(record)

        assert record.changes == {"contact": f"[email:{expected}]"}

    def test_an_email_nested_in_a_list_extra_is_hashed(self):
        """An email nested in a list extra is hashed."""
        expected = audit_email_hash("bob@example.org")
        record = _audit_record("recipients_notified", recipients=["bob@example.org"])

        AuditEmailAutoHash().filter(record)

        assert record.recipients == [f"[email:{expected}]"]

    def test_a_custom_objects_string_form_is_hashed(self):
        """Hash emails exposed by arbitrary-object string conversion."""
        expected = audit_email_hash("carol@example.org")
        record = _audit_record("actor_identified", actor=_StringsAs("actor=carol@example.org"))

        AuditEmailAutoHash().filter(record)

        assert record.actor == f"actor=[email:{expected}]"

    def test_non_email_content_in_the_same_nested_shapes_survives_untouched(self):
        """The recursive walk rewrites ONLY email-shaped text — everything else nested alongside it
        is unaffected.
        """
        record = _audit_record(
            "profile_updated",
            changes={"tier": "vetted", "count": 3, "active": True, "note": None},
            recipients=["ops-team", 42],
        )

        AuditEmailAutoHash().filter(record)

        assert record.changes == {"tier": "vetted", "count": 3, "active": True, "note": None}
        assert record.recipients == ["ops-team", 42]
