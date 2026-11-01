"""Settings-free final text-log escaping for application and isolated workers."""

import unicodedata


def escape_log_controls(value: str) -> str:
    """Keep one event on one physical line without terminal or direction controls."""
    named = {"\n": r"\n", "\r": r"\r", "\t": r"\t", "\x1b": r"\x1b"}
    return "".join(
        named.get(character, f"\\u{ord(character):04x}")
        if unicodedata.category(character) in {"Cc", "Cf", "Zl", "Zp"}
        else character
        for character in value
    )
