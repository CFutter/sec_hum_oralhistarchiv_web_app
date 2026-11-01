"""Canonical process environment selection without loading application settings."""

import os
from collections.abc import Mapping
from typing import Literal, cast

Environment = Literal["dev", "staging", "production"]


def resolve_environment(environ: Mapping[str, str] | None = None) -> Environment:
    """Return ENV_STATE from environ (default: os.environ), or raise ValueError.

    Require exactly one case-insensitive spelling, ``ENV_STATE``, with value
    ``dev``, ``staging`` or ``production``; dotenv files cannot select the mode.
    """
    values = os.environ if environ is None else environ
    variants = [key for key in values if key.casefold() == "env_state"]
    if variants != ["ENV_STATE"]:
        raise ValueError("Set exactly one uppercase ENV_STATE process variable")
    mode = values["ENV_STATE"]
    if mode not in {"dev", "staging", "production"}:
        raise ValueError("ENV_STATE must be dev, staging or production")
    return cast(Environment, mode)
