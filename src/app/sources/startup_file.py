"""Read and validate an explicitly selected source file for startup."""

import os
import stat
from collections.abc import Mapping
from contextlib import ExitStack
from pathlib import Path

from . import catalogue_sources, configure_sources
from .base import CatalogueSource, ConfiguredSource, SourceConfig
from .configuration import parse_source_configs_from_toml
from .json_feed_config import JsonFeedConfig, prepare_json_feed_startup
from .startup import (
    _validate_startup_options,
    validate_source_configs_startup,
    validate_source_startup,
)


def _validate_descriptor(descriptor: int, *, directory: bool) -> None:
    """Require a root-owned directory/regular file without group/other write bits; raise
    ValueError.
    """
    metadata = os.fstat(descriptor)
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(metadata.st_mode):
        expected = "directory" if directory else "regular file"
        raise ValueError(f"Source configuration requires a {expected}")
    if metadata.st_uid != 0:
        raise ValueError("Source configuration and its directories must be root-owned")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(
            "Source configuration and its directories must not be group- or other-writable"
        )


def _read_hardened_file(path: Path) -> str:
    """Read UTF-8 through checked no-follow descriptors for every absolute POSIX path component.

    Reject parent traversal, symlinks, nonroot ownership and group/other writes.
    Raise NotImplementedError off POSIX; validation, decoding and I/O errors propagate.
    """
    if os.name != "posix":
        raise NotImplementedError("Hardened source-file validation requires POSIX")
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Hardened source configuration requires an absolute path without '..'")
    if not path.name:
        raise ValueError("Source configuration path must name a file")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with ExitStack() as descriptors:
        directory_fd = os.open(path.anchor, directory_flags)
        descriptors.callback(os.close, directory_fd)
        _validate_descriptor(directory_fd, directory=True)

        for component in path.parts[1:-1]:
            directory_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            descriptors.callback(os.close, directory_fd)
            _validate_descriptor(directory_fd, directory=True)

        file_fd = os.open(path.name, file_flags, dir_fd=directory_fd)
        descriptors.callback(os.close, file_fd)
        _validate_descriptor(file_fd, directory=False)
        with os.fdopen(file_fd, encoding="utf-8", closefd=False) as source_file:
            return source_file.read()


def _load_source_configs_for_startup(
    path: str | Path, *, environment: str, allow_fixture: bool
) -> tuple[SourceConfig, ...]:
    """Share descriptor security, parsing and pure policy across runtime roles."""
    _validate_startup_options(environment=environment, allow_fixture=allow_fixture)
    source_path = Path(path)
    document = (
        source_path.read_text(encoding="utf-8")
        if environment == "dev"
        else _read_hardened_file(source_path)
    )
    configs = parse_source_configs_from_toml(document)
    validate_source_configs_startup(configs, environment=environment, allow_fixture=allow_fixture)
    return configs


def load_catalogue_sources_for_startup(
    path: str | Path, *, environment: str, allow_fixture: bool = False
) -> tuple[CatalogueSource, ...]:
    """Load the same source-file policy without credentials, adapters or fetching.

    Hardened file ownership/symlink checks and nonsecret endpoint/reference
    validation are identical to scheduler startup. No environment mapping is
    accepted: catalogue serving has no need to resolve feed credentials.
    """
    return catalogue_sources(
        _load_source_configs_for_startup(path, environment=environment, allow_fixture=allow_fixture)
    )


def load_sources_for_startup(
    path: str | Path,
    *,
    environment: str,
    allow_fixture: bool = False,
    environ: Mapping[str, str] | None = None,
) -> tuple[ConfiguredSource, ...]:
    """Read, construct and validate one explicit selection without fetching.

    Development accepts an ordinary readable UTF-8 path. Staging and production
    require a direct absolute POSIX path without parent traversal or symlinks.
    Every opened directory and the regular file must be root-owned and must not
    be group- or other-writable. The caller needs read and search access to
    every directory and read access to the file. Validate and read the same
    opened descriptor.

    The explicit environ mapping is the only credential source; omitted means
    empty, never the process environment. Validate and resolve all feed inputs
    before any adapter is constructed. No global settings, implicit environment
    lookup, network access or runtime activation occurs here. File, decoding,
    parsing, credential, construction and startup-policy errors propagate.
    """
    configs = _load_source_configs_for_startup(
        path, environment=environment, allow_fixture=allow_fixture
    )
    credentials = prepare_json_feed_startup(
        [config for config in configs if isinstance(config, JsonFeedConfig)],
        environment=environment,
        environ={} if environ is None else environ,
    )
    sources = configure_sources(configs, credentials=credentials)
    validate_source_startup(sources, environment=environment, allow_fixture=allow_fixture)
    return sources
