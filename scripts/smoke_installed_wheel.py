"""Check installed-wheel assets outside the checkout using explicit smoke settings.

Run with isolated Python after installation; no live database is needed.
"""

import asyncio
import sysconfig
from importlib import metadata, resources
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from alembic.script import ScriptDirectory
from psycopg_pool import AsyncConnectionPool

import app
from app.paths import ALEMBIC_DIR, ALEMBIC_INI, STATIC_DIR, TEMPLATES_DIR
from app.runtime_preflight import _alembic_config, validate_alembic_head
from app.services.password_validation import warm_password_blocklist

_LICENSE_FILES = (
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "src/app/static/fonts/OFL.txt",
    "src/app/services/data/SECLISTS-LICENSE.txt",
)


def _require(condition: bool, message: str) -> None:
    """Raise RuntimeError with the supplied diagnostic when condition is false."""
    if not condition:
        raise RuntimeError(f"Installed-wheel smoke check failed: {message}")


def _validate_installed_licenses(installed: Path) -> None:
    """Check distribution license metadata and the notices shipped with installed assets."""
    distribution = metadata.distribution("Oral-History-Archive")
    _require(
        distribution.metadata["License-Expression"] == "MIT AND OFL-1.1",
        "distribution License-Expression must be MIT AND OFL-1.1",
    )
    license_files = distribution.metadata.get_all("License-File") or []
    _require(
        sorted(license_files) == sorted(_LICENSE_FILES),
        f"unexpected distribution License-File records: {license_files!r}",
    )
    recorded_files = distribution.files or []
    for relative in _LICENSE_FILES:
        suffix = ("licenses", *Path(relative).parts)
        matches = [
            entry
            for entry in recorded_files
            if len(entry.parts) == len(suffix) + 1
            and entry.parts[0].endswith(".dist-info")
            and entry.parts[1:] == suffix
        ]
        _require(len(matches) == 1, f"distribution license file is not recorded: {relative}")
        license_path = Path(str(distribution.locate_file(matches[0]))).resolve()
        _require(
            license_path.is_relative_to(installed),
            f"distribution license file is outside the installed wheel: {relative}",
        )
        _require(license_path.is_file(), f"distribution license file is missing: {relative}")
        _require(
            bool(license_path.read_text(encoding="utf-8").strip()),
            f"distribution license file is empty: {relative}",
        )

    package = resources.files("app")
    for relative in ("static/fonts/OFL.txt", "services/data/SECLISTS-LICENSE.txt"):
        notice = package.joinpath(*Path(relative).parts)
        _require(notice.is_file(), f"packaged license notice is missing: {relative}")
        _require(
            bool(notice.read_text(encoding="utf-8").strip()),
            f"packaged license notice is empty: {relative}",
        )


def main() -> None:
    """Verify installed assets/head/blocklist, warm the blocklist cache and print success.

    Run outside an event loop. Missing/invalid assets raise RuntimeError; import,
    file and validation failures propagate. Database validation uses a mock cursor.
    """
    installed = Path(sysconfig.get_path("purelib")).resolve()
    app_path = Path(app.__file__).resolve()

    _require(
        app_path.is_relative_to(installed),
        "imported the source checkout instead of the installed wheel",
    )
    _require(
        ALEMBIC_INI.is_relative_to(installed),
        "alembic.ini is outside the installed wheel",
    )
    _require(
        ALEMBIC_DIR.is_relative_to(installed),
        "Alembic migration directory is outside the installed wheel",
    )
    _require(
        (ALEMBIC_DIR / "env.py").is_file(),
        "Alembic env.py is missing",
    )
    _require(
        (ALEMBIC_DIR / "script.py.mako").is_file(),
        "Alembic script.py.mako is missing",
    )

    expected = ScriptDirectory.from_config(_alembic_config()).get_heads()
    _require(
        expected == ["4f73ae3ff827"],
        f"unexpected migration heads: {expected!r}",
    )

    _require(TEMPLATES_DIR.is_dir(), "templates directory is missing")
    _require(STATIC_DIR.is_dir(), "static directory is missing")
    _validate_installed_licenses(installed)

    migration_ini = resources.files("app").joinpath(
        "_migration_assets",
        "alembic.ini",
    )
    _require(migration_ini.is_file(), "packaged alembic.ini is missing")

    blocklist = resources.files("app").joinpath(
        "services",
        "data",
        "common_passwords.txt",
    )
    _require(blocklist.is_file(), "packaged password blocklist is missing")
    _require(
        bool(blocklist.read_text(encoding="utf-8").strip()),
        "packaged password blocklist is empty",
    )
    warm_password_blocklist()
    asyncio.run(_validate_installed_head(expected[0]))
    print(
        "Installed wheel: migration assets, head validation, templates, blocklist and licenses OK"
    )


async def _validate_installed_head(expected: str) -> None:
    """Exercise the installed Alembic-head check against a cursor returning expected."""
    cursor = AsyncMock()
    cursor.fetchone.return_value = None
    cursor.fetchall.return_value = [{"version_num": expected}]
    with patch("app.runtime_preflight.get_db_cursor") as cursor_context:
        cursor_context.return_value.__aenter__ = AsyncMock(return_value=cursor)
        cursor_context.return_value.__aexit__ = AsyncMock(return_value=False)
        await validate_alembic_head(MagicMock(spec=AsyncConnectionPool))


if __name__ == "__main__":
    main()
