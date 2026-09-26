"""Migration CLI usable from any directory after installing the application.

Examples:
    python -m app.migrate upgrade head
    python -m app.migrate current
    python -m app.migrate heads
"""

import logging
import sys

from alembic.config import CommandLine

from .paths import ALEMBIC_DIR, ALEMBIC_INI


def main() -> None:
    """Run Alembic arguments against the bundled/source migration configuration.

    Configures logging and may change PostgreSQL according to sys.argv. Raises
    RuntimeError if asset paths disagree; Alembic/SystemExit errors propagate.
    """
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    # Put the authoritative script path in the config read by Alembic. Both
    # the source INI and the bundled INI resolve their scripts via %(here)s.
    if ALEMBIC_INI.parent / "alembic" != ALEMBIC_DIR:
        raise RuntimeError("Migration INI and script directory disagree")
    CommandLine(prog="python -m app.migrate").main(
        argv=["-c", str(ALEMBIC_INI), *sys.argv[1:]],
    )


if __name__ == "__main__":
    main()
