"""Migration CLI usable from any directory after installing the application.

Examples:
    python -m app.migrate upgrade head
    python -m app.migrate current
    python -m app.migrate heads
"""

import logging
import sys

from alembic.config import CommandLine

from .paths import ALEMBIC_INI


def main() -> None:
    """Run Alembic arguments against the bundled/source migration configuration.

    Configures logging and may change PostgreSQL according to sys.argv. Raises
    RuntimeError for missing migration assets; Alembic/SystemExit errors propagate.
    """
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    # The shipped INI resolves script_location relative to its own %(here)s.
    CommandLine(prog="python -m app.migrate").main(
        argv=["-c", str(ALEMBIC_INI), *sys.argv[1:]],
    )


if __name__ == "__main__":
    main()
