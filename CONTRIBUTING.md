# Contributing

Start with [README.md](README.md) for setup and commands, and [the architecture](docs/architecture/overview.md)
for the relevant contract. Discuss a substantial change before combining it
with unrelated cleanup. Report possible vulnerabilities through
[SECURITY.md](SECURITY.md).

## Development and tests

Use Python 3.11 and the locked environment:

```bash
uv sync --locked --extra dev --extra doc --python 3.11
```

The supported development configuration selects the bundled synthetic fixture
through `deploy/environment/sources.dev.toml`. Keep source selection explicit;
see [the source guide](docs/sources/index.md) before adding or changing an adapter.
Never use production credentials or sensitive source records in a contribution.

Use disposable PostgreSQL 18 and Redis for tests that require them. Shared
fixtures can reset Redis counters and integration fixtures truncate database
data; they must not point at a development, staging or production catalogue.
Some tests also need `redis-server`, `nginx` and `systemd-analyze`. The
[README testing section](README.md#testing) and
[CI workflow](.github/workflows/ci.yml) define the current requirements.

Run the tests affected by the behavior and the repository checks before review:

```bash
bash scripts/check-no-site-refs.sh
bash scripts/check-no-opaque-refs.sh
uv run ruff check .
uv run ruff format --check .
uv run mypy src/app src/config run.py run_scheduler.py run_parser.py scripts gunicorn.conf.py
uv run mypy src/tests
uv run mkdocs build --strict
```

These focused checks do not replace the complete CI suite. Preserve both fixed
and randomized parallel test orders, blocking application/test typing,
branch-coverage gates, required native tools and no-skip CI policy. Add meaningful
regressions and record measured collection; CI enforces no collection minimum.
Record the command, result,
random seed and worker count needed to reproduce a failure.

## Preparing a change

Keep the change bounded and describe its trigger and resulting behavior. Update
the affected contracts and user/operator instructions. For changed interfaces,
attach applicable synthetic UI evidence. Rehearse a changed operator procedure
on a disposable target and record the result; a unit test alone does not prove
a deployed procedure.

A schema or role change must update the migration, schema contract, grants,
verification and recovery checks together. Historical revisions own
their SQL snapshots and must not import current application/configuration code;
use a new revision after the first retained deployment. See the
[migration-history rules](src/alembic/README) for baseline-reset exceptions and
replay checks. Changes to source
interpretation must preserve durable identity and recovery boundaries.

Keep site values and completed restricted records outside the application
repository.
Review dependency updates against the lock and current CI rather than editing
resolved versions without verification. Do not weaken a gate to make a patch
appear green. If an inherited check is blocked, record the exact limitation
and its open repair item.

## Licensing and attribution

Contributions to the application are provided under its [MIT license](LICENSE).
Bundled and introduced third-party material retains its own applicable terms;
see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Include the required notices
and provenance when adding assets or data. Only contribute material you are
entitled to provide, and do not replace another component's license with the
application's license.

