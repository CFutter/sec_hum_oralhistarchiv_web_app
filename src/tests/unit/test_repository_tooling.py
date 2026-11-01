"""Contract pins for the repository's own tooling: CI workflow, tier boundary, developer
container/launcher and linter configuration.
"""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import tomllib
import types
from pathlib import Path
from typing import Any

import pytest

from app.paths import PROJECT_ROOT
from tests.conftest import pytest_collection_modifyitems

CI_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "ci.yml"
WORKFLOW_DIRECTORY = PROJECT_ROOT / ".github" / "workflows"
DEPENDABOT_CONFIG = PROJECT_ROOT / ".github" / "dependabot.yml"
PYPROJECT = PROJECT_ROOT / "pyproject.toml"
SKIP_GATE = PROJECT_ROOT / "scripts" / "check-skips-are-expected.sh"
EXPECTED_SKIPS = PROJECT_ROOT / "scripts" / "expected-skips.txt"

_USES_LINE = re.compile(
    r"^\s*(?:-\s*)?uses:\s*(?P<reference>[^#\s]+)"
    r"(?:\s+#\s*(?P<version>\S.*))?\s*$"
)
_GITHUB_ACTION_COMMIT = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
    r"(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$"
)
_DOCKER_ACTION_DIGEST = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")
_HARDENED_CHECKOUT_STEP = re.compile(
    r"(?m)^(?P<indent>[ ]*)- uses: actions/checkout@[0-9a-f]{40} # \S+\n"
    r"(?P=indent)  with:\n"
    r"(?P=indent)    persist-credentials: false$"
)
_GLOB_CHARS = set("*?[")


def _workflow_text() -> str:
    """Read the CI workflow, failing if it is absent."""
    assert CI_WORKFLOW.exists(), f"CI workflow not found at {CI_WORKFLOW}"
    return CI_WORKFLOW.read_text()


def _mapping_keys(text: str) -> set[str]:
    """Extract complete bare YAML mapping-key lines, excluding URL scheme substrings."""
    return {line.strip() for line in text.splitlines()}


def _workflow_files() -> list[Path]:
    """List YAML workflow files in deterministic path order."""
    return sorted(
        path
        for path in WORKFLOW_DIRECTORY.iterdir()
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    )


def _dependabot_update_blocks(text: str) -> list[str]:
    """Return each two-space-indented update entry without a YAML dependency."""
    blocks: list[list[str]] = []
    current: list[str] | None = None

    for line in text.splitlines():
        if line.startswith("  - package-ecosystem:"):
            if current is not None:
                blocks.append(current)
            current = [line]
        elif current is not None:
            if line and not line.startswith(" ") and not line.startswith("#"):
                blocks.append(current)
                current = None
            else:
                current.append(line)

    if current is not None:
        blocks.append(current)

    return ["\n".join(block) for block in blocks]


def _fake_item(path: str) -> types.SimpleNamespace:
    """Minimal stand-in for a collected pytest item: the hook only touches
    .path and .add_marker, and every added marker is recorded."""
    item = types.SimpleNamespace(path=Path(path), added_markers=[])
    item.add_marker = item.added_markers.append
    return item


def _ruff_lint() -> dict[str, Any]:
    """Read the Ruff lint table from pyproject.toml, failing if the file is absent."""
    assert PYPROJECT.exists(), f"pyproject.toml not found at {PYPROJECT}"
    with PYPROJECT.open("rb") as f:
        return tomllib.load(f)["tool"]["ruff"]["lint"]


def _is_covered(code: str, select: list[str]) -> bool:
    """A rule code is enabled iff some selected prefix prefixes it —
    ruff's own selector semantics ("PL" covers "PLR2004", "E501" covers
    exactly "E501")."""
    return any(code.startswith(prefix) for prefix in select)


def _key_resolves(key: str) -> bool:
    """A per-file-ignores key names real files: glob keys must match at
    least one file from the repo root, plain keys must exist there."""
    if _GLOB_CHARS & set(key):
        return next(iter(PROJECT_ROOT.glob(key)), None) is not None
    return (PROJECT_ROOT / key).is_file()


def _wait_for(path: Path) -> None:
    """Wait up to five seconds for a child-created file, then raise AssertionError."""
    deadline = time.monotonic() + 5
    while not path.exists():
        if time.monotonic() >= deadline:
            raise AssertionError(f"child did not create {path.name}")
        time.sleep(0.01)


class TestCIWorkflowGates:
    """The release/test workflow keeps the gates that stop a silent green run."""

    def test_ci_test_mypy_is_blocking(self) -> None:
        """Test typing failures must fail the required typecheck job."""
        match = re.search(
            r"(?ms)^  typecheck:\n(?P<job>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            _workflow_text(),
        )
        assert match is not None, "typecheck job missing from ci.yml"
        job = match.group("job")

        assert re.search(r"(?m)^        run: uv run mypy src/tests$", job), (
            "typecheck must run test mypy directly, without masking its exit status"
        )
        assert not re.search(r"(?m)^[ \t]*(?:-[ \t]*)?continue-on-error[ \t]*:", job), (
            "neither the typecheck job nor its steps may allow typing failures"
        )

    def test_ci_test_job_requires_db_and_redis(self):
        """Check ci test job requires database and Redis."""
        text = _workflow_text()
        assert 'REQUIRE_DB: "1"' in text
        assert 'REQUIRE_REDIS: "1"' in text
        assert 'REQUIRE_NGINX: "1"' in text
        assert 'REQUIRE_SYSTEMD: "1"' in text
        # The env vars are meaningless without the services they gate on.
        keys = _mapping_keys(text)
        assert "postgres:" in keys, "postgres service block missing from ci.yml"
        assert "redis:" in keys, "redis service block missing from ci.yml"

    def test_action_links_require_no_script_runtime(self):
        """Action forms and their CI checks work without an added script runtime."""
        workflow = _workflow_text()
        assert not re.search(r"(?m)^\s*sudo apt-get install [^\n]*\bnodejs\b", workflow)
        assert "node --test src/tests/unit/action_token_frontend.cjs" not in workflow
        assert not (PROJECT_ROOT / "src/app/static/action-token.js").exists()
        assert not (PROJECT_ROOT / "src/tests/unit/action_token_frontend.cjs").exists()
        for name in (
            "reset_password.html",
            "confirm_verify_email.html",
            "confirm_email.html",
            "action_token_fields.html",
        ):
            template = (PROJECT_ROOT / "src/app/templates" / name).read_text()
            assert not re.search(r"<\s*script\b", template, flags=re.IGNORECASE)

    def test_ci_enforces_a_coverage_floor(self) -> None:
        """Keep the measured overall coverage floor and its pytest wiring."""
        match = re.search(
            r"(?ms)^  tests:\n(?P<job>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            _workflow_text(),
        )
        assert match is not None, "tests job missing from ci.yml"
        job = match.group("job")

        floor = re.search(
            r'(?m)^      COVERAGE_FLOOR: "(?P<floor>\d+(?:\.\d+)?)"$',
            job,
        )
        assert floor is not None, "overall coverage floor missing from the tests job"
        assert 92.5 <= float(floor.group("floor")) <= 100.0, (
            "the overall coverage floor must not drop below the reviewed 92.5% baseline"
        )

        command = re.search(
            r"(?m)^          uv run pytest \$PYTEST_FLAGS \\\n"
            r"(?P<options>(?:            [^\n]+\\\n)+)",
            job,
        )
        assert command is not None, "the multiline pytest coverage command is missing"
        options = {
            line.strip().removesuffix("\\").strip()
            for line in command.group("options").splitlines()
        }
        assert "--cov=src/app --cov=src/config --cov-branch" in options
        assert '--cov-fail-under="$COVERAGE_FLOOR"' in options

    def test_all_remote_workflow_actions_use_immutable_digests(self):
        """Every remote action must be immutable before any repository code runs."""
        workflow_files = _workflow_files()
        assert workflow_files, "no GitHub Actions workflow files found"

        remote_references: list[str] = []
        violations: list[str] = []

        for workflow_file in workflow_files:
            for line_number, line in enumerate(workflow_file.read_text().splitlines(), 1):
                match = _USES_LINE.match(line)
                if match is None:
                    continue

                reference = match.group("reference")
                version = match.group("version")
                if reference.startswith("./"):
                    continue

                remote_references.append(reference)
                immutable = (
                    _DOCKER_ACTION_DIGEST.fullmatch(reference) is not None
                    if reference.startswith("docker://")
                    else _GITHUB_ACTION_COMMIT.fullmatch(reference) is not None
                )
                if not immutable or not version:
                    violations.append(
                        f"{workflow_file.relative_to(PROJECT_ROOT)}:{line_number}: {line.strip()}"
                    )

        assert remote_references, "no remote GitHub Actions dependencies found"
        assert not violations, (
            "remote actions must use a full commit SHA (or container sha256 digest) "
            "and a same-line reviewed version comment:\n" + "\n".join(violations)
        )

    def test_dependabot_proposes_updates_for_pinned_github_actions(self):
        """Weekly Dependabot PRs keep immutable pins maintainable, not mutable."""
        assert DEPENDABOT_CONFIG.exists(), (
            f"Dependabot configuration not found at {DEPENDABOT_CONFIG}"
        )
        blocks = _dependabot_update_blocks(DEPENDABOT_CONFIG.read_text())
        github_actions_blocks = [
            block for block in blocks if 'package-ecosystem: "github-actions"' in block
        ]

        assert len(github_actions_blocks) == 1, (
            "dependabot.yml must contain exactly one github-actions update block"
        )
        github_actions = github_actions_blocks[0]
        assert 'directory: "/"' in github_actions
        assert 'interval: "weekly"' in github_actions

    def test_checkout_never_persists_repository_credentials(self):
        """Later commands do not need the checkout token left in Git configuration."""
        checkout_references = 0
        hardened_checkout_steps = 0

        for workflow_file in _workflow_files():
            text = workflow_file.read_text()
            checkout_references += sum(
                1 for line in text.splitlines() if "uses: actions/checkout@" in line
            )
            hardened_checkout_steps += len(_HARDENED_CHECKOUT_STEP.findall(text))

        assert checkout_references > 0, "no actions/checkout steps found"
        assert hardened_checkout_steps == checkout_references, (
            "every checkout step must set persist-credentials: false"
        )

    def test_ci_runs_the_suite_in_fixed_random_and_parallel_order(self) -> None:
        """Run fixed serial and randomized parallel legs with bounded workers.

        Keep normal pytest output so the random seed remains visible.
        """
        text = _workflow_text()
        match = re.search(
            r"(?ms)^  tests:\n(?P<job>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            text,
        )
        assert match is not None, "tests job missing from ci.yml"
        job = match.group("job")

        assert re.findall(r"(?m)^          - order: (.+)$", job) == [
            "fixed order",
            "parallel workers",
        ]
        assert re.findall(r"(?m)^            pytest_flags: (.+)$", job) == [
            "-p no:randomly",
            "-p randomly -n auto --maxprocesses 15",
        ]
        assert 'TEST_RATE_LIMIT_REDIS_DB: "0"' in job
        assert "-rs --no-fold-skipped" in job
        command = job.split("uv run pytest", 1)[1].split("|", 1)[0]
        assert " -q" not in command
        assert "--quiet" not in command
        assert "--no-header" not in command

    def test_ci_sets_ci_so_that_a_skipped_integration_test_fails_the_run(self):
        """The root conftest's session hook and the skip gate both key on CI."""
        text = _workflow_text()
        assert 'CI: "true"' in text
        assert "bash scripts/check-skips-are-expected.sh pytest-output.log" in text
        assert "tee pytest-output.log" in text

    def test_ci_holds_the_security_modules_to_their_own_coverage_floor(self) -> None:
        """Pin the actual aggregate security report and its complete file selection."""
        match = re.search(
            r"(?m)^      - name: Security modules meet their own coverage floor\n"
            r"        run: >-\n"
            r'          uv run coverage report --fail-under="\$SECURITY_COVERAGE_FLOOR"\n'
            r"          --include='(?P<include>[^'\n]+)'$",
            _workflow_text(),
        )
        assert match is not None, "the blocking security coverage report is missing or changed"
        expected = (
            "src/app/catalogue_runtime.py",
            "src/app/catalogue_sql.py",
            "src/app/cookie_contract.py",
            "src/app/environment.py",
            "src/app/log_text.py",
            "src/app/credentials.py",
            "src/app/doi.py",
            "src/app/federation_contract.py",
            "src/app/federated_tier_rules.py",
            "src/app/field_visibility.py",
            "src/app/main.py",
            "src/app/middleware/*",
            "src/app/request_utils.py",
            "src/app/route_security.py",
            "src/app/routes/auth/*",
            "src/app/routes/health.py",
            "src/app/routes/pages.py",
            "src/app/runtime_preflight.py",
            "src/app/search_mask_contract.py",
            "src/app/search_projection_sql.py",
            "src/app/services/_smtp_child.py",
            "src/app/services/access_tiers.py",
            "src/app/services/account_deletion.py",
            "src/app/services/admin_promotion.py",
            "src/app/services/audit.py",
            "src/app/services/audit_outbox.py",
            "src/app/services/disclosure_audit.py",
            "src/app/services/mail_issuance.py",
            "src/app/services/security_notifications.py",
            "src/app/services/authentication.py",
            "src/app/services/credential_attempts.py",
            "src/app/services/crypto.py",
            "src/app/services/catalogue_lock.py",
            "src/app/services/catalogue_policy.py",
            "src/app/services/database_privileges.py",
            "src/app/services/dataset_admin.py",
            "src/app/services/dataset_admin_queries.py",
            "src/app/services/datasets.py",
            "src/app/services/db.py",
            "src/app/services/db_constraints.py",
            "src/app/services/db_drift.py",
            "src/app/services/db_schema_contract.py",
            "src/app/services/email.py",
            "src/app/services/email_change.py",
            "src/app/services/email_delivery.py",
            "src/app/services/email_outbox.py",
            "src/app/services/email_verification.py",
            "src/app/services/federated_*",
            "src/app/services/harvest.py",
            "src/app/services/outbox_maintenance.py",
            "src/app/services/parsed_record.py",
            "src/app/services/password_*",
            "src/app/services/policy_digest.py",
            "src/app/services/registration_setup.py",
            "src/app/services/schema.py",
            "src/app/services/schema_invariants.py",
            "src/app/services/search_projection.py",
            "src/app/services/search_work.py",
            "src/app/services/seed_admin.py",
            "src/app/services/session*",
            "src/app/services/smtp_process.py",
            "src/app/services/stored_harvest.py",
            "src/app/services/ingestion.py",
            "src/app/services/ingestion_audit.py",
            "src/app/services/tokens.py",
            "src/app/services/totp*",
            "src/app/services/users.py",
            "src/app/sources/*.py",
            "src/app/template_setup.py",
            "src/app/thread_work.py",
            "src/app/url_safety.py",
            "src/config/logging.py",
            "src/config/redis_policy.py",
            "src/config/settings.py",
        )
        actual = tuple(match.group("include").split(","))
        assert actual == expected, "review security coverage scope changes in both CI and this test"
        for pattern in actual:
            assert any(
                path.is_file() and path.suffix == ".py" for path in PROJECT_ROOT.glob(pattern)
            ), f"security coverage pattern matches no Python files: {pattern}"


_EXPECTED_SKIP_LINES = (
    "SKIPPED src/tests/integration/test_deployed_preflight_db.py::"
    "test_runtime_preflight_with_actual_deployed_role_login_defaults - Skipped: "
    "Existing oralhistarchiv database must not be altered by a deployment probe\n"
    "SKIPPED src/tests/integration/test_deployed_preflight_db.py::"
    "test_runtime_preflight_with_actual_deployed_role_login_defaults - Skipped: "
    "Existing deployment roles must not be altered by a deployment probe\n"
    "SKIPPED src/tests/unit/test_nginx_contract.py::test_ordinary_proxy_include_parses_with_nginx"
    " - Skipped: nginx is not installed in this development environment\n"
    "SKIPPED src/tests/unit/test_nginx_contract.py::"
    "test_throttled_capability_token_stays_out_of_access_log"
    " - Skipped: nginx is not installed in this development environment\n"
    "SKIPPED src/tests/unit/test_nginx_contract.py::"
    "test_throttled_capability_token_stays_out_of_error_log"
    " - Skipped: nginx is not installed in this development environment\n"
    "SKIPPED src/tests/unit/test_deployment_units.py::TestProductionModeStartGuard::"
    "test_the_units_pass_systemd_syntax_verification"
    " - Skipped: systemd-analyze is not installed in this development environment\n"
)
_UNEXPECTED_SKIP_LINE = (
    "SKIPPED src/tests/unit/test_totp.py::test_a_code_verifies_once - Skipped: no authenticator\n"
)
_COUNT_LINE = "10 passed, 6 skipped in 1.00s\n"


def _run_skip_gate(
    log: Path, *, ci: bool, expected: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Run the skip gate with selected CI state and an optional written expected-skip list."""
    env = {k: v for k, v in os.environ.items() if k not in ("CI", "EXPECTED_SKIPS_FILE")}
    if ci:
        env["CI"] = "true"
    if expected is not None:
        listed = log.parent / "expected-skips.txt"
        listed.write_text(expected, encoding="utf-8")
        env["EXPECTED_SKIPS_FILE"] = str(listed)
    return subprocess.run(
        ["bash", str(SKIP_GATE), str(log)], env=env, capture_output=True, text=True, check=False
    )


def _declares_skip_reason(path: Path, reason: str) -> bool:
    """Match pytest.skip reasons in a module or its directly imported relative helpers."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    scopes: list[ast.AST] = [tree]
    for statement in tree.body:
        if not isinstance(statement, ast.ImportFrom) or not statement.level or not statement.module:
            continue
        imported_path = (
            path.parents[statement.level - 1]
            .joinpath(*statement.module.split("."))
            .with_suffix(".py")
        )
        if imported_path.is_file():
            imported = ast.parse(imported_path.read_text(encoding="utf-8"))
            names = {alias.name for alias in statement.names}
            scopes.extend(
                definition
                for definition in imported.body
                if isinstance(definition, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and definition.name in names
            )
    for scope in scopes:
        for node in ast.walk(scope):
            if (
                not isinstance(node, ast.Call)
                or not isinstance(node.func, ast.Attribute)
                or not isinstance(node.func.value, ast.Name)
                or (node.func.value.id, node.func.attr) != ("pytest", "skip")
                or not node.args
            ):
                continue
            argument = node.args[0]
            if isinstance(argument, ast.Constant) and argument.value == reason:
                return True
            if isinstance(argument, ast.JoinedStr):
                fragments = []
                for part in argument.values:
                    if isinstance(part, ast.Constant) and isinstance(part.value, str):
                        fragments.append(re.escape(part.value))
                    elif isinstance(part, ast.FormattedValue):
                        fragments.append(".+")
                if re.fullmatch("".join(fragments), reason):
                    return True
    return False


class TestEverySkipIsAnExpectedOne:
    """The skip gate accepts listed local exceptions, rejects every skip
    under CI, and refuses incomplete summaries or failed comparisons."""

    def test_listed_local_skips_pass_without_ci(self, tmp_path):
        """Check listed local skips pass without ci."""
        log = tmp_path / "pytest.log"
        log.write_text(_EXPECTED_SKIP_LINES + _COUNT_LINE, encoding="utf-8")
        result = _run_skip_gate(log, ci=False)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "No unexpected skips." in result.stdout

    def test_listed_local_skips_fail_under_ci(self, tmp_path):
        """Check listed local skips fail under ci."""
        log = tmp_path / "pytest.log"
        log.write_text(_EXPECTED_SKIP_LINES + _COUNT_LINE, encoding="utf-8")
        result = _run_skip_gate(log, ci=True)
        assert result.returncode == 1, result.stdout + result.stderr
        assert "Skipped under CI" in result.stderr
        assert (
            "test_nginx_contract.py::test_ordinary_proxy_include_parses_with_nginx" in result.stderr
        )

    def test_a_skip_that_is_not_listed_fails_and_is_named(self, tmp_path):
        """Check a skip that is not listed fails and is named."""
        log = tmp_path / "pytest.log"
        log.write_text(
            _EXPECTED_SKIP_LINES + _UNEXPECTED_SKIP_LINE + "10 passed, 7 skipped in 1.00s\n",
            encoding="utf-8",
        )
        result = _run_skip_gate(log, ci=False)
        assert result.returncode == 1, result.stdout + result.stderr
        assert "test_totp.py::test_a_code_verifies_once - no authenticator" in result.stderr
        assert "test_nginx_contract.py" not in result.stderr

    @pytest.mark.parametrize(
        "log_text",
        [
            "SKIPPED [2] src/tests/unit/test_nginx_contract.py:108: nginx is not installed\n"
            + _COUNT_LINE,
            _COUNT_LINE,
            _EXPECTED_SKIP_LINES,
        ],
        ids=["skips-folded-without-node-ids", "skips-counted-but-not-listed", "no-count-line"],
    )
    def test_a_summary_that_hides_its_skips_is_refused(self, tmp_path, log_text):
        """Check a summary that hides its skips is refused."""
        log = tmp_path / "pytest.log"
        log.write_text(log_text, encoding="utf-8")
        result = _run_skip_gate(log, ci=False)
        assert result.returncode == 1, result.stdout + result.stderr

    def test_a_failed_skip_comparison_cannot_report_success(self, tmp_path, monkeypatch):
        """Check a failed skip comparison cannot report success."""
        log = tmp_path / "pytest.log"
        log.write_text(_EXPECTED_SKIP_LINES + _COUNT_LINE, encoding="utf-8")
        binary_dir = tmp_path / "bin"
        binary_dir.mkdir()
        comm = binary_dir / "comm"
        comm.write_text("#!/bin/sh\necho 'comparison unavailable' >&2\nexit 2\n", encoding="utf-8")
        comm.chmod(0o755)
        monkeypatch.setenv("PATH", f"{binary_dir}{os.pathsep}{os.environ['PATH']}")

        result = _run_skip_gate(log, ci=False)

        assert result.returncode != 0
        assert "comparison unavailable" in result.stderr
        assert "No unexpected skips." not in result.stdout

    def test_every_listed_skip_names_a_test_that_exists(self):
        """Resolve each listed test and its local or directly imported skip reason."""
        entries = [
            line
            for line in EXPECTED_SKIPS.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]

        for entry in entries:
            node_id, _, reason = entry.partition(" - ")
            path, *qualifiers = node_id.split("::")
            source = (PROJECT_ROOT / path).read_text(encoding="utf-8")
            scope = ast.parse(source).body
            for index, qualifier in enumerate(qualifiers):
                expected_types = (
                    (ast.FunctionDef, ast.AsyncFunctionDef)
                    if index == len(qualifiers) - 1
                    else (ast.ClassDef,)
                )
                definition = next(
                    (
                        node
                        for node in scope
                        if isinstance(node, expected_types) and node.name == qualifier
                    ),
                    None,
                )
                assert definition is not None, f"{node_id} does not exist"
                scope = definition.body
            assert _declares_skip_reason(PROJECT_ROOT / path, reason), (
                f"{reason!r} is not the reason the test gives"
            )

    @pytest.mark.parametrize(
        ("source", "reason", "expected"),
        [
            ("from .helper import required as gate\n", "nginx is unavailable", True),
            ("from .helper import required\n", "nginx has a different reason", False),
            ("from .helper import required\n", "an unimported reason", False),
            ('# pytest.skip("nginx is unavailable")\n', "nginx is unavailable", False),
            ('pytest.skip("literal reason")\n', "literal reason", True),
        ],
    )
    def test_skip_reasons_require_a_real_local_or_imported_declaration(
        self, tmp_path, source, reason, expected
    ):
        """Accept shared-helper templates, rejecting unrelated helpers, comments and drift."""
        (tmp_path / "helper.py").write_text(
            "'''Provide one imported and one unrelated skip helper.'''\n"
            "def required(name):\n"
            "    '''Skip for an unavailable executable.'''\n"
            "    pytest.skip(f'{name} is unavailable')\n"
            "def unrelated():\n"
            "    '''Skip for a reason outside the imported helper.'''\n"
            "    pytest.skip('an unimported reason')\n",
            encoding="utf-8",
        )
        module = tmp_path / "test_sample.py"
        module.write_text(
            "'''Provide a local or shared skip declaration for the provenance check.'''\n" + source,
            encoding="utf-8",
        )
        assert _declares_skip_reason(module, reason) is expected


class TestIntegrationTierMarking:
    """The collection hook is what makes `-m "not integration"` a real tier boundary."""

    def test_integration_marker_is_applied_by_the_collection_hook(self):
        """If the auto-marking hook in the root conftest silently breaks, the
        unit tier starts requiring a database (or the integration tier stops
        being deselectable) and no test notices."""
        integration_item = _fake_item("/repo/src/tests/integration/test_x.py")
        unit_item = _fake_item("/repo/src/tests/unit/test_x.py")
        # Discriminator control: 'integration' as a filename substring, not a
        # directory — the hook must key on path PARTS, not string containment.
        lookalike_item = _fake_item("/repo/src/tests/unit/test_integration_style.py")

        pytest_collection_modifyitems([integration_item, unit_item, lookalike_item])

        # Positive control first: the hook DID mark the integration-dir item,
        # so the two empty lists below show discrimination, not a dead hook.
        assert [m.name for m in integration_item.added_markers] == ["integration"]
        assert unit_item.added_markers == []
        assert lookalike_item.added_markers == []


class TestDevelopmentWorkflow:
    """The developer launcher and devcontainer set up a working local environment."""

    @pytest.mark.parametrize(
        "failure",
        [True, False],
        ids=["scheduler_crash_propagates_exit_code", "graceful_shutdown_reaps_both_children"],
    )
    def test_dev_launcher_propagates_failure_and_reaps_children(self, tmp_path, failure):
        """Check dev launcher propagates failure and reaps children."""
        launcher = tmp_path / "dev.sh"
        launcher.write_text((PROJECT_ROOT / "dev.sh").read_text())
        dispatcher = tmp_path / "python3"
        dispatcher.write_text(
            f'#!/bin/bash\nif [[ "$1" == "-m" ]]; then exit 0; fi\nexec "{sys.executable}" "$@"\n'
        )
        dispatcher.chmod(0o755)
        child = """'''Create launcher lifecycle markers and handle SIGTERM in synthetic children.'''
import signal, time
from pathlib import Path
name = Path(__file__).stem
Path(name + '.started').touch()
def stop(*_args):
    '''Wait 150 ms, write the stopped marker and raise SystemExit(0).'''
    time.sleep(0.15)
    Path(name + '.stopped').touch()
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
"""
        (tmp_path / "run.py").write_text(child + "while True: time.sleep(0.01)\n")
        ending = (
            "while not Path('run.started').exists(): time.sleep(0.01)\nraise SystemExit(7)\n"
            if failure
            else "while True: time.sleep(0.01)\n"
        )
        (tmp_path / "run_scheduler.py").write_text(child + ending)
        process = subprocess.Popen(
            ["bash", str(launcher)],
            cwd=tmp_path,
            env={
                **os.environ,
                "PATH": f"{tmp_path}:{os.environ['PATH']}",
                "PYTHONPATH": str(PROJECT_ROOT / "src"),
                "ENV_STATE": "dev",
            },
            start_new_session=True,
        )
        try:
            _wait_for(tmp_path / "run.started")
            if not failure:
                _wait_for(tmp_path / "run_scheduler.started")
                process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=5) == (7 if failure else 143)
            assert (tmp_path / "run.stopped").exists()
            if not failure:
                assert (tmp_path / "run_scheduler.stopped").exists()
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)

    def test_devcontainer_setup_installs_uv_without_cargo_and_preserves_env(self, tmp_path):
        """Check devcontainer setup installs uv without cargo and preserves env."""
        config = json.loads((PROJECT_ROOT / ".devcontainer/devcontainer.json").read_text())
        assert config["workspaceFolder"] == "/workspaces"
        assert (
            "..:/workspaces:cached"
            in (PROJECT_ROOT / ".devcontainer/docker-compose.yaml").read_text()
        )
        (tmp_path / ".env.example").write_text('DATABASE_URL="postgresql://wrong/old"\n')
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        curl = bin_dir / "curl"
        # A local installer exercises the fresh-install branch without downloading.
        curl.write_text("""#!/bin/sh
cat <<'INSTALLER'
mkdir -p "$UV_INSTALL_DIR"
cat > "$UV_INSTALL_DIR/uv" <<'UV'
#!/bin/sh
printf '%s\\n' "$*" >> uv-calls
UV
chmod +x "$UV_INSTALL_DIR/uv"
INSTALLER
""")
        curl.chmod(0o755)
        tools = tmp_path / "tools"
        tools.mkdir()
        for name in ("bash", "sh", "cat", "cp", "mkdir", "chmod", "python3"):
            found = shutil.which(name)
            assert found is not None, f"{name} is required by setup.sh"
            (tools / name).symlink_to(found)
        env = {
            **os.environ,
            "PATH": f"{bin_dir}:{tools}",
            "UV_INSTALL_DIR": str(tmp_path / "uv-bin"),
        }

        script = PROJECT_ROOT / ".devcontainer/setup.sh"
        subprocess.run(["bash", str(script)], cwd=tmp_path, env=env, check=True, timeout=10)
        assert "@db:5432/oralhistarchiv" in (tmp_path / ".env").read_text()
        assert (
            "sync --locked --extra dev --extra doc --python 3.11"
            in (tmp_path / "uv-calls").read_text()
        )
        (tmp_path / ".env").write_text("existing configuration\n")
        subprocess.run(["bash", str(script)], cwd=tmp_path, env=env, check=True, timeout=10)
        assert (tmp_path / ".env").read_text() == "existing configuration\n"


class TestRuffLintConfiguration:
    """`[tool.ruff.lint]` keeps a non-empty, internally-consistent rule selection."""

    def test_ruff_select_is_nonempty_and_keeps_core_rule_families(self):
        """An empty select list makes ruff revert to its tiny default rule
        set while CI keeps passing."""
        select = _ruff_lint().get("select", [])
        assert select, (
            "[tool.ruff.lint].select is missing or empty — ruff reverts to its "
            "tiny default rule set and CI keeps passing."
        )
        missing = {"F", "B", "PL"} - set(select)
        assert missing == set(), (
            f"Core rule families dropped from [tool.ruff.lint].select: {sorted(missing)}"
        )

    def test_per_file_ignores_reference_only_selected_rules(self):
        """An ignore for a never-enabled rule is config that does nothing."""
        lint = _ruff_lint()
        select = lint.get("select", [])
        ignores = lint.get("per-file-ignores", {})

        # Predicate self-test — positive control for the emptiness assertion
        # below: the coverage check can both accept and reject.
        assert _is_covered("PLR2004", ["PL"])
        assert not _is_covered("ZZZ999", select)

        uncovered = {
            (key, code)
            for key, codes in ignores.items()
            for code in codes
            if not _is_covered(code, select)
        }
        assert uncovered == set(), (
            "per-file-ignores reference rules no select prefix enables (dead "
            f"config — enable the family or drop the ignore): {sorted(uncovered)}"
        )

    def test_per_file_ignore_keys_match_existing_files(self):
        """An ignore key for a path that doesn't exist exempts nothing."""
        ignores = _ruff_lint().get("per-file-ignores", {})

        # Resolver self-test — positive controls for both branches, plus proof
        # it can reject (a path missing the app/ segment).
        assert _key_resolves("pyproject.toml")
        assert _key_resolves("src/tests/**/*.py")
        assert not _key_resolves("src/services/does_not_exist.py")

        dangling = {key for key in ignores if not _key_resolves(key)}
        assert dangling == set(), (
            "per-file-ignores keys match no existing file (the exemption is "
            f"silently inert — fix the path or remove the entry): {sorted(dangling)}"
        )
