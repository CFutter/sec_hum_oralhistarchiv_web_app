"""Contract pins for the repository's own tooling: CI workflow, tier
boundary, developer container/launcher and linter configuration.

These assert raw text and TOML tables under `.github/`, `.devcontainer/`,
`dev.sh` and `pyproject.toml` rather than behaviour reachable through an
import, so a config drift that changes none of those files' *meaning* to
Python still fails a test instead of shipping silently. Deliberately NOT
YAML parsing: pyyaml is not a dependency and adding it would force a
uv.lock regeneration (CI runs `uv sync --locked` and fails on a stale
lock). The strings asserted here are exact enough that a reformat which
changes them is itself a contract change worth a failing test.

Pure unit tests: no DB, no app, no subprocess except where a scenario class
says otherwise.
"""

from __future__ import annotations

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
    assert CI_WORKFLOW.exists(), f"CI workflow not found at {CI_WORKFLOW}"
    return CI_WORKFLOW.read_text()


def _mapping_keys(text: str) -> set[str]:
    """Lines that are bare YAML mapping keys (e.g. a service name).

    A whole-stripped-line match is what makes `redis:` here mean the
    service block header and not the `redis://` scheme inside REDIS_URL.
    """
    return {line.strip() for line in text.splitlines()}


def _workflow_files() -> list[Path]:
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
    deadline = time.monotonic() + 5
    while not path.exists():
        if time.monotonic() >= deadline:
            raise AssertionError(f"child did not create {path.name}")
        time.sleep(0.01)


class TestCIWorkflowGates:
    """The release/test workflow keeps the gates that stop a silent green run."""

    def test_ci_test_job_requires_db_and_redis(self):
        """Without REQUIRE_DB=1 a dead postgres service container ships a
        green run that executed none of the integration tier — a workflow
        edit that drops the env vars must fail a unit test, not pass review
        as a cleanup."""
        text = _workflow_text()
        assert 'REQUIRE_DB: "1"' in text
        assert 'REQUIRE_REDIS: "1"' in text
        # The env vars are meaningless without the services they gate on.
        keys = _mapping_keys(text)
        assert "postgres:" in keys, "postgres service block missing from ci.yml"
        assert "redis:" in keys, "redis service block missing from ci.yml"

    def test_ci_enforces_a_coverage_floor(self):
        """A workflow edit that drops --cov-fail-under lets coverage rot
        silently while every run stays green."""
        assert "--cov-fail-under" in _workflow_text()

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

    def test_ci_runs_the_suite_in_fixed_random_and_parallel_order(self):
        """One ordering hides order-dependent tests; the three legs together
        do not. The random leg must print its seed, so `-q` is not used."""
        text = _workflow_text()
        assert "pytest_flags: -p no:randomly" in text
        assert "pytest_flags: -p randomly" in text
        assert "pytest_flags: -n auto" in text
        assert "-rs --no-fold-skipped" in text
        assert " -q" not in text.split("uv run pytest", 1)[1].split("|", 1)[0]

    def test_ci_sets_ci_so_that_a_skipped_integration_test_fails_the_run(self):
        """The root conftest's session hook and the skip gate both key on CI."""
        text = _workflow_text()
        assert 'CI: "true"' in text
        assert "bash scripts/check-skips-are-expected.sh pytest-output.log" in text
        assert "tee pytest-output.log" in text

    def test_ci_holds_the_security_modules_to_their_own_coverage_floor(self):
        """A separate `coverage report` step over the security modules, so a
        loss of coverage there cannot hide inside the application total."""
        text = _workflow_text()
        assert 'uv run coverage report --fail-under="$SECURITY_COVERAGE_FLOOR"' in text
        for module in (
            "src/app/middleware/*",
            "src/app/route_security.py",
            "src/app/services/authentication.py",
            "src/app/services/session*",
            "src/app/services/totp*",
            "src/app/routes/auth/*",
            "src/config/settings.py",
        ):
            assert module in text, f"{module} is not in the security-module set"


_EXPECTED_SKIP_LINES = (
    "SKIPPED src/tests/integration/test_deployed_preflight_db.py::"
    "test_runtime_preflight_with_actual_deployed_role_login_defaults - Skipped: "
    "Existing oralhistarchiv database must not be altered by a deployment probe\n"
    "SKIPPED src/tests/unit/test_nginx_contract.py::test_ordinary_proxy_include_parses_with_nginx"
    " - Skipped: nginx is not installed in this development environment\n"
)
_UNEXPECTED_SKIP_LINE = (
    "SKIPPED src/tests/unit/test_totp.py::test_a_code_verifies_once - Skipped: no authenticator\n"
)
_COUNT_LINE = "10 passed, 2 skipped in 1.00s\n"


def _run_skip_gate(
    log: Path, *, ci: bool, expected: str | None = None
) -> subprocess.CompletedProcess[str]:
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


class TestEverySkipIsAnExpectedOne:
    """`scripts/check-skips-are-expected.sh` compares a run's unfolded skip
    summary with `scripts/expected-skips.txt`: the two local skips pass
    without CI, nothing passes under CI, and a summary that hides its skips
    is refused."""

    def test_the_two_local_skips_pass_without_ci(self, tmp_path):
        log = tmp_path / "pytest.log"
        log.write_text(_EXPECTED_SKIP_LINES + _COUNT_LINE, encoding="utf-8")
        result = _run_skip_gate(log, ci=False)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "No unexpected skips." in result.stdout

    def test_the_same_two_skips_fail_under_ci(self, tmp_path):
        log = tmp_path / "pytest.log"
        log.write_text(_EXPECTED_SKIP_LINES + _COUNT_LINE, encoding="utf-8")
        result = _run_skip_gate(log, ci=True)
        assert result.returncode == 1, result.stdout + result.stderr
        assert "Skipped under CI" in result.stderr
        assert (
            "test_nginx_contract.py::test_ordinary_proxy_include_parses_with_nginx" in result.stderr
        )

    def test_a_skip_that_is_not_listed_fails_and_is_named(self, tmp_path):
        log = tmp_path / "pytest.log"
        log.write_text(_EXPECTED_SKIP_LINES + _UNEXPECTED_SKIP_LINE + _COUNT_LINE, encoding="utf-8")
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
        log = tmp_path / "pytest.log"
        log.write_text(log_text, encoding="utf-8")
        result = _run_skip_gate(log, ci=False)
        assert result.returncode == 1, result.stdout + result.stderr

    def test_every_listed_skip_names_a_test_that_exists(self):
        """A renamed or deleted test leaves a stale entry that would let a new
        skip under the old name through; the list must track the suite."""
        entries = [
            line
            for line in EXPECTED_SKIPS.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]

        for entry in entries:
            node_id, _, reason = entry.partition(" - ")
            path, _, function = node_id.partition("::")
            source = (PROJECT_ROOT / path).read_text(encoding="utf-8")
            assert f"def {function}(" in source, f"{node_id} does not exist"
            # The first word may be interpolated (the missing binary's name).
            static_part = reason.split(" ", 1)[1]
            assert static_part in source, f"{reason!r} is not the reason the test gives"


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
        launcher = tmp_path / "dev.sh"
        launcher.write_text((PROJECT_ROOT / "dev.sh").read_text())
        dispatcher = tmp_path / "python3"
        dispatcher.write_text(
            f'#!/bin/bash\nif [[ "$1" == "-m" ]]; then exit 0; fi\nexec "{sys.executable}" "$@"\n'
        )
        dispatcher.chmod(0o755)
        child = """import signal, time
from pathlib import Path
name = Path(__file__).stem
Path(name + '.started').touch()
def stop(*_args):
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
            env={**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"},
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
    """`[tool.ruff.lint]` keeps a non-empty, internally-consistent rule selection.

    `select` vanishing was an observed defect: CI enforces the SELECTED
    rules, but nothing guards the selection itself. Two more dead-config
    shapes are pinned alongside it: per-file-ignores values referencing
    rules that were never enabled (an ignore that ignores nothing), and
    per-file-ignores keys pointing at files that don't exist (a draft
    carried ignores for a path with the `app/` segment missing, which
    silently un-exempted 18 E501s).
    """

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
