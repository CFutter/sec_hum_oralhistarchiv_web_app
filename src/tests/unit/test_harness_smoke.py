"""Client-harness interface contracts and suite collection, patching, wait and skip guards."""

import inspect
import typing
import urllib.parse
from datetime import datetime
from unittest.mock import create_autospec

import pytest

import app.middleware.session as session_module
from app.services.authentication import (
    LoginFailureReason,
    PasswordCheck,
    verify_password,
)
from app.services.sessions import SessionLookup, consume_flash, get_session_user
from app.services.users import User
from tests.fixtures import build_client, make_mock_pool, make_sample_user, teardown_client


def test_authenticated_request_succeeds(authenticated_client):
    """An authenticated GET must produce a real 200 page, not a blanket 500."""
    response = authenticated_client.get("/account")
    assert response.status_code == 200
    assert "alice@example.org" in response.text


def test_guest_request_succeeds(guest_client):
    """Guest request succeeds."""
    response = guest_client.get("/login")
    assert response.status_code == 200


def test_guest_is_redirected_from_protected_page(guest_client):
    """require_login raises a 303 to /login — proves the guest path resolves
    to no user rather than erroring."""
    response = guest_client.get("/account", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login?next=")


def test_require_login_preserves_query_string_in_next(guest_client):
    """Preserve both path and query in the login return destination."""
    resp = guest_client.get("/account?tab=security&highlight=totp", follow_redirects=False)

    assert resp.status_code == 303
    next_value = urllib.parse.unquote(resp.headers["location"].removeprefix("/login?next="))
    assert next_value == "/account?tab=security&highlight=totp"


def test_require_login_next_has_no_stray_query_marker(guest_client):
    """POSITIVE CONTROL: no dangling '?' when the URL has no query string —
    an unconditional concatenation would produce '/account?'."""
    resp = guest_client.get("/account", follow_redirects=False)
    assert urllib.parse.unquote(resp.headers["location"].removeprefix("/login?next=")) == "/account"


def test_get_session_user_returns_sessionlookup_namedtuple():
    """Keep SessionLookup fields and NamedTuple identity aligned with the middleware contract."""
    assert issubclass(SessionLookup, tuple)
    assert SessionLookup._fields == ("user", "purpose", "flash_present")
    hints = inspect.signature(get_session_user).return_annotation
    assert hints is SessionLookup


def test_client_builder_reverse_teardown_restores_reals():
    """Restore original session collaborators after reverse-order client teardown."""
    real_get_session_user = session_module.get_session_user
    real_consume_flash = session_module.consume_flash
    assert real_get_session_user is get_session_user
    assert real_consume_flash is consume_flash

    first = build_client(session_user=None)
    second = build_client(session_user=make_sample_user())
    teardown_client(second)
    teardown_client(first)

    assert session_module.get_session_user is real_get_session_user, (
        "teardown leaked a mock over get_session_user"
    )
    assert session_module.consume_flash is real_consume_flash, (
        "teardown leaked a mock over consume_flash"
    )


def test_mock_pool_fails_loudly_when_queried():
    """Mock pool fails loudly when queried."""
    pool = make_mock_pool()
    with pytest.raises(AssertionError, match="mock DB pool"):
        pool.connection()


def test_harness_seam_return_shapes_are_pinned():
    """Keep mocked flash/password results aligned with production return annotations."""
    hints = typing.get_type_hints(consume_flash)
    assert hints["return"] == (tuple[str, str] | None), (
        f"consume_flash return shape changed to {hints['return']!r}; "
        "update tests/fixtures.py build_client(flash=...) to match"
    )

    vp_hints = typing.get_type_hints(verify_password)
    assert vp_hints["return"] is PasswordCheck, (
        f"verify_password return shape changed to {vp_hints['return']!r}; "
        "update the login-route client tests to match"
    )
    assert PasswordCheck._fields == (
        "user",
        "password_ok",
        "locked_until",
        "failure_reason",
        "auth_revision",
    ), (
        f"PasswordCheck fields changed to {PasswordCheck._fields!r}; "
        "update the login-route client tests and their mocks to match"
    )
    pc_hints = typing.get_type_hints(PasswordCheck)
    assert pc_hints == {
        "user": User | None,
        "password_ok": bool,
        "locked_until": datetime | None,
        "failure_reason": LoginFailureReason | None,
        "auth_revision": int | None,
    }, (
        f"PasswordCheck field types changed to {pc_hints!r}; "
        "update the login-route client tests and their mocks to match"
    )


import ast  # noqa: E402
import importlib  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
from pathlib import Path  # noqa: E402

_TESTS_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = _TESTS_ROOT.parents[1]
# Minimum collected-node count; raise it when tests are added.
_COLLECTED_NODE_FLOOR = 8881


def _patch_targets(path: Path) -> list[tuple[int, str]]:
    """Return production patch targets and lines resolved through module-level import aliases."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                aliases[name.asname or name.name.split(".")[0]] = name.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for name in node.names:
                aliases[name.asname or name.name] = f"{node.module}.{name.name}"

    def dotted(node: ast.AST) -> str | None:
        """Resolve an AST name/attribute chain, returning None for other expressions."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = dotted(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def literal(node: ast.AST) -> str | None:
        """Return a literal string value or None for other AST expressions."""
        return (
            node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None
        )

    def object_target(base_node: ast.AST, attr_node: ast.AST) -> str | None:
        """Resolve an attribute patch through a known module alias or return None."""
        base, attr = dotted(base_node), literal(attr_node)
        if not base or not attr:
            return None
        head, _, tail = base.partition(".")
        if head not in aliases:
            # A local object (a FastAPI instance named ``app``, a fixture),
            # not a module: nothing to resolve statically.
            return None
        root = aliases[head]
        return f"{root}.{tail}.{attr}" if tail else f"{root}.{attr}"

    targets: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = dotted(node.func) or ""
        target = None
        if func.endswith("patch") and node.args:
            target = literal(node.args[0])
        elif func.endswith("patch.object") and len(node.args) >= 2:
            target = object_target(node.args[0], node.args[1])
        elif func.endswith("monkeypatch.setattr") and len(node.args) >= 2:
            target = (
                literal(node.args[0])
                if len(node.args) == 2
                else object_target(node.args[0], node.args[1])
            )
        if target and (target.startswith("app.") or target.startswith("config.")):
            targets.append((node.lineno, target))
    return sorted(targets)


def _resolves(target: str) -> bool:
    """Return whether any importable module prefix resolves all remaining target attributes."""
    parts = target.split(".")
    for cut in range(len(parts), 0, -1):
        try:
            obj = importlib.import_module(".".join(parts[:cut]))
        except Exception:
            continue
        try:
            for attr in parts[cut:]:
                obj = getattr(obj, attr)
        except AttributeError:
            continue
        return True
    return False


class TestSuiteIntegrity:
    """Guards that the collected suite is at least as large as the last audited
    one and that every patched production collaborator still exists."""

    def test_collected_node_count_never_drops_below_the_floor(self):
        """Collected node count never drops below the floor."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "--collect-only",
                "-q",
                "-p",
                "no:randomly",
                "-p",
                "no:cacheprovider",
            ],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        collected = [line for line in result.stdout.splitlines() if "::" in line]
        assert result.returncode == 0, (
            f"Collection failed (exit {result.returncode}):\n"
            + (result.stdout + result.stderr)[-6000:]
        )
        assert len(collected) >= _COLLECTED_NODE_FLOOR, (
            f"{len(collected)} nodes collected, floor is {_COLLECTED_NODE_FLOOR}"
        )

    @pytest.mark.parametrize(
        ("exit_status", "count_delta", "failure"),
        [(2, 0, "Collection failed"), (0, -1, "nodes collected"), (0, 0, None)],
        ids=["failed-collection-with-enough-nodes", "successful-but-shrunken", "successful"],
    )
    def test_collection_guard_requires_success_and_sufficient_nodes(
        self, monkeypatch, exit_status, count_delta, failure
    ):
        """Partial collection can print enough nodes while reporting its failure on stderr."""
        count = _COLLECTED_NODE_FLOOR + count_delta
        output = "\n".join(f"src/tests/test_sample.py::test_error_case_{n}" for n in range(count))
        result = subprocess.CompletedProcess(
            args=[],
            returncode=exit_status,
            stdout=output + f"\n{count} tests collected in 1s\n",
            stderr="collector failed" if exit_status else "",
        )
        monkeypatch.setattr(subprocess, "run", create_autospec(subprocess.run, return_value=result))
        if failure:
            with pytest.raises(AssertionError, match=failure):
                self.test_collected_node_count_never_drops_below_the_floor()
        else:
            self.test_collected_node_count_never_drops_below_the_floor()

    def test_every_patched_production_collaborator_resolves(self):
        """Every patched production collaborator resolves."""
        stale: list[str] = []
        for path in sorted(_TESTS_ROOT.rglob("*.py")):
            for lineno, target in _patch_targets(path):
                if not _resolves(target):
                    stale.append(f"{path.relative_to(_REPO_ROOT)}:{lineno} {target}")
        assert stale == [], "patch targets that do not resolve:\n" + "\n".join(stale)

    def test_a_missing_collaborator_is_reported(self):
        """The resolver rejects a target that does not exist and accepts one that does."""
        assert _resolves("app.services.db.get_db_cursor")
        assert _resolves("config.settings.rate_limit_enabled")
        assert not _resolves("app.services.db.get_db_cursor_that_never_existed")

    def test_the_target_extractor_sees_every_patch_shape(self, tmp_path):
        """Positive control for the extractor: all three patching shapes are
        found, with module-level aliases resolved."""
        sample = tmp_path / "test_sample.py"
        sample.write_text(
            "'''Provide patch forms for the AST target extractor.'''\n"
            "from unittest.mock import patch\n"
            "import app.services.db as db_module\n"
            "from app.services import sessions\n"
            "def test_x(monkeypatch):\n"
            "    '''Expose string, object and monkeypatch targets to the AST extractor.'''\n"
            "    with patch('app.services.db.get_db_cursor'):\n"
            "        pass\n"
            "    with patch.object(db_module, 'create_pool'):\n"
            "        pass\n"
            "    monkeypatch.setattr(sessions, 'get_session_user', None)\n"
            "    monkeypatch.setattr('app.services.db.create_pool', None)\n",
            encoding="utf-8",
        )
        assert [t for _, t in _patch_targets(sample)] == [
            "app.services.db.get_db_cursor",
            "app.services.db.create_pool",
            "app.services.sessions.get_session_user",
            "app.services.db.create_pool",
        ]


_MOCK_CONSTRUCTORS = frozenset(
    {"Mock", "MagicMock", "AsyncMock", "NonCallableMock", "NonCallableMagicMock"}
)


def _dotted_name(node: ast.AST) -> str | None:
    """Resolve an AST name/attribute chain, returning None for other expressions."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _is_permissive_replacement(node: ast.AST | None) -> bool:
    """Recognize absent, Mock-family and variadic-lambda replacements that accept arbitrary calls."""
    if node is None:
        return True
    if isinstance(node, ast.Call):
        callee = (_dotted_name(node.func) or "").split(".")[-1]
        return callee in _MOCK_CONSTRUCTORS
    if isinstance(node, ast.Lambda):
        return bool(node.args.vararg or node.args.kwarg)
    return False


def _permissive_patches(path: Path) -> list[str]:
    """Return permissive production-callable patch locations, excluding injected stdlib clocks."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    targets = dict(_patch_targets(path))
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or node.lineno not in targets:
            continue
        func = _dotted_name(node.func) or ""
        if not (
            func.endswith("patch")
            or func.endswith("patch.object")
            or func.endswith("monkeypatch.setattr")
        ):
            continue
        target = targets[node.lineno]
        if target.endswith(".time.time"):
            continue
        obj = _resolve_object(target)
        if obj is None or not callable(obj):
            continue
        replacement: ast.expr | None = None
        for keyword in node.keywords:
            if (
                keyword.arg == "autospec"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            ):
                replacement = keyword.value
                break
            if keyword.arg in ("new", "value"):
                replacement = keyword.value
        if replacement is None:
            string_target = func.endswith("monkeypatch.setattr") and len(node.args) == 2
            plain_patch = func.endswith("patch") and not func.endswith("patch.object")
            positional = node.args[1:] if (string_target or plain_patch) else node.args[2:]
            replacement = positional[0] if positional else None
        if isinstance(replacement, ast.Constant) and replacement.value is True:
            continue
        if isinstance(replacement, ast.Call) and (_dotted_name(replacement.func) or "").endswith(
            "create_autospec"
        ):
            continue
        if _is_permissive_replacement(replacement):
            shown = path.relative_to(_REPO_ROOT) if path.is_relative_to(_REPO_ROOT) else path
            found.append((node.lineno, f"{shown}:{node.lineno} {target}"))
    return [text for _, text in sorted(found)]


def _resolve_object(target: str):
    """Import the longest usable module prefix and resolve attributes, returning None on failure."""
    parts = target.split(".")
    for cut in range(len(parts), 0, -1):
        try:
            obj = importlib.import_module(".".join(parts[:cut]))
        except Exception:
            continue
        try:
            for attr in parts[cut:]:
                obj = getattr(obj, attr)
        except AttributeError:
            continue
        return obj
    return None


class TestDoublesEnforceProductionSignatures:
    """A mock standing in for a production callable is signature-checked."""

    def test_no_patch_of_a_production_callable_is_a_permissive_mock(self):
        """No patch of a production callable is a permissive mock."""
        offenders: list[str] = []
        for path in sorted(_TESTS_ROOT.rglob("*.py")):
            offenders.extend(_permissive_patches(path))
        assert offenders == [], "permissive doubles for production callables:\n" + "\n".join(
            offenders
        )

    def test_a_bare_magicmock_replacement_is_reported(self, tmp_path):
        """The detector flags a bare replacement and accepts an autospecced one."""
        sample = tmp_path / "test_sample.py"
        sample.write_text(
            "'''Provide permissive and signature-checked patches for the AST detector.'''\n"
            "from unittest.mock import MagicMock, create_autospec, patch\n"
            "import app.services.db as db_module\n"
            "def test_x(monkeypatch):\n"
            "    '''Expose permissive and signature-checked production-callable patches.'''\n"
            "    with patch('app.services.db.get_db_cursor'):\n"
            "        pass\n"
            "    with patch('app.services.db.create_pool', new=MagicMock()):\n"
            "        pass\n"
            "    with patch.object(db_module, 'create_pool', autospec=True):\n"
            "        pass\n"
            "    monkeypatch.setattr(db_module, 'get_db_cursor', create_autospec(db_module.get_db_cursor))\n"
            "    monkeypatch.setattr(db_module, 'create_pool', lambda *a, **k: None)\n",
            encoding="utf-8",
        )
        flagged = [line.split(" ", 1)[0].rsplit(":", 1)[1] for line in _permissive_patches(sample)]
        assert flagged == ["6", "8", "13"]


# Every non-yield sleep in src/tests, by (module, enclosing function). A sleep
# is legitimate only as a short interval inside a deadline-bounded poll of a
# real external condition (a child process, a socket, a database lock seen
# through pg_blocking_pids(), a pub/sub message) or as the idle loop of a
# process body that a test spawns. Anything else is a timing-based proof and
# a defect: add the wait to this register only with such a justification.
_REGISTERED_WAITS: frozenset[tuple[str, str]] = frozenset(
    {
        ("integration/server_processes.py", "_wait_for_redis_ping"),
        # Observe a real active PostgreSQL sleep before cancelling its owning request.
        (
            "integration/test_search_work_db.py",
            "test_cancelled_search_query_stops_before_capacity_is_reused",
        ),
        # Poll actual Redis expiry and process readiness under explicit deadlines.
        (
            "unit/test_bounded_rate_limit_storage.py",
            "test_expiry_reclaims_slots_and_clear_removes_registry_member",
        ),
        ("unit/test_bounded_rate_limit_storage.py", "_persistent_redis"),
        # Bounded pg_blocking_pids poll proves account expiry checks wait on a real row lock.
        ("integration/test_account_database_clock_db.py", "_wait_for_blocked_task"),
        ("integration/test_account_deactivation_db.py", "_wait_for_database_block"),
        # Bounded polling observes both deletion transactions blocked by PostgreSQL.
        (
            "integration/test_account_deletion_db.py",
            "test_two_admin_self_deletions_observe_the_shared_lock_and_leave_one_active_admin",
        ),
        ("integration/test_admin_authorization_races_db.py", "_wait_for_database_block"),
        ("integration/test_auth_revision_races_db.py", "_wait_for_database_block"),
        # Cross the real signed/persisted expiry while a PostgreSQL row lock is held.
        ("integration/test_auth_revision_races_db.py", "_wait_for_expiry"),
        # Hold the first INSERT until the competing transaction reaches its conflict wait.
        (
            "integration/test_change_aware_ingestion_db.py",
            "test_direct_concurrent_first_writes_keep_atomic_conflict_and_stricter_tier",
        ),
        ("integration/test_dataset_admin_actions_db.py", "_wait_for_catalogue_block"),
        ("integration/test_federated_authentication_db.py", "_wait_for_blocker"),
        # Bounded polling observes the PostgreSQL blocker of verification/claim races.
        ("integration/test_federated_reservation_claim_db.py", "observed_wait"),
        ("integration/test_pool_saturation_db.py", "_wait_until"),
        (
            "integration/test_pool_saturation_db.py",
            "test_excess_contenders_fail_promptly_while_waiters_stay_within_the_bound",
        ),
        ("integration/test_rate_limit_redis_db.py", "_http_get_through_worker_recycling"),
        ("integration/test_rate_limit_redis_db.py", "_wait_for_http_ready"),
        ("integration/test_rate_limit_redis_db.py", "_wait_for_worker_replacement"),
        # Bounded poll of Gunicorn boot-log PIDs after max_requests recycling.
        (
            "integration/test_rate_limit_redis_db.py",
            "test_worker_recycling_via_max_requests_does_not_restore_the_quota",
        ),
        ("integration/test_redis_tier.py", "_wait_until"),
        ("integration/test_scheduler_db.py", "_poll"),
        ("integration/test_sync_recovery_db.py", "_loop"),
        ("integration/test_totp_rotation_db.py", "_wait_until_all_blocked_by"),
        ("integration/test_users_db.py", "_wait_until_blocked_by"),
        ("unit/test_deployment_units.py", "_wait_for_socket"),
        ("unit/test_nginx_contract.py", "_wait_until_listening"),
        ("unit/test_oai_worker_isolation.py", "_forever_worker"),
        ("unit/test_oai_worker_isolation.py", "_ignore_terminate_worker"),
        # Observe a live child after cancellation; the worker must be reaped before return.
        (
            "unit/test_source_fetch_cancellation.py",
            "test_cancelled_fetch_is_reaped_before_ingestion_lock_and_tracker_release",
        ),
        ("unit/test_repository_tooling.py", "_wait_for"),
    }
)


def _sleep_sites(path: Path) -> list[tuple[int, str]]:
    """Return nonzero AST sleep locations with their enclosing function names."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    sites: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        name = callee.attr if isinstance(callee, ast.Attribute) else getattr(callee, "id", None)
        if name != "sleep":
            continue
        argument = node.args[0] if node.args else None
        if isinstance(argument, ast.Constant) and argument.value == 0:
            continue  # an event-loop yield, not a wait
        current: ast.AST | None = node
        function = "<module>"
        while current in parents:
            current = parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function = current.name
                break
        sites.append((node.lineno, function))
    return sorted(sites)


class TestEveryWaitIsRegistered:
    """A sleep that is not in the register is a timing-based proof and fails here."""

    def test_no_sleep_outside_the_register(self):
        """No sleep outside the register."""
        unregistered: list[str] = []
        for path in sorted(_TESTS_ROOT.rglob("*.py")):
            key_module = str(path.relative_to(_TESTS_ROOT))
            for lineno, function in _sleep_sites(path):
                if (key_module, function) not in _REGISTERED_WAITS:
                    unregistered.append(f"{key_module}:{lineno} in {function}")
        assert unregistered == [], "sleeps outside the register:\n" + "\n".join(unregistered)

    def test_the_register_names_only_waits_that_exist(self):
        """A register entry without a sleep behind it is stale: remove it."""
        present = set()
        for path in sorted(_TESTS_ROOT.rglob("*.py")):
            key_module = str(path.relative_to(_TESTS_ROOT))
            present.update((key_module, function) for _, function in _sleep_sites(path))
        stale = sorted(_REGISTERED_WAITS - present)
        assert stale == [], f"register entries with no sleep behind them: {stale}"

    def test_an_unregistered_sleep_is_reported(self, tmp_path):
        """A bare sleep in a test body is found with its function name, while a zero-second yield
        and a sleep inside a string literal are not.
        """
        sample = tmp_path / "test_sample.py"
        sample.write_text(
            "'''Provide sleep calls and child-program text for the AST wait detector.'''\n"
            "import asyncio, time\n"
            "CHILD = 'import time; time.sleep(30)'\n"
            "async def test_x():\n"
            "    '''Expose a nonzero wait while excluding an event-loop yield.'''\n"
            "    await asyncio.sleep(0)\n"
            "    time.sleep(0.3)\n",
            encoding="utf-8",
        )
        assert _sleep_sites(sample) == [(7, "test_x")]


_SRC_ROOT = _TESTS_ROOT.parent

_SKIPPING_INTEGRATION_ITEM = (
    "def test_integration_item():\n"
    "    '''Skip because the synthetic integration service is unavailable.'''\n"
    '    pytest.skip("the service this test needs is not reachable")\n'
)
_RUNNING_INTEGRATION_ITEMS = (
    "def test_integration_item():\n"
    "    '''Complete an integration sample without side effects.'''\n"
    "    pass\n"
    "\n"
    "\n"
    '@pytest.mark.xfail(strict=True, reason="a guarded defect reports as an expected failure")\n'
    "def test_guarded_defect():\n"
    "    '''Raise AssertionError to exercise strict expected-failure handling.'''\n"
    "    raise AssertionError\n"
)
_PASSING_UNIT_ITEM = (
    "def test_unit_item():\n    '''Complete a unit sample without side effects.'''\n    pass\n"
)
_SKIPPING_UNIT_ITEM = (
    "def test_unit_item():\n"
    "    '''Skip a unit sample outside the integration-skip gate.'''\n"
    '    pytest.skip("a unit-tier skip is outside the gate")\n'
)


def _sample_tree(root: Path, *, integration_body: str, unit_body: str = _PASSING_UNIT_ITEM) -> Path:
    """A two-tier sample suite: ``integration/`` items are marked by the root
    conftest's collection hook exactly as the real tier is."""
    (root / "pytest.ini").write_text(
        "[pytest]\nmarkers =\n    integration: the sample's integration tier\n",
        encoding="utf-8",
    )
    # The sample sends no request, so the suite's autouse counter reset is
    # overridden with a no-op: the sample run must never touch the Redis
    # database of a sibling process (an xdist worker of the run that spawned it).
    (root / "conftest.py").write_text(
        "'''Override sample-suite fixtures without touching sibling Redis databases.'''\n"
        "import pytest\n"
        "\n"
        "\n"
        "@pytest.fixture(autouse=True)\n"
        "def _reset_rate_limiter():\n"
        "    '''Yield without resetting shared Redis state.'''\n"
        "    yield\n",
        encoding="utf-8",
    )
    for tier, body in (("integration", integration_body), ("unit", unit_body)):
        (root / tier).mkdir()
        (root / tier / f"test_{tier}_sample.py").write_text(
            "'''Synthetic suite for integration-skip CI policy.'''\nimport pytest\n\n\n" + body,
            encoding="utf-8",
        )
    return root


def _run_sample_suite(
    tree: Path, *, ci: bool, extra: tuple[str, ...] = ()
) -> subprocess.CompletedProcess[str]:
    """Run a sample suite with the real conftest plugin, isolated worker identity and selected CI
    mode.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTEST_XDIST") and k != "CI"}
    env["PYTHONPATH"] = str(_SRC_ROOT)
    # A fixed base keeps the sample's nominal Redis databases (never used, see
    # the override in _sample_tree) inside the sixteen whatever base the run
    # that spawned it uses; with the parent's base the -n 2 scenario would ask
    # for database 16 or 17 and the root conftest would refuse to import.
    env["TEST_RATE_LIMIT_REDIS_DB"] = "0"
    if ci:
        env["CI"] = "true"
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "tests.conftest",
            "-p",
            "no:randomly",
            "-p",
            "no:cacheprovider",
            "-q",
            "-c",
            str(tree / "pytest.ini"),
            *extra,
            str(tree),
        ],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


class TestSkippedIntegrationTestsFailTheRunUnderCI:
    """Fail CI on skipped integration items while preserving ordinary local skips."""

    @pytest.mark.parametrize("workers", [(), ("-n", "2")], ids=["one-process", "two-xdist-workers"])
    def test_a_skipped_integration_item_fails_the_run_under_ci(self, tmp_path, workers):
        """A skipped integration item fails the run under CI."""
        tree = _sample_tree(tmp_path, integration_body=_SKIPPING_INTEGRATION_ITEM)
        result = _run_sample_suite(tree, ci=True, extra=workers)
        assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
        assert "INTEGRATION TESTS SKIPPED UNDER CI" in result.stdout
        assert "integration/test_integration_sample.py::test_integration_item" in result.stdout

    def test_the_same_skip_stays_a_skip_without_ci(self, tmp_path):
        """The same skip stays a skip without CI."""
        tree = _sample_tree(tmp_path, integration_body=_SKIPPING_INTEGRATION_ITEM)
        result = _run_sample_suite(tree, ci=False)
        assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
        assert "1 passed, 1 skipped" in result.stdout

    def test_a_run_whose_integration_items_all_ran_passes_under_ci(self, tmp_path):
        """A run whose integration items all ran passes under CI."""
        tree = _sample_tree(
            tmp_path, integration_body=_RUNNING_INTEGRATION_ITEMS, unit_body=_SKIPPING_UNIT_ITEM
        )
        result = _run_sample_suite(tree, ci=True)
        assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
        assert "1 passed, 1 skipped, 1 xfailed" in result.stdout
        assert "INTEGRATION TESTS SKIPPED" not in result.stdout
