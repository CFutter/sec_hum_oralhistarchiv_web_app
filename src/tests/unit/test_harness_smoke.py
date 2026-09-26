"""The client harness authenticates for real.

Guards the harness itself: an authenticated request through the harness must
reach its route (200, not 500). A harness whose get_session_user patch returns
anything but a real SessionLookup makes EVERY authenticated request fail at
the unpack, so auth tests would pass for the wrong reason. These tests fail on
such a harness and on any SessionLookup shape drift.
"""

import inspect
import typing
import urllib.parse
from datetime import datetime

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
    # The page actually rendered with the session user, proving the middleware
    # unpacked the lookup and populated request.state.user.
    assert "alice@uzh.ch" in response.text


def test_guest_request_succeeds(guest_client):
    response = guest_client.get("/login")
    assert response.status_code == 200


def test_guest_is_redirected_from_protected_page(guest_client):
    """require_login raises a 303 to /login — proves the guest path resolves
    to no user rather than erroring."""
    response = guest_client.get("/account", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login?next=")


def test_require_login_preserves_query_string_in_next(guest_client):
    """require_login's docstring promises 'path + query' is
    preserved, but session.py:177 (`next_url += "?" + request.url.query`) is
    the ONLY unexecuted line in the module. The existing witness asserts
    `.startswith("/login?next=")`, which is true whether or not the query
    survived. A refactor to a bare `next_url = request.url.path` silently
    drops the user's filters after login."""
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
    """Structural guard: the lookup is a NamedTuple with exactly the fields the
    middleware unpacks. If a field is added/renamed, this and every harness
    construction site fail loudly (the test-side equivalent of the mypy gate)."""
    assert issubclass(SessionLookup, tuple)
    assert SessionLookup._fields == ("user", "purpose", "flash_present")
    hints = inspect.signature(get_session_user).return_annotation
    assert hints is SessionLookup


def test_client_builder_reverse_teardown_restores_reals():
    """Pins the harness's reverse-order teardown contract, self-contained
    (no reliance on file order, randomization, or xdist splitting).
    unittest.mock restores the value seen at patch START: with forward-order
    teardown, closing client1 first re-installs client1's AsyncMock as what
    client2's patch will 'restore', so after both teardowns a mock would be
    permanently installed over the real function for the rest of the
    process. Drives build_client/teardown_client directly — exactly what the
    client_builder fixture's finalizer does — and then requires the
    middleware module to hold the ORIGINAL functions again (identity, not
    equality), not a leaked AsyncMock."""
    real_get_session_user = session_module.get_session_user
    real_consume_flash = session_module.consume_flash
    # Precondition (positive control): nothing before this test leaked a
    # mock — identity with the never-patched originals in
    # app.services.sessions.
    assert real_get_session_user is get_session_user
    assert real_consume_flash is consume_flash

    first = build_client(session_user=None)
    second = build_client(session_user=make_sample_user())
    # REVERSE build order — the pinned guarantee.
    teardown_client(second)
    teardown_client(first)

    assert session_module.get_session_user is real_get_session_user, (
        "teardown leaked a mock over get_session_user"
    )
    assert session_module.consume_flash is real_consume_flash, (
        "teardown leaked a mock over consume_flash"
    )


def test_mock_pool_fails_loudly_when_queried():
    """make_mock_pool's contract: any code path that reaches the pool (via
    pool.connection(), the only route to a cursor) raises instead of silently
    handing back MagicMock results — unit-tier tests must patch the service
    layer. Guards the 'route slipped past the patches and still passed'
    class."""
    pool = make_mock_pool()
    with pytest.raises(AssertionError, match="mock DB pool"):
        pool.connection()


def test_harness_seam_return_shapes_are_pinned():
    """The harness hard-codes the return shapes of the
    two functions it patches away (consume_flash -> (message, category) tuple,
    verify_password -> PasswordCheck(user, password_ok, locked_until, failure_reason,
    auth_revision)). If either annotation changes, this fails and
    fixtures.py / the login-route client tests must be updated in the same
    commit — otherwise every client test keeps passing against a stale
    shape while the real middleware/templates break."""
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
    # Pin the NamedTuple's own field shape too — renaming/retyping a field
    # (or reordering, via _fields) must fail here, not in a template at 3am.
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


# ---------------------------------------------------------------------------
# Suite integrity: guards against the suite silently shrinking or patching
# collaborators that no longer exist.
# ---------------------------------------------------------------------------

import ast  # noqa: E402
import importlib  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
from pathlib import Path  # noqa: E402

_TESTS_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = _TESTS_ROOT.parents[1]
# The number of nodes the suite collects; raise it when tests are added.
_COLLECTED_NODE_FLOOR = 3266


def _patch_targets(path: Path) -> list[tuple[int, str]]:
    """Every dotted production target a test file patches, with its line.

    Recognises ``patch("pkg.mod.name")``, ``patch.object(alias, "name")`` and
    ``monkeypatch.setattr("pkg.mod.name", ...)`` / ``monkeypatch.setattr(alias, "name", ...)``
    where ``alias`` was imported at module level; only targets under ``app.`` or
    ``config.`` are reported (settings values and other data are resolved too:
    a missing attribute is a stale target whatever its kind).
    """
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
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = dotted(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def literal(node: ast.AST) -> str | None:
        return (
            node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None
        )

    def object_target(base_node: ast.AST, attr_node: ast.AST) -> str | None:
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
    """Longest importable module prefix first, then attribute walk; shorter
    prefixes are tried when the walk fails (``config.settings`` is both a
    module and the ``Settings`` instance exported by the package)."""
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
        """A module that stops being collected (a syntax error swallowed by
        ``continue-on-collection-errors``, an accidental rename away from
        ``test_``, a deleted file) shrinks the suite silently; the floor turns
        that into a failure."""
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
        assert "error" not in result.stdout.lower().split("collected in")[0][-200:], result.stdout[
            -2000:
        ]
        assert len(collected) >= _COLLECTED_NODE_FLOOR, (
            f"{len(collected)} nodes collected, floor is {_COLLECTED_NODE_FLOOR}"
        )

    def test_every_patched_production_collaborator_resolves(self):
        """A patch of ``app.x.y`` that no longer exists raises at patch time
        (``AttributeError``) — but only when that test runs; a stale
        ``monkeypatch.setattr`` on a missing attribute with ``raising=False``,
        or a target inside a helper nobody calls any more, stays silent. This
        resolves every target statically."""
        stale: list[str] = []
        for path in sorted(_TESTS_ROOT.rglob("*.py")):
            for lineno, target in _patch_targets(path):
                if not _resolves(target):
                    stale.append(f"{path.relative_to(_REPO_ROOT)}:{lineno} {target}")
        assert stale == [], "patch targets that do not resolve:\n" + "\n".join(stale)

    def test_a_missing_collaborator_is_reported(self):
        """Positive control: the resolver rejects a target that does not exist
        and accepts one that does."""
        assert _resolves("app.services.db.get_db_cursor")
        assert _resolves("config.settings.rate_limit_enabled")
        assert not _resolves("app.services.db.get_db_cursor_that_never_existed")

    def test_the_target_extractor_sees_every_patch_shape(self, tmp_path):
        """Positive control for the extractor: all three patching shapes are
        found, with module-level aliases resolved."""
        sample = tmp_path / "test_sample.py"
        sample.write_text(
            "from unittest.mock import patch\n"
            "import app.services.db as db_module\n"
            "from app.services import sessions\n"
            "def test_x(monkeypatch):\n"
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


# ---------------------------------------------------------------------------
# Suite integrity, continued: signature-enforcing doubles and the sleep register.
# ---------------------------------------------------------------------------

_MOCK_CONSTRUCTORS = frozenset(
    {"Mock", "MagicMock", "AsyncMock", "NonCallableMock", "NonCallableMagicMock"}
)


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _is_permissive_replacement(node: ast.AST | None) -> bool:
    """A replacement that accepts any call shape: none at all (``patch`` then
    auto-creates a ``MagicMock``), a Mock-family constructor, or a lambda that
    swallows ``*args``/``**kwargs``. A named fake with an explicit signature,
    a ``create_autospec(...)`` call and a narrow lambda are signature-enforcing."""
    if node is None:
        return True
    if isinstance(node, ast.Call):
        callee = (_dotted_name(node.func) or "").split(".")[-1]
        return callee in _MOCK_CONSTRUCTORS
    if isinstance(node, ast.Lambda):
        return bool(node.args.vararg or node.args.kwarg)
    return False


def _permissive_patches(path: Path) -> list[str]:
    """Every patch of a callable under ``app.``/``config.`` whose replacement
    is permissive; ``<module>.time.time`` with a return value is a clock
    injection through the module's stdlib reference and is exempt."""
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
            continue  # a settings value or another data attribute
        replacement = None
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
            continue  # autospec=True
        if isinstance(replacement, ast.Call) and (_dotted_name(replacement.func) or "").endswith(
            "create_autospec"
        ):
            continue
        if _is_permissive_replacement(replacement):
            shown = path.relative_to(_REPO_ROOT) if path.is_relative_to(_REPO_ROOT) else path
            found.append((node.lineno, f"{shown}:{node.lineno} {target}"))
    return [text for _, text in sorted(found)]


def _resolve_object(target: str):
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
    """A mock standing in for a production callable is signature-checked.

    A bare ``MagicMock()`` in place of a real function accepts any call shape,
    so a call site that drops or renames an argument keeps passing and the
    test proves nothing about the real signature. Every patch of a callable
    under ``app.`` or ``config.`` therefore uses ``autospec=True``, a
    ``create_autospec(...)`` replacement, or a fake with an explicit
    signature."""

    def test_no_patch_of_a_production_callable_is_a_permissive_mock(self):
        offenders: list[str] = []
        for path in sorted(_TESTS_ROOT.rglob("*.py")):
            offenders.extend(_permissive_patches(path))
        assert offenders == [], "permissive doubles for production callables:\n" + "\n".join(
            offenders
        )

    def test_a_bare_magicmock_replacement_is_reported(self, tmp_path):
        """Positive control: the detector flags a bare replacement and accepts an autospecced one."""
        sample = tmp_path / "test_sample.py"
        sample.write_text(
            "from unittest.mock import MagicMock, create_autospec, patch\n"
            "import app.services.db as db_module\n"
            "def test_x(monkeypatch):\n"
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
        assert flagged == ["4", "6", "11"]


# ---------------------------------------------------------------------------
# Suite integrity, continued: the register of every wait in the suite.
# ---------------------------------------------------------------------------

# Every non-yield sleep in src/tests, by (module, enclosing function). A sleep
# is legitimate only as a short interval inside a deadline-bounded poll of a
# real external condition (a child process, a socket, a database lock seen
# through pg_blocking_pids(), a pub/sub message) or as the idle loop of a
# process body that a test spawns. Anything else is a timing-based proof and
# a defect: add the wait to this register only with such a justification.
_REGISTERED_WAITS: frozenset[tuple[str, str]] = frozenset(
    {
        ("integration/test_account_deactivation_db.py", "_wait_for_database_block"),
        ("integration/test_admin_authorization_races_db.py", "_wait_for_database_block"),
        ("integration/test_auth_revision_races_db.py", "_wait_for_database_block"),
        ("integration/test_federated_authentication_db.py", "_wait_for_blocker"),
        ("integration/test_pool_saturation_db.py", "_wait_until"),
        (
            "integration/test_pool_saturation_db.py",
            "test_excess_contenders_fail_promptly_while_waiters_stay_within_the_bound",
        ),
        ("integration/test_rate_limit_redis_db.py", "_http_get_through_worker_recycling"),
        ("integration/test_rate_limit_redis_db.py", "_wait_for_http_ready"),
        ("integration/test_rate_limit_redis_db.py", "_wait_for_redis_ping"),
        ("integration/test_rate_limit_redis_db.py", "_wait_for_worker_replacement"),
        ("integration/test_redis_tier.py", "_wait_until"),
        ("integration/test_scheduler_db.py", "_poll"),
        ("integration/test_sync_recovery_db.py", "_loop"),
        ("integration/test_totp_rotation_db.py", "_wait_until_all_blocked_by"),
        ("integration/test_users_db.py", "_wait_until_blocked_by"),
        ("unit/test_deployment_units.py", "_wait_for_socket"),
        ("unit/test_nginx_contract.py", "_wait_until_listening"),
        ("unit/test_oai_worker_isolation.py", "_forever_worker"),
        ("unit/test_oai_worker_isolation.py", "_ignore_terminate_worker"),
        ("unit/test_repository_tooling.py", "_wait_for"),
    }
)


def _sleep_sites(path: Path) -> list[tuple[int, str]]:
    """Every ``sleep(...)`` call with a non-zero argument, with its enclosing
    function name (sleeps inside string literals are a spawned child's
    program text and are not calls in this module)."""
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
        """Positive control: a bare sleep in a test body is found with its function name,
        while a zero-second yield and a sleep inside a string literal are not."""
        sample = tmp_path / "test_sample.py"
        sample.write_text(
            "import asyncio, time\n"
            "CHILD = 'import time; time.sleep(30)'\n"
            "async def test_x():\n"
            "    await asyncio.sleep(0)\n"
            "    time.sleep(0.3)\n",
            encoding="utf-8",
        )
        assert _sleep_sites(sample) == [(5, "test_x")]


# ---------------------------------------------------------------------------
# Skipping is opt-in: under CI a skipped integration test fails the run.
# ---------------------------------------------------------------------------

_SRC_ROOT = _TESTS_ROOT.parent

_SKIPPING_INTEGRATION_ITEM = (
    "def test_integration_item():\n"
    '    pytest.skip("the service this test needs is not reachable")\n'
)
_RUNNING_INTEGRATION_ITEMS = (
    "def test_integration_item():\n"
    "    pass\n"
    "\n"
    "\n"
    '@pytest.mark.xfail(strict=True, reason="a guarded defect reports as an expected failure")\n'
    "def test_guarded_defect():\n"
    "    raise AssertionError\n"
)
_PASSING_UNIT_ITEM = "def test_unit_item():\n    pass\n"
_SKIPPING_UNIT_ITEM = (
    'def test_unit_item():\n    pytest.skip("a unit-tier skip is outside the gate")\n'
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
        "import pytest\n\n\n@pytest.fixture(autouse=True)\ndef _reset_rate_limiter():\n    yield\n",
        encoding="utf-8",
    )
    for tier, body in (("integration", integration_body), ("unit", unit_body)):
        (root / tier).mkdir()
        (root / tier / f"test_{tier}_sample.py").write_text(
            "import pytest\n\n\n" + body, encoding="utf-8"
        )
    return root


def _run_sample_suite(
    tree: Path, *, ci: bool, extra: tuple[str, ...] = ()
) -> subprocess.CompletedProcess[str]:
    """Run pytest over a sample tree with the suite's own root conftest loaded
    as a plugin (``-p tests.conftest``), so the hooks exercised are the real
    ones. The environment is the parent's minus any xdist worker identity and
    with ``CI`` set or removed as the scenario needs."""
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
    """With ``CI`` set (GitHub Actions exports ``CI=true``) a run in which an
    integration-tier test skipped exits non-zero although nothing failed;
    without ``CI`` the skip stays a skip. REQUIRE_DB and REQUIRE_REDIS cover a
    dead service; this hook covers every other reason an integration test
    might skip."""

    @pytest.mark.parametrize("workers", [(), ("-n", "2")], ids=["one-process", "two-xdist-workers"])
    def test_a_skipped_integration_item_fails_the_run_under_ci(self, tmp_path, workers):
        tree = _sample_tree(tmp_path, integration_body=_SKIPPING_INTEGRATION_ITEM)
        result = _run_sample_suite(tree, ci=True, extra=workers)
        assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
        assert "INTEGRATION TESTS SKIPPED UNDER CI" in result.stdout
        assert "integration/test_integration_sample.py::test_integration_item" in result.stdout

    def test_the_same_skip_stays_a_skip_without_ci(self, tmp_path):
        tree = _sample_tree(tmp_path, integration_body=_SKIPPING_INTEGRATION_ITEM)
        result = _run_sample_suite(tree, ci=False)
        assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
        assert "1 passed, 1 skipped" in result.stdout

    def test_a_run_whose_integration_items_all_ran_passes_under_ci(self, tmp_path):
        """Positive control and discriminator: with ``CI`` set, an integration
        item that runs, an integration item that is an expected failure and a
        unit-tier skip together still exit 0. The gate keys on real skips in
        the integration tier, nothing else."""
        tree = _sample_tree(
            tmp_path, integration_body=_RUNNING_INTEGRATION_ITEMS, unit_body=_SKIPPING_UNIT_ITEM
        )
        result = _run_sample_suite(tree, ci=True)
        assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
        assert "1 passed, 1 skipped, 1 xfailed" in result.stdout
        assert "INTEGRATION TESTS SKIPPED" not in result.stdout
