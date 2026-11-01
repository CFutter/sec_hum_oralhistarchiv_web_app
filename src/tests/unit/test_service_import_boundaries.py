"""The public service facade preserves contracts without eager runtime assembly."""

import ast
import hashlib
import importlib
import os
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest

from app import services

_SOURCE_ROOT = Path(__file__).resolve().parents[2]
_PROJECT_ROOT = _SOURCE_ROOT.parent
_EXPECTED_SESSION_HASH = "c101e911469c969171040b50d70543313cf968fdef5bacc780776f8fb399ab36"
# Characterize the established ordered API independently of the lazy export map.
_EXPECTED_EXPORT_DIGEST = "0364cc9792fd56ad0cb19e458eecff5bedfd4b3b199c431ba3cff78063d86bc4"


@pytest.mark.parametrize("import_style", ["package", "owner", "public"])
def test_service_import_is_inert_without_runtime_environment(tmp_path, import_style):
    """An isolated interpreter cannot borrow pytest's settings or site packages."""
    source = f"""
import os
import sys

# CPython may insert LC_CTYPE during locale coercion; no application setting is supplied.
assert set(os.environ) <= {{"LC_CTYPE"}}
def assert_no_runtime_modules():
    forbidden = {{"config", "redis", "cryptography", "argon2", "psycopg"}}
    assert not [name for name in sys.modules if name.split('.')[0] in forbidden]
sys.path.insert(0, sys.argv[1])
import app.services
assert not [name for name in sys.modules if name.startswith('app.services.')]
assert not set(app.services.__all__) & vars(app.services).keys()
assert set(app.services.__all__) <= set(dir(app.services))
assert_no_runtime_modules()
if {import_style!r} != 'package':
    if {import_style!r} == 'public':
        from app.services import hash_session_id
    else:
        from app.services.session_ids import hash_session_id
    assert hash_session_id('session-token') == {_EXPECTED_SESSION_HASH!r}
    assert [name for name in sys.modules if name.startswith('app.services.')] == [
        'app.services.session_ids'
    ]
assert_no_runtime_modules()
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-c", source, str(_SOURCE_ROOT)],
        cwd=tmp_path,
        env={},
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_runtime_and_static_maps_preserve_reviewed_public_exports():
    """Check runtime and static maps preserve reviewed public exports."""
    assert len(services.__all__) == 259
    assert (
        hashlib.sha256("\n".join(services.__all__).encode()).hexdigest() == _EXPECTED_EXPORT_DIGEST
    )
    assert list(services._EXPORT_MODULES) == services.__all__
    assert len(services.__all__) == len(set(services.__all__))
    tree = ast.parse(Path(services.__file__).read_text())
    typing_branch = next(
        node
        for node in tree.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "TYPE_CHECKING"
    )
    static_exports = {}
    for node in typing_branch.body:
        assert isinstance(node, ast.ImportFrom)
        for alias in node.names:
            assert alias.asname == alias.name, "Every public type alias must explicitly re-export"
            assert alias.asname not in static_exports
            static_exports[alias.asname] = "." * node.level + (node.module or "")
    assert static_exports == services._EXPORT_MODULES


def test_every_public_export_retains_owner_identity_and_is_cached(monkeypatch):
    """Check every public export retains owner identity and is cached."""
    owners = {}
    for name, module_name in services._EXPORT_MODULES.items():
        module = importlib.import_module(module_name, services.__name__)
        owners[name] = getattr(module, name)
        monkeypatch.delitem(vars(services), name, raising=False)
        assert getattr(services, name) is owners[name]
        assert vars(services)[name] is owners[name]

    def reject_reload(*_args, **_kwargs):
        """Fail if an already-cached service export imports its owner again."""
        raise AssertionError("Cached exports must not re-import their owner")

    monkeypatch.setattr(services, "_import_module", reject_reload)
    for name, owner in owners.items():
        assert getattr(services, name) is owner


def test_unknown_public_name_raises_attribute_error_without_importing(monkeypatch):
    """Check unknown public name raises attribute error without importing."""

    def reject_import(*_args, **_kwargs):
        """Fail if unknown service-attribute lookup attempts any import."""
        raise AssertionError("An unknown public name must not attempt an import")

    monkeypatch.setattr(services, "_import_module", reject_import)
    name = "hash_session_iid"
    with pytest.raises(AttributeError, match=name):
        _ = getattr(services, name)


@pytest.mark.parametrize(
    "failure",
    [ModuleNotFoundError("owner dependency missing"), RuntimeError("owner initialization failed")],
)
def test_lazy_owner_import_errors_propagate_without_caching(monkeypatch, failure):
    """Check lazy owner import errors propagate without caching."""

    def reject_import(*_args, **_kwargs):
        """Raise the injected failure unchanged."""
        raise failure

    monkeypatch.delitem(vars(services), "hash_session_id", raising=False)
    monkeypatch.setattr(services, "_import_module", reject_import)
    with pytest.raises(type(failure)) as raised:
        _ = services.hash_session_id
    assert raised.value is failure
    assert "hash_session_id" not in vars(services)


def test_public_facade_preserves_signatures_and_rejects_unknown_names_in_mypy(tmp_path):
    """Static callers get the real contract instead of permissive __getattr__ Any."""
    valid = tmp_path / "accepted_consumer.py"
    valid.write_text(
        dedent("""\
        from typing import assert_type
        from app.services import User, hash_session_id

        def consume(user: User) -> str:
            assert_type(user.id, int)
            assert_type(user.email, str)
            assert_type(hash_session_id("session"), str)
            return hash_session_id(user.email)
        """)
    )
    invalid = tmp_path / "rejected_consumer.py"
    invalid.write_text(
        dedent("""\
        from app.services import hash_session_id, hash_session_iid

        hash_session_id(123)
        """)
    )
    environment = dict(os.environ)
    environment["MYPYPATH"] = str(_SOURCE_ROOT)
    environment.pop("MYPY_CACHE_DIR", None)
    command = [
        sys.executable,
        "-m",
        "mypy",
        "--config-file",
        str(_PROJECT_ROOT / "pyproject.toml"),
        "--no-incremental",
        "--cache-dir",
        str(tmp_path / "mypy-cache"),
        "--follow-imports=silent",
        "--show-error-codes",
        "--no-pretty",
    ]
    completed = subprocess.run(
        [*command, str(valid), str(invalid)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 1, completed.stdout + completed.stderr
    assert "accepted_consumer.py:" not in completed.stdout
    assert 'has no attribute "hash_session_iid"' in completed.stdout
    assert "[attr-defined]" in completed.stdout
    assert (
        'Argument 1 to "hash_session_id" has incompatible type "int"; expected "str"'
        in completed.stdout
    )
    assert "[arg-type]" in completed.stdout
    assert "Found 2 errors in 1 file (checked 2 source files)" in completed.stdout
