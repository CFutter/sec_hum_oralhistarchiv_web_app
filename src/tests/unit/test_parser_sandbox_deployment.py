"""Parser deployment separates feed parsing from service credentials and identity."""

import pytest

from app.paths import PROJECT_ROOT
from tests.unit.systemd_units import environment_file_paths, unit_directives

_SOCKET_UNIT = PROJECT_ROOT / "oralhistarchiv-parser.socket"
_SERVICE_UNIT = PROJECT_ROOT / "oralhistarchiv-parser@.service"
_REQUIRED_ISOLATION = {
    "DynamicUser": "yes",
    "NoNewPrivileges": "yes",
    "RestrictSUIDSGID": "yes",
    "RestrictNamespaces": "yes",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "ProtectProc": "invisible",
    "ProcSubset": "pid",
    "PrivateTmp": "yes",
    "PrivateDevices": "yes",
    "KillMode": "control-group",
    "IPAddressDeny": "localhost",
}


def test_parser_socket_is_scheduler_only_and_bounds_concurrent_jobs():
    """Check parser socket is scheduler only and bounds concurrent jobs."""
    assert unit_directives(_SOCKET_UNIT, "ListenStream") == ["/run/oralhistarchiv-parser.sock"]
    assert unit_directives(_SOCKET_UNIT, "SocketUser") == ["root"]
    assert unit_directives(_SOCKET_UNIT, "SocketGroup") == ["oralhistarchiv-scheduler"]
    assert unit_directives(_SOCKET_UNIT, "SocketMode") == ["0660"]
    assert unit_directives(_SOCKET_UNIT, "Accept") == ["yes"]
    assert unit_directives(_SOCKET_UNIT, "Service") == ["oralhistarchiv-parser@.service"]
    assert 1 <= int(unit_directives(_SOCKET_UNIT, "MaxConnections")[0]) <= 2
    assert 1 <= int(unit_directives(_SOCKET_UNIT, "Backlog")[0]) <= 8


@pytest.mark.parametrize(("directive", "required"), _REQUIRED_ISOLATION.items())
def test_parser_service_retains_required_isolation(directive, required):
    """Check parser service retains required isolation."""
    assert unit_directives(_SERVICE_UNIT, directive) == [required]


def test_parser_connections_do_not_share_a_fixed_service_identity():
    """Check parser connections do not share a fixed service identity."""
    assert not unit_directives(_SERVICE_UNIT, "User")
    assert not unit_directives(_SERVICE_UNIT, "Group")
    assert not unit_directives(_SERVICE_UNIT, "SupplementaryGroups")
    assert unit_directives(_SERVICE_UNIT, "CapabilityBoundingSet") == [""]
    assert unit_directives(_SERVICE_UNIT, "AmbientCapabilities") == [""]


def test_parser_service_cannot_open_database_unix_sockets_or_read_service_files():
    """Check parser service cannot open database unix sockets or read service files."""
    assert set(unit_directives(_SERVICE_UNIT, "RestrictAddressFamilies")[0].split()) == {
        "AF_INET",
        "AF_INET6",
    }
    inaccessible = {
        path.removeprefix("-")
        for path in unit_directives(_SERVICE_UNIT, "InaccessiblePaths")[0].split()
    }
    assert {"/etc/oralhistarchiv", "/run/postgresql", "/run/oralhistarchiv"} <= inaccessible


def test_parser_dns_does_not_require_a_loopback_network_exception():
    """Check parser dns does not require a loopback network exception."""
    assert unit_directives(_SERVICE_UNIT, "BindReadOnlyPaths") == [
        "-/run/systemd/resolve/resolv.conf:/etc/resolv.conf"
    ]
    assert not unit_directives(_SERVICE_UNIT, "IPAddressAllow")


def test_parser_starts_with_a_settings_free_entrypoint_and_no_environment_files():
    """Check parser starts with a settings free entrypoint and no environment files."""
    assert environment_file_paths(_SERVICE_UNIT) == []
    assert not unit_directives(_SERVICE_UNIT, "PassEnvironment")
    assert unit_directives(_SERVICE_UNIT, "ExecStart") == [
        "/usr/bin/env -i LANG=C.UTF-8 PATH=/usr/bin:/bin HOME=/nonexistent "
        "/opt/oralhistarchiv/.venv/bin/python -I /opt/oralhistarchiv/run_parser.py"
    ]
    assert unit_directives(_SERVICE_UNIT, "StandardInput") == ["socket"]
    assert unit_directives(_SERVICE_UNIT, "StandardOutput") == ["journal"]
    assert unit_directives(_SERVICE_UNIT, "StandardError") == ["journal"]


def test_parser_processes_have_bounded_lifetimes_memory_and_task_counts():
    """Check parser processes have bounded lifetimes memory and task counts."""
    assert unit_directives(_SERVICE_UNIT, "RuntimeMaxSec") == ["250s"]
    assert unit_directives(_SERVICE_UNIT, "TimeoutStopSec") == ["2s"]
    assert unit_directives(_SERVICE_UNIT, "SendSIGKILL") == ["yes"]
    assert unit_directives(_SERVICE_UNIT, "MemoryMax") == ["512M"]
    assert unit_directives(_SERVICE_UNIT, "TasksMax") == ["16"]
    assert unit_directives(_SERVICE_UNIT, "LimitCORE") == ["0"]
