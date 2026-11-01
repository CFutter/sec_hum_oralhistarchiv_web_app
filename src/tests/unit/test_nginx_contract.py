"""Deployment-contract pins for nginx request-log confidentiality."""

import contextlib
import http.client
import os
import re
import shlex
import shutil
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from app.paths import PROJECT_ROOT
from app.services.tokens import action_token_public_id, action_token_url

NGINX_CONFIG = PROJECT_ROOT / "deploy" / "nginx.conf.example"
ORDINARY_PROXY_HEADERS = PROJECT_ROOT / "deploy" / "nginx-ordinary-proxy-headers.conf.example"
SHIBBOLETH_PHASE2_CONFIG = PROJECT_ROOT / "deploy" / "nginx-shibboleth-phase2.conf.example"
SHIBBOLETH_SECRET_CONFIG = PROJECT_ROOT / "deploy" / "nginx-shibboleth-secret.conf.example"
ORDINARY_PROXY_INCLUDE = "/etc/nginx/snippets/oralhistarchiv-ordinary-proxy-headers.conf"
SHIBBOLETH_SECRET_INCLUDE = "/etc/nginx/snippets/oralhistarchiv-shibboleth-secret.conf"
APPLICATION_UPSTREAM = "http://oralhistarchiv"
DEPLOYMENT_RUNBOOK = PROJECT_ROOT / "Deployment.md"
KEY_ROTATION_RUNBOOK = PROJECT_ROOT / "docs" / "runbooks" / "key-rotation.md"
SAFE_LOG_FORMAT = "oralhistarchiv_safe"

_FIXED_FEDERATION_HEADERS = frozenset(
    {
        "X-OHA-Internal-Auth",
        "X-OHA-Shib-Issuer",
        "X-OHA-Shib-Subject",
        "X-OHA-Shib-Mail",
        "X-OHA-Shib-Authn-Context",
        "X-OHA-Shib-Display-Name",
        "X-OHA-Shib-Affiliation",
        "X-OHA-Shib-Entitlement",
        "X-OHA-Shib-Country",
    }
)

_LEGACY_FEDERATION_HEADERS = frozenset(
    {
        "X-Internal-Auth",
        "REMOTE_USER",
        "eduPersonUniqueId",
        "mail",
        "displayName",
        "affiliation",
        "entitlement",
        "eduPersonEntitlement",
        "schacHomeOrganizationCountry",
        "Shib-Identity-Provider",
        "Shib-AuthnContext-Class",
    }
)

_LEGACY_FEDERATION_HEADERS = frozenset(
    {
        "X-Internal-Auth",
        "REMOTE_USER",
        "eduPersonUniqueId",
        "mail",
        "displayName",
        "affiliation",
        "entitlement",
        "eduPersonEntitlement",
        "schacHomeOrganizationCountry",
        "Shib-Identity-Provider",
        "Shib-AuthnContext-Class",
    }
)

# Fail closed: adding a new nginx log variable requires an explicit security
# review.  In particular, no URI, query, Referer, Cookie, Authorization, or
# arbitrary client-header variable belongs in the access log.
_ALLOWED_LOG_VARIABLES = frozenset(
    {
        "$body_bytes_sent",
        "$remote_addr",
        "$request_method",
        "$request_time",
        "$sent_http_x_request_id",
        "$status",
        "$time_iso8601",
    }
)


def _without_comments(text: str) -> str:
    """Drop nginx comments; the example contains no quoted literal ``#``."""
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _config_text() -> str:
    """Read the nginx example without comments, failing if it is missing."""
    assert NGINX_CONFIG.exists(), f"nginx example not found at {NGINX_CONFIG}"
    return _without_comments(NGINX_CONFIG.read_text(encoding="utf-8"))


def _file_without_comments(path: Path) -> str:
    """Read the selected nginx fragment without comments, failing if it is missing."""
    assert path.exists(), f"nginx example not found at {path}"
    return _without_comments(path.read_text(encoding="utf-8"))


def _required_executable(name: str) -> str:
    """Find an executable; fail under REQUIRE_NGINX=1, otherwise skip when absent."""
    executable = shutil.which(name)
    if executable is not None:
        return executable
    if os.environ.get("REQUIRE_NGINX") == "1":
        pytest.fail(f"{name} is required by REQUIRE_NGINX=1")
    pytest.skip(f"{name} is not installed in this development environment")


def _balanced_blocks(text: str, opener: re.Pattern[str]) -> list[str]:
    """Return bodies of matching nginx blocks, including nested content."""
    bodies: list[str] = []
    for match in opener.finditer(text):
        depth = 1
        cursor = match.end()
        body_start = cursor

        while cursor < len(text) and depth:
            if text[cursor] == "{":
                depth += 1
            elif text[cursor] == "}":
                depth -= 1
            cursor += 1

        assert depth == 0, f"unterminated nginx block beginning at offset {match.start()}"
        bodies.append(text[body_start : cursor - 1])

    return bodies


def _direct_directives(block: str, name: str) -> list[str]:
    """Return this block's directives, preserving quoted semicolons and excluding nested blocks."""
    directives: list[str] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    escaped = False

    for character in block:
        if quote is not None:
            if depth == 0:
                current.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif character in {"'", '"'}:
            quote = character
            if depth == 0:
                current.append(character)
        elif character == "{":
            if depth == 0:
                current.clear()
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                current.clear()
        elif character == ";" and depth == 0:
            directive = "".join(current).strip()
            current.clear()
            parts = directive.split(None, 1)
            if len(parts) == 2 and parts[0] == name:
                directives.append(parts[1].strip())
        elif depth == 0:
            current.append(character)

    return directives


def _access_log_is_safe(value: str) -> bool:
    """Accept disabled logging or an explicit reference to the safe log format."""
    tokens = value.split()
    return bool(tokens) and (tokens[0] == "off" or SAFE_LOG_FORMAT in tokens[1:])


def _proxy_headers(block: str) -> dict[str, list[str]]:
    """Return case-insensitive proxy header assignments, retaining duplicates."""
    headers: dict[str, list[str]] = {}
    for directive in _direct_directives(block, "proxy_set_header"):
        name, value = directive.split(None, 1)
        headers.setdefault(name.casefold(), []).append(value)
    return headers


def _static_header_configuration() -> tuple[list[str], str]:
    """Return the application server's header directives and its sole static-location body."""
    selected = [
        (server, location)
        for server in _balanced_blocks(_config_text(), re.compile(r"(?m)^\s*server\s*\{"))
        for location in _balanced_blocks(server, re.compile(r"(?m)^\s*location\s+/static/\s*\{"))
    ]
    assert len(selected) == 1, "expected one application static location"
    server, location = selected[0]
    return _direct_directives(server, "add_header"), location


def test_safe_log_format_uses_only_reviewed_noncredential_variables():
    """Check safe log format uses only reviewed noncredential variables."""
    config = _config_text()
    matches = re.findall(
        rf"(?ms)^\s*log_format\s+{SAFE_LOG_FORMAT}\b(?P<body>.*?);",
        config,
    )

    assert len(matches) == 1, f"expected exactly one {SAFE_LOG_FORMAT!r} log format"
    variables = set(re.findall(r"\$[A-Za-z0-9_]+", matches[0]))
    assert variables, "safe nginx log format unexpectedly contains no variables"
    assert variables <= _ALLOWED_LOG_VARIABLES, (
        "safe nginx log format contains unreviewed variables: "
        f"{sorted(variables - _ALLOWED_LOG_VARIABLES)}"
    )


def test_every_server_selects_the_safe_access_log_format_directly():
    """Check every server selects the safe access log format directly."""
    servers = _balanced_blocks(_config_text(), re.compile(r"(?m)^\s*server\s*\{"))
    assert servers, "nginx example contains no server blocks"

    for index, server in enumerate(servers, start=1):
        access_logs = _direct_directives(server, "access_log")
        assert access_logs, f"server block {index} inherits an unverified global access log"
        assert all(_access_log_is_safe(value) for value in access_logs), (
            f"server block {index} selects an unsafe access_log: {access_logs!r}"
        )
        assert any(SAFE_LOG_FORMAT in value.split()[1:] for value in access_logs), (
            f"server block {index} does not select {SAFE_LOG_FORMAT!r}"
        )


def test_no_location_can_replace_the_safe_log_with_an_unreviewed_format():
    """Check no location can replace the safe log with an unreviewed format."""
    config = _config_text()
    access_logs = re.findall(r"(?ms)^\s*access_log\s+(?P<value>.*?);", config)

    assert access_logs, "nginx example contains no access_log directives"
    assert all(_access_log_is_safe(value.strip()) for value in access_logs)


def test_static_assets_inherit_or_explicitly_use_safe_logging():
    """Check static assets inherit or explicitly use safe logging."""
    static_locations = _balanced_blocks(
        _config_text(),
        re.compile(r"(?m)^\s*location\s+/static/\s*\{"),
    )
    assert static_locations, "nginx example contains no /static/ location"

    for location in static_locations:
        assert all(
            _access_log_is_safe(value) for value in _direct_directives(location, "access_log")
        )


def test_static_cache_headers_preserve_the_server_hsts_policy():
    """Static cache policy cannot replace or weaken the HTTPS server's HSTS policy."""
    server_headers, location = _static_header_configuration()
    server_hsts = [
        value for value in server_headers if value.startswith("Strict-Transport-Security ")
    ]
    static_headers = _direct_directives(location, "add_header")
    static_hsts = [
        value for value in static_headers if value.startswith("Strict-Transport-Security ")
    ]

    assert len(server_hsts) == 1 and server_hsts[0].endswith(" always")
    assert static_hsts == server_hsts
    assert 'Cache-Control "public, no-cache"' in static_headers


def test_static_hsts_survives_success_revalidation_and_missing_assets(tmp_path: Path):
    """Run the shipped static block and require HSTS on its 200, 304 and 404 responses."""
    nginx = _required_executable("nginx")
    server_headers, location = _static_header_configuration()
    server_hsts = [
        value for value in server_headers if value.startswith("Strict-Transport-Security ")
    ]
    assert len(server_hsts) == 1
    expected_hsts = shlex.split(server_hsts[0])[1]
    static_root = tmp_path / "static"
    static_root.mkdir()
    (static_root / "app.css").write_text("body {}\n", encoding="utf-8")
    location = location.replace("/opt/oralhistarchiv/src/app/static/", f"{static_root.as_posix()}/")
    port = _free_local_port()
    nginx_config = tmp_path / "nginx.conf"
    nginx_config.write_text(
        "\n".join(
            [
                "user root;" if os.geteuid() == 0 else "",
                "worker_processes 1;",
                "daemon off;",
                f'error_log "{(tmp_path / "error.log").as_posix()}" error;',
                f'pid "{(tmp_path / "nginx.pid").as_posix()}";',
                "events { worker_connections 16; }",
                "http {",
                *(
                    f'    {name}_temp_path "{(tmp_path / name).as_posix()}";'
                    for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")
                ),
                "    access_log off;",
                "    server {",
                f"        listen 127.0.0.1:{port};",
                *(f"        add_header {value};" for value in server_headers),
                "        location /static/ {",
                location,
                "        }",
                "    }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [nginx, "-p", f"{tmp_path}/", "-c", str(nginx_config)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_until_listening(process, port)
        modified_at = None
        for path, expected_status in (
            ("/static/app.css", 200),
            ("/static/app.css", 304),
            ("/static/missing.css", 404),
        ):
            headers = {"Connection": "close"}
            if expected_status == 304:
                assert modified_at is not None
                headers["If-Modified-Since"] = modified_at
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                connection.request("GET", path, headers=headers)
                response = connection.getresponse()
                response.read()
                assert response.status == expected_status
                assert response.getheader("Strict-Transport-Security") == expected_hsts
                if expected_status in {200, 304}:
                    assert response.getheader("Cache-Control") == "public, no-cache"
                if expected_status == 200:
                    modified_at = response.getheader("Last-Modified")
            finally:
                connection.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_health_location_preserves_the_complete_ordinary_proxy_contract():
    """Check health location preserves the complete ordinary proxy contract."""
    health_locations = _balanced_blocks(
        _config_text(),
        re.compile(r"(?m)^\s*location\s*=\s*/health\s*\{"),
    )

    assert len(health_locations) == 1
    health = health_locations[0]
    assert _direct_directives(health, "proxy_pass") == [APPLICATION_UPSTREAM]
    assert _direct_directives(health, "include") == [ORDINARY_PROXY_INCLUDE]
    assert _direct_directives(health, "proxy_set_header") == []
    assert _direct_directives(health, "proxy_http_version") == []
    assert _direct_directives(health, "access_log") == ["off"]


class TestEdgeRequestAdmissionBackstop:
    """Cover edge request admission backstop."""

    def test_dynamic_proxy_unknown_path_and_health_locations_are_edge_rate_limited(self):
        """Check dynamic proxy unknown path and health locations are edge rate limited."""
        config = _config_text()

        assert re.search(r"(?m)^\s*limit_req_zone\b", config), "no limit_req_zone declared"
        assert re.search(r"(?m)^\s*limit_conn_zone\b", config), "no limit_conn_zone declared"

        for pattern in (
            re.compile(r"(?m)^\s*location\s*/\s*\{"),
            re.compile(r"(?m)^\s*location\s*=\s*/health\s*\{"),
        ):
            for location in _balanced_blocks(config, pattern):
                assert _direct_directives(location, "limit_req"), (
                    "location has no limit_req backstop"
                )
                assert _direct_directives(location, "limit_conn"), (
                    "location has no limit_conn backstop"
                )


def test_phase_one_shibboleth_callback_fails_closed_at_nginx():
    """Separate transition pin: the shipped Phase-1 edge must not proxy SSO."""
    callback_locations = _balanced_blocks(
        _config_text(),
        re.compile(r"(?m)^\s*location\s*=\s*/auth/shibboleth/callback\s*\{"),
    )

    assert len(callback_locations) == 1
    callback = callback_locations[0]
    assert _direct_directives(callback, "return") == ["404"]
    assert _direct_directives(callback, "proxy_pass") == []
    assert _direct_directives(callback, "proxy_set_header") == []
    assert _direct_directives(callback, "shib_request") == []
    assert _direct_directives(callback, "include") == []


def test_every_ordinary_app_proxy_uses_the_shared_header_hygiene_include():
    """A new active application proxy must opt into the complete contract."""
    locations = _balanced_blocks(
        _config_text(),
        re.compile(r"(?m)^\s*location\b[^\{]*\{"),
    )
    proxied: list[str] = []

    for location in locations:
        proxy_targets = _direct_directives(location, "proxy_pass")
        if not proxy_targets:
            continue

        assert proxy_targets == [APPLICATION_UPSTREAM], (
            f"unclassified proxy target requires security review: {proxy_targets!r}"
        )
        proxied.append(location)
        assert _direct_directives(location, "include").count(ORDINARY_PROXY_INCLUDE) == 1
        assert _direct_directives(location, "proxy_set_header") == []
        assert _direct_directives(location, "proxy_http_version") == []

    assert proxied, "nginx example contains no application proxy locations"


def test_ordinary_proxy_include_is_an_exact_fail_closed_header_contract():
    """Check ordinary proxy include is an exact fail closed header contract."""
    config = _file_without_comments(ORDINARY_PROXY_HEADERS)

    assert _direct_directives(config, "proxy_http_version") == ["1.1"]
    headers = _proxy_headers(config)
    expected = {
        "host": ["$host"],
        "x-real-ip": ["$remote_addr"],
        "x-forwarded-for": ["$remote_addr"],
        "x-forwarded-proto": ["$scheme"],
    }
    expected.update(
        {name.casefold(): ['""'] for name in _FIXED_FEDERATION_HEADERS | _LEGACY_FEDERATION_HEADERS}
    )

    assert headers == expected
    assert _direct_directives(config, "proxy_pass_request_headers") == []
    assert _direct_directives(config, "proxy_pass") == []
    assert _direct_directives(config, "include") == []


def test_ordinary_proxy_include_parses_with_nginx(tmp_path: Path):
    """Check ordinary proxy include parses with nginx."""
    nginx = _required_executable("nginx")
    snippet = tmp_path / "ordinary-proxy-headers.conf"
    shutil.copyfile(ORDINARY_PROXY_HEADERS, snippet)

    nginx_config = tmp_path / "nginx.conf"
    nginx_config.write_text(
        f"""
{"user root;" if os.geteuid() == 0 else ""}
worker_processes 1;
error_log stderr notice;
pid "{(tmp_path / "nginx.pid").as_posix()}";

events {{
    worker_connections 16;
}}

http {{
    access_log off;
    client_body_temp_path "{(tmp_path / "client_body").as_posix()}";
    proxy_temp_path "{(tmp_path / "proxy").as_posix()}";
    fastcgi_temp_path "{(tmp_path / "fastcgi").as_posix()}";
    uwsgi_temp_path "{(tmp_path / "uwsgi").as_posix()}";
    scgi_temp_path "{(tmp_path / "scgi").as_posix()}";

    upstream oralhistarchiv {{
        server unix:/run/oralhistarchiv/gunicorn.sock;
    }}

    server {{
        listen 127.0.0.1:18080;

        location / {{
            proxy_pass http://oralhistarchiv;
            include "{snippet.as_posix()}";
        }}

        location = /health {{
            proxy_pass http://oralhistarchiv;
            include "{snippet.as_posix()}";
            access_log off;
        }}
    }}
}}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [nginx, "-t", "-p", f"{tmp_path}/", "-c", str(nginx_config)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_runbook_verifies_health_through_the_configured_tls_virtual_host():
    """Check runbook verifies health through the configured tls virtual host."""
    text = DEPLOYMENT_RUNBOOK.read_text(encoding="utf-8")
    install = text.split("### Install nginx config", 1)[1]
    install = install.split("### Verify client IP propagation", 1)[0]
    verify = install.split("### Verify\n", 1)[1]

    assert "https://localhost" not in verify
    assert "curl -k" not in verify

    ordered_markers = [
        "set -euo pipefail",
        'archive_host="$(',
        'test -n "$archive_host"',
        "sudo nginx -t",
        "sudo systemctl reload nginx",
        "curl --fail --silent --show-error",
        '--resolve "${archive_host}:443:127.0.0.1"',
        '"https://${archive_host}/health"',
        'jq -e \'type == "object" and keys == ["status"] and .status == "alive"\'',
        "stat -Lc '%U:%G %a'",
    ]
    positions = [verify.index(marker) for marker in ordered_markers]

    assert positions == sorted(positions)
    assert "/etc/nginx/sites-enabled/oralhistarchiv" in verify
    assert "/etc/nginx/snippets/oralhistarchiv-ordinary-proxy-headers.conf" in verify
    assert "root:root 644" in verify


def test_phase_two_callback_forwards_only_an_explicit_header_allowlist():
    """Check phase two callback forwards only an explicit header allowlist."""
    config = _file_without_comments(SHIBBOLETH_PHASE2_CONFIG)
    callback_locations = _balanced_blocks(
        config,
        re.compile(r"(?m)^\s*location\s*=\s*/auth/shibboleth/callback\s*\{"),
    )

    assert len(callback_locations) == 1
    callback = callback_locations[0]
    assert _direct_directives(callback, "satisfy") == ["all"]
    assert _direct_directives(callback, "shib_request") == ["/shibauthorizer"]
    assert _direct_directives(callback, "shib_request_use_headers") == ["off"]
    assert _direct_directives(callback, "proxy_pass") == [APPLICATION_UPSTREAM]
    assert _direct_directives(callback, "proxy_pass_request_headers") == ["off"]
    assert _direct_directives(callback, "include") == [SHIBBOLETH_SECRET_INCLUDE]
    assert ORDINARY_PROXY_INCLUDE not in _direct_directives(callback, "include")

    headers = _proxy_headers(callback)
    expected_non_identity = {
        "host": "$host",
        "x-real-ip": "$remote_addr",
        "x-forwarded-for": "$remote_addr",
        "x-forwarded-proto": "$scheme",
        "cookie": "$http_cookie",
    }
    for name, value in expected_non_identity.items():
        assert headers.get(name) == [value]

    expected_identity = {
        "x-oha-shib-issuer": "$oha_shib_issuer",
        "x-oha-shib-subject": "$oha_shib_subject",
        "x-oha-shib-mail": "$oha_shib_mail",
        "x-oha-shib-authn-context": "$oha_shib_authn_context",
        "x-oha-shib-display-name": "$oha_shib_display_name",
        "x-oha-shib-affiliation": "$oha_shib_affiliation",
        "x-oha-shib-entitlement": "$oha_shib_entitlement",
        "x-oha-shib-country": "$oha_shib_country",
    }
    for name, value in expected_identity.items():
        assert headers.get(name) == [value]

    allowed = set(expected_non_identity) | set(expected_identity)
    assert set(headers) == allowed


def test_phase_two_maps_required_identity_and_assurance_from_authorizer_output():
    """Check phase two maps required identity and assurance from authorizer output."""
    config = _file_without_comments(SHIBBOLETH_PHASE2_CONFIG)
    required_mappings = {
        "$oha_shib_issuer": "$upstream_http_variable_shib_identity_provider",
        "$oha_shib_subject": "$upstream_http_variable_edupersonuniqueid",
        "$oha_shib_mail": "$upstream_http_variable_mail",
        "$oha_shib_authn_context": "$upstream_http_variable_shib_authncontext_class",
        "$oha_shib_display_name": "$upstream_http_variable_displayname",
        "$oha_shib_affiliation": "$upstream_http_variable_affiliation",
        "$oha_shib_entitlement": "$upstream_http_variable_entitlement",
        "$oha_shib_country": ("$upstream_http_variable_schachomeorganizationcountry"),
    }
    mappings: dict[str, str] = {}
    for directive in re.findall(r"(?ms)^\s*shib_request_set\s+(.*?);", config):
        variable, value = directive.split()
        assert variable not in mappings, f"duplicate shib_request_set for {variable}"
        mappings[variable] = value

    for variable, value in required_mappings.items():
        assert mappings.get(variable) == value
    assert mappings == required_mappings


def test_phase_two_authorizer_is_internal_and_protocol_handler_is_not_proxied_to_app():
    """Check phase two authorizer is internal and protocol handler is not proxied to app."""
    config = _file_without_comments(SHIBBOLETH_PHASE2_CONFIG)
    authorizers = _balanced_blocks(
        config,
        re.compile(r"(?m)^\s*location\s*=\s*/shibauthorizer\s*\{"),
    )
    handlers = _balanced_blocks(
        config,
        re.compile(r"(?m)^\s*location\s+/Shibboleth\.sso/\s*\{"),
    )

    assert len(authorizers) == 1
    assert _direct_directives(authorizers[0], "internal") == []
    assert re.search(r"(?m)^\s*internal\s*;", authorizers[0])
    assert _direct_directives(authorizers[0], "fastcgi_pass") == [
        "unix:/run/shibboleth/shibauthorizer.sock"
    ]
    assert len(handlers) == 1
    assert _direct_directives(handlers[0], "fastcgi_pass") == [
        "unix:/run/shibboleth/shibresponder.sock"
    ]
    assert _direct_directives(handlers[0], "proxy_pass") == []


def test_phase_two_public_locations_bound_client_and_aggregate_sp_work():
    """Check phase two public locations bound client and aggregate sp work."""
    config = _file_without_comments(SHIBBOLETH_PHASE2_CONFIG)
    request_zones = _http_level_directives("limit_req_zone")
    connection_zones = _http_level_directives("limit_conn_zone")
    assert "$binary_remote_addr zone=oralhistarchiv_sso_req:10m rate=2r/s" in request_zones
    assert "$server_name zone=oralhistarchiv_sso_global_req:64k rate=10r/s" in request_zones
    assert "$binary_remote_addr zone=oralhistarchiv_sso_conn:10m" in connection_zones
    assert "$server_name zone=oralhistarchiv_sso_global_conn:64k" in connection_zones
    https_server = next(
        server
        for server in _balanced_blocks(_config_text(), re.compile(r"(?m)^\s*server\s*\{"))
        if _direct_directives(server, "client_max_body_size")
    )
    assert _direct_directives(https_server, "client_header_timeout") == ["10s"]
    assert _direct_directives(https_server, "client_header_buffer_size") == ["1k"]
    assert _direct_directives(https_server, "large_client_header_buffers") == ["4 8k"]
    for opener in (
        r"(?m)^\s*location\s+/Shibboleth\.sso/\s*\{",
        r"(?m)^\s*location\s*=\s*/auth/shibboleth/callback\s*\{",
    ):
        location = _balanced_blocks(config, re.compile(opener))[0]
        assert _direct_directives(location, "limit_req") == [
            "zone=oralhistarchiv_sso_req burst=10 nodelay",
            "zone=oralhistarchiv_sso_global_req burst=20 nodelay",
        ]
        assert _direct_directives(location, "limit_conn") == [
            "oralhistarchiv_sso_conn 8",
            "oralhistarchiv_sso_global_conn 16",
        ]
        assert _direct_directives(location, "client_max_body_size") == ["64k"]
        assert _direct_directives(location, "client_body_timeout") == ["10s"]
        assert _direct_directives(location, "send_timeout") == ["10s"]
    for opener in (
        r"(?m)^\s*location\s+/Shibboleth\.sso/\s*\{",
        r"(?m)^\s*location\s*=\s*/shibauthorizer\s*\{",
    ):
        location = _balanced_blocks(config, re.compile(opener))[0]
        assert _direct_directives(location, "fastcgi_connect_timeout") == ["1s"]
        assert _direct_directives(location, "fastcgi_send_timeout") == ["5s"]
        assert _direct_directives(location, "fastcgi_read_timeout") == ["5s"]
        assert _direct_directives(location, "fastcgi_request_buffering") == ["on"]
        assert _direct_directives(location, "fastcgi_next_upstream") == ["off"]


def test_secret_template_has_one_nonempty_internal_header_and_no_identity_assertions():
    """Check secret template has one nonempty internal header and no identity assertions."""
    headers = _proxy_headers(_file_without_comments(SHIBBOLETH_SECRET_CONFIG))

    assert headers == {"x-oha-internal-auth": ['"<generate-a-unique-high-entropy-secret>"']}
    for name in _FIXED_FEDERATION_HEADERS - {"X-OHA-Internal-Auth"}:
        assert name.casefold() not in headers


def test_runbook_requires_effective_nginx_log_configuration_verification():
    """Check runbook requires effective nginx log configuration verification."""
    text = DEPLOYMENT_RUNBOOK.read_text()
    heading = "### Nginx logs"
    assert heading in text
    section = text.split(heading, 1)[1].split("\n### ", 1)[0]

    assert SAFE_LOG_FORMAT in section
    assert "load-bearing" in section
    assert "nginx -T" in section
    documented_variables = set(re.findall(r"`(\$[A-Za-z0-9_]+)`", section))
    assert {"$request", "$request_uri", "$uri", "$args", "$http_referer"} <= (documented_variables)


def test_phase_two_sp_runbook_pins_redirect_and_relay_state_safety():
    """Check phase two sp runbook pins redirect and relay state safety."""
    text = (PROJECT_ROOT / "docs/runbooks/federation-integration.md").read_text()
    configure_sp = text.split("## Configure the SP", 1)[1].split(
        "## Registration and attribute release", 1
    )[0]

    assert 'redirectLimit="exact"' in configure_sp
    assert 'relayState="ss:mem"' in configure_sp
    assert "<Logout>SAML2 Local</Logout>" in configure_sp
    assert "/Shibboleth.sso/Login" in configure_sp
    assert "/Shibboleth.sso/Logout" in configure_sp
    assert "off-origin" in configure_sp
    assert "query parameter in HTML is not an" in configure_sp
    assert "shared-browser use must be prohibited" in configure_sp


def test_federation_rollback_boundary_is_ordered_and_pre_revision_is_prohibited():
    """Check federation rollback boundary is ordered and pre revision is prohibited."""
    text = (PROJECT_ROOT / "docs/runbooks/federation-integration.md").read_text()
    section = text.split("## Federation rollback boundary", 1)[1].split("## Evidence record", 1)[0]
    section = " ".join(section.split())
    ordered_markers = [
        "return 404",
        "SHIBBOLETH_ENABLED=false",
        "zero sessions owned by Shibboleth users",
        "/etc/oralhistarchiv/shibboleth.env",
        "do not run an ad-hoc Alembic downgrade",
        "must never be re-enabled",
    ]

    positions = [section.index(marker) for marker in ordered_markers]
    assert positions == sorted(positions)
    assert "4f73ae3ff827" in section


def test_disclosed_internal_secret_stops_web_before_edge_or_config_changes():
    """Check disclosed internal secret stops web before edge or config changes."""
    text = KEY_ROTATION_RUNBOOK.read_text()
    section = text.split("#### Suspected disclosure", 1)[1].split("## 9.", 1)[0]
    ordered_markers = [
        "systemctl stop oralhistarchiv",
        "socket is absent or refuses connections",
        "return 404",
        "SHIBBOLETH_ENABLED=false",
        "execute the manual revocation transaction below",
        "Restart the current application code",
    ]

    positions = [section.index(marker) for marker in ordered_markers]
    assert positions == sorted(positions)
    assert "direct socket access" in section
    assert "DELETE FROM sessions" in section
    assert "expected count is zero" in section


CAPABILITY_REQUEST_PATH = "/reset-password"
CAPABILITY_TOKEN_CANARY = "EDGE-LOG-CAPABILITY-CANARY-0f3b19"


def _http_level_directives(name: str) -> list[str]:
    """Directives the example declares outside any server or location block."""
    config = _config_text()
    outside_blocks = re.sub(r"(?ms)^\s*(?:server|upstream)\s[^\{]*\{.*?^\}", "", config)
    return [value.strip() for value in re.findall(rf"(?m)^\s*{name}\s+(.*?);", outside_blocks)]


def _safe_log_format_block() -> str:
    """The shipped ``oralhistarchiv_safe`` definition, verbatim."""
    config = _config_text()
    match = re.search(rf"(?ms)^\s*log_format\s+{SAFE_LOG_FORMAT}\b.*?;", config)
    assert match is not None, f"the example no longer defines {SAFE_LOG_FORMAT!r}"
    return match.group(0).strip()


def _application_location_limits() -> list[str]:
    """The request-admission directives guarding the application location."""
    locations = _balanced_blocks(_config_text(), re.compile(r"(?m)^\s*location\s*/\s*\{"))
    assert len(locations) == 1, "the example no longer has exactly one application location"
    limits = [f"limit_req {value};" for value in _direct_directives(locations[0], "limit_req")]
    limits += [f"limit_conn {value};" for value in _direct_directives(locations[0], "limit_conn")]
    assert limits, "the application location declares no request-admission limits"
    return limits


def _free_local_port() -> int:
    """Return a released ephemeral loopback port; subsequent binding can race."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_until_listening(process: subprocess.Popen[str], port: int) -> None:
    """Wait up to fifteen seconds for loopback listening, failing on exit or timeout."""
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=1)
            pytest.fail(f"nginx exited before listening\nstdout:\n{stdout}\nstderr:\n{stderr}")
        with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), 0.2):
            return
        time.sleep(0.05)
    pytest.fail("nginx did not accept connections within 15 seconds")


def _request_until_throttled(port: int, path: str, attempts: int = 200) -> list[int]:
    """Request `path` until the edge budget rejects one, or `attempts` times."""
    statuses: list[int] = []
    for _ in range(attempts):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request("GET", path, headers={"Connection": "close"})
            response = connection.getresponse()
            response.read()
            statuses.append(response.status)
        finally:
            connection.close()
        if statuses[-1] == 429:
            break
    return statuses


def _run_reference_edge(
    tmp_path: Path, port: int, flow_path: str = CAPABILITY_REQUEST_PATH
) -> tuple[str, str]:
    """Run a loopback nginx edge with shipped logging/admission settings and return its access/error
    logs.
    """
    nginx = _required_executable("nginx")
    document_root = tmp_path / "root"
    document_root.mkdir()
    (document_root / "index.html").write_text("served\n", encoding="utf-8")
    access_log = tmp_path / "access.log"
    error_log = tmp_path / "error.log"

    # nginx's own default error-log level, which the example does not change.
    error_log_settings = _http_level_directives("error_log") or ["/dev/null error"]
    error_log_level = error_log_settings[0].split()[-1]
    if error_log_level not in {
        "debug",
        "info",
        "notice",
        "warn",
        "error",
        "crit",
        "alert",
        "emerg",
    }:
        error_log_level = "error"

    configuration = "\n".join(
        [
            "user root;" if os.geteuid() == 0 else "",
            "worker_processes 1;",
            "daemon off;",
            f'error_log "{error_log.as_posix()}" {error_log_level};',
            f'pid "{(tmp_path / "nginx.pid").as_posix()}";',
            "events { worker_connections 64; }",
            "http {",
            f'    client_body_temp_path "{(tmp_path / "body").as_posix()}";',
            f'    proxy_temp_path "{(tmp_path / "proxy").as_posix()}";',
            f'    fastcgi_temp_path "{(tmp_path / "fastcgi").as_posix()}";',
            f'    uwsgi_temp_path "{(tmp_path / "uwsgi").as_posix()}";',
            f'    scgi_temp_path "{(tmp_path / "scgi").as_posix()}";',
            f"    {_safe_log_format_block()}",
            *(f"    limit_req_zone {value};" for value in _http_level_directives("limit_req_zone")),
            *(
                f"    limit_conn_zone {value};"
                for value in _http_level_directives("limit_conn_zone")
            ),
            *(
                f"    limit_req_status {value};"
                for value in _http_level_directives("limit_req_status")
            ),
            *(
                f"    limit_conn_status {value};"
                for value in _http_level_directives("limit_conn_status")
            ),
            *(
                f"    limit_req_log_level {value};"
                for value in _http_level_directives("limit_req_log_level")
            ),
            "    server {",
            f"        listen 127.0.0.1:{port};",
            f'        access_log "{access_log.as_posix()}" {SAFE_LOG_FORMAT};',
            "        location / {",
            *(f"            {directive}" for directive in _application_location_limits()),
            f'            root "{document_root.as_posix()}";',
            "            try_files /index.html =404;",
            "        }",
            "    }",
            "}",
            "",
        ]
    )
    nginx_config = tmp_path / "nginx.conf"
    nginx_config.write_text(configuration, encoding="utf-8")

    process = subprocess.Popen(
        [nginx, "-p", f"{tmp_path}/", "-c", str(nginx_config)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_until_listening(process, port)
        # The complete emailed URL is public; its code is a separate email field.
        link = urlsplit(action_token_url(flow_path, CAPABILITY_TOKEN_CANARY))
        assert not link.query and not link.fragment
        assert CAPABILITY_TOKEN_CANARY not in link.geturl()
        statuses = _request_until_throttled(port, link.path)
        assert 429 in statuses, (
            "the shipped request budget never rejected a request, so this test "
            f"never reached the logging path it is about: {statuses[:5]}..."
        )
    finally:
        process.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=10)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)

    return (
        access_log.read_text(encoding="utf-8") if access_log.exists() else "",
        error_log.read_text(encoding="utf-8") if error_log.exists() else "",
    )


@pytest.mark.parametrize(
    "flow_path", ["/reset-password", "/verify-email", "/account/confirm-email"]
)
def test_throttled_capability_token_stays_out_of_access_log(tmp_path: Path, flow_path: str):
    """Check throttled capability token stays out of access log."""
    access_log, _ = _run_reference_edge(tmp_path, _free_local_port(), flow_path)
    assert CAPABILITY_TOKEN_CANARY not in access_log


@pytest.mark.parametrize(
    "flow_path", ["/reset-password", "/verify-email", "/account/confirm-email"]
)
def test_throttled_capability_token_stays_out_of_error_log(tmp_path: Path, flow_path: str):
    """Check throttled capability token stays out of error log."""
    _, error_log = _run_reference_edge(tmp_path, _free_local_port(), flow_path)
    assert action_token_public_id(CAPABILITY_TOKEN_CANARY) in error_log
    assert CAPABILITY_TOKEN_CANARY not in error_log
