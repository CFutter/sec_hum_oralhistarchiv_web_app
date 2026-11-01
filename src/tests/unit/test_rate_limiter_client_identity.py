"""``get_rate_limit_client_id`` and the storage key it feeds."""

import random
import string

from fastapi import FastAPI, Request
from pydantic import SecretStr

import app.middleware.rate_limiting as rl
from app.main import app as live_app
from app.middleware.rate_limiting import get_rate_limit_client_id
from config import settings

_ROUTELESS_APP = FastAPI()


def _request(
    peer: str = "127.0.0.1",
    path: str = "/",
    query_string: bytes = b"",
    headers: list[tuple[bytes, bytes]] | None = None,
) -> Request:
    """Build a GET request with the selected peer, path, headers, and query bytes."""
    return Request(
        {
            "type": "http",
            "client": (peer, 1234),
            "server": ("127.0.0.1", 8000),
            "headers": headers or [],
            "method": "GET",
            "path": path,
            "query_string": query_string,
            "scheme": "http",
            "app": _ROUTELESS_APP,
        }
    )


class TestClientIdentityCanonicalization:
    """Equivalent IP spellings collapse onto one identity; distinct
    addresses never do, and the digest never carries the raw address."""

    def test_ipv4_mapped_ipv6_shares_the_identity_of_its_ipv4_form(self):
        """Check ipv4 mapped ipv6 shares the identity of its ipv4 form."""
        mapped = get_rate_limit_client_id(_request(peer="::ffff:203.0.113.5"))
        plain = get_rate_limit_client_id(_request(peer="203.0.113.5"))
        assert mapped == plain

    def test_ipv6_case_and_zone_id_variants_share_one_identity(self):
        """Check ipv6 case and zone ID variants share one identity."""
        lowercase = get_rate_limit_client_id(_request(peer="2001:db8::1"))
        uppercase = get_rate_limit_client_id(_request(peer="2001:DB8:0:0::1"))
        zoned = get_rate_limit_client_id(_request(peer="2001:db8::1%eth0"))
        assert lowercase == uppercase == zoned

    def test_addresses_in_one_ipv6_prefix_share_one_identity(self):
        """A client that holds a routed /64 can pick a fresh address for
        every request. All of them must draw on the same allowance."""
        first = get_rate_limit_client_id(_request(peer="2001:db8:abcd:1234::1"))
        second = get_rate_limit_client_id(_request(peer="2001:db8:abcd:1234::2"))
        far_apart = get_rate_limit_client_id(_request(peer="2001:db8:abcd:1234:dead:beef:0:9"))
        assert first == second == far_apart

    def test_addresses_in_neighbouring_ipv6_prefixes_stay_apart(self):
        """Check addresses in neighbouring ipv6 prefixes stay apart."""
        inside = get_rate_limit_client_id(_request(peer="2001:db8:abcd:1234::1"))
        neighbour = get_rate_limit_client_id(_request(peer="2001:db8:abcd:1235::1"))
        assert inside != neighbour

    def test_forwarded_ipv6_addresses_in_one_prefix_share_one_identity(self, monkeypatch):
        """The aggregation happens after proxy attribution, so it also covers
        the deployed shape where nginx reports the client address."""
        monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
        first = get_rate_limit_client_id(
            _request(peer="127.0.0.1", headers=[(b"x-real-ip", b"2001:db8:abcd:1234::1")])
        )
        second = get_rate_limit_client_id(
            _request(peer="127.0.0.1", headers=[(b"x-real-ip", b"2001:db8:abcd:1234::7")])
        )
        neighbour = get_rate_limit_client_id(
            _request(peer="127.0.0.1", headers=[(b"x-real-ip", b"2001:db8:abcd:1235::1")])
        )
        assert first == second
        assert first != neighbour

    def test_distinct_addresses_produce_distinct_identities(self):
        """Check distinct addresses produce distinct identities."""
        first = get_rate_limit_client_id(_request(peer="203.0.113.5"))
        second = get_rate_limit_client_id(_request(peer="203.0.113.6"))
        assert first != second

    def test_identity_is_a_full_hmac_digest_with_no_raw_address(self):
        """Check identity is a full HMAC digest with no raw address."""
        identity = get_rate_limit_client_id(_request(peer="203.0.113.5"))
        assert identity.startswith("ip-v2:")
        digest = identity.removeprefix("ip-v2:")
        assert len(digest) == 64
        assert all(character in string.hexdigits for character in digest)
        assert "203.0.113.5" not in identity

    def test_ipv6_identity_carries_neither_the_address_nor_its_prefix(self):
        """Redis and its append-only file must not become a record of who
        connected — neither the exact address nor the network it came from."""
        identity = get_rate_limit_client_id(_request(peer="2001:db8:abcd:1234::1"))
        assert identity.startswith("ip-v2:")
        digest = identity.removeprefix("ip-v2:")
        assert len(digest) == 64
        assert all(character in string.hexdigits for character in digest)
        assert "2001" not in identity
        assert "db8" not in identity
        assert "abcd:1234" not in identity

    def test_untrusted_peer_forwarded_header_does_not_change_the_identity(self, monkeypatch):
        """Check untrusted peer forwarded header does not change the identity."""
        monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
        baseline = get_rate_limit_client_id(_request(peer="5.5.5.5"))
        spoofed = get_rate_limit_client_id(
            _request(peer="5.5.5.5", headers=[(b"x-real-ip", b"9.9.9.9")])
        )
        assert baseline == spoofed

    def test_trusted_peer_forwarded_header_changes_the_identity(self, monkeypatch):
        """Check trusted peer forwarded header changes the identity."""
        monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
        baseline = get_rate_limit_client_id(_request(peer="127.0.0.1"))
        forwarded = get_rate_limit_client_id(
            _request(peer="127.0.0.1", headers=[(b"x-real-ip", b"9.9.9.9")])
        )
        assert baseline != forwarded

    def test_rotating_the_secret_key_changes_every_identity(self, monkeypatch):
        """Check rotating the secret key changes every identity."""
        request = _request(peer="203.0.113.5")
        before = get_rate_limit_client_id(request)

        monkeypatch.setattr(settings, "secret_key", SecretStr("a-completely-different-secret"))
        rotated_key = rl.hmac.new(
            settings.secret_key.get_secret_value().encode("utf-8"),
            rl._RATE_LIMIT_CLIENT_ID_CONTEXT,
            rl.hashlib.sha256,
        ).digest()
        monkeypatch.setattr(rl, "_rate_limit_client_id_key", rotated_key)

        after = get_rate_limit_client_id(request)
        assert before != after


class TestSentinelStorageKeyCarriesNoRequestData:
    """Cover sentinel storage key carries no request data."""

    def test_two_hundred_random_unmatched_paths_produce_one_sentinel_scope(self, monkeypatch):
        """Check two hundred random unmatched paths produce one sentinel scope."""
        monkeypatch.setattr(settings, "rate_limit_trust_proxy", False)
        random_generator = random.Random(20260920)
        scopes: set[str] = set()
        keys: set[str] = set()

        for _ in range(200):
            segment_count = random_generator.randint(1, 5)
            segments = [
                "".join(
                    random_generator.choices(
                        string.ascii_letters + string.digits + "%._~-@",
                        k=random_generator.randint(1, 12),
                    )
                )
                for _ in range(segment_count)
            ]
            path = "/" + "/".join(segments)
            query = "".join(
                random_generator.choices(string.ascii_letters + string.digits + "=&%", k=20)
            ).encode()
            peer = f"203.0.{random_generator.randint(0, 255)}.{random_generator.randint(0, 255)}"
            request = _request(
                peer=peer,
                path=path,
                query_string=query,
                headers=[(b"cookie", b"session=super-secret-value")],
            )

            handler, route_unmatched, _log_path = rl._resolve_rate_limit_handler(request)
            assert route_unmatched is True
            assert handler is rl._coarse_unmatched_route_bucket

            endpoint_scope = f"{handler.__module__}.{handler.__name__}"
            limit_key = get_rate_limit_client_id(request)
            scopes.add(endpoint_scope)
            keys.add(limit_key)

            assert path not in endpoint_scope
            assert "session=super-secret-value" not in endpoint_scope
            assert query.decode() not in endpoint_scope

        assert scopes == {"app.middleware.rate_limiting._coarse_unmatched_route_bucket"}
        assert len(keys) <= 256

    def test_a_named_route_resolves_to_its_own_scope_not_the_sentinel(self):
        """Check a named route resolves to its own scope not the sentinel."""
        request = Request(
            {
                "type": "http",
                "client": ("203.0.113.9", 1234),
                "server": ("127.0.0.1", 8000),
                "headers": [],
                "method": "GET",
                "path": "/health",
                "query_string": b"",
                "scheme": "http",
                "app": live_app,
            }
        )
        handler, route_unmatched, _log_path = rl._resolve_rate_limit_handler(request)
        assert route_unmatched is False
        assert handler is not rl._coarse_unmatched_route_bucket
