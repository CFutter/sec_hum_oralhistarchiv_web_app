"""Real PostgreSQL tests for the federated-identity surface.

Covers atomic, policy-approved federated login (``finalize_shibboleth_login``),
the deadline-bounded races between login finalization and federated-session
policy reconciliation, serialization of concurrent writers on one identity
row, and reconciliation of the federated-session policy state itself.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import psycopg
import pytest
from pydantic import SecretStr

from app.services import federated_authentication as auth
from app.services import federated_session_policy as policy
from app.services import users
from app.services.federated_session_policy import REQUIRED_SHIBBOLETH_AUTHN_CONTEXT
from app.services.sessions import get_session_user
from config import settings
from tests.integration.conftest import TEST_DATABASE_URL

ISSUER = "https://idp.test.example/idp/shibboleth"
OTHER_ISSUER = "https://other-idp.test.example/idp/shibboleth"
SUBJECT = "urn:test:subject:person"
SECRET_A = "Xpsp9j2Hn8DwvzBEPi9ivWneKjPxbGuQxoWYgRrNj_QTgX_gz9wJL65s82RJJJwz"
SECRET_B = "Bvn3v2uTyRLeUmRGXuGTt4IbjaAwhivCcwpDBKlqiuLbWrMqPP2AzUQs6wtawK3C"


def _principal(email: str) -> auth.FederatedPrincipal:
    return auth.FederatedPrincipal(
        issuer=ISSUER,
        subject_id=SUBJECT,
        email=email,
        authn_context=REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
        display_name="Fresh profile",
    )


async def _login(pool, email):
    return await auth.finalize_shibboleth_login(
        pool,
        principal=_principal(email),
        ip_address="127.0.0.1",
    )


async def _apply_trusted_issuer_policy(monkeypatch, db_pool):
    """Trust ``ISSUER`` under ``SECRET_A`` and commit that as the live policy."""
    monkeypatch.setattr(auth.settings, "shibboleth_enabled", True)
    monkeypatch.setattr(auth.settings, "shibboleth_trusted_issuers", [ISSUER])
    monkeypatch.setattr(auth.settings, "shibboleth_internal_secret", SecretStr(SECRET_A))
    await policy.reconcile_federated_session_policy(db_pool)


def _enable_test_federation(monkeypatch, *, secret=SECRET_A):
    monkeypatch.setattr(settings, "shibboleth_enabled", True)
    monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [ISSUER])
    monkeypatch.setattr(settings, "shibboleth_internal_secret", SecretStr(secret))


async def _wait_for_blocker(pid):
    """Poll until some backend is blocked on ``pid``.

    The outer ``asyncio.timeout`` is a guard, not the only bound: its
    cancellation can land inside the psycopg call instead of the sleep and
    be swallowed there, leaving the loop spinning after the timeout already
    expired. The deadline check below is what actually terminates the loop.
    """
    async with await psycopg.AsyncConnection.connect(
        TEST_DATABASE_URL, autocommit=True, connect_timeout=3
    ) as observer:
        async with asyncio.timeout(5):
            deadline = asyncio.get_running_loop().time() + 5
            while True:
                if asyncio.get_running_loop().time() >= deadline:
                    raise TimeoutError(f"no backend blocked on pid {pid} within 5s")
                cur = await observer.execute(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                    "WHERE datname = current_database() AND %s = ANY(pg_blocking_pids(pid)))",
                    (pid,),
                )
                if (await cur.fetchone())[0]:
                    return
                await asyncio.sleep(0.01)


class TestFederatedLoginOutcomes:
    """``finalize_shibboleth_login`` outcomes for each identity state."""

    @pytest.fixture(autouse=True)
    async def _trust_test_issuer(self, monkeypatch, clean_db, db_pool):
        del clean_db  # explicit ordering: reconcile only after the autouse truncate
        await _apply_trusted_issuer_policy(monkeypatch, db_pool)

    async def test_inactive_identity_has_no_profile_refresh_session_or_new_last_login(
        self, db_pool, user_factory, sync_conn
    ):
        previous = datetime(2025, 1, 1, tzinfo=UTC)
        user = user_factory(
            email="inactive@example.org",
            display_name="Reviewed profile",
            auth_method="shibboleth",
            shibboleth_issuer=ISSUER,
            shibboleth_subject_id=SUBJECT,
            is_active=False,
            last_login=previous,
        )

        result = await _login(db_pool, "new-asserted-address@example.org")

        assert isinstance(result, auth.FederatedLoginFailure)
        assert result.reason == "inactive_account"
        assert result.user is not None
        assert result.user.id == user.id
        assert result.user.email == "inactive@example.org"
        assert result.user.display_name == "Reviewed profile"
        assert sync_conn.execute(
            "SELECT last_login FROM users WHERE id = %s", (user.id,)
        ).fetchone() == (previous,)
        assert sync_conn.execute("SELECT count(*) FROM sessions").fetchone() == (0,)

    async def test_new_identity_is_quarantined_without_session_or_last_login(
        self, db_pool, sync_conn
    ):
        result = await _login(db_pool, "new-person@example.org")

        assert isinstance(result, auth.FederatedLoginFailure)
        assert result.reason == "inactive_account"
        assert result.user is not None
        assert result.user.access_tier == "public"
        assert result.user.is_active is False
        assert result.user.email_verified is False
        assert result.user.last_login is None
        assert sync_conn.execute("SELECT count(*) FROM sessions").fetchone() == (0,)
        assert sync_conn.execute(
            """SELECT shibboleth_issuer, shibboleth_subject_id,
                      access_tier, is_active, email_verified, last_login
               FROM users WHERE id = %s""",
            (result.user.id,),
        ).fetchone() == (ISSUER, SUBJECT, "public", False, False, None)

    async def test_active_reviewed_identity_commits_full_session_and_last_login(
        self, db_pool, user_factory, sync_conn
    ):
        user = user_factory(
            email="active@example.org",
            auth_method="shibboleth",
            shibboleth_issuer=ISSUER,
            shibboleth_subject_id=SUBJECT,
            is_active=True,
            access_tier="registered",
        )

        result = await _login(db_pool, user.email)

        assert isinstance(result, auth.FederatedLoginSuccess)
        lookup = await get_session_user(db_pool, result.session_id)
        assert lookup.user.id == user.id
        assert lookup.purpose == "full"
        assert result.user.last_login is not None
        assert sync_conn.execute(
            "SELECT last_login FROM users WHERE id = %s", (user.id,)
        ).fetchone() == (result.user.last_login,)

    async def test_session_failure_rolls_back_profile_last_login_and_session(
        self, db_pool, user_factory, sync_conn, monkeypatch
    ):
        user = user_factory(
            email="old@example.org",
            display_name="Old profile",
            auth_method="shibboleth",
            shibboleth_issuer=ISSUER,
            shibboleth_subject_id=SUBJECT,
            is_active=True,
            last_login=None,
        )
        real = auth.create_session_cur

        async def fail_after_insert(cur, **kwargs):
            await real(cur, **kwargs)
            await cur.execute("SELECT 1 / 0")

        monkeypatch.setattr(auth, "create_session_cur", fail_after_insert)
        with pytest.raises(psycopg.errors.DivisionByZero):
            await _login(db_pool, "new@example.org")

        assert sync_conn.execute(
            "SELECT email, display_name, last_login FROM users WHERE id = %s", (user.id,)
        ).fetchone() == ("old@example.org", "Old profile", None)
        assert sync_conn.execute("SELECT count(*) FROM sessions").fetchone() == (0,)

    async def test_email_collision_preserves_local_identity(self, db_pool, user_factory, sync_conn):
        local = user_factory()

        result = await _login(db_pool, local.email)

        assert result == auth.FederatedLoginFailure("account_conflict")
        assert sync_conn.execute(
            """SELECT auth_method, shibboleth_issuer, shibboleth_subject_id
               FROM users WHERE id = %s""",
            (local.id,),
        ).fetchone() == ("local", None, None)
        assert sync_conn.execute("SELECT count(*) FROM sessions").fetchone() == (0,)


class TestFederatedSessionPolicyRaces:
    """Deadline-bounded races between login finalization and policy reconciliation."""

    @pytest.fixture(autouse=True)
    async def _trust_test_issuer(self, monkeypatch, clean_db, db_pool):
        del clean_db  # explicit ordering: reconcile only after the autouse truncate
        await _apply_trusted_issuer_policy(monkeypatch, db_pool)

    async def test_finalizer_before_policy_change_commits_then_reconciler_deletes_session(
        self,
        db_pool,
        user_factory,
        sync_conn,
        monkeypatch,
    ):
        """The finalizer's FOR SHARE wins: its session commits before deletion."""
        assert await policy.reconcile_federated_session_policy(db_pool) == 0
        user = user_factory(
            email="policy-race@example.org",
            auth_method="shibboleth",
            shibboleth_issuer=ISSUER,
            shibboleth_subject_id=SUBJECT,
        )
        real_cursor = auth.get_db_cursor
        finalizer_held = asyncio.Event()
        release_finalizer = asyncio.Event()
        owner = {}

        @asynccontextmanager
        async def pause_finalizer_before_commit(pool):
            async with real_cursor(pool) as cur:
                yield cur
                owner["pid"] = cur.connection.info.backend_pid
                finalizer_held.set()
                await release_finalizer.wait()

        monkeypatch.setattr(auth, "get_db_cursor", pause_finalizer_before_commit)
        login_task = asyncio.create_task(_login(db_pool, user.email))
        reconcile_task = None
        try:
            await asyncio.wait_for(finalizer_held.wait(), timeout=10)
            monkeypatch.setattr(
                auth.settings,
                "shibboleth_internal_secret",
                SecretStr(SECRET_B),
            )
            changed_fingerprint = policy.federated_session_policy_fingerprint()
            reconcile_task = asyncio.create_task(policy.reconcile_federated_session_policy(db_pool))
            await _wait_for_blocker(owner["pid"])
            release_finalizer.set()
            login_result, revoked = await asyncio.wait_for(
                asyncio.gather(login_task, reconcile_task),
                timeout=10,
            )
        finally:
            release_finalizer.set()
            for task in (login_task, reconcile_task):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(
                *(task for task in (login_task, reconcile_task) if task is not None),
                return_exceptions=True,
            )

        assert isinstance(login_result, auth.FederatedLoginSuccess)
        assert revoked == 1
        assert sync_conn.execute(
            "SELECT count(*) FROM sessions WHERE user_id = %s", (user.id,)
        ).fetchone() == (0,)
        assert sync_conn.execute(
            "SELECT fingerprint FROM federation_policy_state WHERE id = 1"
        ).fetchone() == (changed_fingerprint,)

    async def test_reconciler_before_stale_finalizer_rejects_without_user_or_session_write(
        self,
        db_pool,
        user_factory,
        sync_conn,
        monkeypatch,
    ):
        """The reconciler's FOR UPDATE wins: stale FOR SHARE sees a mismatch."""
        assert await policy.reconcile_federated_session_policy(db_pool) == 0
        user = user_factory(
            email="policy-race@example.org",
            display_name="Reviewed name",
            auth_method="shibboleth",
            shibboleth_issuer=ISSUER,
            shibboleth_subject_id=SUBJECT,
            last_login=None,
        )
        monkeypatch.setattr(
            auth.settings,
            "shibboleth_internal_secret",
            SecretStr(SECRET_B),
        )
        changed_fingerprint = policy.federated_session_policy_fingerprint()
        real_cursor = policy.get_db_cursor
        reconciler_held = asyncio.Event()
        release_reconciler = asyncio.Event()
        owner = {}

        @asynccontextmanager
        async def pause_reconciler_before_commit(pool):
            async with real_cursor(pool) as cur:
                yield cur
                owner["pid"] = cur.connection.info.backend_pid
                reconciler_held.set()
                await release_reconciler.wait()

        monkeypatch.setattr(policy, "get_db_cursor", pause_reconciler_before_commit)
        reconcile_task = asyncio.create_task(policy.reconcile_federated_session_policy(db_pool))
        login_task = None
        try:
            await asyncio.wait_for(reconciler_held.wait(), timeout=10)
            # Model an old worker: its in-memory callback secret and therefore its
            # expected policy fingerprint still have the pre-rotation value.
            monkeypatch.setattr(
                auth.settings,
                "shibboleth_internal_secret",
                SecretStr(SECRET_A),
            )
            login_task = asyncio.create_task(_login(db_pool, user.email))
            await _wait_for_blocker(owner["pid"])
            release_reconciler.set()
            revoked, login_result = await asyncio.wait_for(
                asyncio.gather(reconcile_task, login_task),
                timeout=10,
            )
        finally:
            release_reconciler.set()
            for task in (reconcile_task, login_task):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(
                *(task for task in (reconcile_task, login_task) if task is not None),
                return_exceptions=True,
            )

        assert revoked == 0
        assert login_result == auth.FederatedLoginFailure("untrusted_assertion")
        assert sync_conn.execute(
            "SELECT display_name, last_login FROM users WHERE id = %s", (user.id,)
        ).fetchone() == ("Reviewed name", None)
        assert sync_conn.execute(
            "SELECT count(*) FROM sessions WHERE user_id = %s", (user.id,)
        ).fetchone() == (0,)
        assert sync_conn.execute(
            "SELECT fingerprint FROM federation_policy_state WHERE id = 1"
        ).fetchone() == (changed_fingerprint,)


class TestIdentityRowSerialization:
    """Concurrent writers to one identity row never expose a half-written state."""

    @pytest.fixture(autouse=True)
    async def _trust_test_issuer(self, monkeypatch, clean_db, db_pool):
        del clean_db  # explicit ordering: reconcile only after the autouse truncate
        await _apply_trusted_issuer_policy(monkeypatch, db_pool)

    @pytest.mark.parametrize("login_first", [True, False], ids=["login-first", "approval-first"])
    async def test_pending_login_and_admin_approval_serialize_on_identity_row(
        self,
        db_pool,
        user_factory,
        admin_actor,
        sync_conn,
        monkeypatch,
        login_first,
    ):
        """No assertion can observe or authenticate a half-approved identity."""
        pending = user_factory(
            email="pending-race@example.org",
            auth_method="shibboleth",
            shibboleth_issuer=ISSUER,
            shibboleth_subject_id=SUBJECT,
            federated_status="pending",
            is_active=False,
            access_tier="public",
        )
        before_revision = sync_conn.execute(
            "SELECT auth_revision FROM users WHERE id = %s",
            (pending.id,),
        ).fetchone()[0]
        module = auth if login_first else users
        real_cursor = module.get_db_cursor
        held = asyncio.Event()
        release = asyncio.Event()
        owner = {}

        @asynccontextmanager
        async def pause_before_commit(pool):
            async with real_cursor(pool) as cur:
                yield cur
                owner["pid"] = cur.connection.info.backend_pid
                held.set()
                await release.wait()

        monkeypatch.setattr(module, "get_db_cursor", pause_before_commit)

        async def approve():
            return await users.approve_federated_user(
                db_pool,
                pending.id,
                expected_issuer=ISSUER,
                expected_subject_id=SUBJECT,
                access_tier="vetted",
                actor_id=admin_actor.id,
                actor_session_id=admin_actor.session_id,
            )

        first = asyncio.create_task(_login(db_pool, pending.email) if login_first else approve())
        second = None
        try:
            await asyncio.wait_for(held.wait(), timeout=10)
            second = asyncio.create_task(
                approve() if login_first else _login(db_pool, pending.email)
            )
            await _wait_for_blocker(owner["pid"])

            # The competing transaction is blocked and neither ordering exposes a
            # session or an uncommitted approval to another connection.
            assert sync_conn.execute(
                "SELECT count(*) FROM sessions WHERE user_id = %s",
                (pending.id,),
            ).fetchone() == (0,)
            assert sync_conn.execute(
                "SELECT federated_status, is_active, access_tier FROM users WHERE id = %s",
                (pending.id,),
            ).fetchone() == ("pending", False, "public")

            release.set()
            values = await asyncio.wait_for(asyncio.gather(first, second), timeout=10)
        finally:
            release.set()
            for task in (first, second):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(
                *(task for task in (first, second) if task is not None),
                return_exceptions=True,
            )

        login_result = values[0] if login_first else values[1]
        approved = values[1] if login_first else values[0]
        assert approved.federated_status == "approved"
        assert sync_conn.execute(
            """SELECT federated_status, is_active, access_tier, auth_revision
                 FROM users WHERE id = %s""",
            (pending.id,),
        ).fetchone() == ("approved", True, "vetted", before_revision + 1)

        if login_first:
            assert isinstance(login_result, auth.FederatedLoginFailure)
            assert login_result.reason == "inactive_account"
            assert sync_conn.execute(
                "SELECT count(*) FROM sessions WHERE user_id = %s",
                (pending.id,),
            ).fetchone() == (0,)
        else:
            assert isinstance(login_result, auth.FederatedLoginSuccess)
            assert (await get_session_user(db_pool, login_result.session_id)).user.id == (
                pending.id
            )
            assert sync_conn.execute(
                "SELECT count(*) FROM sessions WHERE user_id = %s",
                (pending.id,),
            ).fetchone() == (1,)

    @pytest.mark.parametrize(
        "login_first", [False, True], ids=["deactivation-first", "login-first"]
    )
    async def test_deactivation_and_login_serialize_on_same_identity_row(
        self,
        db_pool,
        user_factory,
        admin_actor,
        sync_conn,
        monkeypatch,
        login_first,
    ):
        user = user_factory(
            email="person@example.org",
            auth_method="shibboleth",
            shibboleth_issuer=ISSUER,
            shibboleth_subject_id=SUBJECT,
            is_active=True,
            last_login=None,
        )
        module = auth if login_first else users
        real_cursor = module.get_db_cursor
        held = asyncio.Event()
        release = asyncio.Event()
        owner = {}

        @asynccontextmanager
        async def pause_before_commit(pool):
            async with real_cursor(pool) as cur:
                yield cur
                owner["pid"] = cur.connection.info.backend_pid
                held.set()
                await release.wait()

        monkeypatch.setattr(module, "get_db_cursor", pause_before_commit)

        async def deactivate():
            return await users.set_user_active(
                db_pool,
                user.id,
                False,
                actor_id=admin_actor.id,
                actor_session_id=admin_actor.session_id,
            )

        first = asyncio.create_task(_login(db_pool, user.email) if login_first else deactivate())
        second = None
        try:
            await asyncio.wait_for(held.wait(), timeout=10)
            second = asyncio.create_task(
                deactivate() if login_first else _login(db_pool, user.email)
            )
            await _wait_for_blocker(owner["pid"])
            release.set()
            values = await asyncio.wait_for(asyncio.gather(first, second), timeout=10)
        finally:
            release.set()
            for task in (first, second):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(
                *(task for task in (first, second) if task is not None), return_exceptions=True
            )

        login_result = values[0] if login_first else values[1]
        if login_first:
            assert isinstance(login_result, auth.FederatedLoginSuccess)
            assert (await get_session_user(db_pool, login_result.session_id)).user is None
        else:
            assert isinstance(login_result, auth.FederatedLoginFailure)
            assert login_result.reason == "inactive_account"
            assert sync_conn.execute(
                "SELECT last_login FROM users WHERE id = %s", (user.id,)
            ).fetchone() == (None,)
        assert sync_conn.execute(
            "SELECT is_active FROM users WHERE id = %s", (user.id,)
        ).fetchone() == (False,)
        assert sync_conn.execute(
            "SELECT count(*) FROM sessions WHERE user_id = %s", (user.id,)
        ).fetchone() == (0,)


class TestFederatedSessionPolicyReconciliation:
    """``reconcile_federated_session_policy`` revokes sessions the policy no longer authorizes."""

    async def test_first_reconciliation_revokes_only_federated_sessions(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
    ):
        _enable_test_federation(monkeypatch)
        local = user_factory(email="local@example.org")
        federated = user_factory(
            email="federated@example.org",
            auth_method="shibboleth",
            shibboleth_issuer=ISSUER,
            shibboleth_subject_id="urn:test:subject:federated",
        )
        local_raw = session_factory(local.id)
        federated_raw = session_factory(federated.id)

        assert await policy.reconcile_federated_session_policy(db_pool) == 1

        stored = sync_conn.execute(
            "SELECT fingerprint FROM federation_policy_state WHERE id = 1"
        ).fetchone()
        assert stored == (policy.federated_session_policy_fingerprint(),)
        assert (await get_session_user(db_pool, local_raw)).user.id == local.id
        assert await get_session_user(db_pool, federated_raw) == (None, None, False)

        # Once the exact policy is recorded, a new valid federated session remains.
        replacement = session_factory(federated.id)
        assert await policy.reconcile_federated_session_policy(db_pool) == 0
        assert (await get_session_user(db_pool, replacement)).user.id == federated.id

    async def test_callback_secret_rotation_revokes_federated_but_not_local_sessions(
        self,
        db_pool,
        user_factory,
        session_factory,
        monkeypatch,
    ):
        _enable_test_federation(monkeypatch)
        assert await policy.reconcile_federated_session_policy(db_pool) == 0

        local = user_factory(email="local@example.org")
        federated = user_factory(
            email="federated@example.org",
            auth_method="shibboleth",
            shibboleth_issuer=ISSUER,
        )
        local_raw = session_factory(local.id)
        federated_raw = session_factory(federated.id)

        monkeypatch.setattr(settings, "shibboleth_internal_secret", SecretStr(SECRET_B))
        assert await policy.reconcile_federated_session_policy(db_pool) == 1

        assert (await get_session_user(db_pool, local_raw)).user.id == local.id
        assert await get_session_user(db_pool, federated_raw) == (None, None, False)

    async def test_live_sink_deletes_session_after_flag_or_exact_issuer_is_withdrawn(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
    ):
        _enable_test_federation(monkeypatch)
        user = user_factory(
            auth_method="shibboleth",
            shibboleth_issuer=ISSUER,
            shibboleth_subject_id="urn:test:subject:live-policy",
        )

        issuer_raw = session_factory(user.id)
        assert (await get_session_user(db_pool, issuer_raw)).user.id == user.id
        monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [OTHER_ISSUER])
        assert await get_session_user(db_pool, issuer_raw) == (None, None, False)

        # Restoring the issuer cannot resurrect the deleted cookie.
        monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [ISSUER])
        assert await get_session_user(db_pool, issuer_raw) == (None, None, False)

        flag_raw = session_factory(user.id)
        monkeypatch.setattr(settings, "shibboleth_enabled", False)
        assert await get_session_user(db_pool, flag_raw) == (None, None, False)
        assert sync_conn.execute(
            "SELECT count(*) FROM sessions WHERE user_id = %s", (user.id,)
        ).fetchone() == (0,)
