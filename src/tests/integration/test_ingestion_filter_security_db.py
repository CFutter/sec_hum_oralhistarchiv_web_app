"""Local exclusions cannot delete privacy state or bypass source binding review."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from app.services import ingestion
from app.services.db import get_db_cursor
from tests.integration.sync_doubles import FETCH, SourceCase, harvest_result, make_record
from tests.source_fixtures import legacy_source

_ROOT = Path(__file__).resolve().parents[3]


class TestRetainedFilterSecurity(SourceCase):
    """Check retained Filter Security."""

    def _select_public_source(self, sync_conn):
        """Select a public-floor source and commit its matching durable binding."""
        self.source = legacy_source(name=self.source.name, max_visibility="public")
        sync_conn.execute(
            "UPDATE sync_status SET source_fingerprint=%s WHERE source=%s",
            (self.source.adapter.config_fingerprint(), self.source.name),
        )
        sync_conn.commit()

    async def test_explicit_tier_lowering_rolls_back_with_its_metadata_and_event(
        self,
        db_pool,
        sync_conn,
        dataset_factory,
    ):
        """Verify explicit tier lowering rolls back with its metadata and event."""
        self._select_public_source(sync_conn)
        identity = dataset_factory(
            source=self.source.name,
            uuid="atomic-correction",
            visibility_tier="vetted",
            title="Original title",
        )
        with pytest.raises(RuntimeError, match="abort corrected transaction"):
            async with get_db_cursor(db_pool) as cursor:
                await ingestion._upsert_public_catalogue_record(
                    cursor,
                    make_record(
                        "atomic-correction", title="Uncommitted title", visibility_tier="public"
                    ),
                    self.source.policy,
                )
                raise RuntimeError("abort corrected transaction")
        assert sync_conn.execute(
            "SELECT title, visibility_tier FROM oral_history_datasets WHERE id=%s",
            (identity,),
        ).fetchone() == ("Original title", "vetted")
        assert sync_conn.execute(
            "SELECT visibility_tier FROM source_security_state WHERE source=%s AND uuid='atomic-correction'",
            (self.source.name,),
        ).fetchone() == ("vetted",)
        assert sync_conn.execute(
            "SELECT count(*) FROM security_audit_events WHERE event_type='source_restriction_lowered'",
        ).fetchone() == (0,)

    @pytest.mark.parametrize("runner", [ingestion.run_sync, ingestion.run_full_rebuild])
    async def test_known_filter_exclusion_is_withheld_until_a_fresh_matching_correction(
        self, db_pool, sync_conn, dataset_factory, bind_catalogue_policy, runner
    ):
        """Verify known filter exclusion is withheld until a fresh matching correction."""
        policy = bind_catalogue_policy((self.source,))
        assert policy.fingerprint
        identity = dataset_factory(
            uuid="excluded", title="Old retained title", source=self.source.name
        )
        dataset_factory(uuid="neighbour", source=self.source.name)
        offered = harvest_result(
            [make_record("neighbour")], nonmatching_uuids={"excluded", "never-stored"}
        )
        with patch(FETCH, autospec=True, return_value=offered):
            outcome = await runner(db_pool, configured_source=self.source)
        assert outcome.status in {"partial", "failed"}
        assert sync_conn.execute(
            "SELECT title FROM oral_history_datasets WHERE id = %s", (identity,)
        ).fetchone() == ("Old retained title",)
        assert sync_conn.execute(
            "SELECT uuid, reason FROM ingestion_quarantine WHERE source = %s ORDER BY uuid",
            (self.source.name,),
        ).fetchall() == [("excluded", "filter_mismatch")]
        for audience in ("public", "registered", "vetted"):
            # The relation names are a fixed test-only audience allowlist.
            assert sync_conn.execute(
                f"SELECT count(*) FROM catalogue_search_{audience} WHERE id = %s",
                (identity,),
            ).fetchone() == (0,)
        assert sync_conn.execute(
            "SELECT count(*) FROM catalogue_discovery WHERE id = %s", (identity,)
        ).fetchone() == (0,)
        sync_conn.commit()

        corrected = harvest_result(
            [make_record("excluded", title="Fresh corrected title"), make_record("neighbour")]
        )
        with patch(FETCH, autospec=True, return_value=corrected):
            assert (await runner(db_pool, configured_source=self.source)).status == "success"
        assert sync_conn.execute(
            "SELECT title FROM oral_history_datasets WHERE id = %s", (identity,)
        ).fetchone() == ("Fresh corrected title",)
        assert sync_conn.execute(
            "SELECT count(*) FROM ingestion_quarantine WHERE source = %s", (self.source.name,)
        ).fetchone() == (0,)

    async def test_contraction_abort_keeps_quarantine_and_applies_real_tombstones(
        self, db_pool, sync_conn, dataset_factory
    ):
        """Verify contraction abort keeps quarantine and applies real tombstones."""
        for uuid in ("keep", "excluded-a", "excluded-b", "excluded-c", "withdrawn"):
            dataset_factory(uuid=uuid, source=self.source.name, visibility_tier="vetted")
        offered = harvest_result(
            [make_record("keep", title="Uncommitted replacement")],
            nonmatching_uuids={"excluded-a", "excluded-b", "excluded-c"},
            deleted_uuids={"withdrawn"},
        )
        with patch(FETCH, autospec=True, return_value=offered):
            outcome = await ingestion.run_full_rebuild(db_pool, configured_source=self.source)
        assert outcome.status == "failed"
        assert sync_conn.execute(
            "SELECT uuid FROM oral_history_datasets WHERE source = %s ORDER BY uuid",
            (self.source.name,),
        ).fetchall() == [("excluded-a",), ("excluded-b",), ("excluded-c",), ("keep",)]
        assert sync_conn.execute(
            "SELECT uuid FROM ingestion_quarantine WHERE source = %s ORDER BY uuid",
            (self.source.name,),
        ).fetchall() == [("excluded-a",), ("excluded-b",), ("excluded-c",)]
        assert sync_conn.execute(
            "SELECT visibility_tier FROM source_security_state WHERE source = %s AND uuid = 'withdrawn'",
            (self.source.name,),
        ).fetchone() == ("vetted",)

    @pytest.mark.parametrize("asserted", [False, True], ids=["omitted-tier", "explicit-lower-tier"])
    async def test_reintroduction_retains_unasserted_tiers_and_applies_explicit_corrections(
        self, db_pool, sync_conn, dataset_factory, asserted
    ):
        """Verify reintroduction retains unasserted tiers and applies explicit corrections."""
        self._select_public_source(sync_conn)
        dataset_factory(uuid="returning", source=self.source.name, visibility_tier="vetted")
        with patch(FETCH, autospec=True, return_value=harvest_result(deleted_uuids={"returning"})):
            await ingestion.run_sync(db_pool, configured_source=self.source)
        assert sync_conn.execute(
            "SELECT count(*) FROM oral_history_datasets WHERE source = %s", (self.source.name,)
        ).fetchone() == (0,)
        sync_conn.commit()
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [
                    make_record(
                        "returning",
                        title="New upstream payload",
                        visibility_tier="public" if asserted else None,
                    )
                ]
            ),
        ):
            assert (
                await ingestion.run_sync(db_pool, configured_source=self.source)
            ).status == "success"
        assert sync_conn.execute(
            "SELECT title, visibility_tier FROM oral_history_datasets WHERE source = %s AND uuid = 'returning'",
            (self.source.name,),
        ).fetchone() == ("New upstream payload", "public" if asserted else "vetted")
        if asserted:
            assert sync_conn.execute(
                "SELECT payload FROM security_audit_events WHERE event_type='source_restriction_lowered'"
            ).fetchone() == (
                {
                    "source": self.source.name,
                    "uuid": "returning",
                    "old_tier": "vetted",
                    "tier": "public",
                },
            )

    async def test_owner_acknowledgement_is_required_before_rebinding_fetch(
        self, db_pool, sync_conn, tmp_path
    ):
        """Verify owner acknowledgement is required before rebinding fetch."""
        changed = legacy_source(
            name=self.source.name, endpoint="https://replacement.example.org/oai"
        )
        old = self.source.adapter.config_fingerprint()
        target = changed.adapter.config_fingerprint()
        with patch(FETCH, autospec=True) as fetch:
            result = await ingestion.run_full_rebuild(db_pool, configured_source=changed)
        assert result.requires_source_acknowledgement and result.status == "failed"
        fetch.assert_not_called()
        sync_conn.commit()
        program = (
            "import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); "
            "sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name='__main__')"
        )

        def acknowledge(previous):
            """Run the binding-acknowledgement CLI for the exact expected and replacement
            fingerprints.
            """
            return subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    program,
                    str(_ROOT / "src"),
                    str(_ROOT / "scripts/acknowledge_source_binding.py"),
                    "--source",
                    self.source.name,
                    "--expected-fingerprint",
                    previous,
                    "--new-fingerprint",
                    target,
                ],
                env={"ENV_STATE": "dev", "DATABASE_URL": db_pool.conninfo},
                cwd=tmp_path,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )

        assert acknowledge("0" * 64).returncode == 1
        assert sync_conn.execute(
            "SELECT count(*) FROM source_binding_acknowledgements"
        ).fetchone() == (0,)
        sync_conn.commit()
        accepted = acknowledge(old)
        assert accepted.returncode == 0, accepted.stdout + accepted.stderr
        assert sync_conn.execute(
            "SELECT payload FROM security_audit_events WHERE event_type = 'source_binding_acknowledged'"
        ).fetchall() == [
            (
                {
                    "source": self.source.name,
                    "previous_fingerprint": old,
                    "target_fingerprint": target,
                },
            )
        ]
        sync_conn.commit()
        with patch(
            FETCH, autospec=True, return_value=harvest_result([make_record("approved")])
        ) as fetch:
            result = await ingestion.run_full_rebuild(db_pool, configured_source=changed)
        assert result.status == "success"
        fetch.assert_called_once()
        assert sync_conn.execute(
            "SELECT source_fingerprint FROM sync_status WHERE source = %s", (self.source.name,)
        ).fetchone() == (target,)
