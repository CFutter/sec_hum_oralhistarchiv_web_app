"""Explicit ownership of the web application's immutable catalogue snapshot."""

from collections.abc import Sequence

from psycopg_pool import AsyncConnectionPool
from starlette.applications import Starlette

from app.services import CataloguePolicy, CatalogueStatsCache, build_catalogue_policy
from app.sources import SourceMetadata, catalogue_sources


def replace_catalogue_sources(
    app: Starlette, configured_sources: Sequence[SourceMetadata]
) -> CataloguePolicy:
    """Compile and publish a detached snapshot for offline consumers and tests.

    Normal requests only read this snapshot. Embeddings that replace sources or
    code visibility must use publish_catalogue_sources to verify the database
    binding before serving requests; this synchronous helper cannot do that.
    Existing statistics freshness is invalidated and rebound to the same sources.
    There is no await while publishing the replacement, so other async requests cannot
    observe half a replacement. Cross-thread mutation is unsupported.
    """
    configs = tuple(source.config for source in configured_sources)
    sources = catalogue_sources(configs) if configs else ()
    policy = build_catalogue_policy(sources)
    return _publish_policy(app, policy)


def _publish_policy(app: Starlette, policy: CataloguePolicy) -> CataloguePolicy:
    """Invalidate/rebind cached statistics, publish sources and policy, and return policy."""
    sources = policy.sources
    cache: CatalogueStatsCache | None = getattr(app.state, "catalogue_stats_cache", None)
    if cache is not None:
        cache.replace_source_names(
            tuple(source.name for source in sources), policy_fingerprint=policy.fingerprint
        )
    app.state.configured_sources = sources
    app.state.catalogue_policy = policy
    return policy


async def publish_catalogue_sources(
    app: Starlette,
    pool: AsyncConnectionPool,
    configured_sources: Sequence[SourceMetadata],
) -> CataloguePolicy:
    """Verify the durable binding before atomically publishing web metadata.

    Startup may initialize an unbound catalogue or verify the same policy. A
    changed policy requires an explicit operator transition, so an older worker
    cannot restore a superseded binding by restarting.
    """
    from app.services import synchronize_search_policy  # noqa: PLC0415 - runtime-only DB boundary.

    sources = catalogue_sources(tuple(source.config for source in configured_sources))
    policy = build_catalogue_policy(sources)
    await synchronize_search_policy(pool, policy)
    return _publish_policy(app, policy)
