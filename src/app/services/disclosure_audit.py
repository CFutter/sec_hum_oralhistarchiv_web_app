"""Bounded metadata disclosure descriptions for the actual catalogue views.

Events describe field names and record identity, never metadata values, search
text, capability URLs or session bearers. Public-only views emit no event.
"""

import logging
from collections.abc import Sequence
from typing import Literal

from fastapi import Request

from app import is_safe_http_url
from app.sources import AccessTier

from .access_tiers import can_access
from .audit import audit_user_event
from .catalogue_policy import CataloguePolicyInput
from .datasets import (
    FACET_SAMPLE_SIZE,
    Dataset,
    FacetDisclosure,
    can_view_field,
    field_required_tier,
)

DisclosureView = Literal["home", "search", "detail", "resource"]
_CARD_FIELDS = ("authors", "description", "keywords", "languages")
_DETAIL_FIELDS = (
    "project_title",
    "description",
    "resource_description",
    "project_description",
    "keywords",
    "bibliographical_citation",
    "authors",
    "resource_type",
    "languages",
    "doi",
    "license_val",
    "license_url",
)
_MAX_RECORDS = 100
_BATCH_SIZE = 5


def _has_rendered_value(dataset: Dataset, field: str, view: DisclosureView) -> bool:
    """Return whether the view renders a nonempty value, respecting keyword limits and safe URLs."""
    if field == "authors":
        return any(author.name for author in dataset.authors)
    if field == "keywords":
        limit = {"home": 4, "search": 5}.get(view)
        return any(dataset.keywords[:limit])
    if field == "license_url":
        return bool(dataset.license_url) and is_safe_http_url(dataset.license_url)
    return bool(getattr(dataset, field))


def _record_disclosure(
    dataset: Dataset,
    *,
    user_tier: AccessTier,
    configured_sources: CataloguePolicyInput,
    view: DisclosureView,
    resource_exposed: bool,
) -> dict[str, object] | None:
    """Return restricted-field disclosure/denial metadata, or None when neither applies."""
    fields: tuple[str, ...] = _DETAIL_FIELDS if view == "detail" else _CARD_FIELDS
    if view == "resource":
        fields = ()
    if resource_exposed:
        fields = (*fields, "resource_proxies")
    disclosed, denied = [], []
    for name in fields:
        minimum = field_required_tier(dataset, name, configured_sources=configured_sources)
        if minimum == "public":
            continue
        visible = can_view_field(dataset, user_tier, name, configured_sources=configured_sources)
        if view == "detail" and name != "project_title":
            visible = visible and can_access(user_tier, dataset.visibility_tier)
        if not visible:
            denied.append(name)
        elif name == "resource_proxies" or _has_rendered_value(dataset, name, view):
            disclosed.append(name)
    if not disclosed and not denied:
        return None
    return {
        "dataset_id": dataset.id,
        "source": dataset.source,
        "uuid": dataset.uuid,
        "fields": sorted(disclosed),
        "denied_fields": sorted(denied),
        "outcome": "partial" if disclosed and denied else ("full" if disclosed else "denied"),
    }


def audit_metadata_disclosures(
    request: Request,
    datasets: Sequence[Dataset],
    *,
    user_tier: AccessTier,
    configured_sources: CataloguePolicyInput,
    view: DisclosureView,
    resource_exposed: bool = False,
) -> None:
    """Emit bounded per-record field descriptions immediately before response release.

    Card fields mirror the two card templates; detail fields mirror the detail
    template. Empty/default values do not count as disclosures. A resource link
    counts only when its actual upstream target is exposed, rather than an
    internal redirect route. Reads remain best-effort local audit events;
    mutation evidence uses the separate transactional event outbox.
    """
    if view not in {"home", "search", "detail", "resource"}:
        raise ValueError("Unknown catalogue disclosure view")
    if len(datasets) > _MAX_RECORDS:
        raise ValueError("Catalogue disclosure batch exceeds its record bound")
    user = getattr(request.state, "user", None)
    batch = []
    for dataset in datasets:
        event = _record_disclosure(
            dataset,
            user_tier=user_tier,
            configured_sources=configured_sources,
            view=view,
            resource_exposed=resource_exposed,
        )
        if event is None:
            continue
        batch.append(event)
        if len(batch) == _BATCH_SIZE:
            audit_user_event(
                logging.INFO,
                request,
                "metadata_disclosure",
                user.id if user else None,
                view=view,
                user_tier=user_tier,
                disclosures=batch,
            )
            batch = []
    if batch:
        audit_user_event(
            logging.INFO,
            request,
            "metadata_disclosure",
            user.id if user else None,
            view=view,
            user_tier=user_tier,
            disclosures=batch,
        )


def audit_facet_disclosures(
    request: Request,
    disclosures: Sequence[FacetDisclosure],
    *,
    user_tier: AccessTier,
) -> None:
    """Describe protected contributors to actually rendered facet options.

    The facet query produces these identities and field names in the same SQL
    snapshot as the options. No option values or search/filter text are logged.
    """
    if len(disclosures) > FACET_SAMPLE_SIZE:
        raise ValueError("Facet disclosure batch exceeds its record bound")
    if any(
        not record.fields or set(record.fields) - {"keywords", "languages"}
        for record in disclosures
    ):
        raise ValueError("Unknown facet disclosure field")
    user = getattr(request.state, "user", None)
    for start in range(0, len(disclosures), _BATCH_SIZE):
        audit_user_event(
            logging.INFO,
            request,
            "metadata_disclosure",
            user.id if user else None,
            view="facets",
            user_tier=user_tier,
            disclosures=[
                {
                    "dataset_id": record.dataset_id,
                    "source": record.source,
                    "uuid": record.uuid,
                    "fields": list(record.fields),
                    "denied_fields": [],
                    "outcome": "full",
                }
                for record in disclosures[start : start + _BATCH_SIZE]
            ],
        )
