"""Real page selection and exact counts agree for every v1 field subset."""

from app.services import datasets
from tests.source_fixtures import fixture_source

_BITS = {
    "description": 1,
    "project_title": 2,
    "project_description": 4,
    "keywords": 8,
    "authors": 16,
    "languages": 32,
}


async def test_all_masks_agree_across_count_page_keyword_and_language(
    bind_catalogue_policy, db_pool, dataset_factory
):
    """Verify all masks agree across count page keyword and language."""
    base = {
        "source": "mask_archive",
        "title": "record",
        "description": "",
        "project_title": "",
        "project_description": "",
        "keywords": [],
        "authors": [],
        "languages": [],
    }
    identities = {"public": dataset_factory(**{**base, "title": "needle%"})}
    for name in _BITS:
        value = ["needle%"] if name in {"keywords", "authors"} else "needle%"
        if name == "languages":
            value = ["NeedleLang"]
        identities[name] = dataset_factory(**{**base, name: value})

    for mask in range(64):
        source = fixture_source(
            name="mask_archive",
            max_visibility="public",
            field_visibility={
                name: "public" if mask & bit else "vetted" for name, bit in _BITS.items()
            },
        )
        bind_catalogue_policy((source,))
        matching = [
            "public",
            *(name for name, bit in _BITS.items() if name != "languages" and mask & bit),
        ]
        cases = [
            ("needle", "", "", matching),
            ('"needle"', "", "", matching),
            ("needle%", "", "", matching),
            ("", "needle%", "", ["keywords"] if mask & 8 else []),
            ("", "", "NeedleLang", ["languages"] if mask & 32 else []),
        ]
        for term, keyword, language, labels in cases:
            rows, count = await datasets.search_datasets(
                db_pool, "public", term, keyword, language, configured_sources=(source,)
            )
            expected = sorted((identities[label] for label in labels), reverse=True)
            assert [row.id for row in rows] == expected, (mask, term, keyword, language)
            assert count == len(expected), (mask, term, keyword, language)
            page = await datasets.search_catalogue_page(
                db_pool, "public", term, keyword, language, configured_sources=(source,)
            )
            assert [row.id for row in page.datasets] == expected, (mask, term, keyword, language)
