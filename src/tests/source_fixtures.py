"""Explicit configured OAI and native-tier fixture sources for shared tests."""

from app.sources import ConfiguredSource, FixtureConfig, OaiPmhCmdiConfig, configure_sources

TEST_SOURCE_NAME = "swissubase"
TEST_OAI_ENDPOINT = "https://www.swissubase.ch/oai-pmh/v1/oai"
TEST_INSTITUTION_FILTER = "Universität Beispielstadt"


def legacy_source(**config_changes: object) -> ConfiguredSource:
    """Build a fresh validated OAI source without reading runtime settings."""
    values: dict[str, object] = {
        "name": TEST_SOURCE_NAME,
        "endpoint": TEST_OAI_ENDPOINT,
        "institution_filter": TEST_INSTITUTION_FILTER,
        "max_pages": 500,
        "max_visibility": "vetted",
        "requires_record_tier": False,
        "display": {
            "label": "SWISSUbase",
            "resource_link_label": "Access dataset on SWISSUbase",
            "landing_link_label": "View on SWISSUbase",
        },
        "schedule": {
            "incremental_interval_seconds": 3600,
            "rebuild_interval_seconds": 86400,
            "write_timeout_seconds": 120,
        },
    }
    values.update(config_changes)
    return configure_sources((OaiPmhCmdiConfig.model_validate(values),))[0]


def fixture_source(**config_changes: object) -> ConfiguredSource:
    """Build a native-tier-capable source for adapter-independent policy tests."""
    values: dict[str, object] = {
        "name": TEST_SOURCE_NAME,
        "display": {"label": "Fixture archive"},
        "max_visibility": "vetted",
    }
    values.update(config_changes)
    return configure_sources((FixtureConfig.model_validate(values),))[0]
