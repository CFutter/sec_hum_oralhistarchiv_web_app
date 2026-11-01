"""Both supported feed worker APIs must preserve one fixed diagnostic vocabulary."""

from typing import get_args

import pytest

from app.sources import json_feed_pages, json_feed_transport
from app.sources.json_feed_http import FeedErrorCode, FeedTransportError
from app.sources.json_feed_worker_protocol import TRANSPORT_ERROR_FRAMES, encode_transport_error


def test_every_declared_transport_code_has_exactly_one_shared_frame():
    """Every declared transport code has exactly one shared frame."""
    assert set(TRANSPORT_ERROR_FRAMES.values()) == set(get_args(FeedErrorCode))
    assert len(TRANSPORT_ERROR_FRAMES) == len(set(TRANSPORT_ERROR_FRAMES.values()))


@pytest.mark.parametrize("code", get_args(FeedErrorCode))
def test_each_declared_error_round_trips_through_the_shared_encoder(code):
    """Each declared error round trips through the shared encoder."""
    frame = encode_transport_error(FeedTransportError(code))
    assert TRANSPORT_ERROR_FRAMES[frame] == code


def test_unexpected_diagnostics_are_replaced_by_the_worker_category():
    """Unexpected diagnostics are replaced by the worker category."""
    assert encode_transport_error(KeyError("private incoming metadata")) == b"worker"


def test_lower_transport_and_page_validation_share_cursor_lexical_acceptance():
    """Lower transport and page validation share cursor lexical acceptance."""
    assert json_feed_pages.FEED_CURSOR_PATTERN is json_feed_transport.FEED_CURSOR_PATTERN
