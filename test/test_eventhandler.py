"""Unit tests for the eventhandler module."""

import sys
from unittest.mock import Mock

import pytest

sys.path.insert(0, 'src/')
import eventhandler


@pytest.fixture
def handler(stats_obj):
    handler = eventhandler.EventHandler(
        Mock(), Mock(), 9050, stats_obj,
        exit_destinations={}, target_host=None, target_port=None
    )
    yield handler
    if handler.queue_thread.is_alive():
        handler.shutdown()


def test_shutdown_passes_stats_to_teardown(handler):
    handler.shutdown()
    handler.module.teardown.assert_called_with(stats=handler.stats)
