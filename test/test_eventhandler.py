"""Unit tests for the eventhandler module."""

import sys
from unittest.mock import Mock, patch

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


def test_shutdown_controller_not_alive(handler):
    handler.controller.is_alive.return_value = False
    handler.shutdown()
    handler.controller.remove_event_listener.assert_not_called()


def test_wait_controller_not_alive(handler):
    handler.controller.is_alive.return_value = False
    with patch.object(handler.finished_event, "wait",
                      side_effect=[False, True]):
        handler.wait()
    assert handler.finished_event.is_set()
