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


def test_shutdown_reaps_terminated_processes(handler):
    proc = Mock(pid=1)
    with patch.object(eventhandler.multiprocessing, "active_children",
                      return_value=[proc]):
        handler.shutdown()
    proc.terminate.assert_called_once()
    proc.join.assert_called_once()
