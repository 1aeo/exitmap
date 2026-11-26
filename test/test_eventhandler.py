"""Unit tests for the eventhandler module."""

import sys
from unittest.mock import Mock, patch

import pytest
from stem import CircStatus

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


def test_check_finished_waits_for_modules(handler):
    handler.stats.total_circuits = 3
    handler.stats.failed_circuits = 1
    handler.stats.successful_circuits = 2
    handler.stats.finished_streams = 1
    handler.check_finished()
    assert not handler.finished_event.is_set()

    handler.stats.finished_streams = 2
    handler.check_finished()
    assert handler.finished_event.is_set()


def test_check_finished_more_circuits_than_expected(handler):
    handler.stats.total_circuits = 1
    handler.stats.failed_circuits = 1
    handler.stats.successful_circuits = 1
    handler.stats.finished_streams = 1
    handler.check_finished()
    assert handler.finished_event.is_set()


def test_new_circuit_ignores_other_circuits(handler):
    exit_relay = "A" * 40
    handler.exit_destinations[exit_relay] = set()
    for last_hop, successful_circuits in [("B" * 40, 0), (exit_relay, 1)]:
        circ_event = Mock(status=CircStatus.BUILT,
                          path=[("C" * 40, "foo"), (last_hop, "bar")])
        with patch.object(eventhandler.multiprocessing, "Process"):
            handler.new_circuit(circ_event)
        assert successful_circuits == handler.stats.successful_circuits
