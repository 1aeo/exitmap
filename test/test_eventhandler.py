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


def test_module_call_passes_first_hop():
    probe = Mock()
    eventhandler.module_call(
        Mock(), probe, "23", 9050, None, None, None, None, None, "A" * 40
    )
    assert "A" * 40 == probe.call_args.kwargs["first_hop"]


def test_new_circuit_passes_first_hop(handler):
    first_hop, exit_relay = "A" * 40, "B" * 40
    handler.exit_destinations[exit_relay] = set()
    circ_event = Mock(status=CircStatus.BUILT,
                      path=[(first_hop, "foo"), (exit_relay, "bar")])
    with patch.object(eventhandler.multiprocessing, "Process") as process:
        handler.new_circuit(circ_event)
    assert first_hop in process.call_args.kwargs["args"]
