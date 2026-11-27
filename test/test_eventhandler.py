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


def test_wait_gives_up_on_silent_modules(handler, caplog):
    handler.stats.total_circuits = 7
    handler.stats.failed_circuits = 1
    handler.stats.successful_circuits = 5
    handler.stats.finished_streams = 1
    # Silence before wait() is called does not count.
    handler.last_message = float("-inf")
    for clock, waits, finished in [([0, 299], [False, True], False),
                                   ([0, 299, 300], [False, False], True)]:
        with patch.object(eventhandler.time, "monotonic", side_effect=clock):
            with patch.object(handler.finished_event, "wait",
                              side_effect=waits):
                handler.wait()
        handler.check_finished()
        assert finished == handler.finished_event.is_set()
    warnings = [r.levelname for r in caplog.records
                if "No longer waiting for 1 circuit(s)" in r.getMessage()]
    assert ["WARNING"] == warnings
    # The next module of the run waits for its own module processes.
    handler.already_finished = False
    handler.finished_event.clear()
    handler.stats.total_circuits += 1
    handler.stats.successful_circuits += 1
    handler.check_finished()
    assert not handler.finished_event.is_set()


def test_queue_reader_notes_messages(handler):
    handler.shutdown()
    for item in [("23", None), ("23", ("127.0.0.1", 1234))]:
        handler.last_message = 0
        with patch.object(handler, "queue") as queue:
            queue.get.side_effect = [item, EOFError]
            with patch.object(eventhandler.time, "monotonic",
                              return_value=23):
                handler.queue_reader()
        assert 23 == handler.last_message
