"""Unit tests for the eventhandler module."""

import logging
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


def test_nothing_counted_after_giving_up(handler, caplog):
    exit_relay = "A" * 40
    handler.exit_destinations[exit_relay] = set()
    handler.stats.total_circuits = 5
    handler.stats.failed_circuits = 1
    handler.stats.successful_circuits = 2
    handler.stats.finished_streams = 1
    with patch.object(eventhandler.time, "monotonic", side_effect=[0, 300]):
        with patch.object(handler.finished_event, "wait", return_value=False):
            handler.wait()
    # wait() counted two circuits as failed and one module process as
    # finished.  Late events for the circuits and a late message from the
    # module process change nothing.
    for status in [CircStatus.FAILED, CircStatus.BUILT]:
        circ_event = Mock(status=status,
                          path=[("B" * 40, "foo"), (exit_relay, "bar")])
        with patch.object(eventhandler.multiprocessing, "Process") as process:
            handler.new_circuit(circ_event)
        process.assert_not_called()
    handler.queue.put(("23", None))
    # shutdown() stops the thread reading from the queue only once it has
    # read this message.
    with caplog.at_level(logging.DEBUG):
        handler.shutdown()
    handler.controller.close_circuit.assert_called_once_with("23")
    assert "IPC queue received shutdown signal." in caplog.messages
    assert 3 == handler.stats.failed_circuits
    assert 2 == handler.stats.successful_circuits
    assert 2 == handler.stats.finished_streams


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


def test_shutdown_reaps_terminated_processes(handler):
    proc = Mock(pid=1)
    with patch.object(eventhandler.multiprocessing, "active_children",
                      return_value=[proc]):
        handler.shutdown()
    proc.terminate.assert_called_once()
    proc.join.assert_called_once()


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


def test_shutdown_passes_stats_to_teardown(handler):
    handler.shutdown()
    handler.module.teardown.assert_called_with(stats=handler.stats)
