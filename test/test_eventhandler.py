"""Unit tests for the eventhandler module."""

import sys
import types
from unittest.mock import Mock, patch

from stem import CircStatus

sys.path.insert(0, 'src/')
import eventhandler
from stats import Statistics


def _make_handler(module=None):
    controller = Mock()
    controller.is_alive.return_value = True
    if module is None:
        module = types.SimpleNamespace(probe=lambda **kwargs: None)
    return eventhandler.EventHandler(
        controller=controller,
        module=module,
        socks_port=9050,
        stats=Statistics(),
        exit_destinations={},
        target_host=None,
        target_port=None,
    )


def test_check_finished_waits_for_all_built_streams():
    handler = _make_handler()
    handler.stats.total_circuits = 4
    handler.stats.failed_circuits = 2
    handler.stats.successful_circuits = 2
    handler.stats.finished_streams = 0

    try:
        handler.check_finished()
        assert not handler.finished_event.is_set()

        handler.stats.finished_streams = 1
        handler.check_finished()
        assert not handler.finished_event.is_set()

        handler.stats.finished_streams = 2
        handler.check_finished()
        assert handler.finished_event.is_set()
    finally:
        handler.shutdown()


def test_check_finished_tolerates_extra_circuits():
    handler = _make_handler()
    handler.stats.total_circuits = 2
    handler.stats.failed_circuits = 1
    handler.stats.successful_circuits = 2
    handler.stats.finished_streams = 2

    try:
        handler.check_finished()
        assert handler.finished_event.is_set()
    finally:
        handler.shutdown()


def test_new_circuit_ignores_unselected_exit():
    handler = _make_handler()
    handler.exit_destinations = {"A" * 40: frozenset()}

    unselected = Mock()
    unselected.status = CircStatus.BUILT
    unselected.id = "77"
    unselected.path = [("F" * 40, "guard"), ("B" * 40, "stray")]

    empty_path = Mock()
    empty_path.status = CircStatus.BUILT
    empty_path.id = "78"
    empty_path.path = []

    try:
        with patch.object(eventhandler.multiprocessing, "Process") as mock_proc:
            handler.new_circuit(unselected)
            handler.new_circuit(empty_path)
    finally:
        handler.shutdown()

    assert handler.stats.successful_circuits == 0
    mock_proc.assert_not_called()


def test_wait_unblocks_when_controller_dies():
    handler = _make_handler()
    handler.controller.is_alive.return_value = False

    try:
        with patch.object(handler.finished_event, "wait",
                          return_value=False) as mock_wait:
            handler.wait()
        mock_wait.assert_called_once_with(timeout=1.0)
        assert handler.finished_event.is_set()
    finally:
        handler.shutdown()


def test_shutdown_terminates_reaps_and_kills_stalled_children():
    handler = _make_handler()
    call_order = []

    clean_proc = Mock()
    clean_proc.pid = 1001
    clean_proc.name = "clean-probe"
    clean_proc.is_alive.return_value = False

    stubborn_1 = Mock()
    stubborn_1.pid = 1002
    stubborn_1.name = "stubborn-1"
    stubborn_1.is_alive.return_value = True
    stubborn_1.kill.side_effect = lambda: call_order.append(("kill", 1002))
    stubborn_1.join.side_effect = (
        lambda timeout=None: call_order.append(("join", 1002))
    )

    stubborn_2 = Mock()
    stubborn_2.pid = 1003
    stubborn_2.name = "stubborn-2"
    stubborn_2.is_alive.return_value = True
    stubborn_2.kill.side_effect = lambda: call_order.append(("kill", 1003))
    stubborn_2.join.side_effect = (
        lambda timeout=None: call_order.append(("join", 1003))
    )

    closed_proc = Mock()
    closed_proc.pid = 1004
    closed_proc.name = "closed-probe"
    closed_proc.join.side_effect = ValueError("already closed")

    try:
        with patch.object(
            eventhandler.multiprocessing, "active_children",
            return_value=[clean_proc, stubborn_1, stubborn_2, closed_proc],
        ):
            handler.shutdown()
    finally:
        if handler.queue_thread.is_alive():
            handler.shutdown()

    clean_proc.terminate.assert_called_once()
    clean_proc.join.assert_called_once()
    clean_proc.kill.assert_not_called()

    for proc in (stubborn_1, stubborn_2):
        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()
        assert proc.join.call_count == 2

    # All SIGKILLs are dispatched before waiting in join(timeout=1.0).
    kill_indices = [i for i, (op, _) in enumerate(call_order) if op == "kill"]
    second_joins = [
        i for i, (op, pid) in enumerate(call_order)
        if op == "join" and pid in (1002, 1003)
    ][2:]
    assert max(kill_indices) < min(second_joins)
    assert not handler.queue_thread.is_alive()
