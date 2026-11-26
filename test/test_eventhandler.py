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
