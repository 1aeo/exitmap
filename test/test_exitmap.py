import argparse
import importlib.machinery
import importlib.util
import os
import sys
import time
import types
from unittest.mock import Mock, patch
import warnings

import pytest
import stem
# hacky, until exitmap is an installable package
sys.path.insert(0, 'src/')  # noqa
import error
import exitmap


def test_get_modules():
    modules = exitmap.get_modules()
    for m in [
        "checktest",
        "cloudflared",
        "dnspoison",
        "dnsresolution",
        "dnssec",
        "patchingCheck",
        "rtt",
        "testfds"
    ]:
        assert m in modules


def test_lookup_destinations():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host')
    parser.add_argument('--port')
    args = parser.parse_args(["--host", "localhost", "--port", "8000"])
    destinations = exitmap.lookup_destinations(args, "checktest.destinations")
    # Testing only `checktest` to do not take too long
    for module in ["checktest"]:  # exitmap.get_modules():
        print(module)
        destinations = exitmap.lookup_destinations(args, module)
        assert destinations == {('127.0.0.1', '8000')}


def test_parser_cmd_args(mock_argv, args_default):
    warnings.warn("This test won't past if there's `~/.exitmaprc`")
    parsed_args = exitmap.parse_cmd_args()
    parsed_args.tor_dir = None
    assert args_default == parsed_args


def test_select_exits(args, modules):
    for module in ["checktest"]:  # modules:
        exits = exitmap.select_exits(args, modules)
        # {'50485E03CA39D393BD54D315CEBA65E6DD0FDDB9':
        # frozenset({('93.184.215.14', 8000)})}
        assert 1 == len(exits)
        dest = exits['50485E03CA39D393BD54D315CEBA65E6DD0FDDB9']
        list_destinations = list(dest)  # list cause dest is frozenset
        assert 8000 == list_destinations[0][1]  # [("host", port),]


def test_iter_exit_relays(exit_relays, controller, stats_obj, args, caplog):
    exitmap.iter_exit_relays(exit_relays, controller, stats_obj, args)
    log_info_expected = "Done triggering circuit creations after"
    assert log_info_expected in caplog.text


def test_sleep(args):
    start = time.monotonic()
    exitmap.sleep(args.build_delay, args.delay_noise)
    stop = time.monotonic()
    delta = stop - start
    assert delta != 3
    assert delta > 3


def test_bin_exitmap_preserves_exit_status_and_exceptions(args):
    bin_path = os.path.join(os.path.dirname(__file__), "..", "bin", "exitmap")
    loader = importlib.machinery.SourceFileLoader("exitmap_bin_test", bin_path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bin_mod = importlib.util.module_from_spec(spec)
    loader.exec_module(bin_mod)

    for outcome, expected_code in [
        (0, 0),
        (1, 1),
        (SystemExit(1), 1),
        (SystemExit(None), None),
        (KeyboardInterrupt(), 1),
    ]:
        kw = (
            {"return_value": outcome}
            if isinstance(outcome, int)
            else {"side_effect": outcome}
        )
        with patch.object(bin_mod, "parse_cmd_args", return_value=args), \
             patch.object(bin_mod.shutil, "rmtree") as mock_rm, \
             patch.object(bin_mod, "exitmap_main", **kw):
            with pytest.raises(SystemExit) as exc:
                bin_mod.main()
        assert exc.value.code == expected_code
        mock_rm.assert_called_once_with(args.tor_dir)

    with patch.object(bin_mod, "parse_cmd_args", return_value=args), \
         patch.object(bin_mod.shutil, "rmtree") as mock_rm, \
         patch.object(bin_mod, "exitmap_main", side_effect=RuntimeError("boom")):
        with pytest.raises(RuntimeError, match="boom"):
            bin_mod.main()
    mock_rm.assert_called_once_with(args.tor_dir)


def test_iter_exit_relays_stops_when_controller_dies(args, stats_obj):
    run_args = argparse.Namespace(**vars(args))

    pre_dead = Mock()
    pre_dead.is_alive.return_value = False
    with patch.object(exitmap, "sleep") as mock_sleep:
        exitmap.iter_exit_relays(["A" * 40, "B" * 40], pre_dead, stats_obj, run_args)
    pre_dead.new_circuit.assert_not_called()
    assert stats_obj.failed_circuits == 0
    mock_sleep.assert_not_called()

    mid_dead = Mock()
    mid_dead.is_alive.side_effect = [True, False]
    mid_dead.new_circuit.side_effect = stem.SocketClosed("closed")
    with patch.object(exitmap, "sleep") as mock_sleep:
        exitmap.iter_exit_relays(["A" * 40, "B" * 40], mid_dead, stats_obj, run_args)
    assert mid_dead.new_circuit.call_count == 1
    assert stats_obj.failed_circuits == 0
    mock_sleep.assert_not_called()


def test_main_returns_nonzero_and_skips_modules_when_controller_dies(args, tmp_path):
    run_args = argparse.Namespace(**vars(args))
    run_args.tor_dir = str(tmp_path)
    run_args.first_hop = None
    run_args.analysis_dir = None
    run_args.module = ["checktest", "dnsresolution"]
    controller = Mock()
    controller.is_alive.return_value = False

    stem_logger = exitmap.logging.getLogger("stem")
    prev_level = stem_logger.level
    try:
        with patch.object(exitmap, "parse_cmd_args", return_value=run_args), \
             patch.object(exitmap, "bootstrap_tor", return_value=(9050, 9051)), \
             patch.object(exitmap.Controller, "from_port", return_value=controller), \
             patch.object(exitmap.stem.connection, "authenticate"), \
             patch.object(exitmap, "run_module") as mock_run_module:
            ret = exitmap.main()
    finally:
        stem_logger.setLevel(prev_level)

    assert ret == 1
    mock_run_module.assert_called_once()
    controller.close.assert_called_once()


def test_run_module_calls_teardown_across_outcomes(args, stats_obj, monkeypatch):
    teardown_calls = []
    dummy_mod = types.SimpleNamespace(
        setup=lambda **kwargs: None,
        teardown=lambda **kwargs: teardown_calls.append(True),
        probe=lambda **kwargs: None,
    )
    monkeypatch.setitem(sys.modules, "modules.dummy_mr5", dummy_mod)
    monkeypatch.setattr(exitmap.modules, "dummy_mr5", dummy_mod, raising=False)

    with patch.object(exitmap.relayselector, "get_cached_consensus",
                      side_effect=RuntimeError("no consensus")):
        with pytest.raises(RuntimeError, match="no consensus"):
            exitmap.run_module("dummy_mr5", args, Mock(), 9050, stats_obj)
    assert teardown_calls == []

    with patch.object(exitmap.relayselector, "get_cached_consensus", return_value={}), \
         patch.object(exitmap, "select_exits", return_value={}):
        with pytest.raises(error.ExitSelectionError):
            exitmap.run_module("dummy_mr5", args, Mock(), 9050, stats_obj)

    with patch.object(exitmap.relayselector, "get_cached_consensus", return_value={}), \
         patch.object(exitmap, "select_exits", side_effect=RuntimeError("lookup failed")):
        with pytest.raises(RuntimeError, match="lookup failed"):
            exitmap.run_module("dummy_mr5", args, Mock(), 9050, stats_obj)

    assert teardown_calls == [True, True]


def test_run_module_teardown_error_does_not_mask_or_abort(args, stats_obj, monkeypatch):
    def failing_teardown(**kwargs):
        raise RuntimeError("cleanup failed")

    dummy_mod = types.SimpleNamespace(
        teardown=failing_teardown,
        probe=lambda **kwargs: None,
    )
    monkeypatch.setitem(sys.modules, "modules.dummy_mr5_err", dummy_mod)
    monkeypatch.setattr(exitmap.modules, "dummy_mr5_err", dummy_mod, raising=False)

    with patch.object(exitmap, "select_exits", return_value={}):
        with pytest.raises(error.ExitSelectionError):
            exitmap.run_module("dummy_mr5_err", args, Mock(), 9050, stats_obj)

    ctrl = Mock()
    ctrl.is_alive.return_value = True
    with patch.object(exitmap, "select_exits", return_value={"E" * 40: frozenset()}), \
         patch.object(exitmap, "iter_exit_relays"), \
         patch.object(exitmap, "EventHandler") as mock_eh:
        mock_eh.return_value.wait.return_value = None
        exitmap.run_module("dummy_mr5_err", args, ctrl, 9050, stats_obj)

    mock_eh.return_value.shutdown.assert_called_once()


def test_run_module_shuts_down_handler_if_add_listener_fails(args, stats_obj, monkeypatch):
    teardown_calls = []
    dummy_mod = types.SimpleNamespace(
        teardown=lambda **kwargs: teardown_calls.append(True),
        probe=lambda **kwargs: None,
    )
    monkeypatch.setitem(sys.modules, "modules.dummy_mr5_listener", dummy_mod)
    monkeypatch.setattr(exitmap.modules, "dummy_mr5_listener", dummy_mod, raising=False)

    ctrl = Mock()
    ctrl.add_event_listener.side_effect = stem.ControllerError("listener error")

    with patch.object(exitmap, "select_exits", return_value={"E" * 40: frozenset()}), \
         patch.object(exitmap, "EventHandler") as mock_eh:
        with pytest.raises(stem.ControllerError):
            exitmap.run_module("dummy_mr5_listener", args, ctrl, 9050, stats_obj)

    mock_eh.return_value.shutdown.assert_called_once()
    assert teardown_calls == [True]
    assert stats_obj.total_circuits == 0


def test_run_module_calls_teardown_if_shutdown_raises(args, stats_obj, monkeypatch):
    teardown_calls = []
    dummy_mod = types.SimpleNamespace(
        setup=lambda **kwargs: None,
        teardown=lambda **kwargs: teardown_calls.append(True),
        probe=lambda **kwargs: None,
    )
    monkeypatch.setitem(sys.modules, "modules.dummy_mr6_shut", dummy_mod)
    monkeypatch.setattr(exitmap.modules, "dummy_mr6_shut", dummy_mod, raising=False)

    ctrl = Mock()
    with patch.object(exitmap.relayselector, "get_cached_consensus", return_value={}), \
         patch.object(exitmap, "select_exits", return_value={"E" * 40: frozenset()}), \
         patch.object(exitmap, "iter_exit_relays"), \
         patch.object(exitmap, "EventHandler") as mock_eh:
        mock_eh.return_value.shutdown.side_effect = RuntimeError("shutdown boom")
        exitmap.run_module("dummy_mr6_shut", args, ctrl, 9050, stats_obj)

    assert teardown_calls == [True]
