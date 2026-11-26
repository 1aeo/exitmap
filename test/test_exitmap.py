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


def test_main_closes_controller_when_first_hop_not_in_consensus(args, tmp_path):
    run_args = argparse.Namespace(**vars(args))
    run_args.tor_dir = str(tmp_path)
    run_args.first_hop = "A" * 40
    run_args.analysis_dir = None
    controller = Mock()

    stem_logger = exitmap.logging.getLogger("stem")
    prev_level = stem_logger.level
    try:
        with patch.object(exitmap, "parse_cmd_args", return_value=run_args), \
             patch.object(exitmap, "bootstrap_tor", return_value=(9050, 9051)), \
             patch.object(exitmap.Controller, "from_port", return_value=controller), \
             patch.object(exitmap.stem.connection, "authenticate"), \
             patch.object(exitmap.util, "relay_in_consensus", return_value=False), \
             patch.object(exitmap, "run_module") as mock_run_module:
            ret = exitmap.main()
    finally:
        stem_logger.setLevel(prev_level)

    assert ret == 1
    mock_run_module.assert_not_called()
    controller.close.assert_called_once()


def test_select_exits_normalizes_lowercase_and_dollar_exit(args):
    dummy_mod = types.SimpleNamespace(destinations=None)
    lower_args = argparse.Namespace(**vars(args))
    lower_args.exit = "$%s" % args.exit.lower()
    with patch.object(exitmap, "lookup_destinations",
                      return_value={("93.184.215.14", 8000)}):
        exits = exitmap.select_exits(lower_args, dummy_mod)
    assert list(exits.keys()) == [args.exit.upper()]


def test_select_exits_parses_exit_file_with_comments_and_bom(args, tmp_path, caplog):
    fp1 = "50485e03ca39d393bd54d315ceba65e6dd0fddb9"
    fp2 = "FAF0A8829E39063669FA609B904E0FB8D5E1F23F"
    exit_file = tmp_path / "exits.txt"
    exit_file.write_bytes((
        "\ufeff# header comment\n"
        "\n"
        "  $%s  # inline comment\n"
        "not-a-fingerprint\n"
        "%s\n"
        "%s\n" % (fp1, fp1.upper(), fp2)
    ).encode("utf-8"))

    file_args = argparse.Namespace(**vars(args))
    file_args.exit = None
    file_args.exit_file = str(exit_file)

    with patch.object(exitmap, "lookup_destinations", return_value=set()), \
         patch.object(exitmap.relayselector, "get_exits", return_value={}) as mock_get:
        exitmap.select_exits(file_args, types.SimpleNamespace(destinations=None))

    assert mock_get.call_args.kwargs["requested_exits"] == [fp1.upper(), fp2]
    assert 'Ignoring invalid relay fingerprint "not-a-fingerprint"' in caplog.text
    assert "header comment" not in caplog.text


def test_normalize_fingerprint_rejects_empty_and_prefix_or_non_hex_tricks():
    for bad in ("", "   ", "short", "0x" + "A" * 38, "+" + "A" * 39,
                "A" * 19 + "_" + "A" * 20, "G" * 40, "\uff10" * 40):
        assert exitmap._normalize_fingerprint(bad) is None


def test_select_exits_rejects_empty_and_invalid_inputs(args, tmp_path):
    empty_file = tmp_path / "empty.txt"
    empty_file.write_text("# comment only\n   \n\n")

    file_args = argparse.Namespace(**vars(args))
    file_args.exit = None
    file_args.exit_file = str(empty_file)

    with patch.object(exitmap, "lookup_destinations", return_value=set()):
        with pytest.raises(SystemExit) as exc:
            exitmap.select_exits(file_args, types.SimpleNamespace(destinations=None))
    assert exc.value.code == 1

    for bad_exit in ("", "invalid-fp", "0x" + "A" * 38):
        bad_args = argparse.Namespace(**vars(args))
        bad_args.exit = bad_exit
        with patch.object(exitmap, "lookup_destinations", return_value=set()):
            with pytest.raises(SystemExit) as exc:
                exitmap.select_exits(bad_args, types.SimpleNamespace(destinations=None))
        assert exc.value.code == 1


def test_main_validates_fingerprints_before_tor_bootstrap(args):
    for bad_exit in ("", "not-valid"):
        bad_exit_args = argparse.Namespace(**vars(args))
        bad_exit_args.tor_dir = None
        bad_exit_args.exit = bad_exit

        with patch.object(exitmap, "parse_cmd_args", return_value=bad_exit_args), \
             patch.object(exitmap, "bootstrap_tor") as mock_boot:
            with pytest.raises(SystemExit) as exc:
                exitmap.main()
        assert exc.value.code == 1
        mock_boot.assert_not_called()

    bad_exit_file_args = argparse.Namespace(**vars(args))
    bad_exit_file_args.tor_dir = None
    bad_exit_file_args.exit = None
    bad_exit_file_args.exit_file = ""
    with patch.object(exitmap, "parse_cmd_args", return_value=bad_exit_file_args), \
         patch.object(exitmap, "bootstrap_tor") as mock_boot:
        with pytest.raises(SystemExit) as exc:
            exitmap.main()
    assert exc.value.code == 1
    mock_boot.assert_not_called()

    for bad_first in ("", "bad-first-hop", "+" + "A" * 39):
        bad_first_args = argparse.Namespace(**vars(args))
        bad_first_args.tor_dir = None
        bad_first_args.first_hop = bad_first

        with patch.object(exitmap, "parse_cmd_args", return_value=bad_first_args), \
             patch.object(exitmap, "bootstrap_tor") as mock_boot:
            assert exitmap.main() == 1
        mock_boot.assert_not_called()


def test_main_normalizes_first_hop_and_passes_requested_exits(args, tmp_path):
    parent_dir = tmp_path / "run"
    parent_dir.mkdir(mode=0o700)
    os.chmod(parent_dir, 0o700)
    tor_dir = parent_dir / "tor"

    run_args = argparse.Namespace(**vars(args))
    run_args.tor_dir = str(tor_dir)
    run_args.first_hop = "$%s" % args.first_hop.lower()
    run_args.exit = args.exit.lower()
    mock_ctrl = Mock()
    mock_ctrl.is_alive.return_value = True

    prev_umask = os.umask(0o077)
    os.umask(prev_umask)
    stem_logger = exitmap.logging.getLogger("stem")
    prev_level = stem_logger.level
    try:
        with patch.object(exitmap, "parse_cmd_args", return_value=run_args), \
             patch.object(exitmap, "bootstrap_tor", return_value=(9050, 9051)), \
             patch.object(exitmap.Controller, "from_port", return_value=mock_ctrl), \
             patch.object(exitmap.stem.connection, "authenticate"), \
             patch.object(exitmap.util, "relay_in_consensus", return_value=True), \
             patch.object(exitmap, "run_module") as mock_run:
            assert exitmap.main() == 0
    finally:
        os.umask(prev_umask)
        stem_logger.setLevel(prev_level)

    assert run_args.first_hop == args.first_hop.upper()
    assert mock_run.call_args.kwargs["requested_exits"] == [args.exit.upper()]
    mock_ctrl.close.assert_called_once()


def test_parse_cmd_args_config_booleans(tmp_path, monkeypatch, caplog):
    cfg = tmp_path / "exitmaprc"
    cfg.write_text("[Defaults]\nbad_exits = false\nall_exits = true\n")
    monkeypatch.setattr(sys, "argv", ["exitmap", "-f", str(cfg), "checktest"])
    parsed = exitmap.parse_cmd_args()
    assert parsed.bad_exits is False
    assert parsed.all_exits is True

    bad_cfg = tmp_path / "bad_exitmaprc"
    bad_cfg.write_text("[Defaults]\nbad_exits = maybe\n")
    monkeypatch.setattr(
        sys, "argv", ["exitmap", "-f", str(bad_cfg), "checktest"]
    )
    parsed_bad = exitmap.parse_cmd_args()
    assert parsed_bad.bad_exits is False
    assert 'Invalid boolean for "bad_exits"' in caplog.text


def test_parse_cmd_args_reliable_first_hop_and_config_conflict(
        tmp_path, monkeypatch, caplog):
    cfg = tmp_path / "exitmaprc"
    cfg.write_text("[Defaults]\nreliable_first_hop = false\n")
    monkeypatch.setattr(sys, "argv", [
        "exitmap.py", "-f", str(cfg), "checktest",
    ])
    parsed = exitmap.parse_cmd_args()
    assert parsed.reliable_first_hop is False
    assert parsed.first_hop is None

    cfg.write_text("[Defaults]\nreliable_first_hop = true\n")
    parsed_true = exitmap.parse_cmd_args()
    assert parsed_true.reliable_first_hop is True
    assert parsed_true.first_hop is None

    # CLI -i overrides reliable_first_hop = true from config.
    monkeypatch.setattr(sys, "argv", [
        "exitmap.py", "-f", str(cfg), "-i", "B" * 40, "checktest",
    ])
    parsed_cli_first = exitmap.parse_cmd_args()
    assert parsed_cli_first.first_hop == "B" * 40
    assert parsed_cli_first.reliable_first_hop is False

    # CLI --reliable-first-hop overrides first_hop from config.
    cfg.write_text("[Defaults]\nfirst_hop = %s\n" % ("A" * 40))
    monkeypatch.setattr(sys, "argv", [
        "exitmap.py", "-f", str(cfg), "--reliable-first-hop", "checktest",
    ])
    parsed_cli_rel = exitmap.parse_cmd_args()
    assert parsed_cli_rel.reliable_first_hop is True
    assert parsed_cli_rel.first_hop is None

    # Setting both in config triggers mutual-exclusion parser error.
    cfg.write_text(
        "[Defaults]\nfirst_hop = %s\nreliable_first_hop = true\n" % ("A" * 40)
    )
    monkeypatch.setattr(sys, "argv", ["exitmap.py", "-f", str(cfg), "checktest"])
    with pytest.raises(SystemExit):
        exitmap.parse_cmd_args()

    # Invalid boolean logs warning and falls back to False.
    cfg.write_text("[Defaults]\nreliable_first_hop = invalid\n")
    parsed_bad = exitmap.parse_cmd_args()
    assert parsed_bad.reliable_first_hop is False
    assert 'Invalid boolean for "reliable_first_hop"' in caplog.text

    monkeypatch.setattr(sys, "argv", [
        "exitmap.py", "-f", str(cfg), "--first-hop", "A" * 40,
        "--reliable-first-hop", "checktest",
    ])
    with pytest.raises(SystemExit):
        exitmap.parse_cmd_args()


def test_iter_exit_relays_reliable_first_hop(args, stats_obj):
    run_args = argparse.Namespace(**vars(args))
    run_args.first_hop = None
    run_args.reliable_first_hop = True
    mock_ctrl = Mock()
    guards = ["G" * 40, "H" * 40]

    with patch.object(exitmap.relayselector, "get_fingerprints",
                      return_value=guards) as mock_fps, \
         patch.object(exitmap, "sleep"):
        exitmap.iter_exit_relays(["E" * 40], mock_ctrl, stats_obj, run_args)

    mock_fps.assert_called_once_with(
        os.path.join(run_args.tor_dir, "cached-consensus"),
        include_flags={
            stem.Flag.GUARD, stem.Flag.STABLE, stem.Flag.FAST,
            stem.Flag.RUNNING, stem.Flag.VALID,
        },
        exclude_flags={stem.Flag.BADEXIT},
        min_bandwidth_kb=5000,
        require_measured_relays=True,
    )
    hops = mock_ctrl.new_circuit.call_args.args[0]
    assert hops[0] in guards
    assert hops[1] == "E" * 40


def test_iter_exit_relays_static_first_hop_skips_consensus(args, stats_obj):
    run_args = argparse.Namespace(**vars(args))
    run_args.reliable_first_hop = True
    mock_ctrl = Mock()

    with patch.object(exitmap.relayselector, "get_fingerprints") as mock_fps, \
         patch.object(exitmap, "sleep"):
        exitmap.iter_exit_relays(["E" * 40], mock_ctrl, stats_obj, run_args)

    mock_fps.assert_not_called()
    mock_ctrl.new_circuit.assert_called_once_with([run_args.first_hop, "E" * 40])


def test_iter_exit_relays_reliable_first_hop_fallback(args, stats_obj, caplog):
    run_args = argparse.Namespace(**vars(args))
    run_args.first_hop = None
    run_args.reliable_first_hop = True
    mock_ctrl = Mock()
    fallback = ["A" * 40, "B" * 40]

    with patch.object(exitmap.relayselector, "get_fingerprints",
                      side_effect=[["1" * 40], fallback]) as mock_fps, \
         patch.object(exitmap, "sleep"):
        exitmap.iter_exit_relays(["E" * 40], mock_ctrl, stats_obj, run_args)

    assert mock_fps.call_count == 2
    assert "falling back to unfiltered first-hop selection" in caplog.text


def test_iter_exit_relays_raises_when_no_first_hop_candidates(args, stats_obj):
    run_args = argparse.Namespace(**vars(args))
    run_args.first_hop = None
    run_args.reliable_first_hop = False
    exit_fp = "E" * 40
    mock_ctrl = Mock()

    with patch.object(exitmap.relayselector, "get_fingerprints",
                      return_value=[exit_fp]):
        with pytest.raises(error.ExitSelectionError):
            exitmap.iter_exit_relays([exit_fp], mock_ctrl, stats_obj, run_args)


def test_iter_exit_relays_dedupes_consensus_fingerprints(args, stats_obj):
    run_args = argparse.Namespace(**vars(args))
    run_args.first_hop = None
    run_args.reliable_first_hop = False
    exit_fp = "E" * 40
    guard_fp = "G" * 40
    mock_ctrl = Mock()

    with patch.object(exitmap.relayselector, "get_fingerprints",
                      return_value=[exit_fp, exit_fp, guard_fp]), \
         patch.object(exitmap, "sleep"):
        exitmap.iter_exit_relays([exit_fp], mock_ctrl, stats_obj, run_args)

    mock_ctrl.new_circuit.assert_called_once_with([guard_fp, exit_fp])
