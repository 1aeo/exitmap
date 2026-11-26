import argparse
import subprocess
import sys
import time
from unittest.mock import Mock
import warnings

import pytest
# hacky, until exitmap is an installable package
sys.path.insert(0, 'src/')  # noqa
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


def test_parse_cmd_args_config_booleans(tmp_path, monkeypatch):
    config_file = tmp_path / "exitmaprc"
    config_file.write_text("[Defaults]\nbad_exits = false\nall_exits = true\n")
    monkeypatch.setattr(
        sys, "argv", ["exitmap.py", "-f", str(config_file), "checktest"]
    )
    parsed_args = exitmap.parse_cmd_args()
    assert parsed_args.bad_exits is False
    assert parsed_args.all_exits is True

    config_file.write_text("[Defaults]\nbad_exits = foo\n")
    with pytest.raises(SystemExit):
        exitmap.parse_cmd_args()


def test_select_exits(args, modules):
    for module in ["checktest"]:  # modules:
        exits = exitmap.select_exits(args, modules)
        # {'50485E03CA39D393BD54D315CEBA65E6DD0FDDB9':
        # frozenset({('93.184.215.14', 8000)})}
        assert 1 == len(exits)
        dest = exits['50485E03CA39D393BD54D315CEBA65E6DD0FDDB9']
        list_destinations = list(dest)  # list cause dest is frozenset
        assert 8000 == list_destinations[0][1]  # [("host", port),]


def test_select_exits_lowercase_fingerprints(args, modules, tmp_path):
    fingerprint = args.exit
    exit_file = tmp_path / "exits"
    exit_file.write_text(fingerprint.lower() + "\n")
    args_exit = dict(vars(args), exit=fingerprint.lower())
    args_exit_file = dict(vars(args), exit=None, exit_file=str(exit_file))
    for lowercase_args in [args_exit, args_exit_file]:
        exits = exitmap.select_exits(
            argparse.Namespace(**lowercase_args), modules
        )
        assert [fingerprint] == list(exits)


def test_iter_exit_relays(exit_relays, controller, stats_obj, args, caplog):
    exitmap.iter_exit_relays(exit_relays, controller, stats_obj, args)
    log_info_expected = "Done triggering circuit creations after"
    assert log_info_expected in caplog.text


def test_iter_exit_relays_controller_not_alive(stats_obj, args):
    controller = Mock()
    controller.is_alive.return_value = False
    exitmap.iter_exit_relays([args.exit], controller, stats_obj, args)
    controller.new_circuit.assert_not_called()


def test_iter_exit_relays_remembers_circuits(stats_obj, args):
    hops = [args.first_hop, args.exit]
    controller = Mock()
    controller.new_circuit.return_value = "23"
    exitmap.iter_exit_relays([args.exit], controller, stats_obj, args)
    assert {"23": hops} == stats_obj.pending_circuits

    controller.new_circuit.side_effect = exitmap.stem.ControllerError("foo")
    exitmap.iter_exit_relays([args.exit], controller, stats_obj, args)
    assert {
        args.exit: {"first_hop": args.first_hop,
                    "reason": "CREATION_FAILED (foo)"}
    } == stats_obj.failed_circuit_relays


def test_sleep(args):
    start = time.monotonic()
    exitmap.sleep(args.build_delay, args.delay_noise)
    stop = time.monotonic()
    delta = stop - start
    assert delta != 3
    assert delta > 3


def test_bin_exitmap_exit_status(tmp_path, monkeypatch):
    tor_dir = tmp_path / "tor"
    cmd = [sys.executable, "bin/exitmap", "-t", str(tor_dir), "checktest"]
    # main() calls sys.exit(1), since there is no tor executable.
    monkeypatch.setenv("PATH", "")
    assert 1 == subprocess.run(cmd).returncode
    assert not tor_dir.exists()
    # main() returns 1, since other users can access the parent of Tor's data
    # directory, see #47.
    tmp_path.chmod(0o755)
    assert 1 == subprocess.run(cmd).returncode
    assert not tor_dir.exists()
