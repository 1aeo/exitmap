import argparse
import importlib.machinery
import importlib.util
import os
import sys
import time
from unittest.mock import patch
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
