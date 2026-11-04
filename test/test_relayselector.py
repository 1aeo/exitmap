#!/usr/bin/env python3

# Copyright 2016-2020 Philipp Winter <phw@nymity.ch>
# Copyright 2021 The Tor Project, Inc.
#
# This file is part of exitmap.
#
# exitmap is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# exitmap is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with exitmap.  If not, see <http://www.gnu.org/licenses/>.
""" Unit tests for the relay selector module."""

import unittest
import sys
sys.path.insert(0, 'src/')
import relayselector
from stem import exit_policy


class TestRelaySelector(unittest.TestCase):
    """Test the torsocks module."""

    def test_get_exits(self):
        with self.assertRaises(SystemExit) as exits:
            relayselector.get_exits('/tmp',
                                    good_exit=True,
                                    bad_exit=True,
                                    version=None,
                                    nickname=None,
                                    address=None,
                                    country_code='at',
                                    requested_exits=None,
                                    destinations=None)
        self.assertEqual(exits.exception.code, 1)


def test_get_exit_policies(cached_descriptors_path):
    exit_policies = relayselector.get_exit_policies(cached_descriptors_path)
    assert isinstance(
        exit_policies["9C67E543354ED18B7FF00E080AC086762035119C"].exit_policy,
        exit_policy.ExitPolicy
    )
    assert not exit_policies.get(
        "FAF0A8829E39063669FA609B904E0FB8D5E1F23F",
        None
    )


def test_get_cached_consensus(cached_consensus_path):
    cc = relayselector.get_cached_consensus(cached_consensus_path)
    assert isinstance(cc, dict)
    assert 7587 == len(cc)


def test_get_fingerprints(cached_consensus_path):
    fps = relayselector.get_fingerprints(cached_consensus_path, exclude=[])
    assert isinstance(fps, list)
    assert 7587 == len(fps)


def test_router_statuses_with_exit_flag(cached_consensus):
    rs = relayselector.router_statuses_with_exit_flag(cached_consensus)
    assert isinstance(rs, dict)
    assert 2297 == len(rs)


# torexitbsd2: Exit and BadExit in the test consensus.
# AccessNow007: Exit, not BadExit.
_BAD_EXIT = "052848D49E213DE9F85C8721E138DAABA2DE08C8"
_GOOD_EXIT = "0516085D6CAC40ED4CDCEFDFC5CCF6B00DE61DED"
_ABSENT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def test_exit_file_without_all_exits_skips_badexit(tor_dir):
    """A BadExit in the target file is dropped, with an explicit reason."""
    skipped = {}
    selected = relayselector.get_exits(
        tor_dir,
        good_exit=True,
        bad_exit=False,
        requested_exits=[_BAD_EXIT, _GOOD_EXIT, _ABSENT],
        destinations=None,
        skipped=skipped,
    )
    assert _GOOD_EXIT in selected
    assert _BAD_EXIT not in selected
    assert skipped[_BAD_EXIT] == "bad_exit"
    assert skipped[_ABSENT] == "not_in_consensus"


def test_non_fingerprint_request_is_ignored(tor_dir):
    """A path-like exit-file line is not selected and not reported."""
    skipped = {}
    selected = relayselector.get_exits(
        tor_dir, good_exit=True, bad_exit=True,
        requested_exits=["../OUTSIDE", _BAD_EXIT],
        destinations=None, skipped=skipped)
    assert "../OUTSIDE" not in selected
    assert "../OUTSIDE" not in skipped
    assert _BAD_EXIT in selected or skipped.get(_BAD_EXIT) == "bad_exit"


def test_empty_requested_list_selects_nothing(tor_dir):
    """An empty exit file must not fall through to scanning every exit."""
    selected = relayselector.get_exits(
        tor_dir, good_exit=True, bad_exit=False,
        requested_exits=[], destinations=None, skipped={})
    assert selected == {}


def test_relay_in_consensus_without_exit_flag_is_not_exit(tor_dir):
    import os
    import stem
    import stem.descriptor
    non_exit = None
    for desc in stem.descriptor.parse_file(os.path.join(tor_dir, "cached-consensus")):
        if stem.Flag.EXIT not in desc.flags:
            non_exit = desc.fingerprint
            break
    skipped = {}
    relayselector.get_exits(
        tor_dir, good_exit=True, bad_exit=True,
        requested_exits=[non_exit], destinations=None, skipped=skipped)
    assert skipped[non_exit] == "not_exit"


def test_all_exits_includes_badexit_without_exit_flag(tor_dir):
    """A BadExit relay with an exit policy but no EXIT flag is still scanned."""
    fp = "0082C49022C0811D45620D408E068835E2BABA71"
    skipped = {}
    selected = relayselector.get_exits(
        tor_dir, good_exit=True, bad_exit=True,
        requested_exits=[fp], destinations=None, skipped=skipped)
    assert fp in selected
    assert fp not in skipped


def test_all_exits_keeps_badexit_in_the_target_file(tor_dir):
    """--all-exits together with an exit file scans the BadExit relay."""
    skipped = {}
    selected = relayselector.get_exits(
        tor_dir,
        good_exit=True,
        bad_exit=True,
        requested_exits=[_BAD_EXIT, _GOOD_EXIT],
        destinations=None,
        skipped=skipped,
    )
    assert _BAD_EXIT in selected
    assert _GOOD_EXIT in selected
    assert skipped == {}


if __name__ == '__main__':
    unittest.main()
