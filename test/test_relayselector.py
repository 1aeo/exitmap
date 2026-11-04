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


if __name__ == '__main__':
    unittest.main()
