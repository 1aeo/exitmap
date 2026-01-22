#!/usr/bin/env python3

# Copyright 2015-2020 Philipp Winter <phw@nymity.ch>
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
"""
Implements unit tests.
"""

import unittest
import stem.control
from stem import CircStatus
import sys
sys.path.insert(0, 'src/')
import stats


class TestStats(unittest.TestCase):
    """Test the stats module."""

    def setUp(self):
        self.stats = stats.Statistics()

    def test_stats(self):
        self.stats.print_progress(sampling=0)
        self.stats.print_progress
        self.assertTrue(str(self.stats))

        circ_event = stem.response.events.CircuitEvent("foo", "bar")
        circ_event.id = "123"
        circ_event.status = CircStatus.FAILED
        circ_event.reason = "foo"

        self.stats.update_circs(circ_event)
        self.assertEqual(self.stats.failed_circuits, 1)

        circ_event.status = CircStatus.BUILT

        self.stats.update_circs(circ_event)
        self.assertEqual(self.stats.successful_circuits, 1)


def test_stats_print_progress(caplog, stats_obj):
    stats_obj.total_circuits = 1
    stats_obj.finished_streams = 1
    stats_obj.print_progress(1)
    print(stats_obj.__dict__)
    assert (
        "Probed 0 out of 1 exit relays, so we are 0.00% done." in caplog.text
    )


def test_stats_str(stats_obj):
    s = str(stats_obj)
    assert " and 0/0 circuits failed (0.00%)." in s


if __name__ == '__main__':
    unittest.main()
