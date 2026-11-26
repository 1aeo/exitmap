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


def _make_circ_event(cid, status, reason=None):
    circ_event = stem.response.events.CircuitEvent("foo", "bar")
    circ_event.id = cid
    circ_event.status = status
    circ_event.reason = reason
    return circ_event


def test_register_and_failed_circuit(stats_obj):
    first_hop = "F" * 40
    exit_relay = "E" * 40
    stats_obj.register_circuit("42", first_hop, exit_relay)
    assert stats_obj._pending_circuits["42"] == (first_hop, exit_relay)

    stats_obj.update_circs(_make_circ_event("42", CircStatus.FAILED, "TIMEOUT"))

    assert stats_obj.failed_circuits == 1
    assert "42" not in stats_obj._pending_circuits
    assert stats_obj.failed_circuit_relays[exit_relay] == {
        "reason": "TIMEOUT",
        "first_hop": first_hop,
    }


def test_built_and_early_built_circuits(stats_obj):
    stats_obj.register_circuit("7", "F" * 40, "E" * 40)
    stats_obj.update_circs(_make_circ_event("7", CircStatus.BUILT))
    stats_obj.update_circs(_make_circ_event("7", CircStatus.CLOSED, "FINISHED"))

    stats_obj.update_circs(_make_circ_event("8", CircStatus.BUILT))
    stats_obj.register_circuit("8", "F" * 40, "G" * 40)

    assert stats_obj.successful_circuits == 2
    assert stats_obj.failed_circuits == 0
    assert stats_obj._pending_circuits == {}
    assert stats_obj._early_built == set()
    assert stats_obj.failed_circuit_relays == {}


def test_closed_prior_to_build_records_failure(stats_obj):
    first_hop = "F" * 40
    exit_relay = "E" * 40
    stats_obj.register_circuit("55", first_hop, exit_relay)
    stats_obj.update_circs(_make_circ_event("55", CircStatus.CLOSED, "DESTROYED"))

    assert stats_obj.failed_circuits == 1
    assert stats_obj._pending_circuits == {}
    assert stats_obj.failed_circuit_relays[exit_relay] == {
        "reason": "DESTROYED",
        "first_hop": first_hop,
    }


def test_early_closed_before_register_and_stray_closed(stats_obj):
    first_hop = "F" * 40
    exit_relay = "E" * 40

    # Stray circuit CLOSED never registered must not increment failed_circuits.
    stats_obj.update_circs(_make_circ_event("60", CircStatus.CLOSED, "NONE"))
    assert stats_obj.failed_circuits == 0
    assert stats_obj.failed_circuit_relays == {}

    # Exitmap circuit CLOSED before register_circuit() resolves once registered.
    stats_obj.update_circs(
        _make_circ_event("61", CircStatus.CLOSED, "DESTROYED")
    )
    stats_obj.register_circuit("61", first_hop, exit_relay)
    assert stats_obj.failed_circuits == 1
    assert stats_obj.failed_circuit_relays[exit_relay] == {
        "reason": "DESTROYED",
        "first_hop": first_hop,
    }

    # Early BUILT followed by CLOSED before register must not count as failed.
    stats_obj.update_circs(_make_circ_event("62", CircStatus.BUILT))
    stats_obj.update_circs(_make_circ_event("62", CircStatus.CLOSED, "FINISHED"))
    stats_obj.register_circuit("62", first_hop, "D" * 40)
    assert stats_obj.successful_circuits == 1
    assert stats_obj.failed_circuits == 1
    assert "D" * 40 not in stats_obj.failed_circuit_relays


def test_early_failed_event_resolved_on_register(stats_obj):
    first_hop = "F" * 40
    exit_relay = "E" * 40
    stats_obj.update_circs(
        _make_circ_event("99", CircStatus.FAILED, "CONNECTFAILED")
    )
    assert stats_obj._early_failed == {"99": "CONNECTFAILED"}

    stats_obj.register_circuit("99", first_hop, exit_relay)

    assert stats_obj._early_failed == {}
    assert stats_obj.failed_circuit_relays[exit_relay] == {
        "reason": "CONNECTFAILED",
        "first_hop": first_hop,
    }


def test_record_immediate_failure_and_log_and_reset(stats_obj, caplog):
    first_hop = "F" * 40
    exit_fail = "E" * 40
    exit_imm = "D" * 40
    stats_obj.register_circuit("10", first_hop, exit_fail)
    stats_obj.update_circs(_make_circ_event("10", CircStatus.FAILED, "TIMEOUT"))
    stats_obj.update_circs(_make_circ_event("11", CircStatus.FAILED, "NOPATH"))
    stats_obj.record_immediate_failure(first_hop, exit_imm, stem.ControllerError("No path"))

    with caplog.at_level("DEBUG"):
        stats_obj.log_failed_circuits()

    assert "Failed to build circuits for 2 exit relay(s):" in caplog.text
    assert "%s (first hop: %s, reason: TIMEOUT)" % (exit_fail, first_hop) in caplog.text
    assert "%s (first hop: %s, reason: CREATION_FAILED (No path))" % (exit_imm, first_hop) in caplog.text
    assert "1 failed circuit(s) had no registered exit fingerprint." in caplog.text

    stats_obj.reset_failed_circuits()
    assert stats_obj.failed_circuit_relays == {}
    assert stats_obj._pending_circuits == {}
    assert stats_obj._early_failed == {}


if __name__ == '__main__':
    unittest.main()
