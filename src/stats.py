# Copyright 2013-2020 Philipp Winter <phw@nymity.ch>
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
Provides functions to keep track of scanning statistics.
"""

import logging
import threading
from datetime import datetime

from stem import CircStatus

log = logging.getLogger(__name__)


class Statistics(object):

    """
    Keep track of scanning statistics.
    """

    def __init__(self):
        """
        Initialise a Statistics object.
        """

        self.start_time = datetime.now()
        self.total_circuits = 0
        self.failed_circuits = 0
        self.successful_circuits = 0
        self.modules_run = 0
        self.finished_streams = 0
        self.failed_streams = 0
        self.failed_circuit_relays = {}
        self._pending_circuits = {}
        self._early_failed = {}
        self._early_closed = {}
        self._early_built = set()
        self._resolved_cids = set()
        self._lock = threading.Lock()

    def reset_failed_circuits(self):
        """
        Reset per-module failed-circuit tracking state before a scan.

        :returns: ``None``
        """
        with self._lock:
            self.failed_circuit_relays.clear()
            self._pending_circuits.clear()
            self._early_failed.clear()
            self._early_closed.clear()
            self._early_built.clear()
            self._resolved_cids.clear()

    def register_circuit(self, circuit_id, first_hop, exit_relay):
        """
        Register an intended circuit path so failures can be attributed.

        :param str circuit_id: circuit ID returned by controller.new_circuit()
        :param str first_hop: fingerprint of the first-hop relay
        :param str exit_relay: fingerprint of the exit relay
        """
        cid = str(circuit_id)
        with self._lock:
            if cid in self._early_built:
                self._early_built.discard(cid)
            elif cid in self._early_failed:
                reason_str = self._early_failed.pop(cid)
                self.failed_circuit_relays[exit_relay] = {
                    "reason": reason_str,
                    "first_hop": first_hop,
                }
            elif cid in self._early_closed:
                reason_str = self._early_closed.pop(cid)
                self.failed_circuits += 1
                self.failed_circuit_relays[exit_relay] = {
                    "reason": reason_str,
                    "first_hop": first_hop,
                }
            else:
                self._pending_circuits[cid] = (first_hop, exit_relay)

    def record_immediate_failure(self, first_hop, exit_relay, err):
        """
        Record a circuit creation failure raised before a circuit ID exists.

        :param str first_hop: fingerprint of the intended first-hop relay
        :param str exit_relay: fingerprint of the intended exit relay
        :param Exception err: exception raised by Stem
        """
        with self._lock:
            self.failed_circuits += 1
            self.failed_circuit_relays[exit_relay] = {
                "reason": "CREATION_FAILED (%s)" % err,
                "first_hop": first_hop,
            }

    def update_circs(self, circ_event):
        """
        Update statistics and per-relay failure records from a circuit event.

        :param stem.response.events.CircuitEvent circ_event: circuit event
        """
        raw_id = getattr(circ_event, "id", None)
        cid = str(raw_id) if raw_id is not None else None

        if circ_event.status in [CircStatus.FAILED]:
            reason_str = str(circ_event.reason) if circ_event.reason else "UNKNOWN"
            log.debug("Circuit failed because: %s", reason_str)
            with self._lock:
                self.failed_circuits += 1
                if cid is not None:
                    self._resolved_cids.add(cid)
                pending = (
                    self._pending_circuits.pop(cid, None)
                    if cid is not None else None
                )
                if pending is not None:
                    first_hop, exit_relay = pending
                    self.failed_circuit_relays[exit_relay] = {
                        "reason": reason_str,
                        "first_hop": first_hop,
                    }
                elif cid is not None:
                    self._early_failed[cid] = reason_str

        elif circ_event.status in [CircStatus.BUILT]:
            with self._lock:
                self.successful_circuits += 1
                if cid is not None:
                    self._resolved_cids.add(cid)
                    if self._pending_circuits.pop(cid, None) is None:
                        self._early_built.add(cid)

        elif circ_event.status in [CircStatus.CLOSED]:
            if cid is not None:
                with self._lock:
                    pending = self._pending_circuits.pop(cid, None)
                    reason_str = (
                        str(circ_event.reason)
                        if getattr(circ_event, "reason", None)
                        else "CLOSED"
                    )
                    if pending is not None:
                        self._resolved_cids.add(cid)
                        first_hop, exit_relay = pending
                        self.failed_circuits += 1
                        self.failed_circuit_relays[exit_relay] = {
                            "reason": reason_str,
                            "first_hop": first_hop,
                        }
                    elif cid not in self._resolved_cids:
                        self._resolved_cids.add(cid)
                        self._early_closed[cid] = reason_str

    def log_failed_circuits(self):
        """
        Log exit relay fingerprints whose circuits failed during the scan.

        :returns: ``None``
        """
        with self._lock:
            failed = dict(self.failed_circuit_relays)
            unresolved_count = len(self._early_failed)

        if failed:
            log.info("Failed to build circuits for %d exit relay(s):",
                     len(failed))
            for exit_fpr, info in failed.items():
                log.info("  %s (first hop: %s, reason: %s)",
                         exit_fpr, info["first_hop"], info["reason"])

        if unresolved_count:
            log.debug("%d failed circuit(s) had no registered exit fingerprint.",
                      unresolved_count)

    def print_progress(self, sampling=50):
        """
        Print statistics about ongoing probing process.
        """

        if (sampling == 0) or (self.finished_streams % sampling):
            return

        if self.total_circuits == 0:
            return

        percent_done = (self.successful_circuits
                        / float(self.total_circuits)) * 100

        log.info("Probed %d out of %d exit relays, so we are %.2f%% done.",
                 self.successful_circuits, self.total_circuits, percent_done)

    def __str__(self):
        """
        Print the gathered statistics.
        """

        percent = 0
        if self.total_circuits > 0:
            percent = (self.failed_circuits / float(self.total_circuits)) * 100

        return ("Ran %d module(s) in %s and %d/%d circuits failed (%.2f%%)." %
                (self.modules_run,
                 str(datetime.now() - self.start_time),
                 self.failed_circuits,
                 self.total_circuits,
                 percent))
