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
from datetime import datetime

from stem import CircStatus

log = logging.getLogger(__name__)

# Mapping from Tor circuit failure reasons to friendly JSON keys and error messages
# Reference: https://spec.torproject.org/control-spec/replies.html#circuit-status-changed
CIRCUIT_FAILURE_MAP = {
    # Circuit construction failures
    "TIMEOUT": ("circuit_timeout", "Tor Circuit Error: Construction timed out"),
    "CONNECTFAILED": ("relay_connect_failed", "Tor Circuit Error: Could not connect to relay"),
    "NOPATH": ("circuit_no_path", "Tor Circuit Error: No path available"),
    
    # Relay resource/status issues
    "RESOURCELIMIT": ("relay_resource_limit", "Tor Circuit Error: Relay at capacity"),
    "HIBERNATING": ("relay_hibernating", "Tor Circuit Error: Relay is hibernating"),
    
    # Circuit closed/destroyed
    "DESTROYED": ("circuit_destroyed", "Tor Circuit Error: Circuit was closed"),
    "FINISHED": ("circuit_finished", "Tor Circuit Error: Circuit finished normally"),
    
    # Connection issues
    "OR_CONN_CLOSED": ("relay_connection_closed", "Tor Circuit Error: Connection to relay closed"),
    "CHANNEL_CLOSED": ("channel_closed", "Tor Circuit Error: Relay channel closed unexpectedly"),
    "IOERROR": ("io_error", "Tor Circuit Error: I/O error on connection"),
    
    # Protocol/internal errors
    "TORPROTOCOL": ("tor_protocol_error", "Tor Circuit Error: Protocol violation"),
    "INTERNAL": ("tor_internal_error", "Tor Circuit Error: Internal error"),
    "REQUESTED": ("circuit_requested", "Tor Circuit Error: Circuit close requested"),
    "NOSUCHSERVICE": ("no_such_service", "Tor Circuit Error: Hidden service not found"),
    
    # Measurement/guard issues  
    "MEASUREMENT_EXPIRED": ("measurement_expired", "Tor Circuit Error: Measurement expired"),
    "GUARD_LIMIT_REACHED": ("guard_limit", "Tor Circuit Error: Guard circuit limit reached"),
}


def get_circuit_failure_info(reason):
    """
    Convert Tor circuit failure reason to JSON key and friendly error message.
    """
    reason_str = str(reason).upper() if reason else "UNKNOWN"
    if reason_str in CIRCUIT_FAILURE_MAP:
        return CIRCUIT_FAILURE_MAP[reason_str]
    return ("circuit_failed", "Tor Circuit Error: Unknown failure (%s)" % reason_str)


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
        # Track failed circuit details: {exit_fingerprint: {...}}
        self.failed_circuit_relays = {}
        # Circuit registry: {circuit_id: {"first_hop": fpr, "exit_relay": fpr, "timestamp": ...}}
        # This allows us to know the intended path even when Tor doesn't report it on failure
        self.pending_circuits = {}

    def register_circuit(self, circuit_id, first_hop, exit_relay):
        """
        Register a circuit we're about to create, so we can track failures.
        
        Args:
            circuit_id: The circuit ID returned by controller.new_circuit()
            first_hop: Fingerprint of the first hop (guard) relay
            exit_relay: Fingerprint of the exit relay
        """
        cid = str(circuit_id)  # Normalize to string for consistent lookup
        self.pending_circuits[cid] = {
            "first_hop": first_hop,
            "exit_relay": exit_relay,
            "timestamp": datetime.now().timestamp()
        }
        log.debug("Registered circuit %s: %s -> %s" % (cid, first_hop[:8], exit_relay[:8]))
        if len(self.pending_circuits) % 100 == 0:
            log.info("Circuit registry: %d circuits registered" % len(self.pending_circuits))

    def resolve_circuit(self, circuit_id):
        """
        Look up the intended path for a circuit by its ID.
        
        Returns:
            Tuple of (first_hop, exit_relay) or (None, None) if not found
        """
        info = self.pending_circuits.get(str(circuit_id))
        return (info["first_hop"], info["exit_relay"]) if info else (None, None)

    def complete_circuit(self, circuit_id):
        """Remove a circuit from the pending registry (it completed or failed)."""
        self.pending_circuits.pop(str(circuit_id), None)  # pop with default avoids KeyError check

    def record_immediate_failure(self, first_hop, exit_relay, error_str):
        """
        Record a circuit that failed immediately (before getting a circuit_id).
        This happens when controller.new_circuit() throws an exception.
        """
        self.failed_circuits += 1
        self.failed_circuit_relays[exit_relay] = {
            "reason_key": "circuit_creation_failed",
            "error": "Tor Circuit Error: Failed to create circuit (%s)" % error_str,
            "tor_reason": "CREATION_FAILED",
            "first_hop": first_hop,
            "timestamp": datetime.now().timestamp()
        }
        log.debug("Recorded immediate circuit failure for %s: %s" % (exit_relay[:8], error_str))

    def update_circs(self, circ_event):
        """
        Update statistics with the given circuit event.
        Uses the circuit registry to get the intended path.
        """
        cid = str(circ_event.id)
        status = circ_event.status

        if status == CircStatus.FAILED:
            log.debug("Circuit %s failed: %s" % (cid, circ_event.reason))
            self.failed_circuits += 1
            
            first_hop, exit_relay = self.resolve_circuit(cid)
            reason_key, error_msg = get_circuit_failure_info(circ_event.reason)
            
            if exit_relay:
                self.failed_circuit_relays[exit_relay] = {
                    "reason_key": reason_key,
                    "error": error_msg,
                    "tor_reason": str(circ_event.reason) if circ_event.reason else "UNKNOWN",
                    "first_hop": first_hop,
                    "timestamp": datetime.now().timestamp()
                }
                log.debug("Recorded failure for %s via %s: %s" % (
                    exit_relay[:8], first_hop[:8] if first_hop else "?", reason_key))
                if len(self.failed_circuit_relays) % 50 == 0:
                    log.info("Captured %d circuit failures" % len(self.failed_circuit_relays))
            else:
                # Circuit not in registry - record as unresolved failure
                # Use circuit ID as placeholder fingerprint to maintain count consistency
                unresolved_key = "UNRESOLVED_%s" % cid
                self.failed_circuit_relays[unresolved_key] = {
                    "reason_key": reason_key,
                    "error": error_msg,
                    "tor_reason": str(circ_event.reason) if circ_event.reason else "UNKNOWN",
                    "first_hop": None,
                    "timestamp": datetime.now().timestamp(),
                    "unresolved": True
                }
                log.debug("Circuit %s not in registry - recorded as unresolved failure" % cid)
            
            self.complete_circuit(cid)

        elif status == CircStatus.BUILT:
            self.successful_circuits += 1
            self.complete_circuit(cid)

    def get_failed_circuit_relays(self):
        """
        Return the dictionary of failed circuit relays.
        """
        return self.failed_circuit_relays

    def print_progress(self, sampling=50):
        """
        Print statistics about ongoing probing process.
        """

        if (sampling == 0) or (self.finished_streams % sampling):
            return

        if self.total_circuits == 0:
            return

        percent_done = (self.successful_circuits /
                        float(self.total_circuits)) * 100

        log.info("Probed %d out of %d exit relays, so we are %.2f%% done." %
                 (self.successful_circuits, self.total_circuits, percent_done))

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
