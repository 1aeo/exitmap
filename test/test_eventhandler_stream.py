#!/usr/bin/env python3

# Copyright 2026 1AEO
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

"""STREAM reason recording used to split SOCKS5 reply 4."""

import multiprocessing
import sys
import time

from stem import StreamStatus

sys.path.insert(0, "src/")

from eventhandler import observe_stream


class _Stream(object):
    def __init__(self, status, stream_id, source_port=None, reason=None):
        self.status = status
        self.id = stream_id
        self.source_port = source_port
        self.reason = reason


def test_closed_reason_is_stored_by_source_port():
    """NEWRESOLVE remembers the port; CLOSED stores that port's reason."""
    ports, reasons = {}, {}
    opened = _Stream(StreamStatus.NEWRESOLVE, "9", source_port=4242)
    closed = _Stream(StreamStatus.CLOSED, "9", reason="TORPROTOCOL")

    assert observe_stream(ports, reasons, opened) is False
    assert ports["9"] == 4242
    assert observe_stream(ports, reasons, closed) is True
    assert reasons[4242] == "TORPROTOCOL"
    assert "9" not in ports


def test_done_and_destroy_stay_distinct():
    """Exit errors and dead streams are not stored as TORPROTOCOL."""
    ports, reasons = {}, {}
    observe_stream(ports, reasons, _Stream(StreamStatus.NEWRESOLVE, "1", source_port=1000))
    observe_stream(ports, reasons, _Stream(StreamStatus.CLOSED, "1", reason="DONE"))
    observe_stream(ports, reasons, _Stream(StreamStatus.NEWRESOLVE, "2", source_port=1001))
    observe_stream(ports, reasons, _Stream(StreamStatus.FAILED, "2", reason="DESTROY"))

    assert reasons[1000] == "DONE"
    assert reasons[1001] == "DESTROY"


def test_closed_without_source_port_is_ignored():
    """A terminal event we never saw open cannot be tied to a socket."""
    reasons = {}
    assert observe_stream({}, reasons, _Stream(StreamStatus.CLOSED, "3", reason="DESTROY")) is True
    assert reasons == {}


def test_remap_does_not_record_a_reason():
    """REMAP replaces the target and does not carry the close reason."""
    ports, reasons = {"9": 4242}, {}
    assert observe_stream(ports, reasons, _Stream(StreamStatus.REMAP, "9")) is False
    assert ports["9"] == 4242
    assert reasons == {}


def _wait_for_reason(reasons, port, found):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        value = reasons.get(port)
        if value:
            found.put(value)
            return
        time.sleep(0.02)
    found.put(None)


def test_reason_map_is_visible_in_a_child_process():
    """The shared map is what probe processes read after a STREAM event."""
    manager = multiprocessing.Manager()
    try:
        reasons = manager.dict()
        found = multiprocessing.Queue()
        proc = multiprocessing.Process(target=_wait_for_reason, args=(reasons, 4242, found))
        proc.start()
        reasons[4242] = "TORPROTOCOL"
        proc.join(5)
        assert found.get(timeout=1) == "TORPROTOCOL"
    finally:
        manager.shutdown()
