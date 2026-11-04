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

"""new_stream records a CLOSED reason under the port it already parses."""

import sys
from unittest.mock import MagicMock

from stem import StreamStatus

sys.path.insert(0, "src/")

from eventhandler import EventHandler


class _Stream(object):
    def __init__(self, status, stream_id, source_port=None, reason=None):
        self.status = status
        self.id = stream_id
        self.reason = reason
        self.source_port = source_port

    def __str__(self):
        if self.source_port:
            return "SOURCE_ADDR=127.0.0.1:%d" % self.source_port
        return "REASON=%s" % (self.reason or "")


def _handler():
    handler = EventHandler.__new__(EventHandler)
    handler._stream_ports = {}
    handler._port_stream = {}
    handler.stream_reasons = {}
    handler.attacher = MagicMock()
    handler.check_finished = MagicMock()
    return handler


def test_closed_reason_uses_the_attach_port():
    handler = _handler()
    handler.new_stream(_Stream(StreamStatus.NEWRESOLVE, "9", source_port=4242))
    handler.attacher.prepare.assert_called_once_with(4242, stream_id="9")
    handler.new_stream(_Stream(StreamStatus.CLOSED, "9", reason="TORPROTOCOL"))
    assert handler.stream_reasons == {4242: "TORPROTOCOL"}
    assert handler._stream_ports == {}


def test_done_and_destroy_stay_distinct():
    handler = _handler()
    handler.new_stream(_Stream(StreamStatus.NEWRESOLVE, "1", source_port=1000))
    handler.new_stream(_Stream(StreamStatus.CLOSED, "1", reason="DONE"))
    handler.new_stream(_Stream(StreamStatus.NEWRESOLVE, "2", source_port=1001))
    handler.new_stream(_Stream(StreamStatus.FAILED, "2", reason="DESTROY"))
    assert handler.stream_reasons == {1000: "DONE", 1001: "DESTROY"}


def test_reused_port_drops_the_previous_reason():
    handler = _handler()
    handler.new_stream(_Stream(StreamStatus.NEWRESOLVE, "1", source_port=4242))
    handler.new_stream(_Stream(StreamStatus.NEWRESOLVE, "2", source_port=4242))
    handler.new_stream(_Stream(StreamStatus.CLOSED, "1", reason="TORPROTOCOL"))
    assert handler.stream_reasons == {}
    handler.new_stream(_Stream(StreamStatus.CLOSED, "2", reason="DONE"))
    assert handler.stream_reasons == {4242: "DONE"}


def test_remap_does_not_attach_or_record():
    handler = _handler()
    handler._stream_ports["9"] = 4242
    handler.new_stream(_Stream(StreamStatus.REMAP, "9"))
    handler.attacher.prepare.assert_not_called()
    assert handler.stream_reasons == {}
    assert handler._stream_ports == {"9": 4242}
