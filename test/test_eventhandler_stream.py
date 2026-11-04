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

import sys

from stem import StreamStatus

sys.path.insert(0, "src/")

from eventhandler import remember_stream_port


class _Stream(object):
    def __init__(self, status, stream_id, source_port=None, reason=None):
        self.status = status
        self.id = stream_id
        self.reason = reason
        self.source_port = source_port

    def __str__(self):
        if self.source_port:
            return "SOURCE_ADDR=127.0.0.1:%d" % self.source_port
        return "REASON=%s" % self.reason


def test_closed_reason_is_stored_by_source_port():
    ports, reasons = {}, {}
    assert remember_stream_port(ports, reasons, _Stream(StreamStatus.NEWRESOLVE, "9", source_port=4242)) is False
    assert remember_stream_port(ports, reasons, _Stream(StreamStatus.CLOSED, "9", reason="TORPROTOCOL")) is True
    assert reasons == {4242: "TORPROTOCOL"}
    assert ports == {}


def test_done_and_destroy_stay_distinct():
    ports, reasons = {}, {}
    remember_stream_port(ports, reasons, _Stream(StreamStatus.NEWRESOLVE, "1", source_port=1000))
    remember_stream_port(ports, reasons, _Stream(StreamStatus.CLOSED, "1", reason="DONE"))
    remember_stream_port(ports, reasons, _Stream(StreamStatus.NEWRESOLVE, "2", source_port=1001))
    remember_stream_port(ports, reasons, _Stream(StreamStatus.FAILED, "2", reason="DESTROY"))
    assert reasons == {1000: "DONE", 1001: "DESTROY"}


def test_closed_without_open_and_remap_store_nothing():
    ports, reasons = {"9": 4242}, {}
    assert remember_stream_port({}, reasons, _Stream(StreamStatus.CLOSED, "3", reason="DESTROY")) is True
    assert remember_stream_port(ports, reasons, _Stream(StreamStatus.REMAP, "9")) is False
    assert reasons == {}
    assert ports == {"9": 4242}
