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
""" Unit tests for the torsocks module."""

import unittest
import socket
import sys

import pytest
import socks

sys.path.insert(0, 'src/')
import torsocks


class TestTorsocks(unittest.TestCase):
    """Test the torsocks module."""

    def test_send_queue(self):
        self.assertRaises(AssertionError, torsocks.send_queue,
                          ("127.0.0.1", 38662))


def test__torsocket():
    t = torsocks._Torsocket()
    with pytest.raises(TypeError):
        _ = t.resolve("localhost")


def test__torsocket_send_queue(monkeypatch):
    # Every socket must send its name to the queue once, no matter how many
    # sockets were created before.
    sent = []
    monkeypatch.setattr(torsocks, "send_queue", sent.append)
    # Leave out the SOCKS handshake, there is no Tor to talk to.
    monkeypatch.setitem(socks.socksocket._proxy_negotiators, socks.SOCKS5,
                        lambda *args: None)
    for _ in range(3):
        with torsocks._Torsocket() as t:
            # PySocks' connect() calls this once it is connected to the proxy.
            t._proxy_negotiators[socks.SOCKS5](t, "192.0.2.1", 80)
    assert len(sent) == 3


def test_torsocket():
    ts = torsocks.torsocket()
    assert isinstance(ts, torsocks._Torsocket)


def test_getaddrinfo():
    args = ("check.torproject.org", 443)
    addr = torsocks.getaddrinfo(*args)
    assert [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("check.torproject.org", 443),
        )
    ] == addr


if __name__ == '__main__':
    unittest.main()
