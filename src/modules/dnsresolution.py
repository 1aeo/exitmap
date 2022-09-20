#!/usr/bin/env python3

# Copyright 2021 The Tor Project Inc.
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
Module to detect broken DNS resolution.
"""

import logging

import torsocks
import socket
import error
from util import exiturl

log = logging.getLogger(__name__)

destinations = None
domains = {
    "www.example.com": [],
    "www.torproject.org": [],
}


def resolve(exit_desc, domain):
    """
    Resolve a `domain' and report errors.
    """

    exit = exiturl(exit_desc.fingerprint)
    sock = torsocks.torsocket()
    sock.settimeout(10)

    # Resolve the domain using Tor's SOCKS extension.

    try:
        ipv4 = sock.resolve(domain)
    except error.SOCKSv5Error as err:
        log.error("Exit relay %s could not resolve IPv4 address for "
                  "\"%s\" because: %s" % (exit, domain, err))
        return
    except socket.timeout as err:
        log.error("Socket over exit relay %s resolving \"%s\" timed out (%s)" %
                  (exit, domain, err))
        return
    except EOFError as err:
        log.error("EOF error: %s" % err)
        return

    log.debug("%s resolved domain %s to %s" % (exit, domain, ipv4))


def probe(exit_desc, run_python_over_tor, run_cmd_over_tor, **kwargs):
    """
    Probe the given exit relay and check if all domains resolve as expected.
    """

    for domain in domains:
        run_python_over_tor(resolve, exit_desc, domain)


if __name__ == "__main__":
    log.critical("Module can only be run over Tor, and not stand-alone.")
