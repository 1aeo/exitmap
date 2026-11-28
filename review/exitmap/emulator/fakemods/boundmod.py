"""
Test module for the fake Tor: the probes of the scenarios in @bound.

A probe sleeps for $FAKEMOD_SLEEP seconds (0.5 by default) and then appends
the name of the module and the fingerprint of the exit relay to the file
$FAKEMOD_OUT, like a probe of fakemod.  $BOUNDMOD_ROLES is a list of roles,
separated by commas.  The first probe that starts takes the first role, the
second probe the second one, and so on; the other probes have none.  A role
says what the probe does first:

stuck   opens a connection over Tor and closes it, like a probe of sockmod.
        Then it reads, without a timeout, from a local socket that never
        gets data.  The probe does not return.
killed  sleeps for 1 s and then sends SIGKILL to its own process.
chatty  resolves a name over Tor 15 times and sleeps for 1 s after each.
        exitmap gets one message for every name.
silent  sleeps for 12 s and opens no connection.

exitmap shuffles the exit relays and starts no probe for a circuit that
failed.  That is why a role goes to the n-th probe and not to a relay.

teardown() appends a line to the file $FAKEMOD_OUT.teardown.
"""
import os
import signal
import socket
import time

import torsocks

destinations = None


def connect():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect(("192.0.2.1", 80))
    finally:
        sock.close()


def resolve():
    sock = torsocks.torsocket()
    sock.settimeout(5)
    try:
        sock.resolve("example.com")
    finally:
        sock.close()


def my_role():
    """
    Return the role of this probe, or None.
    """

    roles = os.environ.get("BOUNDMOD_ROLES")
    for number, role in enumerate(roles.split(",") if roles else []):
        # Only one probe can create the file of a role.
        try:
            os.close(os.open("%s.role%d" % (os.environ["FAKEMOD_OUT"], number),
                             os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        except FileExistsError:
            continue
        return role
    return None


def probe(exit_desc, target_host, target_port, run_python_over_tor,
          run_cmd_over_tor, **kwargs):
    role = my_role()
    if role == "stuck":
        run_python_over_tor(connect)
        # The fake tor passes no data and closes its connections sooner or
        # later, so the read is from a socket of our own.
        ours, theirs = socket.socketpair()
        ours.recv(1)
    elif role == "killed":
        time.sleep(1)
        os.kill(os.getpid(), signal.SIGKILL)
    elif role == "chatty":
        for _ in range(15):
            run_python_over_tor(resolve)
            time.sleep(1)
    elif role == "silent":
        time.sleep(12)
    time.sleep(float(os.environ.get("FAKEMOD_SLEEP", "0.5")))
    with open(os.environ["FAKEMOD_OUT"], "a") as f:
        f.write("%s %s\n" % (__name__, exit_desc.fingerprint))


def teardown(**kwargs):
    with open(os.environ["FAKEMOD_OUT"] + ".teardown", "a") as f:
        f.write("%s\n" % __name__)
