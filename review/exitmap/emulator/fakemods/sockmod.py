"""
Test module for the fake Tor: opens one connection over the SOCKS port, so
that a stream has to be attached.  The (circuit, socket) message is sent
before the SOCKS request, i.e., the stream is normally attached by stem's
event thread (EventHandler.new_stream).

A probe whose connection was opened appends the name of the module and the
fingerprint of the exit relay to the file $FAKEMOD_OUT.  The socket has a
timeout of $SOCKMOD_TIMEOUT seconds (5 by default).  The probe for the relay
$SOCKMOD_NOCONNECT opens no connection: it sleeps for $FAKEMOD_SLEEP seconds
(0.5 by default) and returns.
"""
import os
import socket
import time

destinations = None


def connect(fpr):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(float(os.environ.get("SOCKMOD_TIMEOUT", "5")))
    try:
        sock.connect(("192.0.2.1", 80))
    finally:
        sock.close()
    with open(os.environ["FAKEMOD_OUT"], "a") as f:
        f.write("%s %s\n" % (__name__, fpr))


def probe(exit_desc, target_host, target_port, run_python_over_tor,
          run_cmd_over_tor, **kwargs):
    if exit_desc.fingerprint == os.environ.get("SOCKMOD_NOCONNECT"):
        time.sleep(float(os.environ.get("FAKEMOD_SLEEP", "0.5")))
        return
    run_python_over_tor(connect, exit_desc.fingerprint)
