"""
Test module for the fake Tor: like sockmod, but the (circuit, socket) message
is sent only after the SOCKS request, i.e., the stream is attached by the
thread reading from the IPC queue (EventHandler.queue_reader).

The message is sent $SOCKMOD_LATE seconds after the request (0.4 by default).
The socket has a timeout of $SOCKMOD_TIMEOUT seconds (5 by default).
"""
import os
import socket
import struct
import time

import torsocks

destinations = None


def connect_late(fpr):
    sock = torsocks.orig_socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(float(os.environ.get("SOCKMOD_TIMEOUT", "5")))
    try:
        sock.connect((torsocks.proxy_addr, torsocks.proxy_port))
        sock.sendall(b"\x05\x01\x00")
        sock.recv(2)
        sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("192.0.2.1") +
                     struct.pack(">H", 80))
        time.sleep(float(os.environ.get("SOCKMOD_LATE", "0.4")))
        torsocks.send_queue(sock.getsockname())
        if len(sock.recv(10)) != 10:
            raise EOFError("no SOCKS reply")
    finally:
        sock.close()
    with open(os.environ["FAKEMOD_OUT"], "a") as f:
        f.write("%s %s\n" % (__name__, fpr))


def probe(exit_desc, target_host, target_port, run_python_over_tor,
          run_cmd_over_tor, **kwargs):
    run_python_over_tor(connect_late, exit_desc.fingerprint)
