"""Reproducers for stem's close() deadlocks which need no tor.

usage: notor.py <stem tree> <variant> [seconds until something counts as blocked]

A real stem Controller talks over a socketpair to FakeTor, a few lines that
answer what Controller.authenticate() and the variants send, emit an event
on demand, stop answering on demand (like a tor that got a SIGSTOP) and close
the connection on demand (like a tor that died).  The variants are in
variants.py, they are the same ones withtor.py runs against a real tor.

Exit status: 0 everything returned, 1 something is still blocked (thread
stacks are printed), 2 something returned in an unexpected way, 3 the
reproducer itself failed.
"""
import os
import socket
import sys
import threading
import traceback

sys.path.insert(0, sys.argv[1])

import stem  # noqa: E402
import stem.socket  # noqa: E402
from stem.control import Controller, EventType  # noqa: E402

import common  # noqa: E402
import variants  # noqa: E402

try:
  import queue
except ImportError:
  import Queue as queue


class FakeTor(object):
  """Just enough of tor's control port for stem's Controller."""

  EVENT = EventType.BW

  def __init__(self, patience):
    self._requests = queue.Queue()  # request lines, as they arrive
    self._stopped = False
    self._patience = patience
    self._conn = None
    self._write_lock = threading.Lock()

  def connect(self):
    """Provides the controller's end of a new connection."""

    client, self._conn = socket.socketpair()
    thread = threading.Thread(target = self._serve, args = (self._conn,), name = 'fake tor')
    thread.daemon = True
    thread.start()
    return client

  def _serve(self, conn):
    for line in conn.makefile('rb'):
      request = line.decode().strip()
      self._requests.put(request)

      if self._stopped:
        continue
      elif request == 'QUIT':
        self._write(conn, '250 closing connection\r\n')
        self.die()
      elif request.startswith('PROTOCOLINFO'):
        self._write(conn, '250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL\r\n250-VERSION Tor="0.4.9.11"\r\n250 OK\r\n')
      elif request == 'GETINFO version':
        self._write(conn, '250-version=0.4.9.11\r\n250 OK\r\n')
      elif request.startswith('GETINFO '):
        self._write(conn, '250-%s=0\r\n250 OK\r\n' % request[8:])
      elif request.startswith('GETCONF '):
        self._write(conn, '250 %s\r\n' % request[8:])
      else:
        self._write(conn, '250 OK\r\n')  # AUTHENTICATE, SETEVENTS

  def _write(self, conn, content):
    with self._write_lock:
      try:
        conn.sendall(content.encode())
      except OSError:
        pass  # the controller hung up

  def emit(self):
    self._write(self._conn, '650 BW 1 2\r\n')

  def emit_reload(self):
    self._write(self._conn, '650 SIGNAL RELOAD\r\n')

  def stop(self):
    self._stopped = True

  def expect(self, request):
    while self._requests.get(timeout = self._patience) != request:
      pass

  def die(self):
    self._conn.shutdown(socket.SHUT_RDWR)
    self._conn.close()

  def wait_queued(self, count):
    pass  # the controller reads what we emitted before it reads the end of the stream

  def restart(self):
    self._stopped = False


class FakeTorSocket(stem.socket.ControlSocket):
  def __init__(self, tor):
    super(FakeTorSocket, self).__init__()
    self._tor = tor
    self.connect()

  def _make_socket(self):
    return self._tor.connect()


def main():
  name = sys.argv[2]
  patience = float(sys.argv[3]) if len(sys.argv) > 3 else 3.0
  variant = variants.VARIANTS[name]

  run = common.Run(patience)
  tor = FakeTor(patience)
  controller = Controller(FakeTorSocket(tor))
  controller.authenticate()

  variant(run, tor, controller)
  run.report('no tor, variant %s: %s [stem %s in %s, python %s]' % (name, variant.__doc__, stem.__version__, os.path.dirname(stem.__file__), sys.version.split()[0]))


if __name__ == '__main__':
  try:
    main()
  except Exception:
    traceback.print_exc()
    sys.stdout.flush()
    os._exit(3)
