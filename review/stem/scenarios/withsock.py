"""Reproducers for stem's close() deadlocks with a real tor and a socket file.

usage: withsock.py <stem tree> <variant> <control port> <scratch directory> [seconds until something counts as blocked]

Like withtor.py, but the controller connects to tor's ControlSocket (a unix
socket file) rather than to its ControlPort.  Starts its own tor
(DisableNetwork 1) and uses SIGSTOP for a tor that does not answer and
SIGKILL for a tor that died.  Events are SIGNAL events, caused with 'SIGNAL
CLEARDNSCACHE' over a second, plain control connection.  That one uses the
control port, so tor listens on both.  The variants are in variants.py, they
are the same ones notor.py runs without tor.

The socket file is made in tor's data directory, which is a new directory in
the scratch directory.  The path of the scratch directory must be short:
paths of unix sockets are limited to about 100 bytes.

The tor binary is 'tor', or what the environment variable TOR_CMD says.

Exit status: 0 everything returned, 1 something is still blocked (thread
stacks are printed), 2 something returned in an unexpected way, 3 the
reproducer itself failed.
"""
import os
import shutil
import signal
import sys
import tempfile
import time
import traceback

sys.path.insert(0, sys.argv[1])

import stem  # noqa: E402
import stem.connection  # noqa: E402
import stem.process  # noqa: E402
import stem.socket  # noqa: E402
from stem.control import Controller, EventType  # noqa: E402

import common  # noqa: E402
import variants  # noqa: E402

try:
  import queue
except ImportError:
  import Queue as queue

TOR_CMD = os.environ.get('TOR_CMD', 'tor')


class RealTor(object):
  EVENT = EventType.SIGNAL

  def __init__(self, port, scratch, patience, take_ownership):
    self.port = port
    self._patience = patience
    self._take_ownership = take_ownership
    self._data_dir = tempfile.mkdtemp(prefix = 'tor-%i-' % port, dir = scratch)
    self.socket_path = os.path.join(self._data_dir, 'socket')  # tor wants it in a directory with mode 0700, mkdtemp() made one
    self._sent = queue.Queue()  # requests the controller has sent
    self._controller = None
    self._launch()

  def _launch(self):
    # a torrc file rather than launch_tor_with_config(): with a torrc from
    # stdin tor exits when it is asked to reload its configuration

    torrc_path = self._data_dir + '.torrc'

    with open(torrc_path, 'w') as torrc_file:
      torrc_file.write('ControlPort %i\nControlSocket %s\nSocksPort 0\nDataDirectory %s\nDisableNetwork 1\n' % (self.port, self.socket_path, self._data_dir))

    self.process = stem.process.launch_tor(tor_cmd = TOR_CMD, torrc_path = torrc_path, completion_percent = 0, timeout = None, take_ownership = self._take_ownership)
    self._trigger = stem.socket.ControlPort(port = self.port)
    stem.connection.authenticate(self._trigger)

  def attach(self, controller):
    """Notes the requests this controller sent, once send() returned."""

    self._controller = controller
    control_socket = controller.get_socket()
    send = control_socket.send

    def noting_send(message):
      send(message)
      self._sent.put(message)

    control_socket.send = noting_send

  def emit(self):
    self._trigger.send('SIGNAL CLEARDNSCACHE')
    reply = self._trigger.recv()

    if not reply.is_ok():
      raise ValueError('SIGNAL failed: %s' % reply)

  def emit_reload(self):
    self._trigger.send('SIGNAL RELOAD')
    reply = self._trigger.recv()

    if not reply.is_ok():
      raise ValueError('SIGNAL failed: %s' % reply)

  def stop(self):
    os.kill(self.process.pid, signal.SIGSTOP)

  def expect(self, request):
    while self._sent.get(timeout = self._patience) != request:
      pass

  def die(self):
    os.kill(self.process.pid, signal.SIGKILL)
    self.process.wait()

  def wait_queued(self, count):
    deadline = time.time() + self._patience

    while self._controller._event_queue.qsize() < count:
      if time.time() > deadline:
        raise ValueError('%i events are queued, expected %i' % (self._controller._event_queue.qsize(), count))

      time.sleep(0.001)

  def restart(self):
    self._launch()

  def cleanup(self):
    try:
      self.process.kill()
    except OSError:
      pass

    self.process.wait()
    shutil.rmtree(self._data_dir, ignore_errors = True)

    try:
      os.remove(self._data_dir + '.torrc')
    except OSError:
      pass


def main():
  name, port, scratch = sys.argv[2], int(sys.argv[3]), sys.argv[4]
  patience = float(sys.argv[5]) if len(sys.argv) > 5 else 3.0
  variant = variants.VARIANTS[name]

  run = common.Run(patience)

  # A controller that took ownership makes tor exit when it disconnects, the
  # reconnecting variants can't have that.

  tor = RealTor(port, scratch, patience, take_ownership = name not in ('6e', 'c1', 'c2'))

  try:
    controller = Controller.from_socket_file(tor.socket_path)
    controller.authenticate()
    tor.attach(controller)
    variant(run, tor, controller)
  except Exception:
    traceback.print_exc()
    sys.stdout.flush()
    tor.cleanup()
    os._exit(3)

  run.report('real tor over a socket file, variant %s: %s [stem %s in %s, python %s]' % (name, variant.__doc__, stem.__version__, os.path.dirname(stem.__file__), sys.version.split()[0]), tor.cleanup)


if __name__ == '__main__':
  try:
    main()
  except Exception:
    traceback.print_exc()
    sys.stdout.flush()
    os._exit(3)
