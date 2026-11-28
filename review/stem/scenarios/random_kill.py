"""Kills a real tor at a random moment while a stem controller is in use.

usage: random_kill.py <stem tree> <port|sock> <control port> <trials> [senders]

Every trial starts a tor (DisableNetwork 1) and connects a stem Controller to
its ControlPort (port) or to its ControlSocket (sock).  An event listener
asks tor for something on every event.  <senders> application threads
(default 0) send requests in a tight loop.  A second connection, always over
the control port, changes an option of tor in a loop to cause the events.
After 0.3 to 0.5 seconds tor gets a SIGKILL, then nothing is done for three
seconds.  If stem's two threads and the senders have ended by then and a
close() returns, the trial is 'ok'.  If not, it is a 'DEADLOCK'.

Prints one line per trial: the verdict, the thread that closed the socket
('Tor listener' is stem's reader thread, 'Event notifier' its event thread)
and where in stem the threads are that have not ended.  The last line counts
the verdicts and the threads that closed the socket.

Every trial is a process of its own: this script runs itself with the number
of the trial and a directory as further arguments.  The moment of the SIGKILL
depends on the number of the trial only.  tor's data and its socket file are
in a temporary directory that is removed at the end.  The environment
variable SCENARIO_SCRATCH names the directory to make that one in (default:
where python makes temporary files).  For 'sock' its path must be short, as
paths of unix sockets are limited to about 100 bytes.  The tor binary is
'tor', or what the environment variable TOR_CMD says.

Exit status: 0 no trial was a deadlock, 1 at least one was, 2 the arguments
are wrong, 3 a trial failed.
"""
import collections
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

if len(sys.argv) not in (5, 6, 8) or sys.argv[2] not in ('port', 'sock'):
  sys.stderr.write(__doc__.split('\n\n')[1] + '\n')
  sys.exit(2)

sys.path.insert(0, sys.argv[1])

import stem  # noqa: E402
import stem.process  # noqa: E402
from stem.control import Controller, EventType  # noqa: E402

TOR_CMD = os.environ.get('TOR_CMD', 'tor')
TIMEOUT = 90  # seconds for one trial, it takes four to seven
STEM_DIR = os.path.dirname(os.path.abspath(stem.__file__))


def position(thread):
  """Where a thread is: its innermost three frames in stem."""

  frame = sys._current_frames().get(thread.ident)
  chain = []

  while frame is not None and len(chain) < 3:
    path, filename = os.path.split(os.path.abspath(frame.f_code.co_filename))

    if path == STEM_DIR:
      chain.append('%s:%i' % (filename, frame.f_lineno))

    frame = frame.f_back

  return ' < '.join(chain) or 'not in stem'


def trial(mode, port, senders, number, directory):
  """One trial.  Prints its line and ends the process."""

  socket_path = os.path.join(directory, 'socket')
  config = {'ControlPort': str(port), 'SocksPort': '0', 'DataDirectory': directory, 'DisableNetwork': '1'}

  if mode == 'sock':
    config['ControlSocket'] = socket_path

  tor = stem.process.launch_tor_with_config(config = config, tor_cmd = TOR_CMD, take_ownership = True, completion_percent = 0)
  replies = []  # an entry for every reply the listener got
  closed_by = []  # names of the threads that closed the socket

  def listener(event):
    try:
      controller.get_info('traffic/read')
      replies.append(event)
    except stem.ControllerError:
      pass

  def make_events():
    try:
      with Controller.from_port(port = port) as other:
        other.authenticate()
        count = 0

        while True:
          count += 1
          other.set_conf('ContactInfo', 'event %i' % count)
    except stem.ControllerError:
      pass

  def send():
    while True:
      try:
        controller.get_info('traffic/written')
      except stem.ControllerError:
        if not controller.is_alive():
          return

  controller = Controller.from_socket_file(socket_path) if mode == 'sock' else Controller.from_port(port = port)
  controller.authenticate()

  # notes which thread closes the socket

  control_socket = controller.get_socket()
  socket_close = control_socket._close

  def _close():
    closed_by.append(threading.current_thread().name)
    socket_close()

  control_socket._close = _close
  controller.add_event_listener(listener, EventType.CONF_CHANGED)

  threads = [threading.Thread(target = make_events, name = 'event maker')]
  threads += [threading.Thread(target = send, name = 'application sender') for i in range(senders)]

  for thread in threads:
    thread.daemon = True
    thread.start()

  random.seed(number)
  time.sleep(0.3 + random.random() * 0.2)
  os.kill(tor.pid, signal.SIGKILL)
  time.sleep(3)  # the application does nothing, stem notices on its own (its reader thread may wait a second)

  watched = [controller._event_thread, controller._reader_thread] + threads[1:]
  not_ended = ['%s at %s' % (thread.name, position(thread)) for thread in watched if thread.is_alive()]

  closing = threading.Thread(target = controller.close, name = 'application close()')
  closing.daemon = True
  closing.start()
  closing.join(3)

  print('trial %2i: %s; socket closed by %s; is_alive() %s; close() %s; %i listener replies; not ended: %s' % (
    number, 'DEADLOCK' if (not_ended or closing.is_alive()) else 'ok', closed_by[0] if closed_by else 'nobody', controller.is_alive(),
    'BLOCKED' if closing.is_alive() else 'returned', len(replies), ', '.join(not_ended) or '-'))
  sys.stdout.flush()
  tor.wait()

  try:
    os.remove(socket_path)
  except OSError:
    pass

  os._exit(0)


def stop(pid):
  """Kills what is left of a trial: the processes of its process group."""

  try:
    os.killpg(pid, signal.SIGKILL)
  except OSError:
    pass  # nothing is left


def run_trial(arguments):
  """Runs a trial in a process of its own, returns what it printed."""

  # setsid: the trial and the tor it starts get a process group of their own

  proc = subprocess.Popen([sys.executable, '-B', os.path.abspath(__file__)] + arguments, stdout = subprocess.PIPE, preexec_fn = os.setsid)
  timer = threading.Timer(TIMEOUT, stop, (proc.pid,))
  timer.start()

  try:
    output = proc.stdout.read()  # returns when the trial ended, or when the timer ended it
  finally:
    timer.cancel()
    timer.join()

    # We did not wait() for the trial yet, so its process group can't be
    # another's by now.  This is for a tor the trial did not get to kill.

    stop(proc.pid)
    proc.stdout.close()
    proc.wait()

  return output.decode('utf-8', 'replace').strip()


def tally(verdict, closers):
  """How many trials had this verdict, and which threads closed the socket in them."""

  if not closers:
    return '0 %s' % verdict

  return '%i %s (socket closed by %s)' % (sum(closers.values()), verdict, ', '.join('%s x%i' % item for item in sorted(closers.items())))


def main():
  mode, port, trials = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
  senders = int(sys.argv[5]) if len(sys.argv) > 5 else 0

  if len(sys.argv) == 8:
    trial(mode, port, senders, int(sys.argv[6]), sys.argv[7])  # we are one of the trials, this does not return

  print('stem %s in %s, python %s: tor on a %s, senders: %i, trials: %i' % (stem.__version__, STEM_DIR, sys.version.split()[0], 'ControlSocket' if mode == 'sock' else 'ControlPort', senders, trials))
  sys.stdout.flush()

  closers = {'ok': collections.Counter(), 'DEADLOCK': collections.Counter()}  # verdict => thread that closed the socket => trials
  failed = False
  directory = tempfile.mkdtemp(prefix = 'random-kill-', dir = os.environ.get('SCENARIO_SCRATCH'))

  try:
    for number in range(1, trials + 1):
      line = run_trial(sys.argv[1:4] + [str(trials), str(senders), str(number), directory])
      result = re.match(r'trial +\d+: (ok|DEADLOCK); socket closed by ([^;]+);', line)

      if not result:
        print('%strial %2i: failed, giving up' % (line and line + '\n', number))
        failed = True
        break

      print(line)
      sys.stdout.flush()

      closers[result.group(1)][result.group(2)] += 1
  finally:
    shutil.rmtree(directory, ignore_errors = True)

  done = sum(sum(counter.values()) for counter in closers.values())
  print('%i trials: %s, %s' % (done, tally('ok', closers['ok']), tally('deadlocked', closers['DEADLOCK'])))
  sys.exit(3 if failed else (1 if closers['DEADLOCK'] else 0))


if __name__ == '__main__':
  main()
