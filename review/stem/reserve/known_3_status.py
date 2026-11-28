"""
Third item under "Known, and not covered by that fix": tor dies while a
request awaits its reply. msg() then calls close(), which joins the status
listener threads while msg() still holds its lock. A State.CLOSED listener
that uses the controller never returns, and neither does the request.

usage: python known_3_status.py [control port to start tor with]

Starts its own tor, so tor has to be in the PATH. Ends by itself after a few
seconds and reports what is still blocked.
"""

import os
import shutil
import signal
import sys
import tempfile
import threading

import stem
import stem.process

from stem.control import Controller, State

CONTROL_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 28951
data_directory = tempfile.mkdtemp()

tor = stem.process.launch_tor_with_config(
  config = {
    'ControlPort': str(CONTROL_PORT),
    'SocksPort': '0',
    'DisableNetwork': '1',
    'DataDirectory': data_directory,
  },
  take_ownership = True,
  completion_percent = 0,
)

controller = Controller.from_port(port = CONTROL_PORT)
controller.authenticate()
status_result, request_result = [], []


def status_listener(controller, state, timestamp):
  if state == State.CLOSED:
    try:
      status_result.append(controller.get_info('traffic/written'))
    except stem.ControllerError as exc:
      status_result.append(type(exc).__name__)


def request():
  try:
    request_result.append(controller.get_info('traffic/read'))
  except stem.ControllerError as exc:
    request_result.append(type(exc).__name__)


controller.add_status_listener(status_listener)

# tor cannot reply while it is stopped, and is killed half a second later

os.kill(tor.pid, signal.SIGSTOP)
threading.Timer(0.5, os.kill, (tor.pid, signal.SIGKILL)).start()

request_thread = threading.Thread(target = request)
request_thread.daemon = True
request_thread.start()
request_thread.join(4)

print('stem %s' % stem.__version__)
print('request:         %s' % (request_result[0] if request_result else 'still blocked'))
print('status listener: %s' % (status_result[0] if status_result else 'still blocked'))
tor.wait()
shutil.rmtree(data_directory, ignore_errors = True)
