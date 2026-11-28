"""
Second item under "Known, and not covered by that fix": tor dies while a
request is being sent, so the thread inside msg() closes the socket rather
than the reader thread. It joins the event thread while it holds the msg
lock, and a listener that makes a request then blocks it for good.

usage: python known_2_send.py [path for the control socket]

Starts its own tor with a ControlSocket, so tor has to be in the PATH. Ends
by itself after a few seconds and reports what is still blocked.
"""

import os
import shutil
import signal
import sys
import tempfile
import threading
import time

import stem
import stem.process

from stem.control import Controller, EventType

data_directory = tempfile.mkdtemp()
socket_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(data_directory, 'control')

tor = stem.process.launch_tor_with_config(
  config = {
    'ControlSocket': socket_path,
    'SocksPort': '0',
    'DisableNetwork': '1',
    'DataDirectory': data_directory,
  },
  take_ownership = True,
  completion_percent = 0,
)

controller = Controller.from_socket_file(socket_path)
controller.authenticate()
in_listener, listener_result, request_result = threading.Event(), [], []


def listener(event):
  in_listener.set()
  time.sleep(2)  # tor is killed meanwhile

  try:
    listener_result.append(controller.get_info('traffic/read'))
  except stem.ControllerError as exc:
    listener_result.append(type(exc).__name__)


def request():
  # more than the socket buffers take, so the send blocks until tor is killed

  try:
    request_result.append(controller.msg('GETINFO %s' % ('x' * 4000000)))
  except stem.ControllerError as exc:
    request_result.append(type(exc).__name__)


controller.add_event_listener(listener, EventType.CONF_CHANGED)
controller.set_conf('ContactInfo', 'this triggers a CONF_CHANGED event')
in_listener.wait(5)

# tor does not read while it is stopped, and is killed half a second later

os.kill(tor.pid, signal.SIGSTOP)
threading.Timer(0.5, os.kill, (tor.pid, signal.SIGKILL)).start()

request_thread = threading.Thread(target = request)
request_thread.daemon = True
request_thread.start()
request_thread.join(5)

print('stem %s' % stem.__version__)
print('request:  %s' % (request_result[0] if request_result else 'still blocked'))
print('listener: %s' % (listener_result[0] if listener_result else 'still blocked'))
tor.wait()
shutil.rmtree(data_directory, ignore_errors = True)

if os.path.exists(socket_path):
  os.remove(socket_path)  # tor was killed, so a socket outside its data directory is still there
