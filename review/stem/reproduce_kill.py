"""
Kills tor while an event listener is waiting for the reply to a request.
The listener should get a SocketClosed and close() should return.

usage: python reproduce_kill.py [control port to start tor with]

Starts its own tor, so tor has to be in the PATH. Ends by itself after a few
seconds and reports whether the listener and close() are still blocked.
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
main_is_idle, listener_result = threading.Event(), []


def listener(event):
  main_is_idle.wait()

  # tor cannot reply while it is stopped, and is killed half a second later

  os.kill(tor.pid, signal.SIGSTOP)
  threading.Timer(0.5, os.kill, (tor.pid, signal.SIGKILL)).start()

  try:
    listener_result.append(controller.get_info('traffic/read'))
  except stem.ControllerError as exc:
    listener_result.append(type(exc).__name__)


controller.add_event_listener(listener, EventType.CONF_CHANGED)
controller.set_conf('ContactInfo', 'this triggers a CONF_CHANGED event')
main_is_idle.set()
time.sleep(3)

print('stem %s' % stem.__version__)
print('listener: %s' % (listener_result[0] if listener_result else 'still waiting for its reply'))

close_thread = threading.Thread(target = controller.close)
close_thread.daemon = True
close_thread.start()
close_thread.join(3)

print('close(): %s' % ('still blocked' if close_thread.is_alive() else 'returned'))
tor.wait()
shutil.rmtree(data_directory, ignore_errors = True)
