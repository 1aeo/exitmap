"""
First item under "Known, and not covered by that fix": close() by the
application while an event listener uses the controller. Neither close() nor
the listener returns.

usage: python known_1_close.py [control port]

Needs a running tor with a ControlPort that asks for no password (9051 by
default), which keeps running.
"""

import sys
import threading
import time

import stem

from stem.control import Controller, EventType

controller = Controller.from_port(port = int(sys.argv[1]) if len(sys.argv) > 1 else 9051)
controller.authenticate()
in_listener = threading.Event()


def listener(event):
  in_listener.set()
  time.sleep(1)  # the application calls close() meanwhile

  try:
    print('listener: asking tor for traffic/read...')
    print('listener: got %s' % controller.get_info('traffic/read'))
  except stem.SocketClosed:
    print('listener: got a SocketClosed (expected)')


controller.add_event_listener(listener, EventType.SIGNAL)
controller.signal('CLEARDNSCACHE')  # causes a SIGNAL event
in_listener.wait(5)

print('main: calling close()...')
controller.close()
print('main: close() returned (expected)')
