"""
Fourth item under "Known, and not covered by that fix": reconnect() holds
the msg lock while it waits for the event listener lock, and an event
listener that makes a request takes them the other way round. They meet when
events are still queued as tor closes the connection.

usage: python known_4_reconnect.py [control port]

Needs a running tor with a ControlPort that asks for no password (9051 by
default), which keeps running.
"""

import sys
import threading
import time

from stem.control import Controller, EventType, State

controller = Controller.from_port(port = int(sys.argv[1]) if len(sys.argv) > 1 else 9051)
controller.authenticate()
all_queued, calls, asked, reconnected = threading.Event(), [], [], []


def listener(event):
  calls.append(event)

  if len(calls) == 1:
    all_queued.wait(5)  # the other events queue up behind this call
    controller.msg('QUIT')  # tor hangs up on us
    time.sleep(0.05)  # our reader thread notices, and closes the socket

  time.sleep(0.005)

  if controller.is_alive():
    if not asked:
      asked.append(True)
      print('listener: alive again at event %i, asking tor for traffic/read...' % len(calls))

    controller.get_info('traffic/read')


def status_listener(controller, state, timestamp):
  if state == State.CLOSED and not reconnected:
    reconnected.append(True)
    print('status listener: calling reconnect() after %i of 60 events...' % len(calls))
    controller.reconnect()
    print('status listener: reconnect() returned (expected)')


controller.add_event_listener(listener, EventType.SIGNAL)
controller.add_status_listener(status_listener)

for i in range(60):
  controller.signal('CLEARDNSCACHE')  # causes a SIGNAL event

time.sleep(0.5)
all_queued.set()
time.sleep(3)

print('main: calling close()...')
controller.close()
print('main: close() returned (expected)')
