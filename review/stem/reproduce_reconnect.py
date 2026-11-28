"""
Shows the one known deadlock that comes with limiting how long the reader
thread waits for the event thread: a listener that is still busy when the
application reconnects, and uses the controller afterwards, deadlocks with
reconnect().

usage: python reproduce_reconnect.py [control port] [seconds the listener is busy]

Needs a running tor with a ControlPort that asks for no password (9051 by
default), which keeps running. With the default of 1.2 seconds this returns
on stem 1.8.x as released, and hangs with the fix. With 0.9 seconds it
returns on both.
"""

import sys
import time

from stem.control import Controller, EventType, State

controller = Controller.from_port(port = int(sys.argv[1]) if len(sys.argv) > 1 else 9051)
controller.authenticate()
busy = float(sys.argv[2]) if len(sys.argv) > 2 else 1.2
reconnected = []


def listener(event):
  if reconnected:
    return

  controller.msg('QUIT')  # tor hangs up on us
  time.sleep(busy)

  if controller.is_alive():
    print('listener: alive, asking tor for traffic/read...')
    print('listener: got %s' % controller.get_info('traffic/read'))
  else:
    print('listener: not alive, nothing to do')


def status_listener(controller, state, timestamp):
  if state == State.CLOSED and not reconnected:
    reconnected.append(True)
    print('status listener: calling reconnect()...')
    controller.reconnect()
    print('status listener: reconnect() returned')


controller.add_event_listener(listener, EventType.SIGNAL)
controller.add_status_listener(status_listener)
controller.signal('CLEARDNSCACHE')  # causes a SIGNAL event
time.sleep(busy + 2)

print('main: calling close()...')
controller.close()
print('main: close() returned')
