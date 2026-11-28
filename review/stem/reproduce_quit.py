"""
An event listener that uses the controller after tor closed the connection
never returns, and neither does close().

usage: python reproduce_quit.py [control port]

Needs a running tor with a ControlPort that asks for no password (9051 by
default). Tor keeps running: QUIT makes it hang up on this connection, as it
does when it dies.
"""

import sys
import time

import stem

from stem.control import Controller, EventType

controller = Controller.from_port(port = int(sys.argv[1]) if len(sys.argv) > 1 else 9051)
controller.authenticate()


def listener(event):
  controller.msg('QUIT')  # tor hangs up on us
  time.sleep(1)  # our reader thread notices, and closes the socket

  try:
    print('listener: asking tor for traffic/read...')
    print('listener: got %s' % controller.get_info('traffic/read'))
  except stem.SocketClosed:
    print('listener: got a SocketClosed (expected)')


controller.add_event_listener(listener, EventType.SIGNAL)
controller.signal('CLEARDNSCACHE')  # causes a SIGNAL event
time.sleep(3)

print('main: calling close()...')
controller.close()
print('main: close() returned (expected)')
