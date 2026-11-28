"""The variants, shared by notor.py (FakeTor), withtor.py and withsock.py (a real tor).

Every variant gets a Run (see common.py), a connected and authenticated stem
Controller, and a 'tor' that can...

  tor.EVENT            event type that emit() causes
  tor.emit()           make tor send one event to the controller
  tor.emit_reload()    make tor send a SIGNAL RELOAD event (tor got a SIGHUP)
  tor.stop()           tor reads requests from now on, but does not answer
  tor.expect(request)  returns when the controller has sent this request
  tor.die()            tor is gone, the control connection gets closed
  tor.wait_queued(n)   returns when n events wait in the controller's queue
  tor.restart()        start tor again after die()

Every step waits for the step before it rather than sleeping.  The
exceptions: p3 gives stem's reader thread 50 ms, and the listeners of e1 and
c2 are busy for a fixed time.
"""
import threading
import time

import common

from stem.control import State

BUSY = common.HARD_LIMIT  # listeners that are 'busy' wait for an Event, at most this long


def afterwards(run, controller, listener = None, close = True):
  """What an application may do next, from other threads.  All must return."""

  calls = [run.call('later: msg()', lambda: controller.msg('GETINFO traffic/written'))]

  if listener:
    calls.append(run.call('later: remove_event_listener()', lambda: controller.remove_event_listener(listener)))

  if close:
    calls.append(run.call('later: close()', controller.close))

  run.wait(*calls)
  run.expect(calls[0], 'raised SocketClosed')

  if all(call.finished.is_set() for call in calls):
    run.check(not controller.is_alive(), 'the controller is still alive')

    for thread in (controller._reader_thread, controller._event_thread):
      thread.join(run.patience)
      run.check(not thread.is_alive(), 'the "%s" thread did not end' % thread.name)


def v1(run, tor, controller):
  """a listener waits for a reply when tor dies"""

  proceed = threading.Event()

  def in_listener(event, n):
    proceed.wait(BUSY)
    return controller.get_info('traffic/read')

  listener, (listening,) = run.listener('listener: get_info()', in_listener)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(listening)
  tor.stop()
  proceed.set()
  tor.expect('GETINFO traffic/read')
  common.settle(controller)
  tor.die()

  run.wait(listening)
  run.expect(listening, 'raised SocketClosed')
  afterwards(run, controller, listener)


def v2(run, tor, controller):
  """the application waits for a reply when tor dies while a listener is busy, the listener then sends a request"""

  go = threading.Event()
  closing = common.hook_closing(controller)

  def in_listener(event, n):
    go.wait(BUSY)
    return controller.get_info('traffic/read')

  listener, (listening,) = run.listener('listener: busy, get_info()', in_listener)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(listening)
  tor.stop()
  application = run.call('application: get_info()', lambda: controller.get_info('traffic/written'))
  tor.expect('GETINFO traffic/written')
  common.settle(controller)
  tor.die()
  run.check(closing.wait(run.patience), 'nobody closed the socket')
  go.set()

  run.wait(application, listening)
  run.expect(application, 'raised SocketClosed')
  run.expect(listening, 'raised SocketClosed')
  afterwards(run, controller, listener)


def v3a(run, tor, controller):
  """the application calls close() while a listener waits for a reply from a stopped tor"""

  proceed = threading.Event()

  def in_listener(event, n):
    proceed.wait(BUSY)
    return controller.get_info('traffic/read')

  listener, (listening,) = run.listener('listener: get_info()', in_listener)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(listening)
  tor.stop()
  proceed.set()
  tor.expect('GETINFO traffic/read')
  common.settle(controller)
  close = run.call('application: close()', controller.close)

  run.wait(close, listening)
  run.expect(listening, 'raised SocketClosed')
  afterwards(run, controller, listener, close = False)


def v3b(run, tor, controller):
  """the application calls close() while a listener is busy, the listener then sends a request"""

  go = threading.Event()
  closing = common.hook_closing(controller)

  def in_listener(event, n):
    go.wait(BUSY)
    return controller.get_info('traffic/read')

  listener, (listening,) = run.listener('listener: busy, get_info()', in_listener)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(listening)
  close = run.call('application: close()', controller.close)
  run.check(closing.wait(run.patience), 'nobody closed the socket')
  go.set()

  run.wait(close, listening)
  run.expect(listening, 'raised SocketClosed')
  afterwards(run, controller, listener, close = False)


def v4(run, tor, controller):
  """tor dies while a listener is busy without using the controller, the application waits for a reply"""

  go = threading.Event()
  listener, (listening,) = run.listener('listener: busy', lambda event, n: go.wait(BUSY) and None)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(listening)
  tor.stop()
  application = run.call('application: get_info()', lambda: controller.get_info('traffic/written'))
  tor.expect('GETINFO traffic/written')
  common.settle(controller)
  tor.die()

  # the only place where we wait for something that does not come

  in_time = application.finished.wait(run.patience)
  run.note('the application %s while the listener stayed busy for %0.1fs after tor died' % ('GOT ITS SocketClosed' if in_time else 'was STILL WAITING', run.patience))
  released = time.time()
  go.set()

  run.wait(application, listening)
  run.expect(application, 'raised SocketClosed')

  if application.finished.is_set() and not in_time:
    run.note('the application got its SocketClosed %0.3fs after the listener returned' % (application.finished_at - released))

  afterwards(run, controller, listener)


def v5(run, tor, controller):
  """tor dies while an event is queued behind a busy listener, the listener sends a request for the queued event"""

  go = threading.Event()
  closing = common.hook_closing(controller)

  def in_listener(event, n):
    if n == 1:
      go.wait(BUSY)
    else:
      return controller.get_info('traffic/read')

  listener, (first, second) = run.listener('listener: busy', in_listener, expected = 2)
  second.name = 'listener: get_info() (event 2)'
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(first)
  tor.emit()
  tor.wait_queued(1)
  tor.die()
  run.check(closing.wait(run.patience), 'nobody closed the socket')
  go.set()

  run.wait(first)
  controller._event_thread.join(run.patience)  # the second event is handled or dropped
  run.expect(second, 'raised SocketClosed')
  afterwards(run, controller, listener)


def v5b(run, tor, controller):
  """tor dies while a listener is busy, the listener then sends a request (nothing else is going on)"""

  go = threading.Event()
  closing = common.hook_closing(controller)

  def in_listener(event, n):
    go.wait(BUSY)
    return controller.get_info('traffic/read')

  listener, (listening,) = run.listener('listener: busy, get_info()', in_listener)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(listening)
  tor.die()
  run.check(closing.wait(run.patience), 'nobody closed the socket')
  go.set()

  run.wait(listening)
  run.expect(listening, 'raised SocketClosed')
  afterwards(run, controller, listener)


def v6a(run, tor, controller):
  """control: tor dies while the application waits for a reply, the listener is idle"""

  listener, (listening,) = run.listener('listener: returns', lambda event, n: None)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait(listening)
  tor.stop()
  application = run.call('application: get_info()', lambda: controller.get_info('traffic/written'))
  tor.expect('GETINFO traffic/written')
  common.settle(controller)
  tor.die()

  run.wait(application)
  run.expect(application, 'raised SocketClosed')
  afterwards(run, controller, listener)


def v6a2(run, tor, controller):
  """control: tor dies while nothing is going on"""

  closing = common.hook_closing(controller)
  listener, (listening,) = run.listener('listener: returns', lambda event, n: None)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait(listening)
  tor.die()
  run.check(closing.wait(run.patience), 'nobody closed the socket')
  afterwards(run, controller, listener)


def v6b(run, tor, controller):
  """control: the application calls close() while the listener is idle"""

  listener, (listening,) = run.listener('listener: returns', lambda event, n: None)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait(listening)
  close = run.call('application: close()', controller.close)

  run.wait(close)
  afterwards(run, controller, listener, close = False)


def v6c(run, tor, controller):
  """control: a listener calls close()"""

  listener, (listening,) = run.listener('listener: close()', lambda event, n: controller.close())
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()

  run.wait(listening)
  run.expect(listening, 'returned')
  afterwards(run, controller, listener)


def _status_listeners(run, controller):
  spawned, inline = run.activity('status listener, spawn = True'), run.activity('status listener, spawn = False')
  states = []

  def listener(activity):
    def status_listener(controller, state, timestamp):
      states.append(state)
      activity.run(lambda: '%s in "%s"' % (state, threading.current_thread().name))

    return status_listener

  controller.add_status_listener(listener(spawned), True)
  controller.add_status_listener(listener(inline), False)
  return spawned, inline, states


def v6d(run, tor, controller):
  """control: status listeners (spawn True and False) when the application calls close()"""

  spawned, inline, states = _status_listeners(run, controller)
  close = run.call('application: close()', controller.close)

  if run.wait(close):
    # close() joins the threads of its status listeners, no need to wait

    run.check(states == [State.CLOSED, State.CLOSED], 'status listeners were called with %s' % states)

  afterwards(run, controller, close = False)


def v6d2(run, tor, controller):
  """control: status listeners (spawn True and False) when tor dies"""

  spawned, inline, states = _status_listeners(run, controller)
  tor.die()

  if not spawned.finished.wait(run.patience) or not inline.finished.wait(run.patience):
    run.fail('status listeners were not called')
  else:
    run.check(states == [State.CLOSED, State.CLOSED], 'status listeners were called with %s' % states)

  afterwards(run, controller)


def v6e(run, tor, controller):
  """control: connect() after close(), reconnect() after tor died and came back"""

  listener, events = run.listener('listener: returns', lambda event, n: None, expected = 3)
  controller.add_event_listener(listener, tor.EVENT)

  def reconnect():
    tor.emit()
    events[0].finished.wait(BUSY)

    controller.close()
    controller.connect()
    controller.authenticate()
    first = controller.get_info('traffic/read')
    tor.emit()
    events[1].finished.wait(BUSY)

    closing = common.hook_closing(controller)
    tor.die()
    closing.wait(BUSY)
    tor.restart()
    controller.reconnect()
    second = controller.get_info('traffic/read')
    tor.emit()
    events[2].finished.wait(BUSY)
    alive = controller.is_alive()
    controller.close()
    return (first.isdigit(), second.isdigit(), alive)

  sequence = run.call('application: close(), connect(), tor dies, reconnect(), close()', reconnect)
  sequence.finished.wait(4 * run.patience)
  run.expect(sequence, 'returned (True, True, True)')
  afterwards(run, controller, listener, close = False)


def v4l(run, tor, controller):
  """tor dies while the application waits for a reply and holds a lock of its own, a listener waits for that lock"""

  lock, has_lock, proceed = threading.Lock(), threading.Event(), threading.Event()

  def in_application():
    with lock:
      has_lock.set()
      proceed.wait(BUSY)
      return controller.get_info('traffic/written')

  def in_listener(event, n):
    with lock:
      pass

  listener, (listening,) = run.listener('listener: wants the lock', in_listener)
  controller.add_event_listener(listener, tor.EVENT)

  application = run.call('application: lock, get_info()', in_application)
  has_lock.wait(run.patience)
  tor.emit()
  run.wait_started(listening)
  tor.stop()
  proceed.set()
  tor.expect('GETINFO traffic/written')
  common.settle(controller)
  tor.die()

  run.wait(application, listening)
  run.expect(application, 'raised SocketClosed')
  afterwards(run, controller, listener)


def v7(run, tor, controller):
  """tor dies while a SIGNAL RELOAD event is queued behind a busy listener, no listener uses the controller"""

  go = threading.Event()
  closing = common.hook_closing(controller)
  listener, (listening,) = run.listener('listener: busy', lambda event, n: go.wait(BUSY) and None)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(listening)
  tor.emit_reload()  # handled by the Controller's own listener, which notifies status listeners of State.RESET
  tor.wait_queued(1)
  tor.die()
  run.check(closing.wait(run.patience), 'nobody closed the socket')
  go.set()

  run.wait(listening)
  ended = run.call('stem: event thread ends', controller._event_thread.join)
  run.wait(ended)
  afterwards(run, controller, listener)


def v7r(run, tor, controller):
  """tor sends a SIGNAL RELOAD event and dies right away, the application has no listener (a race, nothing is held back)"""

  closing = common.hook_closing(controller)
  event_thread = controller._event_thread

  tor.emit_reload()
  tor.die()
  run.check(closing.wait(run.patience), 'nobody closed the socket')

  ended = run.call('stem: event thread ends', event_thread.join)
  run.wait(ended)
  afterwards(run, controller)


def vq(run, tor, controller):
  """tor stays up: a listener sends QUIT, tor hangs up, the listener sends another request"""

  def in_listener(event, n):
    controller.msg('QUIT')
    return controller.get_info('traffic/read')

  listener, (listening,) = run.listener('listener: QUIT, get_info()', in_listener)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()

  run.wait(listening)
  run.expect(listening, 'raised SocketClosed')
  afterwards(run, controller, listener)


def v4b(run, tor, controller):
  """tor dies while a listener is busy without using the controller, the application then sends a request"""

  go = threading.Event()
  closing = common.hook_closing(controller)
  listener, (listening,) = run.listener('listener: busy', lambda event, n: go.wait(BUSY) and None)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(listening)
  tor.die()
  run.check(closing.wait(run.patience), 'nobody closed the socket')
  run.note('is_alive() is %s when the application sends its request' % controller.is_alive())
  application = run.call('application: get_info()', lambda: controller.get_info('traffic/written'))

  # here too we wait for something that does not come

  in_time = application.finished.wait(run.patience)
  run.note('the application %s while the listener stayed busy for %0.1fs after tor died' % ('GOT ITS SocketClosed' if in_time else 'was STILL WAITING', run.patience))
  released = time.time()
  go.set()

  run.wait(application, listening)
  run.expect(application, 'raised SocketClosed')

  if application.finished.is_set() and not in_time:
    run.note('the application got its SocketClosed %0.3fs after the listener returned' % (application.finished_at - released))

  afterwards(run, controller, listener)


def v4e(run, tor, controller):
  """tor dies while the application waits for the reply of remove_event_listener() and an event arrived, no listener is called"""

  listener, (listening,) = run.listener('listener: never called', lambda event, n: None)
  controller.add_event_listener(listener, tor.EVENT)

  tor.stop()
  application = run.call('application: remove_event_listener()', lambda: controller.remove_event_listener(listener))
  tor.expect('SETEVENTS SIGNAL CONF_CHANGED STATUS_SERVER')
  common.settle(controller)
  tor.emit()  # the event thread wants the lock that remove_event_listener() holds
  tor.die()

  run.wait(application)
  run.expect(application, 'raised SocketClosed')
  afterwards(run, controller)


def vqw(run, tor, controller):
  """tor stays up: a listener sends QUIT, waits until the controller noticed that tor hung up, sends another request"""

  closing = common.hook_closing(controller)

  def in_listener(event, n):
    controller.msg('QUIT')
    closing.wait(BUSY)
    return controller.get_info('traffic/read')

  listener, (listening,) = run.listener('listener: QUIT, get_info()', in_listener)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()

  run.wait(listening)
  run.expect(listening, 'raised SocketClosed')
  afterwards(run, controller, listener)


# --- further variants (3c 3e 3f s1 w x1 x2 x3) ---

def _wait_queued(run, controller, count):
  deadline = time.time() + run.patience

  while controller._event_queue.qsize() < count and time.time() < deadline:
    time.sleep(0.001)

  run.check(controller._event_queue.qsize() >= count, 'the event was not queued')


def v3c(run, tor, controller):
  """the application calls close() while a SIGNAL RELOAD event is queued behind a busy listener, no listener uses the controller"""

  go = threading.Event()
  closing = common.hook_closing(controller)
  listener, (listening,) = run.listener('listener: busy', lambda event, n: go.wait(BUSY) and None)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(listening)
  tor.emit_reload()
  _wait_queued(run, controller, 1)
  close = run.call('application: close()', controller.close)
  run.check(closing.wait(run.patience), 'nobody closed the socket')
  go.set()

  run.wait(close, listening)
  afterwards(run, controller, listener, close = False)


def v3e(run, tor, controller):
  """the application calls close() while a listener is busy, the listener then calls close() itself"""

  go = threading.Event()
  closing = common.hook_closing(controller)

  def in_listener(event, n):
    go.wait(BUSY)
    controller.close()

  listener, (listening,) = run.listener('listener: busy, close()', in_listener)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(listening)
  close = run.call('application: close()', controller.close)
  run.check(closing.wait(run.patience), 'nobody closed the socket')
  go.set()

  run.wait(close, listening)
  run.expect(listening, 'returned')
  afterwards(run, controller, listener, close = False)


def v3f(run, tor, controller):
  """one application thread calls close() while another waits for a reply and a listener is busy, the listener then sends a request"""

  go = threading.Event()
  closing = common.hook_closing(controller)

  def in_listener(event, n):
    go.wait(BUSY)
    return controller.get_info('traffic/read')

  listener, (listening,) = run.listener('listener: busy, get_info()', in_listener)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(listening)
  tor.stop()
  application = run.call('application: get_info()', lambda: controller.get_info('traffic/written'))
  tor.expect('GETINFO traffic/written')
  common.settle(controller)
  close = run.call('application: close()', controller.close)
  run.check(closing.wait(run.patience), 'nobody closed the socket')
  go.set()

  run.wait(close, application, listening)
  run.expect(application, 'raised SocketClosed')
  run.expect(listening, 'raised SocketClosed')
  afterwards(run, controller, listener, close = False)


def vs1(run, tor, controller):
  """tor dies while the application waits for a reply, a status listener (spawn = True) then sends a request"""

  notified = run.activity('status listener: get_info()')

  def status_listener(controller, state, timestamp):
    if state == State.CLOSED:
      notified.run(lambda: controller.get_info('traffic/read'))

  controller.add_status_listener(status_listener, True)
  tor.stop()
  application = run.call('application: get_info()', lambda: controller.get_info('traffic/written'))
  tor.expect('GETINFO traffic/written')
  common.settle(controller)
  tor.die()

  run.check(notified.started.wait(run.patience), 'the status listener was not called')
  run.wait(application, notified)
  run.expect(application, 'raised SocketClosed')
  run.expect(notified, 'raised SocketClosed')
  afterwards(run, controller)


def vw(run, tor, controller):
  """the application leaves a 'with controller' block while a listener is busy, the listener then sends a request"""

  go = threading.Event()
  closing = common.hook_closing(controller)

  def in_listener(event, n):
    go.wait(BUSY)
    return controller.get_info('traffic/read')

  listener, (listening,) = run.listener('listener: busy, get_info()', in_listener)
  controller.add_event_listener(listener, tor.EVENT)

  def with_block():
    with controller:
      tor.emit()
      run.wait_started(listening)

  leaving = run.call('application: with controller', with_block)
  run.check(closing.wait(run.patience), 'nobody closed the socket')
  go.set()

  run.wait(leaving, listening)
  run.expect(listening, 'raised SocketClosed')
  afterwards(run, controller, listener, close = False)


def vx1(run, tor, controller):
  """variant 1 plus a status listener (spawn = True) that uses the controller when it is told of CLOSED"""

  proceed = threading.Event()

  def in_listener(event, n):
    proceed.wait(BUSY)
    return controller.get_info('traffic/read')

  status = run.activity('status listener: get_info()')

  def status_listener(controller, state, timestamp):
    if state == State.CLOSED:
      status.run(lambda: controller.get_info('traffic/written'))

  controller.add_status_listener(status_listener, True)
  listener, (listening,) = run.listener('listener: get_info()', in_listener)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(listening)
  tor.stop()
  proceed.set()
  tor.expect('GETINFO traffic/read')
  common.settle(controller)
  tor.die()

  run.wait(listening, status)
  run.expect(listening, 'raised SocketClosed')
  run.expect(status, 'raised SocketClosed')
  afterwards(run, controller, listener)


def vx2(run, tor, controller):
  """tor dies while a listener is busy without using the controller, the application then calls close()"""

  go = threading.Event()
  closing = common.hook_closing(controller)
  listener, (listening,) = run.listener('listener: busy', lambda event, n: go.wait(BUSY) and None)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(listening)
  tor.die()
  run.check(closing.wait(run.patience), 'nobody closed the socket')
  close = run.call('application: close()', controller.close)

  in_time = close.finished.wait(run.patience)
  run.note('close() %s while the listener stayed busy for %0.1fs after tor died' % ('RETURNED' if in_time else 'was STILL WAITING', run.patience))
  go.set()

  run.wait(close, listening)
  afterwards(run, controller, listener, close = False)


def vx3(run, tor, controller):
  """tor dies while an event is queued behind a busy listener: order of the CLOSED notice and the listener calls"""

  go = threading.Event()
  order = []
  notified = threading.Event()

  def status_listener(controller, state, timestamp):
    order.append('status %s' % state)
    notified.set()

  def in_listener(event, n):
    if n == 1:
      go.wait(BUSY)

    order.append('listener returns from event %i' % n)

  controller.add_status_listener(status_listener, False)
  listener, (first, second) = run.listener('listener: busy', in_listener, expected = 2)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(first)
  tor.emit()
  tor.wait_queued(1)
  tor.die()

  early = notified.wait(run.patience)
  run.note('status listeners %s of CLOSED while the first listener call was still busy' % ('WERE TOLD' if early else 'were not told'))
  go.set()

  run.wait(first, second)
  notified.wait(run.patience)
  controller._event_thread.join(run.patience)
  run.note('order: %s' % ', '.join(order))
  afterwards(run, controller, listener)


# --- further variants (j1 j2 p3 k1 e1 c1 c2) ---

def _variant1_until_death(run, tor, controller, status_listener, spawn):
  proceed = threading.Event()

  def in_listener(event, n):
    proceed.wait(BUSY)
    return controller.get_info('traffic/read')

  controller.add_status_listener(status_listener, spawn)
  listener, (listening,) = run.listener('listener: get_info()', in_listener)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(listening)
  tor.stop()
  proceed.set()
  tor.expect('GETINFO traffic/read')
  common.settle(controller)
  tor.die()
  return listener, listening


def vj1(run, tor, controller):
  """variant 1 plus a status listener with spawn = False that calls controller.close() when it is told of CLOSED"""

  status = run.activity('status listener (spawn False): close()')

  def status_listener(controller, state, timestamp):
    if state == State.CLOSED:
      status.run(controller.close)

  listener, listening = _variant1_until_death(run, tor, controller, status_listener, False)
  run.wait(listening, status)
  run.expect(listening, 'raised SocketClosed')
  afterwards(run, controller, listener)


def vj2(run, tor, controller):
  """variant 1 plus a status listener with spawn = True that calls controller.close() when it is told of CLOSED"""

  status = run.activity('status listener (spawn True): close()')

  def status_listener(controller, state, timestamp):
    if state == State.CLOSED:
      status.run(controller.close)

  listener, listening = _variant1_until_death(run, tor, controller, status_listener, True)
  run.wait(listening, status)
  run.expect(listening, 'raised SocketClosed')
  afterwards(run, controller, listener)


def vp3(run, tor, controller):
  """tor dies while an application send is in flight (emulated: the caller holds the send lock), so the application's msg() closes; a busy listener then sends a request"""

  go = threading.Event()
  closing = common.hook_closing(controller)

  def in_listener(event, n):
    go.wait(BUSY)
    return controller.get_info('traffic/read')

  listener, (listening,) = run.listener('listener: busy, get_info()', in_listener)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(listening)
  closer = []

  def in_application():
    with controller.get_socket()._get_send_lock():
      tor.die()
      time.sleep(0.05)  # the reader meets the end of the stream, but can't get the send lock
      closer.append(closing.is_set())
      return controller.get_info('traffic/written')

  application = run.call('application: get_info()', in_application)
  run.check(closing.wait(run.patience), 'nobody closed the socket')
  go.set()

  run.wait(application, listening)
  run.note('the socket was closed %s' % ('by the reader before the application sent' if closer and closer[0] else 'by the application thread'))
  run.expect(application, 'raised SocketClosed')
  run.expect(listening, 'raised SocketClosed')
  afterwards(run, controller, listener)


def vk1(run, tor, controller):
  """tor dies while a listener is busy, the listener then calls controller.close()"""

  go = threading.Event()
  closing = common.hook_closing(controller)

  def in_listener(event, n):
    go.wait(BUSY)
    controller.close()

  listener, (listening,) = run.listener('listener: busy, close()', in_listener)
  controller.add_event_listener(listener, tor.EVENT)

  tor.emit()
  run.wait_started(listening)
  tor.die()
  run.check(closing.wait(run.patience), 'nobody closed the socket')
  go.set()

  run.wait(listening)
  run.expect(listening, 'returned')
  afterwards(run, controller, listener)


def ve1(run, tor, controller):
  """tor dies while 40 events are queued behind a listener that takes 5 ms each, the application calls close() once it knows: listener calls after close() returned"""

  go = threading.Event()
  closing = common.hook_closing(controller)
  calls = []

  def listener(event):
    if not calls:
      calls.append(time.time())
      go.wait(BUSY)
    else:
      calls.append(time.time())
      time.sleep(0.005)

  controller.add_event_listener(listener, tor.EVENT)
  tor.emit()
  deadline = time.time() + run.patience

  while not calls and time.time() < deadline:
    time.sleep(0.001)

  for i in range(40):
    tor.emit()

  tor.wait_queued(40)
  _wait_queued(run, controller, 40)
  tor.die()
  run.check(closing.wait(run.patience), 'nobody closed the socket')
  go.set()
  close = run.call('application: close()', controller.close)
  run.wait(close)
  returned = time.time()
  event_thread = controller._event_thread
  alive = event_thread.is_alive()
  event_thread.join(run.patience)
  later = len([c for c in calls if c > returned])
  run.note('close() returned with the event thread %s; listener calls begun after close() returned: %s' % ('ALIVE' if alive else 'ended', 'SOME' if later else 'none'))
  run.note('raw: %i listener calls in all, %i after close() returned' % (len(calls), later))
  afterwards(run, controller, listener, close = False)


def vc1(run, tor, controller):
  """the application calls close() while a status listener (spawn = True) calls reconnect() when it is told of CLOSED"""

  status = run.activity('status listener: reconnect()')
  done = []

  def status_listener(controller, state, timestamp):
    if state == State.CLOSED and not done:
      done.append(True)
      status.run(controller.reconnect)

  listener, (listening,) = run.listener('listener: returns', lambda event, n: None)
  controller.add_event_listener(listener, tor.EVENT)
  controller.add_status_listener(status_listener, True)
  tor.emit()
  run.wait(listening)
  close = run.call('application: close()', controller.close)
  run.wait(close, status)
  run.expect(status, 'returned')

  if close.finished.is_set() and status.finished.is_set():
    final = run.call('application: second close()', controller.close)
    run.wait(final)

  afterwards(run, controller, listener, close = False)


def vc2(run, tor, controller):
  """the application calls close() while a listener is busy for 50 ms (it does not use the controller) and a status listener (spawn = True) calls reconnect() when it is told of CLOSED"""

  status = run.activity('status listener: reconnect()')
  done = []

  def status_listener(controller, state, timestamp):
    if state == State.CLOSED and not done:
      done.append(True)
      status.run(controller.reconnect)

  listener, (listening,) = run.listener('listener: busy for 50 ms', lambda event, n: time.sleep(0.05))
  controller.add_event_listener(listener, tor.EVENT)
  controller.add_status_listener(status_listener, True)
  tor.emit()
  run.wait_started(listening)
  close = run.call('application: close()', controller.close)
  run.wait(close, status, listening)
  run.expect(status, 'returned')

  if close.finished.is_set() and status.finished.is_set():
    final = run.call('application: second close()', controller.close)
    run.wait(final)

  afterwards(run, controller, listener, close = False)


VARIANTS = {
  '1': v1, '2': v2, '3a': v3a, '3b': v3b, '4': v4, '5': v5, '5b': v5b,
  '6a': v6a, '6a2': v6a2, '6b': v6b, '6c': v6c, '6d': v6d, '6d2': v6d2, '6e': v6e,
  '4L': v4l, '7': v7, '7r': v7r, 'q': vq, 'qw': vqw, '4b': v4b, '4E': v4e,
  '3c': v3c, '3e': v3e, '3f': v3f, 's1': vs1, 'w': vw, 'x1': vx1, 'x2': vx2, 'x3': vx3,
  'j1': vj1, 'j2': vj2, 'p3': vp3, 'k1': vk1, 'e1': ve1, 'c1': vc1, 'c2': vc2,
}
