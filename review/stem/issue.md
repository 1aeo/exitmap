Title: Controller deadlocks when tor disconnects while an event listener uses it

### Summary

If tor closes the control connection (it died, was restarted, or we sent QUIT) while an event listener uses the controller, the listener usually never returns. From then on `close()`, `msg()` and `remove_event_listener()` block forever in every other thread, although `is_alive()` is False.

This is on `maint` (0782931d) with Python 3.10 to 3.13. The tags 1.8.3, 1.8.2 and 1.8.1 hang in the same way: the join that causes it (see "Cause") is from 2012 (fa2aeb91).

I think this is the hang of tpo/network-health/exitmap#61. exitmap uses the controller from its event listeners, and in the log there (gk's comment of 2026-01-26) the instrumented stem reports from `_recv` and `_close` right after a listener started to attach a stream. The next request, a `close_circuit()` from another thread, then never returns although `is_alive()` is False. tpo/network-health/exitmap!33 made exitmap check `is_alive()` before such requests. That cannot help when a listener's request is already pending as tor goes away, and exitmap still hangs then.

### Steps to reproduce

Any tor with a ControlPort that needs no password will do, and it keeps running: QUIT only makes tor close this one connection, which looks the same to us as tor dying.

```python
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
```

On `maint` this prints

```
listener: asking tor for traffic/read...
main: calling close()...
```

and has to be killed. Expected:

```
listener: asking tor for traffic/read...
listener: got a SocketClosed (expected)
main: calling close()...
main: close() returned (expected)
```

The same happens when the listener already awaits its reply as tor goes away (SIGSTOP tor, let the listener send a GETINFO, SIGKILL tor), and when the listener waits for another thread that awaits a reply.

### Cause

Where the three threads are when the script above hangs (`faulthandler`, Python 3.11):

```
Tor listener (reader thread)   threading.py join  <-  stem/control.py:862 _close  <-  stem/socket.py:229 close  <-  stem/socket.py:292 _recv
Event notifier (event thread)  stem/socket.py:240 _send  <-  stem/control.py:662 msg  <-  get_info  <-  the listener  <-  stem/control.py:4045 _handle_event
main                           stem/socket.py:192 close  <-  stem/control.py:742 close
```

* When tor hangs up, our reader thread gets the SocketClosed in `_recv()`, takes the send lock and calls `close()` (stem/socket.py:290-293).
* `BaseSocket.close()` calls the controller's `_close()` under that lock, and `_close()` joins the event thread (stem/control.py:860-862).
* The reader only puts the SocketClosed on the reply queue once `recv()` raised, that is after the join (stem/control.py:958-964, "the msg() method relies on this to unblock callers").
* So a listener that waits for the send lock (as above), for a reply (stem/control.py:663) or for the msg lock of another thread that awaits a reply cannot finish, and the join never returns.

No listener of the application is needed for this: stem's own listener for SIGHUP takes the send lock too (stem/control.py:1071-1074), so a `SIGNAL RELOAD` event that is still queued when tor goes away is enough.

### Not caused by !4, but its safety note missed the event thread

!4 did not cause this: 1.8.3, which does not contain !4, hangs the same way.

!4's description ("Safety: ...") and my comment in tpo/network-health/exitmap#67 ("No deadlock.") said it is safe for `_close()` to join the reader thread while holding the send lock, because the reader can exit without that lock. That is true, but `_close()` joins the event thread the same way, and neither text considered that. If a listener is using the controller, it may be waiting for the send lock, or for a reply that only arrives after the join, so the join never returns. This happens when our reader thread closes the socket (this issue) and when the application calls `close()` (the first item under "Known" below, which the proposed fix does not change).

### Proposed fix

Our reader thread should not wait for the event thread without a limit. The merge request that follows bounds that wait to a second in `BaseController._close()`. A `close()` by the application keeps joining both threads as it does now.

### Known, and not covered by that fix

The reader is not the only thread that joins the event thread while it holds a lock a listener needs:

* A `close()` by the application (also leaving a `with` block, or `connect()` and `reconnect()` on a live controller) while an event listener uses the controller blocks in the same join, with the application thread holding the send lock.
* So does a thread inside `msg()` that closes the socket before the reader does when tor disconnects (its send fails, or the reader could not get the send lock because a send was in flight). It holds the msg lock, which a listener needs for a request.

Two more lock problems are next to it:

* `msg()` calls `close()` when it gets a SocketClosed, and `close()` joins the status listener threads while `msg()` still holds its lock (stem/control.py:678 -> 751-753). A `State.CLOSED` listener that uses the controller can therefore block when a request was pending as tor went away.
* `reconnect()` holds the msg lock while it waits for the event listener lock (stem/control.py:1125 -> 3999), and a listener that makes a request takes them the other way round (4040 -> 614). After a disconnect the reader's join keeps the two apart today, unless events are still queued when the event thread stops. With the proposed fix they can also meet when a listener call is still running a second after the disconnect.

None of the four is new: 1.8.3 has them as well. I can file them separately, with reproducers, if you would like them tracked.
