Title: Fix reader thread deadlock when tor disconnects

When tor closes the control connection while an event listener uses the controller, the listener usually never returns, and every later `close()`, `msg()` and `remove_event_listener()` then blocks forever. Our reader thread joins the event thread while it holds the socket's send lock, and before it has enqueued the SocketClosed that unblocks `msg()` callers. #N has the details, a short reproducer and the thread positions. I think this is the hang of tpo/network-health/exitmap#61.

**Change.** In `BaseController._close()` the reader thread waits for the event thread for at most a second (`EVENT_THREAD_JOIN_TIMEOUT`, new) rather than without a limit. A `close()` by the application still joins both threads and still handles the queued events first (`test_asynchronous_event_handling` is untouched and passes).

**What behaves differently.** The reader's wait only runs out when the event thread is stuck, or a listener call takes about half a second or more: once we are closed the event thread counts `EVENTS_LISTENING_TIMEOUT` (0.1 seconds) from the first event it finishes and stops after the event it is handling when that time is up. Then:

* `State.CLOSED` listeners and callers waiting in `msg()` are notified while the event thread still calls listeners, rather than once it ended.
* A `close()` after that returns without waiting for it, so a listener call can still run, or begin for an event that was queued, after `close()` returned.
* A `reconnect()` after that begins while the event thread still runs, and keeps it.

**Known cost.** That last point can turn a program that works on `maint` into a deadlock. It takes all of this: a listener call that is still running a second after tor disconnected us, an application that reconnects as soon as it learns of the disconnect, a tor that accepts the new connection, and the listener using the controller after that. `reconnect()` then holds the msg lock and wants the event listener lock, the listener holds the event listener lock and wants the msg lock. On `maint` the join holds the reconnect back until the listener is done. A `State.CLOSED` listener that reconnects and a listener that checks `is_alive()` before its request show it with one listener call of 1.2 seconds, or with two calls in a row of 0.6 seconds. With one call of 0.9 seconds or two of 0.45 it works as on `maint`. exitmap does not reconnect.

**The hunk in `_event_loop()`.** An event thread that a reconnect keeps could stop after the first queued event at the next close, because it still counted its 0.1 seconds from the earlier one. `maint` already has this when a listener closes the controller itself and it is connected again while the next queued event is handled. The bounded wait would add a second way to get there, so the event thread now forgets the earlier close once we are alive again.

**Why a second.** Not waiting at all would announce `State.CLOSED` before the queued events are handled on every disconnect, and put the deadlock above in reach of every listener. Waiting for `EVENTS_LISTENING_TIMEOUT` is not enough either: as the event thread only starts counting when it has finished an event, it outlasts such a wait by a listener call or two when more events are queued than it handles in that time. A second leaves room for that and for listener calls of a few hundred milliseconds. It is also how long callers are held up when the event thread is stuck.

**Not covered** (see the end of #N): a `close()` by the application while a listener uses the controller, a `msg()` caller that closes the socket before the reader does, the status listener threads that `msg()` joins, and the lock order of `reconnect()` and event listeners. In a test with the fix (a listener that asks tor on every event, two or four threads sending in a tight loop, tor killed at a random moment) the second of these was left in 13 of 480 disconnects (3 of 240 on a ControlPort, 10 of 240 on a ControlSocket).

**Test.** `test_event_handler_msg_after_disconnect` in test/integ/control/base_controller.py: an event handler sends QUIT, waits until we noticed that tor hung up, and makes another request. On unmodified `maint` it fails after 10 seconds ("event handler is still blocked on its request"), with the fix it takes one second, the reader's wait. I am happy to drop the test if you prefer the code change alone.

**Tested** with tor 0.4.9.11 and Python 3.10 to 3.13:

* The reproducer of #N, and its variant in which tor is killed while the listener awaits a reply: the listener and `close()` stay blocked on `maint` and return with this change.
* `run_tests.py --unit`: same result as `maint`, no new line in the static checks.
* `run_tests.py --integ --test control.base_controller --test socket.control_socket --test control.controller` on 3.10 and 3.11: same result as `maint` apart from the new test. `control.base_controller` alone 30 times on each: no failure, no lingering thread.
* 35 scripted scenarios (tor dies or hangs up, or the application closes, with listeners and callers in various states), 994 runs per tree: all against a fake tor on a socketpair, 29 also against a tor on a ControlPort and 20 of those also on a ControlSocket. 13 block on `maint` (375 of 391 runs; two of the 13 depend on a race) and return in every run with this change. 13 work on `maint` and still do, 9 of them with the reader thread closing the socket. The other 9 belong to "Not covered" and block on both.
* exitmap against an emulated tor that dies at 17 different moments: on `maint`, upstream exitmap hangs in 11 of them. With this change it hangs in one, in a wait of its own that involves no stem call.

Where these ran there is no IPv6 and there are no man pages, so a few existing tests fail on `maint` as well. The pipeline is the complete run. I can attach the scripts behind the last two items.

**Correction to !4.** Its "Safety" note missed the event thread, see #N.

Closes: #N.
