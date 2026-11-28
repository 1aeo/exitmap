`EventHandler.shutdown()` joins the thread reading from the IPC queue without
a timeout, and the thread is not a daemon thread, so exitmap cannot exit while
it runs. Three ways to get there:

1. `shutdown()` is left before it stops the thread, e.g. because the module's
   `teardown()` raises. Python then never exits (and with the current
   `bin/exitmap` the exception is not even printed, see #69):

   ```python
   import sys
   from unittest.mock import Mock
   sys.path.insert(0, "src/")
   import eventhandler, stats

   module = Mock()
   module.teardown.side_effect = RuntimeError("teardown() failed")
   handler = eventhandler.EventHandler(Mock(), module, 9050,
                                       stats.Statistics(), {}, None, None)
   handler.shutdown()  # raises; on current main Python then never exits
   ```

2. The thread is blocked in a request to the controller:

   ```python
   import sys, threading, time
   from unittest.mock import Mock
   sys.path.insert(0, "src/")
   import eventhandler, stats

   controller = Mock()
   controller.get_circuit.side_effect = lambda circ_id: threading.Event().wait()
   handler = eventhandler.EventHandler(controller, Mock(), 9050,
                                       stats.Statistics(), {}, None, None)
   handler.queue.put(("1", None))  # a module finished; the thread gets stuck
   time.sleep(0.2)
   handler.shutdown()              # never returns on current main
   print("shutdown() returned")
   ```

   This is what happens when Tor dies while an event callback is waiting for a
   reply: stem never releases the lock the thread needs. The snippet calls
   `shutdown()` directly. In a real scan exitmap only gets that far with the
   change for #70 (`wait()` returns, and the event listener is left
   alone); on its own this change makes no difference in that case. Against
   a control-port emulator, at 5 of 17 moments at which Tor dies, exitmap
   with the change for #70 alone still hung in this thread; with both
   changes it exited at these 5 as well. The commit message says so too.

3. The sentinel which stops the thread cannot be delivered, because a module
   process was terminated while it was writing to the queue and still holds
   the queue's write lock. Rare, but then even a bounded join is not enough:
   Python waits for the queue's feeder thread at exit.

Fix: make it a daemon thread, stop waiting for it after five seconds (with a
warning), and call `cancel_join_thread()` on the queue in that case.
