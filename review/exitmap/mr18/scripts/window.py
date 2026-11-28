"""How long after the give-up can a late report or event still be counted?

N module processes hang; wait() gives up; shutdown() runs at once, as in
run_module().  From the log records' timestamps:
  listener  give-up warning -> remove_event_listener() returned (fake
            controller: no Tor round trip, so this is a lower bound)
  last kill give-up warning -> "Calling module's teardown()" (all module
            processes terminated; none can report after that)
  sentinel  give-up warning -> reader thread exited (it counts reports until
            it reads the sentinel)

Usage: python window.py SRC_DIR LABEL
"""

import multiprocessing
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import late_events as le  # noqa: E402

CircStatus = le.CircStatus


class TimedController(le.Controller):
    def remove_event_listener(self, listener):
        self.removed_at = time.time()


def run(n):
    stats = le.statsmod.Statistics()
    ctl = TimedController()
    exits = ["%040X" % (i + 1) for i in range(n)]
    mod = le.Module(exits)
    stats.total_circuits += n
    h = le.new_handler(stats, ctl, mod, exits)
    for i, e in enumerate(exits):
        le.deliver(h, le.CircEvent(str(i + 1), CircStatus.BUILT, e))
    h.check_finished()
    mark = len(le.LOGH.records)
    times = {}
    orig_emit = le.LOGH.emit

    def emit(record):
        msg = record.getMessage()
        if "No longer waiting" in msg:
            times["give_up"] = record.created
        elif "teardown()" in msg:
            times["last_kill"] = record.created
        orig_emit(record)

    le.LOGH.emit = emit
    try:
        h.wait()
        h.shutdown()
        times["reader_done"] = time.time() if not h.queue_thread.is_alive() \
            else float("nan")
    finally:
        le.LOGH.emit = orig_emit
    del le.LOGH.records[mark:]
    g = times["give_up"]
    print("%-13s %2d hung processes: listener removed after %6.2f ms, last "
          "process terminated after %7.2f ms, reader stopped by %7.2f ms"
          % (le.LABEL, n, (ctl.removed_at - g) * 1e3,
             (times["last_kill"] - g) * 1e3, (times["reader_done"] - g) * 1e3),
          flush=True)
    for p in multiprocessing.active_children():
        p.terminate()
        p.join(1)


for n in (1, 10, 50):
    run(n)
