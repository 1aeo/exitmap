"""Hold the queue reader or new_circuit() for 2.5 s on the line that counts,
after it has checked already_finished (if it does), while wait() gives up on
another thread.  Without a lock around the check and the count, the report,
the BUILT or the FAILED event is then counted twice.

Real EventHandler and Statistics, fake controller and events (from
late_events.py, which must be next to this script); IDLE_TIMEOUT is 0, so
wait() gives up at its first look, after 1 s.

usage: trace_pause.py SRC_DIR LABEL
"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import late_events as le  # noqa: E402  (imports eventhandler from SRC_DIR)

eh = le.eventhandler
eh.IDLE_TIMEOUT = 0          # wait() gives up at its first look (after 1 s)
CircStatus = le.CircStatus
SRCFILE = eh.__file__
LINES = open(SRCFILE).read().split("\n")


def line_of(func_name, text):
    """1-based line of the first `text` inside function `func_name`."""
    start = None
    for i, l in enumerate(LINES):
        if l.strip().startswith("def %s(" % func_name):
            start = i
        elif start is not None and l.strip() == text:
            return i + 1
    raise LookupError(text)


READER_COUNT = line_of("queue_reader", "self.stats.finished_streams += 1")
CIRC_COUNT = line_of("new_circuit", "self.stats.update_circs(circ_event)")


def make_tracer(target_line, state):
    def local(frame, event, arg):
        if (event == "line" and frame.f_lineno == target_line and
                not state["paused"]):
            state["paused"] = True
            state["lock_held_at_pause"] = frame.f_locals[
                "self"].check_finished_lock.locked()
            time.sleep(2.5)  # checked, not yet counted; wait() gives up now
        return local

    def glob(frame, event, arg):
        if frame.f_code.co_filename == SRCFILE and \
                frame.f_code.co_name in ("queue_reader", "new_circuit"):
            return local
        return None
    return glob


def run(scenario):
    e1 = "A" * 40
    stats = le.statsmod.Statistics()
    stats.total_circuits = 1
    state = {"paused": False}
    target = READER_COUNT if scenario == "report" else CIRC_COUNT
    threading.settrace(make_tracer(target, state))
    try:
        h = le.new_handler(stats, le.Controller(), le.Module([e1]), [e1])
        if scenario == "report":
            stats.successful_circuits = 1      # circuit 1 built, probe running
            h.queue.put(("1", None))           # the probe reports back
        else:
            status = (CircStatus.BUILT if scenario == "built"
                      else CircStatus.FAILED)
            t = threading.Thread(target=h.new_circuit,
                                 args=(le.CircEvent("1", status, e1,
                                                    "TIMEOUT"),),
                                 daemon=True)
            t.start()
    finally:
        threading.settrace(None)
    time.sleep(0.2)
    waiter = threading.Thread(target=h.wait, daemon=True)
    waiter.start()
    waiter.join(10)
    time.sleep(3)                          # let the paused thread finish
    s = stats
    counted = s.failed_circuits + s.successful_circuits
    ok = (counted == s.total_circuits and
          s.finished_streams == s.successful_circuits)
    print("%-22s %-6s paused on line %d: %-5s (lock held then: %-5s) "
          "wait() returned: %-5s counters t%d f%d b%d s%d: %s"
          % (le.LABEL, scenario, target, state["paused"],
             state.get("lock_held_at_pause"), not waiter.is_alive(),
             s.total_circuits, s.failed_circuits, s.successful_circuits,
             s.finished_streams, "ok" if ok else "COUNTED TWICE"),
          flush=True)
    h.shutdown()


for scenario in ("report", "built", "failed"):
    run(scenario)
