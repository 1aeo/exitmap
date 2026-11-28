"""Deliver the late event while wait() is inside its give-up block.

eventhandler.max is shadowed by a wrapper: when wait() has computed what it
gives up on (first max() call: circuits, second: module processes), the
wrapper delivers the late event on another thread and waits up to 1 s for the
counter to change, then returns.  With mr18, wait() holds
check_finished_lock at that point.  Afterwards the event thread is joined with
a timeout to detect a deadlock.

Usage: python during_giveup.py SRC_DIR LABEL   (same arguments as late_events)
"""

import builtins
import multiprocessing
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import late_events as le  # noqa: E402  (imports the tree given in argv)

eventhandler = le.eventhandler
CircStatus = le.CircStatus


def run(scenario):
    stats = le.statsmod.Statistics()
    ctl = le.Controller()
    e1 = "A" * 40
    mod = le.Module([e1])
    stats.modules_run += 1
    stats.total_circuits += 1
    h = le.new_handler(stats, ctl, mod, [e1])
    if hasattr(stats, "pending_circuits"):
        stats.pending_circuits["1"] = ["F" * 40, e1]
    if scenario == "report":
        le.deliver(h, le.CircEvent("1", CircStatus.BUILT, e1))
    h.check_finished()

    seen = {"calls": 0}
    threads = []

    def hooked_max(*args):
        result = builtins.max(*args)
        seen["calls"] += 1
        want = {"failed": 1, "built": 1, "report": 2}[scenario]
        if seen["calls"] != want:
            return result
        seen["lock_held"] = h.check_finished_lock.locked()
        seen["computed"] = result
        if scenario == "report":
            attr = "finished_streams"
            before = getattr(stats, attr)
            mod.release[e1].set()     # the real module process reports
        else:
            attr = ("failed_circuits" if scenario == "failed"
                    else "successful_circuits")
            before = getattr(stats, attr)
            status = (CircStatus.FAILED if scenario == "failed"
                      else CircStatus.BUILT)
            t = threading.Thread(target=h.new_circuit,
                                 args=(le.CircEvent("1", status, e1,
                                                    reason="TIMEOUT"),),
                                 daemon=True)
            t.start()
            threads.append(t)
        seen["counted_inside"] = le.until(
            lambda: getattr(stats, attr) > before, timeout=1.0)
        return result

    eventhandler.max = hooked_max
    try:
        h.wait()
    finally:
        del eventhandler.max
    for t in threads:
        t.join(5)
    stuck = [t for t in threads if t.is_alive()]
    if scenario == "report":
        # Give the reader thread time to process the report, if it counts it.
        le.until(lambda: False, timeout=1.0)
    after = le.snap(stats)
    procs = len(multiprocessing.active_children())
    if not stuck:
        h.shutdown()
    print("%-14s %-7s lock held while late event ran: %-5s | late event "
          "counted while wait() was in its block: %-5s | event thread stuck:"
          " %-5s | counters after wait(): %s | module processes at shutdown:"
          " %d" % (le.LABEL, scenario, seen.get("lock_held"),
                   seen.get("counted_inside"), bool(stuck), after, procs),
          flush=True)
    return not stuck


def main():
    ok = True
    for scenario in ("failed", "built", "report"):
        ok = run(scenario) and ok
    for p in multiprocessing.active_children():
        p.terminate()
        p.join(1)
    if not ok:
        print("DEADLOCK detected; exiting hard")
        sys.stdout.flush()
        os._exit(2)


if __name__ == "__main__":
    main()
