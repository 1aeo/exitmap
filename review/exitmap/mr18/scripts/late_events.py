"""Reproduce the double count after wait() gives up.

Real EventHandler, Statistics, multiprocessing.Queue, reader thread and forked
module processes (module_call); fake controller, fake module, fake circuit
events.  Module 1 of a run gives up (IDLE_TIMEOUT patched to 0.2 s, so wait()
gives up at its first 1-second check); a late event is delivered after wait()
returned and before shutdown() ran, i.e. in the window the claim is about;
then module 2 of the same run is driven step by step on the same Statistics.

Usage: python late_events.py SRC_DIR LABEL
"""

import json
import logging
import multiprocessing
import sys
import threading
import time

SRC, LABEL = sys.argv[1], sys.argv[2]
sys.path.insert(0, SRC)
multiprocessing.set_start_method("fork")

import eventhandler  # noqa: E402
import stats as statsmod  # noqa: E402
from stem import CircStatus  # noqa: E402

eventhandler.IDLE_TIMEOUT = 0.2


class ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append((record.levelname, record.getMessage()))


LOGH = ListHandler()
logging.getLogger().addHandler(LOGH)
logging.getLogger().setLevel(logging.DEBUG)


class Desc(object):
    def __init__(self, fpr):
        self.fingerprint = fpr


class Controller(object):
    def __init__(self):
        self.removed = 0

    def is_alive(self):
        return True

    def get_circuit(self, circ_id):
        # What stem does for a circuit Tor no longer has.
        raise ValueError("Tor has no circuit %s" % circ_id)

    def close_circuit(self, circ_id):
        pass

    def get_server_descriptor(self, relay):
        return Desc(relay)

    def remove_event_listener(self, listener):
        self.removed += 1


class Module(object):
    """probe() blocks until the event for its exit relay is set."""

    def __init__(self, exits):
        self.release = {e: multiprocessing.Event() for e in exits}

    def probe(self, exit_desc, **kwargs):
        self.release[exit_desc.fingerprint].wait(30)

    def teardown(self, **kwargs):
        pass


class CircEvent(object):
    def __init__(self, circ_id, status, exit_fpr, reason=None):
        self.id = circ_id
        self.status = status
        self.reason = reason
        self.path = [("F" * 40, "first"), (exit_fpr, "exit")]

    def __str__(self):
        return "CIRC %s %s" % (self.id, self.status)


def deliver(handler, event):
    """Run new_circuit() on its own thread, as stem's event thread does."""
    t = threading.Thread(target=handler.new_circuit, args=(event,),
                         daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive(), "new_circuit() blocked"


def until(pred, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.005)
    return pred()


def snap(s):
    return "t%d f%d b%d s%d" % (s.total_circuits, s.failed_circuits,
                                s.successful_circuits, s.finished_streams)


def new_handler(stats, ctl, mod, exits):
    return eventhandler.EventHandler(ctl, mod, 9050, stats,
                                     exit_destinations={e: set()
                                                        for e in exits},
                                     target_host=None, target_port=None)


def module1(stats, ctl, scenario):
    e1 = "A" * 40
    mod = Module([e1])
    stats.modules_run += 1
    stats.total_circuits += 1
    h = new_handler(stats, ctl, mod, [e1])
    if hasattr(stats, "pending_circuits"):
        stats.pending_circuits["1"] = ["F" * 40, e1]
    if scenario in ("none_built", "late_report"):
        # Circuit 1 is built; its module process hangs.
        deliver(h, CircEvent("1", CircStatus.BUILT, e1))
    h.check_finished()
    mark = len(LOGH.records)
    t0 = time.monotonic()
    h.wait()
    waited = time.monotonic() - t0
    gave_up = snap(stats)
    warn = [m for _, m in LOGH.records[mark:] if "No longer waiting" in m]
    # The window: wait() returned, shutdown() has not started yet.
    if scenario == "late_report":
        before = stats.finished_streams
        mod.release[e1].set()   # the real module process reports (1, None)
        until(lambda: stats.finished_streams > before)
    elif scenario == "late_failed":
        deliver(h, CircEvent("1", CircStatus.FAILED, e1, reason="TIMEOUT"))
    elif scenario == "late_built":
        deliver(h, CircEvent("1", CircStatus.BUILT, e1))
    late = snap(stats)
    procs = len(multiprocessing.active_children())
    h.shutdown()
    return dict(waited=round(waited, 2), warn=warn[0][-60:] if warn else None,
                after_give_up=gave_up, after_late=late,
                procs_at_shutdown=procs, already_finished=h.already_finished)


def module2(stats, ctl, n, order):
    exits = [chr(ord("B") + i) * 40 for i in range(n)]
    cids = [str(101 + i) for i in range(n)]
    mod = Module(exits)
    stats.modules_run += 1
    stats.total_circuits += n
    h = new_handler(stats, ctl, mod, exits)
    if hasattr(stats, "pending_circuits"):
        for c, e in zip(cids, exits):
            stats.pending_circuits[c] = ["F" * 40, e]
    start = snap(stats)
    pending, running = set(cids), set()
    mark = len(LOGH.records)
    h.check_finished()
    ended = "right after requesting its circuits" \
        if h.finished_event.is_set() else None
    if order == "interleaved":
        plan = [(w, i) for i in range(n) for w in ("built", "reported")]
    else:
        plan = ([("built", i) for i in range(n)] +
                [("reported", i) for i in range(n)])
    for what, i in plan:
        if ended:
            break
        if what == "built":
            deliver(h, CircEvent(cids[i], CircStatus.BUILT, exits[i]))
            pending.discard(cids[i])
            running.add(cids[i])
        else:
            before = stats.finished_streams
            mod.release[exits[i]].set()
            assert until(lambda: stats.finished_streams > before), "no report"
            running.discard(cids[i])
        if h.finished_event.is_set():
            ended = "after circuit %s was %s" % (cids[i], what)
    lost = (sorted(pending), sorted(running))
    t0 = time.monotonic()
    h.wait()
    waited = time.monotonic() - t0
    gave_up = [m for _, m in LOGH.records[mark:] if "No longer waiting" in m]
    h.shutdown()
    if ended is None:
        outcome = "HANG: never finished, wait() gave up (5 min for real): %s" \
            % gave_up[0][-50:]
    elif lost[0] or lost[1]:
        outcome = "EARLY: ended %s; never built %s, terminated %s" % (
            ended, lost[0], lost[1])
    else:
        outcome = "ok"
    return dict(start=start, end=snap(stats), outcome=outcome,
                waited=round(waited, 2))


def main():
    rows = []
    scenarios = ["none_built", "late_report", "none_pending", "late_failed",
                 "late_built"]
    for scenario in scenarios:
        for n, order in [(1, "interleaved"), (3, "interleaved"),
                         (3, "built-first")]:
            stats = statsmod.Statistics()
            ctl = Controller()
            m1 = module1(stats, ctl, scenario)
            m2 = module2(stats, ctl, n, order)
            leftover = multiprocessing.active_children()
            for p in leftover:
                p.terminate()
                p.join(1)
            row = dict(label=LABEL, scenario=scenario, n=n, order=order,
                       m1=m1, m2=m2, leftover=len(leftover))
            rows.append(row)
            print(json.dumps(row), flush=True)
    print("SUMMARY %s" % LABEL)
    for r in rows:
        print("%-12s n=%d %-11s | m1: give-up %s -> late %s | m2: start %s"
              " end %s | %s" % (r["scenario"], r["n"], r["order"],
                                r["m1"]["after_give_up"],
                                r["m1"]["after_late"], r["m2"]["start"],
                                r["m2"]["end"], r["m2"]["outcome"]))
    alive = [t.name for t in threading.enumerate()
             if t is not threading.main_thread()]
    print("threads left:", alive, "children left:",
          len(multiprocessing.active_children()))


if __name__ == "__main__":
    main()
