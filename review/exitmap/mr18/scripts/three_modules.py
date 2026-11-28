"""Late circuit event after module 1's give-up; then modules 2 and 3 of the
same run (n circuits each, given order).  Usage: python three_modules.py SRC LABEL"""
import multiprocessing, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import late_events as le
for scenario in ("late_failed", "late_built", "late_report"):
    for n, order in [(1, "interleaved"), (3, "interleaved"), (3, "built-first")]:
        stats = le.statsmod.Statistics(); ctl = le.Controller()
        m1 = le.module1(stats, ctl, scenario)
        m2 = le.module2(stats, ctl, n, order)
        m3 = le.module2(stats, ctl, n, order)
        for p in multiprocessing.active_children():
            p.terminate(); p.join(1)
        print("%-13s %-11s n=%d %-11s | m1 late %s | m2 %s | m3 start %s: %s" % (
            le.LABEL, scenario, n, order, m1["after_late"], m2["outcome"][:40],
            m3["start"], m3["outcome"][:70]), flush=True)
