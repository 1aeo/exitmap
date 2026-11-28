"""The controller dies while wait() waits: does wait() return?

Only meaningful for trees on a212bd7 (the tip and mr18): the wait() of mr16
alone on main (d33d69d) has no controller check.
wait() runs on a daemon thread; if it is still alive 4 s after the controller
died, it is deadlocked and we exit hard.

Usage: python controller_dies.py SRC_DIR LABEL
"""

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import late_events as le  # noqa: E402

le.eventhandler.IDLE_TIMEOUT = 300   # the real value: only the death matters


class DyingController(le.Controller):
    alive = True

    def is_alive(self):
        return self.alive


stats = le.statsmod.Statistics()
ctl = DyingController()
mod = le.Module(["A" * 40])
stats.total_circuits = 1
h = le.new_handler(stats, ctl, mod, ["A" * 40])
t = threading.Thread(target=h.wait, daemon=True)
t.start()
time.sleep(0.5)
ctl.alive = False
t.join(4)
print("%-14s wait() returned after the controller died: %s; lock held: %s"
      % (le.LABEL, not t.is_alive(), h.check_finished_lock.locked()),
      flush=True)
os._exit(0 if not t.is_alive() else 3)
