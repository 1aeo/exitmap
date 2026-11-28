"""One built circuit whose module never returns.  On upstream main wait()
never returns.  With the mr16 commit it gives up after IDLE_TIMEOUT seconds.
usage (from the root of a checkout): stuck_probe.py [seconds]
The argument replaces the 300 seconds, only to try it quickly."""
import sys, time, types
from unittest.mock import Mock
sys.path.insert(0, "src/")
import eventhandler
from stats import Statistics
from stem import CircStatus

EXIT = "B" * 40

def probe(exit_desc, run_python_over_tor, **kwargs):
    time.sleep(100000)  # stands for a read without a timeout

if len(sys.argv) > 1:
    eventhandler.IDLE_TIMEOUT = int(sys.argv[1])  # only to try it quickly
stats = Statistics()
stats.total_circuits = 1
handler = eventhandler.EventHandler(
    Mock(), types.SimpleNamespace(probe=probe), 9050, stats,
    exit_destinations={EXIT: set()}, target_host=None, target_port=None)
handler.new_circuit(Mock(id="1", status=CircStatus.BUILT,
                         path=[("A" * 40, "guard"), (EXIT, "exit")]))
start = time.monotonic()
handler.wait()
handler.shutdown()
print("Scan finished after %.0f seconds." % (time.monotonic() - start))
