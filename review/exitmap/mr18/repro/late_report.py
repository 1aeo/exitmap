import multiprocessing
import sys
import time
import types
from unittest.mock import Mock
sys.path.insert(0, "src/")
import eventhandler
from stats import Statistics
from stem import CircStatus

EXIT = "B" * 40
multiprocessing.set_start_method("fork")  # the default on Linux up to Python 3.13
release = multiprocessing.Event()


def probe(exit_desc, run_python_over_tor, **kwargs):
    release.wait()  # stands for a module process which is slow to report


eventhandler.IDLE_TIMEOUT = 1  # only to try it quickly
stats = Statistics()
stats.total_circuits = 1
handler = eventhandler.EventHandler(
    Mock(), types.SimpleNamespace(probe=probe), 9050, stats,
    exit_destinations={EXIT: set()}, target_host=None, target_port=None)
handler.new_circuit(Mock(id="1", status=CircStatus.BUILT,
                         path=[("A" * 40, "guard"), (EXIT, "exit")]))
handler.wait()   # gives up on the module process
release.set()    # which reports back before shutdown() terminated it
time.sleep(0.5)
handler.shutdown()
print("%d module process(es) counted as finished for %d built circuit(s)."
      % (stats.finished_streams, stats.successful_circuits))
