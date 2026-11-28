"""Feed the real EventHandler built circuits while another thread logs to the
log file, as exitmap's main thread and queue reader thread do.
usage (from the root of a checkout): exitmap_forklog.py <logfile>|- [N]"""
import logging
import sys
import threading
import time
import types
from unittest.mock import Mock

sys.path.insert(0, "src/")
import eventhandler  # noqa: E402
from stats import Statistics  # noqa: E402
from stem import CircStatus  # noqa: E402

# "-" logs to stderr, like exitmap without -o/--logfile.
logging.basicConfig(filename=None if sys.argv[1] == "-" else sys.argv[1],
                    level=logging.INFO)
log = logging.getLogger("repro")
EXITS = ["%040X" % i for i in range(int(sys.argv[2]) if len(sys.argv) > 2
                                    else 200)]


def probe(exit_desc, **kwargs):
    log.info("Probing an exit relay.")


def other_thread(stop):
    while not stop.is_set():
        log.info("Some other thread of exitmap logs a message.")


stats = Statistics()
stats.total_circuits = len(EXITS)
handler = eventhandler.EventHandler(
    Mock(), types.SimpleNamespace(probe=probe), 9050, stats,
    exit_destinations={e: set() for e in EXITS},
    target_host=None, target_port=None)
stop = threading.Event()
threading.Thread(target=other_thread, args=(stop,), daemon=True).start()
for i, exit_fpr in enumerate(EXITS):
    handler.new_circuit(Mock(id=str(i), status=CircStatus.BUILT,
                             path=[("A" * 40, "guard"), (exit_fpr, "exit")]))
deadline = time.monotonic() + 10
while (stats.finished_streams < stats.successful_circuits and
       time.monotonic() < deadline):
    time.sleep(0.1)
stop.set()
print("%d of %d modules finished." % (stats.finished_streams,
                                      stats.successful_circuits))
sys.stdout.flush()
# Don't wait for the blocked processes or the queue reader thread.
import multiprocessing  # noqa: E402
import os  # noqa: E402
for proc in multiprocessing.active_children():
    proc.kill()
os._exit(0)
