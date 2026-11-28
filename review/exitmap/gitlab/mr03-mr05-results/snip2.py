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
