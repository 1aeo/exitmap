import sys
from unittest.mock import Mock
sys.path.insert(0, "src/")
import eventhandler, stats

module = Mock()
module.teardown.side_effect = RuntimeError("teardown() failed")
handler = eventhandler.EventHandler(Mock(), module, 9050,
                                    stats.Statistics(), {}, None, None)
handler.shutdown()  # raises; on current main Python then never exits
