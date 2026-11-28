**Title:** Count nothing once the scan of a module is over

When `wait()` gives up, it counts the circuits which are neither built nor failed yet as failed, and the module processes which have not reported back as finished, because all modules of a run share the statistics. But a module process can still report back, and Tor can still report one of these circuits, until `shutdown()` has removed the event listener and terminated the processes. These are then counted a second time, and the next module of the run ends too early, before all its circuits are built or before all its module processes reported back. If a circuit is built that late, exitmap also starts a module process for it, which `shutdown()` terminates before it can report back, and the next module waits for that process until `wait()` gives up again.

After a hang, this needs a module process which reports back within the few milliseconds that `shutdown()` takes. But if exitmap was stopped, e.g., with Ctrl-Z, for longer than the time limit, `wait()` gives up as soon as exitmap continues unless a message from a module process comes first. The module processes continue as well and may report back just then.

So once the scan of a module is over, because `check_finished()` found it finished, because the controller died or because `wait()` gave up, count no more reports and circuit events, and start no module process for a circuit which is reported after that. `wait()` now corrects the counters while holding `check_finished_lock`, and the queue reader and `new_circuit()` hold it while they count, so that what arrives while `wait()` gives up is counted either before the correction or not at all. As `check_finished()` does, `wait()` also sets `finished_event` then.

Failed circuits which we did not create can still end the scan before all circuits of the module are requested. The exit relays whose circuits are built after that are now no longer probed. So far their module processes were started, and one which had not finished when the last circuit was requested was terminated by `shutdown()`, after which the next module of the run waited for it until `wait()` gave up.

Not changed here: the next module of the run still counts the circuits of this module which Tor reports after the next module has added its event listener, and can then end that many circuits early. After a give-up, that needs a circuit to stay pending for longer than five minutes; after an early end, it can be the circuits requested last.

This is a follow-up to !MR16. It removes the limit that the description of !MR16 names for what is reported between the give-up and the end of `shutdown()`: neither a module process which reports back nor a circuit which Tor reports is counted twice any more.

How we tested it:

* A reproducer that needs no Tor; run it from the root of a checkout. It prints "2 module process(es) counted as finished for 1 built circuit(s)." without this change and 1 with it:

  ```python
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
  ```

* Against a small control-port emulator in place of Tor, on Python 3.11, 3.12 and 3.13, with the limit set to 5 seconds in a copy and two modules in one run (10 exits each, every probe sleeping 4 seconds), we stopped exitmap, its module processes and the fake tor with SIGSTOP 1 second after the last circuit was requested (Ctrl-Z stops them the same way, with SIGTSTP) and continued them 7 seconds later. Without this change, `wait()` gave up in 17 of 28 runs, and the second module then ran only 0 to 3 of its 10 probes; in the other runs the probes reported back before `wait()` looked at the clock. With it, the second module ran all 10 probes in all 28 runs, `wait()` having given up in 14 of them. With Python 3.10 this setup does not show the problem: there, the `time.sleep()` of the fake probes does not count the time they were stopped, so they were still sleeping when they were terminated.
* The new unit test lets `wait()` give up, then delivers a FAILED and a BUILT event and a report from a module process. None of them is counted, no module process is started, and the thread reading from the queue still closes the circuit of the late report and ends; without the change the test fails.

Relates to #ISSUE16.
