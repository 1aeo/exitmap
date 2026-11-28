# Phase 1: upstream issue drafts for the 16 patches

One issue per merge request, as you announced in !34 ("will open an issue for
each merge request"), in the order of `phase1-upstream`: most important
first, optional last (see the report for the reasons). gk's own suggestion in
that thread was one issue and then a branch with all the commits; they added
that piecemeal MRs would work as well. Each patch is a single commit on
upstream `main` (`d02f923`); its commit message is the MR description. After
filing an issue, append `Closes #<n>.` to the commit message of the matching
commit, as in the earlier MRs (`Closes #66`, `Closes #68.`).

The reproducers below need no Tor process unless noted. Run them from the root
of an upstream checkout.

Numbers 4 and 5, mr15 and mr16, are new: they are not among your 14
branches. The final cross-check found mr15. mr16 is the bound you asked for
on 2026-11-27. Both go in before mr02.

---

## 1. mr01 — `bin/exitmap` always exits with status 0

Filed on 2026-11-28 as #69, with the merge request !61 (commit `cb56066`,
branch `preserve-exit-status` of `1aeo/exitmap`, fork pipeline 435961
passed). The text below is what was filed.

**Title:** bin/exitmap exits with status 0 after errors

`bin/exitmap` ignores the value `main()` returns and calls `sys.exit(failed)`
inside its `finally` block. A `sys.exit()` in a `finally` block replaces
whatever exception is being propagated, so `SystemExit(1)` from
`bootstrap_tor()` and any unhandled exception (including its traceback) are
lost as well. Scripts and cron jobs running exitmap cannot tell that a scan
did not happen.

```
$ mkdir -p -m 755 /tmp/p; ./bin/exitmap -t /tmp/p/tor checktest; echo $?
Parent directory /tmp/p is not owned by the user or hasn't mask 700.
Removing tmp files...
0
```

Fix: use the return value of `main()` as exit status and move `sys.exit()`
out of the `finally` block (2 lines).

---

## 2. mr03 — exitmap keeps going, or hangs, after Tor died

**Title:** exitmap hangs or keeps creating circuits after the controller died

Follow-up to #61. The aliveness checks added there only run when exitmap
handles an event from Tor or a message from a module, and once after all
circuits were requested.

* If Tor dies while no module is running, nothing sets `finished_event` and
  `EventHandler.wait()` blocks forever.
* If Tor dies while circuits are still being created, `iter_exit_relays()`
  tries (and fails) to create every remaining circuit, sleeping the build
  delay each time. This is the 46 minutes of "could not be created" lines gk
  posted in #61 (note_3286040).
* Afterwards exitmap runs the remaining modules, and `main()` returns 0.
* If Tor dies while one of exitmap's event callbacks is waiting for a reply
  (`GETINFO desc/id/...` in `new_circuit()`, `ATTACHSTREAM` in `new_stream()`),
  stem's event thread never returns from the callback: stem's reader thread
  joins the event thread before it delivers `SocketClosed` to it
  (`BaseController._close()`). The callback keeps stem's listener lock, and
  the reader thread keeps the socket's send lock, so
  `controller.remove_event_listener()` in `shutdown()` and
  `controller.close()` in `main()` both block forever.

Reproduce by killing the Tor process exitmap started while a scan is running.
We checked the first two cases against a private Tor network and all of them
against the emulator described below:

* For the first three cases use an exit file with ten or more fingerprints,
  two modules, `-v debug` and `-d 3`. Kill Tor after a few circuits (the
  remaining ones "could not be created", the next module runs, exit status
  0), or after the last circuit was requested and before a module runs
  (hang).
* gk's steps from #61 (note_3330854) show the last case. Their test patch no
  longer applies (`git apply -3` leaves conflicts). Two lines of it are
  enough: `import time`, and `time.sleep(5)` directly before
  `self.controller.attach_stream(stream_id, circuit_id)` in
  `Attacher._attach()`. With Tor gone during that sleep, current `main` hung
  in every run against the emulator, nearly always in
  `remove_event_listener()`.

Fix: `wait()` checks once a second whether the controller is alive,
`iter_exit_relays()` stops when it is not, `main()` returns 1, and neither
`remove_event_listener()` nor `close()` is called on a dead controller.

How this was tested:

* A private Tor network on one machine (Tor 0.4.9.11, a directory authority
  and two relays, all exits, no outside connections), two modules in one
  run. We killed exitmap's Tor once the first circuit was built, while
  exitmap was still requesting circuits, and in a second run 2 seconds after
  the last circuit was requested, while no module was running and two
  stopped relays held up the circuits. Current `main` went on with the
  remaining circuits and the second module and exited with 0 in the first
  run, and was still waiting 90 seconds after Tor died in the second. With
  this change exitmap logged "Terminating because the controller is not
  alive." and exited 3 and 1 seconds after Tor died, without running the
  second module.
* A real Tor cannot be made to die at an exact point of the protocol, e.g.
  while a `GETINFO` is pending, so the real `bin/exitmap` and stem 1.8.2 were
  also run against a small control-port emulator which emits CIRC/STREAM
  events and can stall or exit at a chosen request. Of its 17 moments at
  which Tor dies, current `main` hangs in 11. With this change exitmap exits
  in all where only stem's event thread is stuck, and when Tor dies while
  circuits are created, while exitmap is idle, while modules run, or right at
  the end of a scan: 11 of 17.

What it does not fix:

* the thread reading from the IPC queue being stuck in the controller, which
  makes `shutdown()` wait forever for it (5 of the remaining 6). That is the
  subject of #ISSUE05; with both changes exitmap exited in 16 of the 17.
* Tor dying while the main thread itself is inside `controller.new_circuit()`
  and an event callback has a request pending. This deadlock is inside stem
  and needs a fix there, see tpo/network-health/stem#11; with that fix as
  well, exitmap exited in all 17.
* the exit status of `bin/exitmap`, which ignores what `main()` returns: it
  stays 0 until !61 is merged.

_Not part of the issue:_ the text above is final (also in `review/exitmap/gitlab/mr03/issue_body.md`). File it together with mr05's and put the number of mr05's issue in place of `#ISSUE05`.

---

## 3. mr05 — shutdown() waits forever for the queue reader thread

**Title:** shutdown() can wait forever for the thread reading from the IPC queue

`EventHandler.shutdown()` joins the thread reading from the IPC queue without
a timeout, and the thread is not a daemon thread, so exitmap cannot exit while
it runs. Three ways to get there:

1. `shutdown()` is left before it stops the thread, e.g. because the module's
   `teardown()` raises. Python then never exits (and with the current
   `bin/exitmap` the exception is not even printed, see #69):

   ```python
   import sys
   from unittest.mock import Mock
   sys.path.insert(0, "src/")
   import eventhandler, stats

   module = Mock()
   module.teardown.side_effect = RuntimeError("teardown() failed")
   handler = eventhandler.EventHandler(Mock(), module, 9050,
                                       stats.Statistics(), {}, None, None)
   handler.shutdown()  # raises; on current main Python then never exits
   ```

2. The thread is blocked in a request to the controller:

   ```python
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
   ```

   This is what happens when Tor dies while an event callback is waiting for a
   reply: stem never releases the lock the thread needs. The snippet calls
   `shutdown()` directly. In a real scan exitmap only gets that far with the
   change for #ISSUE03 (`wait()` returns, and the event listener is left
   alone); on its own this change makes no difference in that case. Against
   a control-port emulator, at 5 of 17 moments at which Tor dies, exitmap
   with the change for #ISSUE03 alone still hung in this thread; with both
   changes it exited at these 5 as well. The commit message says so too.

3. The sentinel which stops the thread cannot be delivered, because a module
   process was terminated while it was writing to the queue and still holds
   the queue's write lock. Rare, but then even a bounded join is not enough:
   Python waits for the queue's feeder thread at exit.

Fix: make it a daemon thread, stop waiting for it after five seconds (with a
warning), and call `cancel_join_thread()` on the queue in that case.

_Not part of the issue:_ the text above is final (also in `review/exitmap/gitlab/mr05/issue_body.md`). Send it together with mr03 and put the number of mr03's issue in place of `#ISSUE03`. Without !61 (#69) the first case ends with exit status 0 and no message instead of a traceback.

---

## 4. mr15 — module processes block forever on the log stream (new)

**Title:** Module processes forked while a log message is written never finish

exitmap forks a process for every probe from stem's event thread
(`EventHandler.new_circuit()`), while the main thread and the thread reading
from the IPC queue go on logging. Python's `logging` module re-initialises the
locks of its handlers in a forked process, but not the lock of the stream's
buffer (`io.BufferedWriter`). A process which is forked while another thread
is writing to the log stream inherits that lock in the locked state and blocks
forever as soon as it logs a message itself. With `-v debug` that is at the
latest "Informing event handler that module finished.", i.e. before it
reports back.

On current `main` nobody notices: `check_finished()` stops waiting for as many
modules as there are failed circuits, and `shutdown()` terminates the blocked
process. The exit relay is simply not probed. If no circuit failed, the scan
never finishes.

The mechanism, without exitmap:

```python
import logging, multiprocessing, threading

logging.basicConfig(filename="/tmp/forklog.log", level=logging.INFO)
log = logging.getLogger()

def other_thread():
    while True:
        log.info("x" * 100)

threading.Thread(target=other_thread, daemon=True).start()
blocked = 0
for i in range(20):
    proc = multiprocessing.Process(target=log.info, args=("child",))
    proc.start()
    proc.join(timeout=1)
    if proc.is_alive():
        blocked += 1
        proc.kill()
print("%d of 20 processes blocked at their first log message" % blocked)
```

With Python 3.10 to 3.13 this prints "20 of 20" after about 20 seconds. The
loop writes a few hundred MB to `/tmp/forklog.log` in that time; delete the
file afterwards. Without `filename=` (logging to stderr) the result is the
same on a terminal; with stderr redirected about half to nearly all processes
block. With `PYTHONUNBUFFERED` set none does, because stderr is unbuffered
then.

The same with exitmap's `EventHandler` (200 built circuits, a module which
logs one line, one more thread logging in a loop). Save it as
`exitmap_forklog.py` and run it from the root of a checkout, with the name of
a log file as argument, or `-` for stderr:

```python
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
```

Current `main` finished 0 or 1 of 200 modules when logging to a file, and
between 0 and 174 of 200 when logging to stderr (it varies from run to run).
With the fix it was 200 of 200 in every run.

These loops log far more than a scan does. In emulated scans (real
`bin/exitmap`, 30 exits, 0.05 s between circuits, `-v debug`, `-o`), 6 of 50
scans on current `main` in which no circuit failed never finished; with the
fix none of 100 did. (The rate depends on the load of the machine: a later
series of the same scans gave 3 of 120.) Counted per forked process, the log stream's lock was
inherited locked in 15 of 3,000 cases with `-v debug` and a log file, 5 of
3,600 with `-v info` and a log file, 1 of 2,400 with `-v debug` on stderr and
0 of 3,000 with `-v info` on stderr; with the fix in 0 of 12,000. With 0.5 s
or more between circuits it did not happen in about 20,000 forks, so it is
practically unreachable with the defaults (`-v info`, stderr, `-d 3`).

Fix: hold the locks of the root logger's handlers around `proc.start()`, so
that no other thread is inside a write at that moment (+11/−1, no test: a
real one needs threads and a fork, a fast one would only assert mocks).

---

## 5. mr16 — exitmap hangs if a module process never reports back (new)

**Title:** exitmap hangs if a module process never reports back

After all circuits were requested, `EventHandler.wait()` blocks until every
circuit is built or failed and the modules reported back, and nothing limits
that wait. A module process which is killed, cannot be started, or blocks in
a read without a timeout (in the tree, `cloudflared` sets none) never reports
back. `check_finished()` stops waiting for one module per failed circuit, so
the scan still ends if at least as many circuits failed as such processes are
missing. Otherwise exitmap never ends: `teardown()` is not called, the
remaining modules do not run, and a cron job waits until somebody kills it.
Today that happens mostly when a single relay or a few exits are scanned.

That changes with the fix for the completion accounting (#N): exitmap then
waits for the module of every built circuit, and a single module process
which never reports back blocks any scan, a full one too. This patch is meant
to go in before that fix.

Reproducer (no Tor needed; run it from the root of a checkout). One built
circuit, and a module which never returns:

```python
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
```

Current `main`: never returns. With the fix it prints, after five minutes (or
after three seconds if `3` is given as argument):

```
No message from a module process for 300 seconds.  No longer waiting for 0 circuit(s) and 1 module process(es).
Scan finished after 300 seconds.
```

Fix: `wait()` gives up once no module process has sent a message for five
minutes (`IDLE_TIMEOUT`); the time only counts once all circuits were
requested. It logs the warning above, counts the circuits it no longer waits
for as failed and the module processes as finished (the statistics are shared
by all modules of a run, so the next module would wait for them again
otherwise), and returns. `shutdown()` then terminates the module processes
which are still running, calls `teardown()` and logs the summary, as at the
end of every scan. The exit status stays 0, as it does when circuits fail.

Why this is not the timeout of #64: it is for the case juga gave for that
timeout in #64, that nothing is put on the queue any more. But that timeout
was five seconds on `queue.get()` itself, it applied during the whole scan,
and when it fired the thread reading from the queue died. This one

* does not limit the thread reading from the queue: `get()` still blocks
  without a timeout;
* only counts once all circuits were requested, so it cannot fire while a scan
  is still creating circuits;
* is not a limit for a module or for a scan, but for silence: a module process
  sends a message whenever it opens a connection over Tor and when it is done,
  and every message of any module process starts the five minutes again. A
  module which takes an hour and opens a connection at least every five
  minutes is not affected;
* ends the scan in the regular way when it fires.

Why five minutes: it is what exitmap gives Tor to start (`timeout=300` in
`bootstrap_tor()`). The modules in the tree which set timeouts use 10 or 20
seconds, exitmap sets Tor's `CircuitBuildTimeout` to 40 seconds, and Tor
fails a stream which is not attached to a circuit after two minutes
(`SocksTimeout`), which bounds what a module without a timeout waits for
while it connects.

What it costs: a module process which opens no connection for more than five
minutes is terminated if no other module process sends a message in that time
either. That can only hit the module processes which are still running at
the end of the scan. In the tree, `patchingCheck` and `cloudflared` use one
connection per probe; they are affected if a download takes more than five
minutes at that point. The five minutes also pass while exitmap itself is
stopped, e.g., with Ctrl-Z.

Limits, for the merge request:

* The counting follows the `check_finished()` of `main`. The second number of
  the warning is what it still waits for, one module process less per failed
  circuit, so it can be lower than the number of module processes which
  `shutdown()` then terminates: with one failed circuit and two silent module
  processes the warning says 1. If Tor reported a circuit which exitmap did
  not create, the warning can count a module process which is not missing, or
  read "0 circuit(s) and 0 module process(es)", and every following module of
  the run waits five minutes again.
* A circuit which `wait()` gives up on counts as failed, and the
  `check_finished()` of `main` stops waiting for one module process per failed
  circuit. If the other module processes of that module had all reported
  back, a later module of the run therefore ends that many module processes
  early, as after any failed circuit today.
* The fix for the completion accounting (#N) removes the three points above.
* A module process which reports back between the give-up and the
  termination of the processes is counted twice, and a later module of the
  same run can then end with module processes still running. After a hang
  that window is a few milliseconds; after exitmap was stopped with Ctrl-Z for
  longer than five minutes, it is the moment the module processes, which
  continue with exitmap, report back. A circuit which Tor reports in the
  window is counted twice as well; a later module of the run can then end
  before all its circuits are built or all its module processes have reported
  back, or wait five minutes and give up with "0 circuit(s) and 0 module
  process(es)". We have the fix ready and will send it as a follow-up merge
  request once this one is merged.
* Without the change which ends the scan when the controller dies (#M), this
  patch also ends the wait if Tor died while exitmap was waiting: five minutes
  later, with the warning above, and exitmap then goes on as it does today
  after Tor's death.

How this was tested: we could not make a module hang at a chosen point in a
scan of the Tor network, so the real `bin/exitmap` ran against a private Tor
network on one machine (Tor 0.4.9.11, a directory authority and two relays,
all exits, no outside connections) and against a small control-port emulator.

* With the real Tor and the limit as shipped, a probe blocked in `recv()` on
  its Tor stream was given up 301 seconds after the last message: exitmap
  logged the warning, called `teardown()` and exited with 0. Current `main`
  was still waiting when we stopped it after seven minutes. A healthy scan
  took 7.6 seconds with and without the patch, and a probe that waited two
  minutes for Tor's `SocksTimeout` was not cut off.
* With the limit lowered to 20 seconds in a copy, probes that were stuck or
  killed ended the scan 21 seconds after the last message, with one warning;
  with two modules in one run the second module ran in full. A probe that
  resolved a name every four seconds for 48 seconds was not cut off; one that
  slept for 45 seconds was, which is the cost described above.
* The emulator showed the same with ten exits, failed circuits and circuits
  that were never reported.
* The unit tests patch the clock, so they take no time.

File the issue for mr02 (section 6) before this one, so that this text can
name it in place of `#N`; its merge request still comes after this one. `#M`
is the issue of mr03. Open the merge request after mr03 is merged: both turn
the single line of `wait()` into a loop, and the commit on `phase1-upstream`
is the form that fits on top of mr03.

If gk asks for documentation, two sentences for `doc/HACKING.md`, after the
list of `probe()`'s arguments: "Your module should not block forever, so set
timeouts for its network interaction. Once all circuits are requested,
exitmap terminates the probes which are still running if no probe opened a
connection or finished for five minutes." In the series they would have to
be kept apart from the paragraphs mr13 and mr14 add to the same file.

---

## 6. mr02 — scans end while modules are still running

**Title:** Scan is finished while modules are still running if circuits failed

`EventHandler.check_finished()` ends a scan when all circuits are built or
failed and `finished_streams >= successful_circuits - failed_circuits`. With
`F` failed circuits it therefore stops waiting for up to `F` of the last
running modules, and `shutdown()` terminates them. Every scan with failed circuits
(3–6% is normal, see #4) silently loses the results of the exits probed last.

Reproducer (feeds the real `EventHandler` one FAILED and one BUILT circuit
event, with a module whose `probe()` takes two seconds):

```python
import sys, time, types
from unittest.mock import Mock
sys.path.insert(0, "src/")
import eventhandler
from stats import Statistics
from stem import CircStatus

EXIT = "B" * 40

def probe(exit_desc, run_python_over_tor, **kwargs):
    time.sleep(2)
    print("probe() finished")

stats = Statistics()
stats.total_circuits = 2
handler = eventhandler.EventHandler(
    Mock(), types.SimpleNamespace(probe=probe), 9050, stats,
    exit_destinations={EXIT: set()}, target_host=None, target_port=None)
handler.new_circuit(Mock(id="1", status=CircStatus.FAILED, reason="TIMEOUT"))
handler.new_circuit(Mock(id="2", status=CircStatus.BUILT,
                         path=[("A" * 40, "guard"), (EXIT, "exit")]))
start = time.monotonic()
handler.wait()
handler.shutdown()
print("Scan finished after %.1fs with %d of %d modules done." % (
    time.monotonic() - start, stats.finished_streams,
    stats.successful_circuits))
```

Current `main`: `Scan finished after 0.0s with 0 of 1 modules done.`
With the fix: `probe() finished` / `Scan finished after 2.0s with 1 of 1 modules done.`

The fix has three parts which belong together:

1. Wait for the modules of all built circuits (drop `- failed_circuits`).
2. Once every built circuit needs a finished module, circuits which Tor builds
   on its own must not be counted. Today they are counted as built and then
   raise a `KeyError` in `new_circuit()`. Ignore built circuits whose last hop
   is not one of the selected exits. (exitmap asks Tor not to build such
   circuits; gk described in #36 how they stall a scan.)
3. Failed circuits we did not create cannot be told apart and are still
   counted, so compare with `>=` instead of `==`; otherwise the scan never
   finishes once more circuits were seen than expected.

Two things to mention in the MR so nobody is surprised:

* The scan now waits for every module process. One which never reports back
  delays the end of the scan until `wait()` gives up on it (mr16: five
  minutes without a message from any module process); so far it was
  terminated at the end of the scan if enough circuits had failed. That
  takes no faulty module: the process may be killed, or, before mr15, block
  on the log stream's lock. A module without timeouts can do it too; in the
  tree `cloudflared` opens its connection without one.
* A failed circuit that exitmap did not create can still end a scan before our
  last circuit is built. That is not new, and fixing it needs per-circuit
  bookkeeping.

Submit after mr15 and mr16, with the commit from `phase1-upstream`. That one
also changes one line in `wait()`, so that mr16 counts the module processes
of all built circuits as well, and its message says that a module process
which never reports back "now delays the end of the scan until wait() gives
up on it". The single branch `mr02/fix-check-finished` is for `main` without
mr16: there such a process "now blocks the scan", and its message says so.

---

## 7. mr08 — an empty exit file scans every exit

**Title:** An empty --exit-file makes exitmap scan all exit relays

`relayselector.get_exits()` skips the `requested_exits` filter when the list
is empty instead of only when it is `None` (which is what its docstring says).
`select_exits()` passes `[]` for an empty file, so instead of scanning nothing
exitmap builds circuits to every exit relay.

```python
>>> import sys; sys.path.insert(0, "src/")
>>> import relayselector
>>> len(relayselector.get_exits("test/data", requested_exits=[]))
2290
```

Fix: test for `None` (2 lines).

---

## 8. mr09 — lowercase fingerprints are never selected

**Title:** -e/--exit and -E/--exit-file do not accept lowercase fingerprints

Requested exit fingerprints are compared as given to the uppercase
fingerprints from the consensus, so `exitmap -e <lowercase fingerprint> ...`
ends with "No exit relays meet basic filter conditions" and "Exit selection
yielded 0 exits". Worse, lowercase lines in an exit file which also contains
uppercase fingerprints are skipped without any message. `-i/--first-hop`
already accepts lowercase, since `util.relay_in_consensus()` converts it.

Fix: convert the given fingerprints to uppercase (2 lines).

---

## 9. mr10 — booleans in ~/.exitmaprc are always true

**Title:** Boolean options in the config file are always true

Values from the config file are strings. argparse converts string defaults
with the option's `type`, but `store_true` options have none, so
`bad_exits = false` becomes the true string `"false"`:

```
$ printf '[Defaults]\nbad_exits = false\n' > /tmp/exitmaprc
$ python3 -c 'import sys; sys.path.insert(0, "src/"); import exitmap
sys.argv = ["exitmap", "-f", "/tmp/exitmaprc", "checktest"]
print(repr(exitmap.parse_cmd_args().bad_exits))'
'false'
```

With that value exitmap scans bad exits only.

Fix: convert the values of boolean options with `getboolean()`. The option's
default tells whether it is boolean, so the config defaults are now applied
once, after all arguments were added (the earlier `set_defaults()` call was
redundant). A value which is not a boolean is now an error
(`exitmap: error: bad_exits in <path of the config file>: Not a boolean:
maybe`); so far it silently counted as true, and an empty value as false.

---

## 10. mr12 — implements #22

Comment on #22 first, then open the MR with `Closes #22.` (already in the
commit message).

**Suggested comment:** We have a small patch for this: exitmap remembers the
first hop and exit relay of every circuit it creates and, when a circuit fails
(FAILED event or an error from `new_circuit()`), logs

```
Circuit with exit relay "<fingerprint>" and first hop "<fingerprint>" failed because: TIMEOUT
```

and keeps the same data in `Statistics.failed_circuit_relays`. That is one
INFO line per failed circuit, written when the failure happens rather than as
a list at the end; happy to change the level or the timing if you prefer. It
replaces the debug message "Circuit with exit relay ... could not be created".

Known limit: a circuit whose FAILED event is handled before `new_circuit()`
returned its ID cannot be assigned to an exit and is only counted, as today.

Submit after mr03: without it exitmap keeps requesting circuits after Tor
died, and every remaining exit is then logged as a failed circuit.

---

## 11. mr11 — option to use the filters from #65 (follow-up to #65/!44)

**Title:** Add an option to only use reliable relays as first hops

!44 added the filters to `get_fingerprints()` and announced a follow-up to
make them usable from the command line. This adds `-r/--reliable-first-hop`,
which restricts the random first hops to relays with the Guard, Stable, Fast,
Running and Valid flags that are not BadExit, are authority-measured and have
a consensus bandwidth of at least 5000 KB/s. These settings follow the test in
#65 (15 of 318 circuits failed with all relays, 5 of 318 with such guards);
the BadExit exclusion is not in the description of that test, but in the
example of !44.

If fewer than two relays pass the filters, exitmap logs a warning and picks the first
hops from all relays. That happens while fewer than three bandwidth
authorities are measuring: every relay is unmeasured then (dir-spec, as on
the public network in February 2018), and without the fallback every scan
with `-r` would stop at the first circuit.

The option cannot be combined with a first hop, whether that comes from
`-i/--first-hop` or from `first_hop` in the config file; exitmap exits with an
error in that case. (`-i ''` overrides a first hop from the config file.
`reliable_first_hop = true` in the config file cannot be switched off on the
command line, like the other boolean options.)

Submit after mr10: without it `reliable_first_hop = false` in the config file
would switch the option on.

Relates to #65 and #4.

---

## 12. mr06 — teardown() skipped when no exits are selected (optional)

**Title:** Module's teardown() is not called if no exit relays are selected

`run_module()` calls the module's `setup()` before selecting exits. If the
selection is empty it raises `ExitSelectionError`, which `main()` logs before
continuing with the next module. `teardown()` is never called, so e.g.
`patchingCheck` leaves the reference files it downloaded in `setup()` behind.

Fix: call `teardown()` before raising the exception.

Note: if this and mr14 are both merged, this call has to pass `stats=stats`
too, and whichever lands second has to carry that change. In the order of
`phase1-upstream` that is mr14, and its commit there has the two lines. If
you submit this one after mr14 instead, nothing will remind you: rebasing it
onto a `main` with mr14 is clean, and tests and flake8 pass without the
change. The second of the two then needs two one-line edits:

* `src/exitmap.py`: `module.teardown()` becomes `module.teardown(stats=stats)`
* `test/test_exitmap.py`: `module.teardown.assert_called_once()` becomes
  `module.teardown.assert_called_once_with(stats=stats_obj)`

Without them a module with `def teardown(stats, **kwargs)` raises a
`TypeError` when no exits are selected, and the remaining modules are skipped.

Submit after mr01: if `teardown()` raises when no exit was selected, the run
stops there, and without mr01 it ends with status 0 and no message.

---

## 13. mr13 — first hop for modules (optional)

**Title:** Pass the first hop of a circuit to the module's probe()

A module only gets the descriptor of the exit relay. When a probe fails it
cannot log which first hop the circuit used, which is what one needs to tell
a broken exit from a bad first hop (#4). The patch passes the first hop's
fingerprint as keyword argument `first_hop` and documents it in
`doc/HACKING.md`.

All modules in the tree accept `**kwargs`. Modules outside the tree need to do
so as well: one which lists its parameters without `**kwargs` fails with a
`TypeError`, which is logged for every exit relay.

---

## 14. mr14 — statistics for teardown() (optional)

**Title:** Pass the scan statistics to the module's teardown()

`teardown()` is called without arguments, so a module cannot store or report
the scan's statistics (circuits built/failed, and with #22 the failed exits)
together with its own results. The patch passes the `Statistics` object as
keyword argument `stats`, lets `patchingCheck.teardown()` accept keyword
arguments, and documents `setup()` and `teardown()` in `doc/HACKING.md`.

Modules outside the tree which define `teardown()` need to accept `**kwargs`;
a `teardown()` without parameters raises a `TypeError` once this is merged.
Submit after mr01 and mr05: with them that error is printed and exitmap exits;
without them it is swallowed and exitmap hangs at exit.

If mr06 is merged as well, see the note there: the second `teardown()` call
it adds has to pass `stats=stats` too. The mr14 commit on `phase1-upstream`
does that; the single `mr14` branch, which does not have mr06, cannot.

---

## 15. mr04 — terminated module processes are not reaped (optional)

**Title:** Module processes terminated at shutdown are not joined

`EventHandler.shutdown()` calls `terminate()` on the module processes which
are still running but never joins them. They stay around as zombies until the
next module process is started or exitmap exits, and they may still be running
when the module's `teardown()` is called right afterwards.

Fix: join each process after terminating it (2 lines). This is tidying up
rather than a bug with a visible symptom.

---

## 16. mr07 — controller not closed if the first hop is unknown (optional)

**Title:** Controller is not closed if the first hop is not in the consensus

`main()` checks `--first-hop` against the consensus right before the `try`
block whose `finally` clause closes the controller, and returns 1 without
closing it. Moving the check into the `try` block fixes that; with
`git diff -w` the change is a single moved line.

---

## Separate: the torsocks fix for #46 (`mr17`, not in `phase1-upstream`)

No new issue: #46 ("Support scanning multiple targets over the full exit
list", open) is the issue. Open the merge request with
`review/exitmap/torsocks/mr-description.md`, then post
`review/exitmap/torsocks/issue46-comment.md` in #46 with the number of the
merge request in place of `!NN`. The commit ends with "Relates to #46."; the
comment offers to change that to "Closes #46" if gk agrees. It depends on
none of the 16 patches, and none of them on it. The evidence is in the
README of that folder.

---

## Separate: late reports after `wait()` gave up (`mr18`, not in `phase1-upstream`)

A follow-up to mr16. No issue of its own: it removes the limit that the
merge request of mr16 names in its "Limits" (the bullet that ends "We have
the fix ready ..."). Send it once the merge requests of mr03, mr16 and mr02
are merged, mr02 in its `phase1-upstream` form: the commit (`fc40ee8`, on
the tip of `phase1-upstream`) changes lines that mr16 adds and mr02 changes,
next to mr03's check of the controller. Cherry-pick it onto upstream `main`
rather than pushing its branch, which carries all 16 patches; end its
commit message with `Relates to #<issue of mr16>.`. The merge request text
is `review/exitmap/mr18/mr-description.md`, with `!MR16` and `#ISSUE16`
replaced; the evidence is in the README of that folder.
---

## Not for exitmap: the deadlock in stem

Filed on 2026-11-28 as tpo/network-health/stem#11, with the fix as
tpo/network-health/stem!11; the mr03 draft above already names #11. The
material behind it is in `review/stem/`: the issue text, the merge request
text, the commit as a patch file, three scripts (two reproducers of the bug,
one that shows the known cost of the fix) and the test scripts behind its
numbers.
