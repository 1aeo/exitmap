# mr18: count nothing once the scan of a module is over

A follow-up to mr16 (the time limit of `wait()`), separate from the 16
patches of `phase1-upstream`.

- Branch: `mr18/ignore-late-events`, one commit (`fc40ee8`) on the tip of
  `phase1-upstream` (`a212bd7`), author and committer `1aeo <tor@1aeo.com>`,
  unsigned, no trailers. `src/eventhandler.py` +26/-12,
  `test/test_eventhandler.py` +32.
- `0001-Count-nothing-once-the-scan-of-a-module-is-over.patch`: the same
  commit, for `git am`.
- `mr-description.md`: the merge request text. `!MR16` and `#ISSUE16` stand
  for the merge request and the issue of mr16.
- `repro/late_report.py`: the reproducer of the merge request text, which
  needs no Tor.

## How to submit

Once the merge requests of mr03, mr16 and mr02 are merged upstream. The
commit changes lines that mr16 adds and mr02 changes, next to mr03's check
of the controller in `wait()`, and it needs mr02 in its `phase1-upstream`
form, which also changes mr16's modules line (the single branch of mr02
does not).

Do not push `mr18/ignore-late-events`: it carries all 16 patches of the
series, and upstream will have merged other commits than those (mr01, for
example, as `cb56066`). Make a new branch from upstream `main` instead and
`git cherry-pick fc40ee8` onto it; it applies cleanly, and so does the
patch file with `git am`, on the series up to mr02 (`6585d86`). Run the
tests and flake8, end the commit message with
`Relates to #<issue of mr16>.`, push that branch and open the merge request
with `mr-description.md`. No issue of its own: it removes a limit that the
merge request of mr16 names.

## What it fixes

When `wait()` gives up, it counts the circuits which are neither built nor
failed yet as failed and the module processes which have not reported back
as finished, because all modules of a run share the statistics. Until
`shutdown()` has removed the event listener and terminated the processes, a
module process can still report back and Tor can still report one of those
circuits. Each is then counted a second time, and the next modules of the
run start with counters that are off:

| Arrives after the give-up | What happens |
| --- | --- |
| report from a module process | the next module stops waiting for its module processes one too early; `shutdown()` terminates the last one |
| FAILED event | the next module stops waiting for its circuits one too early |
| BUILT event | exitmap starts a module process that `shutdown()` terminates; the next module waits for it until `wait()` gives up again, and the module after that stops waiting for its circuits one too early |

After a hang the window is a few milliseconds (`results/window_*.txt`, with
a fake controller, so without Tor's reply to SETEVENTS: the listener is
removed 0.07 ms after the give-up, the module processes are terminated
within 1 to 43 ms). After a stop with Ctrl-Z it can be wide open: as soon
as exitmap continues, `wait()` gives up unless a message from a module
process comes first, and the module processes, stopped and continued with
it, may report back just then.

## The change

- `wait()` sets `already_finished` and `finished_event` and corrects the
  counters while holding `check_finished_lock`.
- The queue reader counts a finished module process, and `new_circuit()`
  counts a circuit event, only while holding that lock and only if
  `already_finished` is not set. Otherwise `new_circuit()` returns, so no
  module process is started either. The reader still closes the circuit of
  a late report.
- `already_finished` is also set when `check_finished()` finds the scan
  finished or the controller dead, so the same holds after every end of a
  module's scan. After a normal end nothing more is expected, unless
  circuits were counted that are not ours (a failed circuit that Tor built
  on its own, see mr02's message) or counted twice (a circuit that Tor
  rejects with 551, see the report). Then `check_finished()` can end the
  scan while `iter_exit_relays()` still requests circuits. With this patch
  the exits whose circuits are built after that are neither counted nor
  probed, and their circuits stay open. Before, such an exit was probed if
  its probe ended before the last circuit was requested; otherwise
  `shutdown()` terminated the probe, which also left the circuit open, and
  the next module waited for it until `wait()` gave up. In the review's
  emulator runs (`scripts/early_end.py`, `results/early_end/`, made with
  `89160dd`; 10 exits, two answered with 551, build delay 1 s), 7 exits
  were probed on `a212bd7` and 6 with mr18 with probes of 0.5 s, and 6 on
  both with probes of 0.9 s, where on `a212bd7` the second module then
  waited until `wait()` gave up. The commit message says this.
- Lock order: `check_finished_lock` is taken before the lock of a logging
  handler (`update_circs()` logs) and before the lock in `Statistics` on your
  fork's `main`; nothing takes them the other way round. mr15 holds the
  logging locks only around `proc.start()`, after `check_finished_lock` was
  released.
- Not changed: a circuit which Tor reports only after the next module of
  the run has added its listener is counted by that module. That needs a
  circuit to stay pending for longer than the five minutes of the give-up.

## Tests and numbers

The scripts and results were made with the code of `fc40ee8`, except the
Ctrl-Z runs, which used `89160dd`, the first version of the commit; its
`src/eventhandler.py` differs from `fc40ee8` only in two comments.

- Unit tests: `test_nothing_counted_after_giving_up` (new) lets `wait()`
  give up, then delivers a FAILED and a BUILT event and a report from a
  module process. None is counted, no module process is started, and the
  queue reader closed the late report's circuit and went on to the shutdown
  signal, so a reader that hangs, dies or skips its work on a late report
  fails it. It fails on `a212bd7`. `test_wait_gives_up_on_silent_modules`
  (mr16) is unchanged; it now also checks that `wait()` sets
  `finished_event`. 50 tests pass on Python 3.10, 3.11, 3.12 and 3.13, and
  flake8 is clean.
- `results/mutate18.txt`: 26 altered versions of the change. The tests
  catch 22. The 4 others: three that remove the lock from one of the three
  places, and one that only reorders two statements inside the lock. The
  race scripts of the next point count the same with the first three,
  because `wait()` sets `already_finished` before anything they deliver is
  handled. `scripts/trace_pause.py` holds the queue reader or `new_circuit()`
  for 2.5 s on the line that counts while `wait()` gives up: `a212bd7`
  counts the report, the BUILT and the FAILED event twice
  (`results/trace_pause_tip.txt`) and mr18 each once
  (`results/trace_pause_mr18.txt`). Without the lock in the queue reader the
  report is counted twice, without it in `new_circuit()` the BUILT and the
  FAILED event, and without it in `wait()` all three; the reordering counts
  each once. `mutate18.py` runs `trace_pause.py` on every version that the
  tests miss.
- `results/late_events_*.txt`, `during_giveup_*.txt`, `three_modules_*.txt`,
  `controller_dies_*.txt`, `window_*.txt`: the real `EventHandler`,
  `Statistics`, queue, reader thread and forked module processes with a fake
  controller; a late report, FAILED or BUILT event is delivered after the
  give-up or while `wait()` is inside it, then the next modules of the run
  are driven. On `a212bd7`, the next module ends early or waits again in 8
  of the 9 cases with a late event (the 6 cases without one are fine), and
  the event that arrives during the give-up is counted in all 3 cases. With
  mr18 all 15 and all 3 are correct, and `wait()` still returns when the
  controller dies.
- `results/late_report.txt`: `repro/late_report.py`, run from the root of a
  tree, prints 2 module processes counted as finished for 1 built circuit
  on `a212bd7` and 1 with mr18, on Python 3.13 and 3.10.
- `results/ctrlz_*.txt`: the real `bin/exitmap` against the emulator's fake
  tor (`../emulator`), limit 5 s, modules `boundmod` and `fakemod2` over 10
  exits each, every probe sleeping 4 s; exitmap, its module processes and
  the fake tor are stopped with SIGSTOP 1 s after the last circuit was
  requested and continued 7 s later.

| Python | without mr18: `wait()` gave up | second module after it | with mr18: `wait()` gave up | second module |
| --- | --- | --- | --- | --- |
| 3.13 (`ctrlz_round1_py313.txt`, `ctrlz_tip.txt`, `ctrlz_mr18.txt`) | 10 of 16 | 0 to 3 of 10 probes | 7 of 16 | 10 of 10 in all 16 |
| 3.12 | 3 of 6 | 1 to 3 | 3 of 6 | 10 of 10 in all 6 |
| 3.11 | 4 of 6 | 0 | 4 of 6 | 10 of 10 in all 6 |
| 3.10 | 6 of 6 | 10 of 10 | 6 of 6 | 10 of 10 in all 6 |

With Python 3.10 these runs show nothing: in every run `wait()` gave up, no
probe of the first module reported back, and the second module ran all 10
probes. Python 3.10's `time.sleep()` calls `select()` with a relative
timeout, which does not count the time the process was stopped, so after
SIGCONT the test probes sleep on and `shutdown()` terminates them first.
This comes from the test probe, not from exitmap: socket timeouts, in which
real probes wait, count that time on 3.10 as well. With the probe waiting in
`recv()` with a timeout instead (`boundmod_sockprobe.diff`), 3.10 shows the
same race (`ctrlz_*_py310_sockprobe.txt`): without the change, the second
module ran 1, 0, 2 and 1 of its 10 probes in the 4 of 5 runs in which
`wait()` gave up; with it, all 10 in 5 of 5.

## Running the scripts

    python3 scripts/late_events.py <tree>/src <label>      # also during_giveup,
                                                            # controller_dies,
                                                            # three_modules, window,
                                                            # trace_pause
    python3 scripts/ctrlz.py ../emulator <tree> <label> 8
    python3 scripts/mutate18.py <mr18 tree> <python with pytest>
    cd <tree> && python3 <this folder>/repro/late_report.py

`<tree>` is an export of `mr18/ignore-late-events` or of `phase1-upstream`;
`mutate18.py` needs the export of `mr18/ignore-late-events`, as its altered
versions are made for that code. The scripts need a python3 with stem and
PySocks; `ctrlz.py` runs exitmap with the same interpreter and uses the
emulator's `run.py`.
