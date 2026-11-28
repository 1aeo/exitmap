# Emulator: a fake Tor for end-to-end runs of exitmap

`faketor/tor` is a small Python program that exitmap starts in place of Tor.
It plays one scripted scenario: it answers the control port, reports circuits
and streams, and exits or stops answering at a chosen moment. `run.py` runs
`bin/exitmap` of a checkout against it and tells for each scenario whether
exitmap ended or hung. No Tor and no network are needed.

- `run.py`: the driver, with the tables of scenarios.
- `faketor/tor`: the fake tor. Its docstring lists what a scenario can ask for.
- `fakemods/`: the exitmap modules that the probes run.
- `data/`, `trim_data.py`: Tor directory data and the script that trimmed it.

## What the fake tor implements

- `tor --version`, the configuration on stdin (only `DataDirectory` is used),
  two ports chosen by the kernel, and the log lines from which stem and
  exitmap learn the ports and that Tor is ready.
- One control connection without authentication: PROTOCOLINFO, AUTHENTICATE,
  SETEVENTS, GETCONF, EXTENDCIRCUIT, CLOSECIRCUIT, ATTACHSTREAM, QUIT, and
  GETINFO for `version`, `circuit-status` and `desc/id/<fingerprint>`.
  SETCONF, RESETCONF and TAKEOWNERSHIP get `250 OK` and have no effect.
- A CIRC event, BUILT or FAILED, 0.2 s after EXTENDCIRCUIT. A STREAM NEW
  event 0.2 s after a SOCKS5 request; ATTACHSTREAM completes that request.

It is not Tor. It builds no circuit, passes no data, contacts no relay, checks
no signature, and its timing is the scenario's. A result shows how exitmap and
stem handle one sequence of replies and events, not that Tor produces it.

## How to run it

It was run on Linux with Python 3.13, and every row of the first table of
"Expected results" once with Python 3.10, 3.11 and 3.12. The fake tor needs
`python3` on the `PATH`. exitmap needs an interpreter with its requirements;
`run.py` checks stem and PySocks. In the commands `~/exitmap` is a clone of
this repository with the branches `phase1-upstream` (upstream `main` and 16
patches) and `mr16/bound-module-wait` (upstream `main` and only the patch for
the time limit of `wait()`). If a clone has them as remote branches only, put
`origin/` in front of the names. Both start from the same commit of upstream
`main`, which `mr16/bound-module-wait~1` names. `run.py` uses only `bin/` and
`src/` of a tree, so a later state of a branch that changes only other files,
such as the tests, gives the same results.

    mkdir /tmp/em-up /tmp/em-16
    git -C ~/exitmap archive mr16/bound-module-wait~1 | tar -x -C /tmp/em-up  # upstream main
    git -C ~/exitmap archive phase1-upstream | tar -x -C /tmp/em-16           # + 16 patches
    python3 run.py --exitmap /tmp/em-up --stem ~/stem-maint @death
    python3 run.py --exitmap /tmp/em-16 --stem ~/stem-fixed @death @normal

- `--exitmap DIR`: the exitmap tree. `run.py` copies its `bin/` and `src/` to
  a temporary directory and adds the fake modules there. DIR is not changed.
- `--stem DIR`: a stem checkout, the directory that holds `stem/`. Use stem's
  branch `maint` for stem without the fix, and `maint` with the patch from
  `../../stem/` applied (`git am`) for the fixed stem; measured on `maint` at
  0782931d. Without `--stem` the stem installed for the interpreter is used.
  The output says which one ran.
- `--python PATH`: the interpreter for exitmap; by default the one that runs
  `run.py`. `--jobs N`: run N scenarios at a time. `--keep DIR`: work in DIR,
  which must be new or empty, and keep it.
- `--idle-timeout N`: set the time limit of `wait()` to N seconds in the copy
  of the tree. It is for `@bound`; see there.
- A scenario is a name from the tables below, or `@death`, `@normal`,
  `@bound`, or `@all` for these three groups. A name given twice is run twice.

## The 17 scenarios in which Tor goes away (`@death`)

Three threads send requests: the main thread, stem's event thread (it calls
exitmap's listener) and exitmap's queue reader (it reads the probes' messages).
The last two columns describe the moment at which Tor exits.

| Scenario | Tor exits | Request without a reply | Main thread |
| --- | --- | --- | --- |
| `H_die_in_getinfo` | 0.5 s after the first EXTENDCIRCUIT | event thread: GETINFO desc/id, which takes 1 s here | inside stem with the next EXTENDCIRCUIT |
| `H2_die_in_getinfo_wait` | 0.8 s after the first EXTENDCIRCUIT | event thread: GETINFO desc/id, which takes 1 s here | waits for the scan to end |
| `H3_getinfo_prompt_iter` | when it gets the first GETINFO desc/id | event thread: that request | sleeps between two circuits |
| `AT_evt_prompt_wait` | when it gets the first ATTACHSTREAM | event thread: that request | waits for the scan to end |
| `AT_evt_prompt_iter` | when it gets the first ATTACHSTREAM | event thread: that request | sleeps between two circuits |
| `AT_evt_hang_qr_blocked` | 1 s after it got the first ATTACHSTREAM | event thread: that request. The queue reader waits behind it. | waits for the scan to end |
| `H4_getinfo_hang_qr_blocked` | 1 s after it got the second GETINFO desc/id | event thread: that request. The queue reader waits behind it. | waits for the scan to end |
| `CC_qr_prompt` | when it gets the first CLOSECIRCUIT | queue reader: that request | waits for the scan to end |
| `GC_qr_prompt` | when it gets the first GETINFO circuit-status | queue reader: that request | waits for the scan to end |
| `AT_qr_prompt` | when it gets the first ATTACHSTREAM | queue reader: that request | waits for the scan to end |
| `CC_qr_hang_evt_blocked` | 1 s after it got the first CLOSECIRCUIT | queue reader: that request. The event thread waits behind it. | waits for the scan to end |
| `GC_qr_hang_evt_blocked` | 1 s after it got the first GETINFO circuit-status | queue reader: that request. The event thread waits behind it. | waits for the scan to end |
| `AT_qr_hang_evt_blocked` | 1 s after it got the first ATTACHSTREAM | queue reader: that request. The event thread waits behind it. | waits for the scan to end |
| `F_die_creating` | 0.1 s after the 4th of 10 EXTENDCIRCUIT | none | sleeps between two circuits |
| `G_die_idle` | 2 s after the last EXTENDCIRCUIT. Circuits 4 and 5 of 5 never complete. | none | waits for the scan to end |
| `J_die_modules_running` | 0.3 s after the last EXTENDCIRCUIT, while all probes run | none | waits for the scan to end |
| `Q_die_at_end` | when it gets the SETEVENTS that ends the scan | main thread: that request | sends that request |

"Waits behind it": the thread has a request of its own and waits for the lock
that stem holds until the earlier request has its reply. In the three
`*_qr_hang_evt_blocked` scenarios the fake tor reports a circuit that exitmap
did not ask for. Upstream exitmap requests the descriptor of its last hop, so
the event thread waits. With the 16 patches exitmap ignores that circuit, so
there it does not wait. exitmap shuffles the exits: "first" names no fixed relay.

## The 14 normal scenarios (`@normal`)

| Scenario | What happens | Probes: upstream, patched |
| --- | --- | --- |
| `N_fakemod` | 5 exits, module `fakemod`: every probe sleeps for 0.5 s. Nothing goes wrong. | 5, 5 |
| `N_sockmod` | 5 exits, `sockmod`: every probe opens a stream, which the event thread attaches. | 5, 5 |
| `N_sockmod_late` | 5 exits, `sockmod_late`: the queue reader attaches the streams. | 5, 5 |
| `N_failed` | 10 exits. Circuits 3 and 6 fail. | 6, 8 |
| `N_two_modules` | 10 exits, `fakemod` and then `fakemod2`. Circuits 3, 6 and 13 of the 20 fail. | 14, 17 |
| `N_three_modules` | 5 exits, `fakemod`, `sockmod` and `fakemod2`. Circuit 2 fails. | 13, 14 |
| `N_nodesc` | 10 exits. Circuit 3 fails, and Tor has no descriptor for two of the exits. | 6 or 7, 7 or 8 |
| `N_reject` | 10 exits. Tor refuses EXTENDCIRCUIT no. 2 and 5. | 6, 8 |
| `N_zero_exits` | `-e` names a relay which is not an exit. Two modules. | 0, 0 |
| `N_one_exit` | `-e` names one exit. Two modules. | 2, 2 |
| `N_firsthop` | `-i` names a first hop which is not in the consensus. | 0, 0 |
| `N_exitfile` | `-E` names a file which does not exist. | 0, 0 |
| `N_setupexc` | Module `failsetup`: its `setup()` raises an exception. | 0, 0 |
| `N_badmodule` | The first module does not exist. The second one, `fakemod`, runs. | 5, 5 |

The last column is the `probes` number of the output, for upstream exitmap and
for exitmap with the 16 patches. Upstream exitmap stops waiting too early: for every
circuit that failed, one probe is cut off. In `N_nodesc` the number is one
higher when the circuit that fails belongs to an exit without descriptor.

## The 10 scenarios for the time limit of `wait()` (`@bound`)

Once all circuits are requested, exitmap waits in `EventHandler.wait()` for
the circuits to be built or to fail and for the probes to report back. A probe
sends a message when it opens a connection over Tor and when it is done.
Upstream exitmap waits without a limit. The patch "Stop waiting for module
processes which never report back" lets `wait()` give up when no message came
for 300 s (`IDLE_TIMEOUT`). It looks once a second, and only the time in
`wait()` counts. exitmap then logs one warning and ends the scan in the usual
way: it terminates the probes that still run, calls the module's `teardown()`
and goes on to the next module. The warning calls the process of a probe a
module process. Before it gives up, `wait()` counts the circuits and module
processes that it no longer waits for as failed and finished, in the
statistics that all modules of a run share, so that the next module does not
wait for them again.

`--idle-timeout N` makes the limit N seconds: `run.py` replaces the line
`IDLE_TIMEOUT = 300` in its copy of `src/eventhandler.py`. A line `limit:` in
the output says that it did, or that the tree has no such line and nothing was
changed. `--keep DIR` keeps the copy in `DIR/exitmap/`. The scenarios are made
for a limit of 5 s:

    mkdir /tmp/em-one
    git -C ~/exitmap archive mr16/bound-module-wait | tar -x -C /tmp/em-one  # upstream main + that patch
    python3 run.py --exitmap /tmp/em-up --idle-timeout 5 @bound
    python3 run.py --exitmap /tmp/em-one --idle-timeout 5 @bound
    python3 run.py --exitmap /tmp/em-16 --idle-timeout 5 @bound

The module is `boundmod`. A probe takes 0.5 s unless the table says otherwise.
"The first probe" is the one that starts first, whatever its exit is.

| Scenario | What happens |
| --- | --- |
| `B_stuck` | 10 exits. The first probe opens a connection and then blocks in a read without a timeout. |
| `B_stuck_failed` | The same, and circuits 3 and 6 fail. |
| `B_killed` | 10 exits. The first probe is killed with SIGKILL after 1 s. |
| `B_lost_circuit` | 10 exits. Circuit 4 never completes: the fake tor reports it neither as built nor as failed. |
| `B_chatty` | 5 exits. The first probe resolves a name 15 times, 1.2 s apart. It is healthy, and exitmap gets a message each time. |
| `B_silent` | 5 exits. The first probe sleeps for 12 s and opens no connection. It is healthy. The other four are done after 2 s. |
| `B_silent_chatty` | 5 exits. The first probe is the one of `B_silent`, the second the one of `B_chatty`. |
| `B_build_delay` | 2 exits, 7 s between the two circuits, a probe takes 3 s. No message comes for 7 s; 3 s of them are after the last circuit was requested. |
| `B_two_modules` | `B_stuck`, and `fakemod2` runs as a second module after `boundmod`. |
| `B_two_modules_failed` | 10 exits, circuit 3 fails, and the first two probes block like the one of `B_stuck`. `fakemod2` runs as a second module over the same exits. |

`B_stuck_300` is `B_stuck` with a timeout of 345 s, for the limit as the patch
has it. It takes five minutes and is in no group:

    python3 run.py --exitmap /tmp/em-one B_stuck_300
    python3 run.py --exitmap /tmp/em-16 B_stuck_300

What these scenarios are not:

- Not the 300 s of the patch, except `B_stuck_300`. The 5 s are set in a copy
  of the source, and without `--idle-timeout` the scenarios that wait for the
  limit show HANG with the patch too: their timeouts are 25 and 40 s.
- Not a module of exitmap. `boundmod` is a test module. Its blocked read is
  from a local socket, because the fake tor passes no data, and the probe of
  `B_killed` sends the signal to itself.
- Not a claim about Tor. `B_lost_circuit` shows what exitmap does if a circuit
  never completes, not that Tor loses circuits.
- Not all causes. No scenario has a probe process that could not be started,
  or one that is killed while it sends a message.

## How to read the output

    F_die_creating              exit 0 after  9.4s         probes=3
    G_die_idle                  HANG (killed after 26s)    probes=3
          main thread:         eventhandler.py:333 wait <- exitmap.py:488 run_module <- ...
          queue reader thread: connection.py:400 _recv <- ... <- eventhandler.py:247 queue_reader
    summary: 2 scenarios, 1 exit, 1 hang (G_die_idle)

- `exit N after S`: exitmap ended on its own with exit status N. Upstream
  exitmap always exits with 0. With the 16 patches it exits with 1 after Tor
  went away, and in `N_firsthop`, `N_exitfile` and `N_setupexc`.
- `HANG`: exitmap still ran after the timeout of the scenario (25, 40 or
  60 s, and 345 s for `B_stuck_300`). `run.py` then makes it print the stack
  of every thread, innermost frame first, waits a second and kills it. By
  then the main thread can be further on than in the table, for example in
  the next EXTENDCIRCUIT.
- `probes`: the number of probes that ran to their end.
- `traceback`: the last line of the last traceback that exitmap printed.
- `ERROR`: exitmap did not get as far as starting the fake tor. `run.py` then
  exits with 1. Hangs do not change its exit status.
- `--keep DIR` leaves `exitmap.log` (debug log), `faketor.log` (commands
  received, events sent) and `output.txt` (what exitmap printed) per scenario.

A `B_` scenario has two more numbers, a line `probes:` if it runs two
modules, and a line for each warning, here with the 16 patches:

    limit:   IDLE_TIMEOUT = 5 instead of 300 in the copy of src/eventhandler.py
    B_stuck                     exit 0 after  9.0s         probes=9 warnings=1 teardown=1
          warning:             No message from a module process for 5 seconds.  No longer waiting for 0 circuit(s) and 1 module process(es).
    B_two_modules_failed        exit 0 after 12.4s         probes=17 warnings=1 teardown=1
          probes:              boundmod 7, fakemod2 10
          warning:             No message from a module process for 5 seconds.  No longer waiting for 0 circuit(s) and 2 module process(es).

- `probes:`: the probes of each module that ran to their end, in the order
  of the command line.
- `warnings`: how often exitmap logged that `wait()` gave up. The text of
  each warning follows in a line `warning:`. `run.py` looks for the wording
  of the patch, and prints that line for the scenarios of the other groups
  too.
- `teardown`: how often the `teardown()` of `boundmod` was called. `fakemod2`
  has none.

## Expected results

| exitmap | stem | Hangs | Exits | Scenarios that hang |
| --- | --- | --- | --- | --- |
| upstream `main` | without the fix | 11 | 6 | all but the three `*_qr_prompt`, `F_die_creating`, `J_die_modules_running`, `Q_die_at_end` |
| upstream `main` | fixed | 1 | 16 | `G_die_idle`: exitmap waits in its own `wait()`, no thread is inside stem |
| with the 16 patches | without the fix | 1 | 16 | `H_die_in_getinfo` |
| with the 16 patches | fixed | 0 | 17 | none |

The 14 normal scenarios end in all four combinations. Each row was run at
least five times and gave this result every time; that does not rule out a
rare other outcome. These runs were measured on d02f923 and, for the 16
patches, on 6d7c1b1, an earlier state of `phase1-upstream` whose `src/`
differs from c5d6ae1 only in `wait()`, where two lines moved and the comments
changed. On c5d6ae1, `@death` and `@normal` were run once with each of the
two stem checkouts and once with stem 1.8.2, with the results of rows 3 and
4 and of the table of `@normal`. The released stem 1.8.2 gave the results of
the rows without the fix. The scenarios depend on delays of 0.1 s and more,
so a busy machine can change a result. One scenario at a time, `@death` took
5 minutes for row 1, about 1 minute for rows 2 and 3 and half a minute for
row 4, and `@normal` 35 seconds. `--jobs 4` cut row 1 to 80 seconds (same
hangs).

`@bound` with `--idle-timeout 5` and stem 1.8.2:

| Scenario | upstream `main` | upstream `main` + the patch | with the 16 patches |
| --- | --- | --- | --- |
| `B_stuck` | HANG, `probes=9` | 9.0 s, `probes=9 warnings=1` | 9.0 s, `probes=9 warnings=1` |
| `B_stuck_failed` | 3.4 s, `probes=6` | 3.4 s, `probes=6` | 9.0 s, `probes=7 warnings=1` |
| `B_killed` | HANG, `probes=9` | 9.0 s, `probes=9 warnings=1` | 9.0 s, `probes=9 warnings=1` |
| `B_lost_circuit` | HANG, `probes=9` | 9.0 s, `probes=9 warnings=1` | 9.0 s, `probes=9 warnings=1` |
| `B_chatty` | 19.0 s, `probes=5` | 19.0 s, `probes=5` | 19.0 s, `probes=5` |
| `B_silent` | 13.0 s, `probes=5` | 7.5 s, `probes=4 warnings=1` | 7.5 s, `probes=4 warnings=1` |
| `B_silent_chatty` | 19.3 s, `probes=5` | 19.3 s, `probes=5` | 19.3 s, `probes=5` |
| `B_build_delay` | 10.5 s, `probes=2` | 10.5 s, `probes=2` | 10.5 s, `probes=2` |
| `B_two_modules` | HANG, `probes=9` | 12.4 s, `probes=19 warnings=1` | 12.4 s, `probes=19 warnings=1` |
| `B_two_modules_failed` | HANG, `probes=7` | 12.4 s, `probes=17 warnings=1` | 12.4 s, `probes=17 warnings=1` |

A time stands for `exit 0 after` that time, give or take 0.1 s. Where the
table has no `warnings`, the number was 0. `teardown` was 1 in every run that
ended and 0 in every HANG. Every warning named 0 circuits and 1 module
process, except in `B_lost_circuit` (1 circuit and 0 module processes) and in
`B_two_modules_failed` with the 16 patches (0 circuits and 2 module
processes). The line `probes:` said `boundmod 9, fakemod2 10` in
`B_two_modules` and `boundmod 7, fakemod2 10` in `B_two_modules_failed` in
every run that ended, and `fakemod2 0` in every HANG. On upstream `main` the
option changes nothing: that tree has no limit.

- `B_stuck`, `B_killed`, `B_lost_circuit`, `B_two_modules`,
  `B_two_modules_failed`: upstream exitmap waits without end and does not
  call `teardown()`. With the patch the scan ends after one warning.
- `B_two_modules`: the second module adds 3.4 s and no second warning. It
  does not wait again for the stuck probe of the first module.
- `B_two_modules_failed`: circuit 3 failed, so upstream exitmap waits for all
  but one of the 9 probes of `boundmod`, and two of them never report back.
  With the patch the warning named 1 module process, the one that upstream
  exitmap still waits for, and all 10 probes of `fakemod2` ran to their end.
  The version of the patch before the review (measured on 113c611, nine
  runs with Python 3.10 to 3.13) named 2 module processes, one more than
  upstream exitmap waits for, and only 9 probes of `fakemod2` ran to their
  end. With the 16 patches exitmap waits for both stuck probes: the warning
  named 2, and `fakemod2` ran all 10.
- `B_stuck_failed`: two circuits failed, so upstream exitmap waits for all
  but two of the 8 probes. It ends when 6 are done and terminates the other
  two, the stuck one and a healthy one. The patch alone does not change that.
  With the 16 patches exitmap waits for every probe, and the limit ends the
  wait: 7 probes.
- `B_chatty`, `B_silent_chatty`, `B_build_delay`: the same on all three
  trees. A limit of 5 s does not cut off a probe that sends messages for
  17 s, nor a silent probe while another one sends messages, nor a scan with
  7 s between two circuits.
- `B_silent`: the limit ends a healthy probe. This is what the limit costs:
  a probe that sends no message for longer than the limit is terminated if no
  other probe sends one in that time.

Measured on d02f923 (upstream `main`), 5f86e2b and c5d6ae1 (then
`mr16/bound-module-wait` and `phase1-upstream`) with Python 3.13; the later
states d33d69d and a212bd7 of the two branches change only
`test/test_eventhandler.py`. Each cell was run at least three times,
`B_two_modules_failed` at least ten times on the two trees with the patch,
and the two scenarios with two modules once more with each of Python 3.10,
3.11 and 3.12. All runs agree. One scenario at a time, `@bound` took 225
seconds on upstream `main` and 112 and 117 seconds on the other two trees.

Three copies of the tree with the 16 patches, each without one part of the
patch, show which scenario needs which part (one run each with
`--idle-timeout 5`, measured on copies of c5d6ae1):

- Without the two lines that add to `failed_circuits` and `finished_streams`,
  `B_two_modules` took 17.8 s and `B_two_modules_failed` 17.7 s, both with
  `warnings=2`: the second module waited again for the stuck probes of the
  first one.
- Without the line `self.last_message = time.monotonic()` in `wait()`,
  `B_build_delay` ended after 9.3 s with `probes=1 warnings=1`.
- Without that line in `queue_reader()`, `B_chatty` ended after 6.5 s with
  `probes=4 warnings=1` and `B_silent_chatty` with `probes=3 warnings=1`. The
  scenarios with a warning in the table ended 1 s earlier, give or take
  0.1 s.

The results not named here were those of the table.

With the limit of 300 s, as the patch has it, `B_stuck_300` gave `exit 0 after
304.0s`, `probes=9 warnings=1 teardown=1`, and the warning said `300 seconds`
and named 0 circuits and 1 module process. It was run once with upstream
`main` + the patch and once with the 16 patches, both at the same time.

Without `--idle-timeout`, one run of `@bound` on the tree with the 16 patches
showed HANG in `B_stuck`, `B_stuck_failed`, `B_killed`, `B_lost_circuit`,
`B_two_modules` and `B_two_modules_failed`, and `B_silent` ended after 12.9 s
with `probes=5`. With `--idle-timeout 5`, `@death` and `@normal` gave the
same results on that tree as without it (one run each, stem 1.8.2).

## The data

`data/` is a part of exitmap's own test data: `test/data/cached-consensus`,
valid after 2024-03-04 18:00:00, and `test/data/cached-descriptors`.
`trim_data.py` kept 30 exit relays and 30 other relays; its docstring says how
it picks them. `python3 trim_data.py ~/exitmap/test/data data 30 30` rebuilds
all seven files byte for byte from these two files of upstream `main` or of
`phase1-upstream` (checked on d02f923 and c5d6ae1). `exits.txt` and
`others.txt` list the fingerprints. `e2.txt`, `e5.txt` and `e10.txt` are the
first 2, 5 and 10 lines of `exits.txt`. The consensus still has the signatures
of the full one. They do not fit, and nothing checks them.
