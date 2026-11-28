# Scenarios for the reader thread deadlock in stem

When tor closes the control connection, stem's reader thread closes the
controller and waits for the event thread while it holds the lock that every
request needs. A listener that uses the controller then never returns, nor
does a later `close()` or `msg()`. The fix limits that wait to one second.

These scripts were used to check the fix. They need Python 3 and a Unix
system, and all but `notor` a tor binary (it runs with `DisableNetwork 1`).
A stem tree is a checkout of stem's repository. The scripts take it as an
argument and import stem from there. They do not use an installed stem.

## Files

- `variants.py`, `common.py`: the scenarios (the scripts call them variants) and what they share.
- `notor.py`: runs one scenario against a fake tor, a few lines of Python on a socket pair.
- `withtor.py`, `withsock.py`: the same against a real tor, on a ControlPort and on a ControlSocket (a unix socket file).
- `run_all.py`: runs all scenarios with one of these three, against one or more stem trees.
- `random_kill.py`: kills a real tor at a random moment while several threads use the controller.

## How to run them

    python3 run_all.py notor 2 <stem tree> <stem tree with the fix>
    python3 run_all.py withtor 1 <stem tree> <stem tree with the fix>
    python3 run_all.py withsock 1 <stem tree> <stem tree with the fix>
    python3 notor.py <stem tree> 5b
    python3 withtor.py <stem tree> 5b <control port> <scratch directory>
    python3 withsock.py <stem tree> 5b <control port> <scratch directory>
    python3 random_kill.py <stem tree> port <control port> 120 4
    python3 random_kill.py <stem tree> sock <control port> 120 4

`run_all.py` runs each scenario that many times against each stem tree (one
is enough): all 35 with `notor`, 29 with `withtor` and 20 with `withsock`.
Its tor listens on control port 28750, or on the one in the environment
variable `SCENARIO_PORT`. Lines 4 to 6 run one scenario, `5b`, and print all
of its output. Any other can take its place, but `4E` only runs against the
fake tor. The scratch directory must exist. The files of tor are made there
and removed at the end, but they stay if tor does not start. The last two
are the random kill: 120 trials with 4 threads that send requests. `TOR_CMD`
names the tor binary (default `tor`). `withsock` and `sock` make a socket
file in a temporary directory, and such paths are limited to about 100
bytes. If tor fails with "Failed to bind one of the listener ports", the
port is in use or the path is too long: set `SCENARIO_SCRATCH` to a short
directory, or give `withsock.py` one.

## How to read the output

`notor.py`, `withtor.py` and `withsock.py` print a line for every call they
made: what it returned or raised, or `BLOCKED` if it did not return within 3
seconds. That number is the last, optional argument. Keep it well above the
one second of the fix. Then comes the verdict:

- `RESULT OK`: every call returned as expected. Exit status 0.
- `RESULT BLOCKED` and the calls that are blocked. The lines above say where each thread is, a dump of all threads follows. Exit status 1.
- `RESULT WRONG`: every call returned, but see the `WRONG:` lines. Exit status 2.
- No `RESULT` line: the script itself failed. Exit status 3 if tor did not start, for instance. A script that is not done after 60 seconds prints `Timeout`, dumps all threads and ends with exit status 1.

`run_all.py` prints blocked runs/runs for every scenario and stem tree, as
in `2/2`, plus other verdicts, as in `0/2 +1 WRONG`. `ERROR` is a run
without a `RESULT` line. The totals of the three groups follow the table,
then the `WRONG:` lines of every `WRONG` run and the end of the output of
every `ERROR` run. Its exit status is 1 if a run was `WRONG` or `ERROR`.
`random_kill.py` prints a line per trial: `ok` or `DEADLOCK`, the thread
that closed the socket and where the threads are that did not end.
`Tor listener` is stem's reader thread, `Event notifier` its event thread,
`application sender` a thread that sends requests. The last line has the
counts. Its exit status is 1 if a trial deadlocked.

## Scenarios: tor goes away and the reader thread joins the event thread (the bug)
- `1`: a listener waits for a reply when tor dies
- `2`: the application waits for a reply when tor dies while a listener is busy, the listener then sends a request
- `5`: tor dies while an event is queued behind a busy listener, the listener sends a request for the queued event
- `5b`: tor dies while a listener is busy, the listener then sends a request (nothing else is going on)
- `4L`: tor dies while the application waits for a reply and holds a lock of its own, a listener waits for that lock
- `7`: tor dies while a SIGNAL RELOAD event is queued behind a busy listener, no listener uses the controller
- `7r`: tor sends a SIGNAL RELOAD event and dies right away, the application has no listener (a race, nothing is held back)
- `q`: tor stays up: a listener sends QUIT, tor hangs up, the listener sends another request
- `qw`: tor stays up: a listener sends QUIT, waits until the controller noticed that tor hung up, sends another request
- `4E`: tor dies while the application waits for the reply of remove_event_listener() and an event arrived, no listener is called
- `j1`: variant 1 plus a status listener with spawn = False that calls controller.close() when it is told of CLOSED
- `j2`: variant 1 plus a status listener with spawn = True that calls controller.close() when it is told of CLOSED
- `k1`: tor dies while a listener is busy, the listener then calls controller.close()

## Scenarios: not covered by the fix
- `3a`: the application calls close() while a listener waits for a reply from a stopped tor
- `3b`: the application calls close() while a listener is busy, the listener then sends a request
- `3c`: the application calls close() while a SIGNAL RELOAD event is queued behind a busy listener, no listener uses the controller
- `3e`: the application calls close() while a listener is busy, the listener then calls close() itself
- `3f`: one application thread calls close() while another waits for a reply and a listener is busy, the listener then sends a request
- `s1`: tor dies while the application waits for a reply, a status listener (spawn = True) then sends a request
- `w`: the application leaves a 'with controller' block while a listener is busy, the listener then sends a request
- `x1`: variant 1 plus a status listener (spawn = True) that uses the controller when it is told of CLOSED
- `p3`: tor dies while an application send is in flight (emulated: the caller holds the send lock), so the application's msg() closes; a busy listener then sends a request

## Scenarios: work today and must keep working
- `4`: tor dies while a listener is busy without using the controller, the application waits for a reply
- `6a`: control: tor dies while the application waits for a reply, the listener is idle
- `6a2`: control: tor dies while nothing is going on
- `6b`: control: the application calls close() while the listener is idle
- `6c`: control: a listener calls close()
- `6d`: control: status listeners (spawn True and False) when the application calls close()
- `6d2`: control: status listeners (spawn True and False) when tor dies
- `6e`: control: connect() after close(), reconnect() after tor died and came back
- `4b`: tor dies while a listener is busy without using the controller, the application then sends a request
- `x2`: tor dies while a listener is busy without using the controller, the application then calls close()
- `x3`: tor dies while an event is queued behind a busy listener: order of the CLOSED notice and the listener calls
- `e1`: tor dies while 40 events are queued behind a listener that takes 5 ms each, the application calls close() once it knows: listener calls after close() returned
- `c1`: the application calls close() while a status listener (spawn = True) calls reconnect() when it is told of CLOSED

## Measured results

A run that blocks takes 6 seconds, any other at most about 3. With two stem
trees, unmodified and fixed, `run_all.py` took 4 minutes for `notor 1`, 3 for
`withtor 1` and 1.5 for `withsock 1`. A trial of the random kill takes about
4 seconds, and 7 if it deadlocks.

The numbers are from Python 3.10 to 3.13 and tor 0.4.9.11. Unmodified stem
is `maint` at 0782931d. Each stem version got 994 runs: 560 against the fake
tor, 314 against a real tor on a ControlPort and 120 against a real tor on a
ControlSocket. All 35 scenarios ran against the fake tor, 29 of them also on
a ControlPort and 20 of those also on a ControlSocket (`run_all.py` has the
lists). `variants.py` has one more, `c2`, which was not part of these runs.

- tor goes away and the reader thread joins the event thread (the bug): blocked in 375 of 391 runs on unmodified stem (the 16 others are scenarios `7r` and `q`, whose outcome depends on timing), 0 of 391 with the fix.
- not covered by the fix: blocked in 212 of 212 runs on both. One of these, `x1`, blocks in the reader thread's join on unmodified stem and in the join of the status listener threads with the fix.
- work today and must keep working: blocked in 0 of 391 runs on both.

Random kill with the fix, Python 3.11: 240 trials on a ControlPort and 240
on a ControlSocket, half with 2 and half with 4 senders. 467 were ok and 13
deadlocked (3 on the ControlPort, 10 on the ControlSocket). In all 13 the
socket was closed by a sending application thread. That is the situation of
scenario `p3`. On unmodified stem a shorter run, 10 trials for each of the
four combinations, deadlocked in all 40.
