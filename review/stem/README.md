# stem: fix for the hang when Tor closes the control connection

exitmap needs one fix in stem. This folder holds it, prepared the same way as
the exitmap patches: one issue, one commit, small, in upstream style. It is
filed: issue tpo/network-health/stem#11 and merge request
tpo/network-health/stem!11 (2026-11-28, see "How it was submitted").

**In short.** When Tor closes the control connection while an event listener
uses the controller, stem deadlocks. The fix is five lines of code: stem's
reader thread waits for its event thread for one second at most. The price
shows only when a listener call is still running a second after the
disconnect. The application is then told that the connection is closed while
that call still runs. And if it reconnects at once and the listener goes on
to use the controller, the two deadlock, which current stem avoids. exitmap
does not reconnect. The decisions that were yours are under "Decisions for
you"; the submission is under "How it was submitted".

## What is in this folder

| File | What it is |
| --- | --- |
| `issue.md` | The issue to file first in `tpo/network-health/stem`. Line 1 is the title |
| `merge_request.md` | Title (line 1) and description of the merge request |
| `0001-Fix-reader-thread-deadlock-when-tor-disconnects.patch` | The commit, for `git am` on stem's `maint` (0782931d) |
| `reproduce_quit.py` | The reproducer from the issue |
| `reproduce_kill.py` | Second reproducer: starts its own Tor and kills it while a listener waits for a reply |
| `reproduce_reconnect.py` | Shows the one known case in which the fix deadlocks and current stem does not (see "The cost") |
| `reserve/known_1_close.py` to `known_4_reconnect.py` | One reproducer for each of the four deadlocks the fix does not cover, in the order of the issue. Not sent with the issue; they back its offer to file these separately |
| `reserve/unit_test.patch` | A second test that needs no Tor. Not part of the commit; offer it if the maintainers ask |
| `scenarios/` | The scripted scenarios and the random-kill test behind the numbers in the merge request. It has its own README |

The scripts import whatever `stem` Python finds first. To test a stem
checkout, put its top directory on `PYTHONPATH`. Without that they use the
installed stem (pip installs 1.8.2), also when you start them from inside a
checkout:

    PYTHONPATH=/path/to/stem python reproduce_quit.py 9051
    PYTHONPATH=/path/to/stem python reproduce_kill.py
    PYTHONPATH=/path/to/stem python reproduce_reconnect.py 9051 1.2

`reproduce_quit.py`, `reproduce_reconnect.py`, `known_1_close.py` and
`known_4_reconnect.py` need a running Tor whose ControlPort asks for no
password; that Tor keeps running. On current stem `reproduce_quit.py` prints
two lines and then hangs (stop it with Ctrl-C); with the fix it prints four
and ends. The other three scripts start their own Tor, so `tor` has to be on
the `PATH`, and end by themselves after a few seconds. `reproduce_kill.py`
prints `close(): still blocked` on current stem and `close(): returned` with
the fix. The four `known_` scripts hang or print `still blocked` on current
stem and with the fix alike.

`reserve/unit_test.patch` is a plain diff: `git apply reserve/unit_test.patch`
on top of the commit, then `git commit --amend -a`. The test fails on current
stem after 5 seconds and adds one second to the unit suite with the fix.

## The bug

stem's controller has two threads of its own. The reader thread reads from
Tor's control socket. The event thread calls the application's event
listeners. Listeners may use the controller, and exitmap's do: they attach
streams and close circuits.

When Tor closes the connection, the reader thread closes the controller, and
as part of that it waits for the event thread to finish. It waits while it
holds the lock every request needs, and before it has told waiting requests
that the connection is gone. A listener that is using the controller at that
moment can never finish, so the two threads wait for each other. Every later
`close()`, `msg()` and `remove_event_listener()` then blocks as well.

This has been in stem since 2012 and is in every release. I think it is the
hang gk described in exitmap#61 ("Tor dying on us ... `exitmap`/`stem` ...
just keeps hanging"); the log there fits, but there is no thread dump from
those runs.

exitmap!33 and our mr03 work around it where exitmap can: they stop using a
controller that is no longer alive. One case is out of exitmap's reach. While
circuits are being created, exitmap's main thread makes requests of its own.
If Tor dies during one of them while a listener also uses the controller, the
main thread is stuck inside stem and never gets to its check.

## The fix

The reader thread waits for the event thread for at most one second instead
of without a limit. A `close()` by the application while the connection is
alive is not changed.

    stem/control.py                       | 19 +++++++++++++-
    test/integ/control/base_controller.py | 48 +++++++++++++++++++++++++++++++++++

The code change is five lines: a new constant for the second, two lines that
apply it in `BaseController._close()`, and two lines in the event thread's
loop (explained under "The cost"). The other 13 added lines in
`stem/control.py` are comments and blank lines (the 19 above also counts the
one replaced line), and the 48 lines in the test file are the new test.

### Why one second

I tried three limits and compared each with current stem.

| Limit | Result |
| --- | --- |
| None (the reader does not wait) | Fixes the hang. Breaks an immediate reconnect whenever a listener call that uses the controller is under way at the disconnect, however short: in every run. |
| 0.1 s (a constant stem already has) | Fixes the hang. But when 0.1 s or more of listener work is still queued at the disconnect, the application is told that the connection is closed before the last listener calls have run, on almost every such disconnect. And a listener call longer than 0.1 s can run into the deadlock described under "The cost". |
| 1 s (submitted) | Fixes the hang. Behaves like current stem as long as a single listener call takes less than about a second (0.9 s measured) and, when more calls are queued behind it, each takes less than about half a second (two calls of 0.45 s measured). |

The price of the longer limit: when a listener is stuck, other threads get
their error after one second instead of 0.1 seconds. Today they never get
it.

### The cost

With the fix two things differ from current stem. Both need a listener call
that is still running one second after Tor disconnected. A single call of
1.2 seconds does that, and so do two calls in a row of 0.6 seconds.

**A deadlock that current stem does not have.** It needs all of this at once:

- a listener call that is still running one second after Tor disconnected,
- an application that reconnects as soon as it learns of the disconnect,
- a Tor that accepts the new connection right away,
- and the listener using the controller after that.

Current stem holds the reconnect back until the listener is done; with the
fix it does not, and the two then block each other. `reproduce_reconnect.py`
shows it: with a listener that is busy for 1.2 seconds it hangs with the fix
and works on current stem; with 0.9 seconds it works on both. The cause is
older than the fix: `reconnect()` and a listener that makes a request take
the same two locks in opposite order. Current stem already deadlocks this way
when listener work is still queued at the moment its event thread stops
(number 4 under "What it does not fix"). None of the stem users whose source
the reviewers read does this: exitmap, sbws and onionprobe never reconnect,
and nyx only does on a key press.

**An earlier "connection closed" notice.** This is not a deadlock and needs
no reconnect. The application learns that the connection is closed while the
listener call still runs: "connection closed" listeners are called and
requests that were waiting get their error. A `close()` after that returns
without waiting for the call. On current stem all three come after the call.
With a listener that is busy for 2 seconds they come after 1.0 s with the fix
and after 2.0 s on current stem; with 0.5 seconds there is no difference. A
script that ends after `close()`, or an application that frees what its
listeners use at that point, therefore cuts such a call off, where current
stem lets it finish. A reviewer's test script whose listener works for 2
seconds and then writes a file lost the file in 5 of 5 runs with the fix and
kept it in 5 of 5 on current stem. The first review round found no stem user
that is exposed to this.

**The two lines in the event thread's loop.** If the application reconnects
while the old event thread is still running, stem keeps that thread. Without
the two lines it would remember the earlier disconnect and stop after the
first queued event at the next `close()`. Current stem already does that in
one case: a listener closes the controller itself and the controller is
connected again while the next queued event is handled. The two lines repair
that as well.

The merge request text says all of this.

### What it does not fix

Four related deadlocks stay as they are. None is new (stem 1.8.3 has all
four), none showed up in the exitmap runs, and each needs a larger change.
The issue text names them and offers to file them separately, with
reproducers; one script for each is in `reserve/`.

1. The application calls `close()` (or leaves a `with` block, or reconnects)
   while a listener uses the controller.
2. Tor disconnects and a thread that is sending a request closes the
   connection before the reader thread does. This needs a request to be in
   flight at that very moment. With a listener that asks Tor on every event,
   two or four threads sending requests in a tight loop and Tor killed at a
   random moment, 13 of 480 disconnects still ended this way with the fix (3
   of 240 on a control port, 10 of 240 on a control socket). The other 467
   were clean. In principle this one can still hit exitmap, when Tor dies at
   the very moment exitmap sends a request.
3. A "connection closed" status listener that uses the controller, when a
   request was pending as Tor went away.
4. The lock order of `reconnect()` and event listeners mentioned above.

Numbers 3 and 4 also limit what the fix does for an application that
reconnects by itself. In a reviewer's runs of the issue's scenario with the
fix, a "connection closed" listener that calls `reconnect()` still blocked in
16 of 16 runs, and a thread that polls `is_alive()` and then reconnects
blocked in 15 of 53 runs in one setup and in none of 600 in another. On
current stem all of these block anyway. exitmap does not reconnect.

## Decisions for you

1. **Submit it?** Done on 2026-11-28 (stem#11, stem!11). The mr03 issue
   draft now refers to it as `stem#11`. A merged fix reaches
   a scan only when stem is installed from `maint`: pip still installs 1.8.2,
   the 1.8.3 tag is not on PyPI. gk wrote in January that his exitmap scans
   used a patched stem checkout. The texts do not ask for a release; say so
   if you want one, and install stem from `maint` for your own scans.
2. **Keep the test?** I recommend yes. It runs in stem's CI against a real
   Tor, fails on current stem and passes with the fix. It adds one second to
   every run. The merge request text offers to drop it, since your earlier
   stem change (!4) had none.
3. **One second.** If you or the maintainers prefer another limit, it is one
   number in the code, plus the sentences in the commit message, the issue
   and the merge request that quote it. The table above says what moves with it.
4. **Commit identity.** Author and committer are `1aeo <tor@1aeo.com>`, as in
   your two merged stem commits, unsigned, and without trailers, as you
   asked for all of this work. No commit in stem's history names a tool in
   such lines (its five `Co-authored-by` lines credit a person).
   No maintainer asked for a clean identity on GitLab: when !4 still carried
   the Cursor identity, gk asked whether the patch is under LGPLv3 or a
   compatible licence, you said yes, and you then changed the identity
   yourself. He may ask again. If you want to save that round trip, add one
   line of your own at the end of the merge request, for example "As with
   !4, I provide this patch under the LGPLv3, the licence of stem." Whether
   to mention the tooling is your call; the texts do not.
5. **The follow-ups.** The issue offers to file the four remaining deadlocks
   separately, with reproducers. The four scripts are in `reserve/`; each
   hangs or prints `still blocked` on stem 1.8.3, on current `maint` and with
   the fix. I would wait for
   the maintainers' answer before filing anything.
6. **The texts speak as you.** `issue.md` and `merge_request.md` are in the
   first person. Read both, and the commit message at the top of the patch
   file, before they are posted. Besides the offers (decisions 2 and 5, and
   "I can attach the scripts" for the scenarios and the exitmap emulator)
   they say in your name:
   - that the "Safety" note of !4 and your "No deadlock." comment in
     exitmap#67 missed the event thread (issue, section "Not caused by !4,
     but its safety note missed the event thread"; the merge request has one
     line on !4);
   - "I think this is the hang of exitmap#61" (both; "The bug" above says
     what that rests on);
   - the results under "Tested" and "Test" and the numbers in "Known cost"
     and "Not covered" (merge request). These are the runs of "How it was
     checked" below, made in this session's container. Run
     `reproduce_quit.py` and the new test once yourself before you file, so
     that you can answer questions about them from your own run.
   - in the issue: that `maint` on Python 3.10 to 3.13 and the tags 1.8.3,
     1.8.2 and 1.8.1 hang, the thread positions under "Cause", and that
     exitmap "still hangs" after exitmap!33 (see the first question below).
     These are runs of this session too.

## How it was submitted

On 2026-11-28, with your approval and your token:

1. Issue tpo/network-health/stem#11, from `issue.md` (line 1 is the title).
2. Your fork `1aeo/stem` (you created it) got one branch,
   `fix/reader-thread-deadlock`, with one commit on `maint` 0782931d:
   afb81f63, author and committer `1aeo <tor@1aeo.com>`, unsigned, no
   trailers. Its tree is that of the reviewed commit; its message ends with
   `Closes: #11.` in place of `Closes: #N.`.
3. The pipeline in the fork passed: Python 3.10 and 3.11 against Tor
   nightly (0.5.0.0-alpha-dev), Python 3.11 against Tor stable (0.4.9.17),
   and pages. `control.base_controller`, which holds the new test, passed
   in each. The static checks list four pyflakes findings in
   `stem/control.py`; `maint` has the same four.
4. Merge request tpo/network-health/stem!11 against `maint`, from
   `merge_request.md` with `#11` in place of `#N`, with "Allow commits from
   members who can merge to the target branch" switched on. GitLab shows it
   as closing #11.

The patch file in this folder still ends with `Closes: #N.`; the commit in
the merge request is the one to refer to.

## Questions the maintainers may ask

- **"exitmap#61 is closed since !33. Do we still need this?"** Yes. With
  current stem the hang never went away for a listener request that is
  pending when Tor dies: the checks of !33 run before a request, and
  `new_circuit()` in `iter_exit_relays()` has none. Against the emulator, of
  17 moments at which Tor dies, exitmap hung in 8 right after !33, in 10
  right before !36, and in 11 since !36 and on `main`; with the stem fix in
  1, its own wait. !36 added one place, `remove_event_listener()` in
  `shutdown()`. In an emulation of gk's own steps from #61, exitmap `main`
  hangs there today, and exited before !36. mr03 skips that call on a dead
  controller, and the stem fix removes the cause.
- **"Why a new constant? Why not the existing 0.1 s, or no wait?"** See "Why
  one second". With 60 queued listener calls of 5 ms, current stem and the
  fix announce "closed" after the last handled call in 5 of 5 runs; with
  0.1 s one call began after the notice in 5 of 5; with no wait 20 or 21
  calls did. It is one number, and you can offer to change it.
- **"Does this add a deadlock?"** Yes, one, under four conditions at once
  (see "The cost"). exitmap cannot reach it.
- **"What is the hunk in `_event_loop()` for?"** See "The two lines in the
  event thread's loop" under "The cost".
- **"Why not fix the application's `close()` too?"** That changes the normal
  close path, which promises that queued events are handled before `close()`
  returns; `test_asynchronous_event_handling` checks that promise.
- **"Is the test worth a second per job?"** It is the only evidence in the
  maintainers' own pipeline. It cannot be faster than the constant, because
  its handler is stuck until the reader's wait runs out.
- **Licence or tooling.** See decision 4.

## How it was checked

Real-Tor runs used Tor 0.4.9.11, in a container without access to the Tor
network. The unit suite, the reproducers and the fake-Tor scenarios ran on
Python 3.10 to 3.13, the other checks on one to three of these versions
(stem's integration tests: 3.10 and 3.11; the stress runs: 3.11, some also
3.13).

After most of these runs the commit was amended three times without changing
the code in `stem/control.py`: the commit message was corrected, comments
were reworded, and the test got its `finally`. I compared the parsed
`stem/control.py` of each version to be sure. The scripts in this folder and
stem's own tests were run again on the commit as it is now.

- **Both reproducers of the bug** show it on current stem and not with the
  fix: `reproduce_quit.py` hangs, `reproduce_kill.py` reports
  `close(): still blocked`. The one from the issue also hangs on the tags
  1.8.3, 1.8.2 and 1.8.1.
- **35 scripted scenarios**, each run several times, half of the runs on
  current stem and half on the fix (994 runs each). All 35 ran against a
  fake Tor (a few lines of Python at the other end of a socket pair, 560 of
  the 994 runs), 29 of them also against a real Tor on a control port (314
  runs) and 20 of those also against a real Tor on a control socket file
  (120 runs):

  | Scenarios | Current stem | With the fix |
  | --- | --- | --- |
  | 13 where Tor goes away and the reader thread then waits for the event thread (the bug) | blocked in 375 of 391 runs | blocked in 0 of 391 |
  | 9 from the first three of the four cases under "What it does not fix" | blocked in all 212 runs | blocked in all 212 |
  | 13 that work today | 0 of 391 blocked | 0 of 391 blocked |

  One of the 9 is the bug's own case plus a "connection closed" listener
  that uses the controller. On current stem it blocks in the reader thread's
  wait like the 13 of the first row; with the fix it blocks in number 3
  instead. The 16 runs that did not block on current stem belong to two
  scenarios whose outcome depends on timing. In four of the 13 that work today (108 of
  the 391 runs) a listener stays busy for longer than the second; there the
  order differs as described under "The cost", and nothing blocks on either.
  Six scenarios ran only against the fake Tor, two of them in the first row.
  A reviewer later ran five of the six against a real Tor on a control port,
  with the same result; the sixth needs a Tor that is stopped and still
  sends an event, which only the fake one can do. The first version of the
  fix (0.1 s) gave the same picture in 1,872 runs per version. The scripts
  are in `scenarios/`.
- **Tor killed at a random moment** while a listener asks Tor on every
  event and two or four threads send requests in a tight loop: 480 trials
  with the fix, 467 clean, 13 left in number 2 of "What it does not fix".
  The script is in `scenarios/`. A reviewer's rerun of it gave 302 clean
  trials of 307 with the fix (the other 5 again in number 2, all on a
  control socket), and a deadlock in 43 of 43 trials on current stem.
- **Reconnecting**, compared with current stem in every case:
  - A listener call that ends within milliseconds of the disconnect and
    only uses the controller while it is alive, a few events queued,
    reconnect from a "connection closed" listener, against the fake Tor:
    200 of 200 runs fine on both.
  - 200 events queued for a listener that takes 2 ms each, 120 reconnects:
    fine on both, a new event thread each time.
  - A listener call that is still running at the disconnect and uses the
    controller after the reconnect: fine on both for one call of up to
    0.9 s and for two calls of 0.45 s; with one call of 1.2 s or two of
    0.6 s the fix blocks in every run and current stem in none. This is the
    deadlock under "The cost".
  - After a reconnect that kept the old event thread, a later `close()`
    still delivers the events queued at that time: 300 of 300 events (10
    runs) on both, 10 of 300 without the two lines in the event loop.
- **stem's own tests**: the unit suite gives the same result as current stem
  on all four Python versions, and stem's style checks report nothing new.
  The three integration modules that cover the controller give the same
  result as current stem on Python 3.10 and 3.11, apart from the new test;
  the module with the new test passed 30 of 30 runs on each. In this
  container two unit tests fail on both versions because there are no `man`
  pages (both in `test.unit.manual`), and three integration tests because
  there is no IPv6 (`test_get_listeners`, `test_get_ports` and
  `test_transition_to_relay` in `control.controller`). The integration
  modules ran in a copy of each tree with `IPv4Only` added to the ORPort
  line of `test/settings.cfg`, for the same reason, and through a wrapper
  that keeps `run_tests.py` from starting its background tests, which every
  `--integ` run starts whatever `--test` says.
- **The new test** fails after 10 seconds on current stem ("event handler is
  still blocked on its request") and passes with the fix in one second.
- **exitmap** against an emulated Tor that dies at 17 different moments: see
  the table in `../exitmap/phase1-review-report.md`, decision 4. The
  emulator is in `../exitmap/emulator/`.
- **Reviews.** A design panel compared three approaches before I wrote the
  fix. Four reviewers then attacked the first version (0.1 s). One of them
  found a defect in the code: after a reconnect that kept the old event
  thread, a later `close()` could deliver only the first of its queued
  events. The two lines in the event loop repair it. The reviewers are also
  the reason for the one-second limit, for a `finally` in the test and for
  several corrections to the texts. A final round of four reviewers then
  went through the final commit, the three texts and this report, and a
  second reviewer tried to refute each serious finding. They found no defect
  in the code or the test. They found eleven statements to correct in the
  texts and in this report, and asked for the scripts behind the quoted
  numbers to be in this folder; all of that is applied. A last check of the
  corrected material by three more reviewers found no blocker: one
  miscounted group of scenarios in the merge request and about a dozen small
  inaccuracies in this report, which are corrected as well. Finally a
  reviewer who had not seen the scripts in `scenarios/` ran them from their
  README: 684 scenario runs gave the picture of the table above.

Not done: Tor nightly, Python 2, and stem's CI itself. stem's whole
integration suite was run once per version by a reviewer, on Python 3.11 and
3.13; in this container many of its tests fail for reasons that have nothing
to do with the change, the same ones on both versions. The pipeline of your
fork is the real run.
