# Phase 1 review: the 16 patches for upstream exitmap

The patches exist in two forms.

- **One branch for upstream.** `phase1-upstream` holds all 16 as single
  commits on upstream `main` (`d02f923`, unchanged upstream since
  2026-08-05), most important first. Every commit passes the tests and
  flake8 on its own, so upstream can stop taking them at any point.
- **One branch per patch.** `mr01/…` to `mr16/…` each hold one patch alone on
  upstream `main`, for separate merge requests. Their names still carry the
  old numbers; the order is the table below. They exist as branches only in
  this session; on GitHub they are parents of the snapshot (see "The snapshot
  branch and your `main`").

Every one of these commits has `1aeo <tor@1aeo.com>` as author and committer,
is unsigned and carries no trailer (decision 3). Two more fixes are ready as
branches of their own and are not part of `phase1-upstream`: mr17 for the
open upstream issue #46 (see "Separate: the torsocks fix") and mr18, which
removes a limit of mr16 and goes after it (see "Separate: mr18").

**Submitted so far** (2026-11-28): mr01 as #69 with the merge request !61,
and the stem fix as stem#11 with stem!11. Nothing else has been pushed to
GitLab.

On GitHub, this session can push only to `claude/gallant-newton-bdte6o`.
That branch holds everything: the new `main`, the single branches and this
folder. You created `phase1-upstream` and deleted the old `mrNN` branches;
moving your `main` is a force push you run yourself (see "The snapshot
branch and your `main`").

In the table under "What the review changed", "before" is the branch as it
is on GitHub and "after" the revised commit. Sizes are `git diff --shortstat`
against upstream.

## The order

| # | Patch | Tier | Without it | Needs |
|---|---|---|---|---|
| 1 | mr01 exit status | required | `bin/exitmap` exits with status 0 after every failure and drops the traceback | |
| 2 | mr03 dead controller | required | When Tor dies during a scan, exitmap hangs, or keeps requesting circuits for hours and then exits with 0 | 1 for the exit status |
| 3 | mr05 queue reader | required | exitmap cannot exit while the queue reader thread is stuck, which it is in part of the Tor deaths and when `teardown()` raises | 1; completes 2 |
| 4 | mr15 fork while logging | required | A probe forked while another thread writes a log line blocks forever at its own first log line, and its exit is not scanned. Rare | |
| 5 | mr16 bound on the wait | required | exitmap waits forever for a probe that never reports back (blocked, killed, not started): today when fewer circuits failed than probes are missing, after 6 always | after 2 |
| 6 | mr02 scan completion | required | Every scan stops waiting for up to as many running probes as circuits failed, and kills them | 4 and 5 |
| 7 | mr08 empty exit file | required | An empty `-E` file scans every exit instead of none | |
| 8 | mr09 lowercase fingerprints | required | Exits given in lowercase are skipped without a message | |
| 9 | mr10 config booleans | required | `bad_exits = false` in `~/.exitmaprc` counts as true | |
| 10 | mr12 failed circuits | recommended | The log says how many circuits failed, not for which exits (upstream #22) | after 2 |
| 11 | mr11 reliable first hop | recommended | The first-hop filters merged with !44 cannot be switched on | 9 |
| 12 | mr06 teardown without exits | optional | `teardown()` is skipped when no exit is selected | 1 |
| 13 | mr13 first hop to probe | optional | A module cannot see which first hop its circuit used | |
| 14 | mr14 statistics to teardown | optional | `teardown()` cannot see the scan statistics | 1 and 3; carries two lines for 12 |
| 15 | mr04 reap children | optional | No visible symptom | |
| 16 | mr07 controller close | optional | No visible symptom | |

Required means: scan results are lost, a scan hangs or ends as a silent
failure, the wrong relays are scanned, or the configuration is misread.
Recommended: nothing breaks without it, but an upstream issue asks for it.
Optional: an extension for module authors, or tidying.

**How the order came about.** Three independent rankings (as an operator, as
the maintainers judging from their own comments on GitLab, and by
dependencies and risk) put every one of the first 15 patches in the same
tier. mr16 did not exist yet; it was placed afterwards (last bullet). Inside the required
tier they differ; there the order above is the one that two of the three
prefer for each pair:

- mr01 is first: two lines, and everything after it relies on the exit
  status.
- mr03 and mr05 come next. They finish what the maintainers started for
  their own issue #61 and change nothing in a healthy scan. Against the
  emulated Tor that dies at 17 different moments, upstream hangs in 11, with
  mr03 in 6 or 7, and with mr03 and mr05 in 1 (the deadlock in stem,
  decision 4).
- mr15 and mr02 follow. mr02 has the largest effect on scan results. On its
  own it has a price: exitmap then waits forever for a probe that never
  reports back. mr15 removes one cause of such probes.
- The three small input fixes close the tier.
- mr16 is the bound you asked for on 2026-11-27 (decision 1). Three
  independent design studies each put it directly before mr02: then no
  commit of the branch makes exitmap wait without a limit where it did not
  before, and mr02 has no price left
  that a reviewer has to accept.

If you weigh lost probes above hangs, mr15, mr16 and mr02 can go ahead of
mr03 and mr05. Nothing breaks, but mr16 and mr03 both rewrite `wait()`, so
the branch has to be rebuilt for that order; say so if you want it. In the
optional tier the branch follows the maintainer ranking; the other two had
mr13 ahead of mr06, and nothing depends on that.

**Rules for the order.** Each was tested by at least one of the rankers or
designers against the emulator or with the real `bin/exitmap`. The first
five are musts, the last two are strong preferences:

- mr16 before mr02. With mr02 and without mr16 a probe that never reports
  back hangs the scan for good, and mr02's commit message describes the
  behaviour with mr16.
- mr15 before mr02. A probe that blocks on the log lock is such a probe: it
  hung 4 of 90 fast scans with debug logging to a file under mr02 alone, and
  none of 90 with mr15. With mr16 the scan would end, five minutes late and
  without that exit.
- mr01 before mr05, mr06 and mr14. Each of them can end a run with an
  exception that only mr01 makes visible: a `teardown()` that raises (mr05,
  mr06) or that does not accept `stats` (mr14). Without mr01 such a run ends
  with status 0 and no message.
- mr05 before mr14. Without it, a module outside the tree with
  `def teardown():` makes exitmap hang at exit.
- mr10 before mr11. Without it, `reliable_first_hop = false` in the
  configuration file switches the option on.
- mr03 directly before mr05, and before mr12 and mr16. mr05 alone changes
  none of the 17 Tor-death outcomes. mr12 without mr03 logs every remaining
  exit as a failed circuit after Tor died. mr16 on the branch adds its check
  to the loop that mr03 gives `wait()`.
- mr06 and mr14: whichever comes second has to carry `stats=stats` for the
  call mr06 adds, and the stricter assertion in mr06's test. On the branch
  that is mr14.

**Where upstream can stop.** After 1; after 3 (Tor's death ends the scan with
status 1 in 16 of 17 emulated moments); after 6; after 9 (everything
required); after 11 (everything recommended). Any other stop is safe too: no
prefix of the branch breaks one of the rules above.

**The torsocks fix (mr17) is not numbered.** By importance it is
recommended, next to mr12 and mr11: upstream issue #46 reports what it
fixes, and neither the DNS modules nor dnshealth are affected. It shares no
file with the 16 and no rule involves it, so send it as its own merge
request at any time; I would send it with the first group. See "Separate:
the torsocks fix".

**What I would not offer.** mr04 and mr07 (15 and 16) have no effect anyone
can observe, and each would cost the maintainers an issue and a review. All
three rankings say to leave them out. They are last so that you can cut
them: offer `phase1-upstream~2` in place of `phase1-upstream`. mr13 and mr14
(13 and 14) are extensions nobody upstream asked for, and each can break a
module outside the tree: a `probe()` without `**kwargs`, a `teardown()`
without parameters. Your dnshealth module uses both, which is the reason to
offer them.

## Four things to decide

### 1. The bound on waiting for probes (mr16)

You asked whether "a probe that never reports back blocks the scan" is how
exitmap works today, and then for the bound as a patch. It is written: the
fifth commit of `phase1-upstream`, and alone on upstream `main` as the
branch `mr16/bound-module-wait`.

**How exitmap behaves without it.**

- **Upstream today** stops waiting for up to as many probes as circuits
  failed. That is the bug mr02 fixes, since it cuts off healthy probes as well. A
  full scan always has failed circuits (3 to 6%; 177 of 2,764 in gk's run in
  !36), so a probe that never reports back is killed with the others at the
  end. Upstream only hangs when more probes are stuck than circuits failed,
  for example in a small scan without failures.
- **With mr02 and no bound** the count is right, and one such probe makes
  exitmap wait forever: `teardown()` does not run, and no `scan_stats.json`
  or `circuit_failures.json` is written. Emulated with two failed circuits
  and one probe that never ends: upstream ended in 5 of 5 runs, having
  probed 6 of 8; with mr02 it hung in 4 of 6 (in the other two the stuck
  exit's circuit happened to be one of the failed ones).
- **Your production code** (tag `archive/pre-rebase-main-20261126`) kept
  upstream's rule. `shutdown()` then gave the processes still running a
  grace period (`EXITMAP_GRACE_TIMEOUT`, 10 seconds by default), terminated
  the rest, logged "Terminated N stalled relays" and passed their
  fingerprints to `teardown()`, where dnshealth recorded them as timeouts.
  The current `main` on GitHub already has mr02 and no grace period.

Where such probes come from:

- A process forked while another thread writes a log message inherits the
  locked log stream and blocks at its own first log message. This is in
  exitmap itself, and mr15 fixes it; that is why mr15 comes before mr02. It
  needs the other thread to log within about a millisecond of the fork:
  - In emulated scans with 0.05 s between circuits, 16 of 240 scans never
    finished without the fix (with `-v debug`, or with `-v info` and a log
    file), and none of 190 with it.
  - With 0.5 s or more between circuits it did not happen in about 20,000
    forked processes. With `-v info` and upstream's defaults it is
    practically unreachable. With `-v debug` and a log file a ranker counted
    18 blocked probes in 15,000 at about 80 probes per second and 1 in
    12,000 at about 19 per second. gk's runs in #61 log at debug level with
    one second between circuits, so for the maintainers it is rare, not
    unreachable.
  - Your deploy wrapper, when it was last in this repository (January), ran
    with `--build-delay 0` and sent stderr to a file. That is the worst
    case, and it was not measured separately. "Terminated N stalled relays"
    in your production logs may well have been these processes; I could not
    check that.
- A probe process that is killed from outside.
- A module without timeouts. In the tree `cloudflared` opens its connection
  without one. Your dnshealth has its own hard timeout.
- A fork that fails, or an exception in the event callback after the circuit
  was counted. A ranker simulated it with two failed circuits: upstream
  ends, mr02 without a bound waits.

**What mr16 does.** The thread that reads the probes' messages notes when it
read the last one. Once all circuits are requested, `wait()` looks once a
second and gives up when no probe has sent a message for 300 seconds. A
probe sends a message whenever it opens a connection over Tor and when it is
done. So the clock measures the silence of all probes together, not the
length of a probe or of the scan. When it gives up, exitmap

- logs one warning, for example `No message from a module process for 300
  seconds.  No longer waiting for 0 circuit(s) and 1 module process(es).`;
- counts those circuits as failed and those probes as finished, because all
  modules of a run share the counters and the next module would wait for
  them again;
- returns. `shutdown()` then terminates the processes still running,
  `teardown()` runs, the summary is logged and the next module starts. The
  exit status stays 0, as it does when circuits fail.

On `main` it counts the probes the way `check_finished()` does there, one
less per failed circuit; mr02 changes that line along with its own rule.

**How it was checked.**

- Against a real Tor: a private network on this machine (Tor 0.4.9.11, one
  directory authority and two relays, all exits, inside a network namespace
  with only loopback) and the real `bin/exitmap`. With the shipped 300
  seconds a probe blocked in `recv()` was given up 300.9 seconds (mr16 on
  `main`) and 301.0 seconds (the series) after the last message: exit status
  0, `teardown()` ran, the summary was logged. Upstream `main` was still
  waiting after 421 seconds, when it was stopped. A healthy scan took 7.6
  seconds with and without the patch (three runs each), and a probe that
  waited 114 seconds for Tor's `SocksTimeout` was not cut off.
- The same with the limit lowered to 20 seconds in a copy, three runs each
  on both forms: healthy and chatty probes (14 messages over 48 seconds)
  never warned; a probe silent for 45 seconds was cut off (the cost above);
  stuck and killed probes ended the scan 20.9 seconds after the last
  message; with two modules and a stuck probe in the first, the second
  module ran in full and there was one warning.
- The emulator: ten scenarios with the limit at 5 seconds, 3 to 14 runs per
  cell, on upstream `main`, on mr16 alone and on the series, all as
  expected. One of them, two modules with two stuck probes and one failed
  circuit in the first, shows the review's change: the version before the
  review lost 1 of the second module's 10 probes, the final version none.
  The scenarios are in `review/exitmap/emulator/`.
- None of this is the Tor network: three relays on one machine, circuits in
  under 0.1 seconds, three probes per scan. How often 300 seconds of silence
  occur in a full scan is not known.


**What it costs.**

- With mr02, five minutes at the end of a scan in which something is stuck.
  A healthy scan is not changed.
- A healthy probe is terminated if it sends nothing for five minutes while
  no other probe sends anything either. That can only happen to the probes
  still running at the end of the scan. In the tree it would take a
  download of more than five minutes in `patchingCheck` or `cloudflared`.
  dnshealth ends every probe after 180 seconds on its own
  (`DNS_HARD_TIMEOUT`), so it is not affected unless you raise that limit
  to about 300.
- The warning gives numbers, not the exits. Your production code logged a
  count too, but passed the fingerprints to `teardown()`, where dnshealth
  wrote a timeout result for each of those exits. One of the three design
  studies built that (eight more lines and a table of running probes). I
  left it out to keep the patch small; it can follow as its own patch, for
  upstream or only for your fork.
- After exitmap gave up, `failed_circuits` includes circuits that never got
  a result and `finished_streams` includes the abandoned probes. In
  dnshealth such circuits end up in `unresolved_failures`.
- The exit status stays 0. A wrapper learns of abandoned probes only from
  the warning.
- The five minutes also pass while exitmap is stopped, e.g. with Ctrl-Z. If
  that lasts five minutes or more during the final wait, exitmap gives up on
  the running probes as soon as it continues.

**Why this shape.** Three independent design studies built the alternatives
and ran them against the emulator with the limit at 5 seconds:

- Watching the counters only, a deadline per probe, and a fixed time for
  the whole wait each cut off a healthy probe that resolved names for about
  20 seconds. With a module like `rtt`, whose probes can run for minutes,
  that would hit the last probes of every scan.
- Detecting dead processes without a time limit cannot see a process that
  blocks. It also ended healthy scans early when the control port was slow,
  because exitmap counts a circuit as built before it starts the probe.
- Without the reset when `wait()` starts, the time between two circuits
  counts: with 7 seconds between circuits the last exit was given up while
  its probe ran. That is the failure of #64.
- An option for the limit invites a value below Tor's own timeouts, which
  loses circuits (5 seconds against a circuit that takes 7). The constant
  is 300 because that is what exitmap gives Tor to start, and well
  above the 40 seconds Tor has for a circuit and the two minutes it keeps
  an unattached stream.

**What is left to decide.**

- Whether to offer it. I recommend it: with it mr02 has no price, and the
  maintainers lost weeks of reports to scans that never ended (#61). They
  also removed a timeout once (#64), so expect questions; the commit
  message and the issue draft answer the ones I could foresee. If they
  decline, mr02 goes in as on its single branch `mr02/fix-check-finished`,
  whose message says "now blocks the scan", and what you said before
  applies: keep it for now.
- An outer timeout around your scans stays sensible either way. The bound
  covers `wait()` only, not a main thread stuck inside stem while circuits
  are being created (decision 4). In a ranker's emulated run a blocked scan
  ended cleanly on Ctrl-C (SIGINT: `teardown()` ran, the summary was
  logged, status 1), but not on SIGTERM. So use
  `timeout -s INT 8h bin/exitmap …`; `timeout` then reports status 124
  unless you add `--preserve-status`.

### 2. One issue and the branch, or one issue per patch

Decided: one issue per patch, as you wanted. mr01 went in that way on
2026-11-28 (#69, !61), and the texts for mr03 and mr05 are ready in
`review/exitmap/gitlab/`. What follows is how this was set out before.

The branch and the 16 issue texts are prepared; the text of one issue that
covers the whole branch is not written. `phase1-upstream` is what gk
suggested in !34: "filing an issue and then providing a branch with all the
commits". They added that "a piecemeal approach for the MRs" could work as
well, and one issue per merge request is what you announced there; the
drafts are written that way, in the order of the table. If you go patch by
patch, each commit needs `Closes #n.` at the end of its message once its
issue exists.

### 3. Commit identity

Done as you said on 2026-11-27: all 16 upstream-bound commits, on
`phase1-upstream` and on the 16 single branches, have
`1aeo <tor@1aeo.com>` as author and committer. They are unsigned. mr15 and
mr16 have the same identity although I wrote them.

No commit made in this work carries a trailer (`Co-Authored-By`, session
lines or similar), as you asked on 2026-11-28: not the 16 upstream-bound
commits, not the fork-only commits of the proposed `main`, not the new
snapshot. For reference: no commit in upstream exitmap names a tool in a
trailer, but eleven of your merged commits there have "Cursor Agent" as
committer and fifteen end with
`Co-authored-by: 1aeo <1aeo@users.noreply.github.com>`; no maintainer
commented on either. On stem!4 gk asked about the licence.

The GitHub-only commits (the two fork-only commits, the merge into `main` and
the snapshot) have `1aeo <github@1aeo.com>` as author and committer, as you
said on 2026-11-28. On GitLab your commits are mixed: 22 of your 31 exitmap
commits use `tor@1aeo.com` and 9 `github@1aeo.com`, among them the three
latest; both stem commits use `tor@1aeo.com`. The earlier snapshots on
`claude/gallant-newton-bdte6o`, which carried trailers, are gone from it:
the branch was replaced by the new snapshot (force push, at your request).

### 4. One fix belongs in stem

The hang that mr03 cannot prevent is a deadlock inside stem: Tor dies while
the main thread is in the middle of a request and an event callback uses the
controller. The fix is a separate small merge request for stem, and it is
filed: issue tpo/network-health/stem#11 and merge request
tpo/network-health/stem!11 (2026-11-28; the pipeline in your fork passed
against Tor stable and nightly). `review/stem/README.md` has the details. It
does not depend on the sixteen exitmap patches.

Against the emulated Tor that dies at 17 different moments (the emulator is
in `review/exitmap/emulator/`):

| | stem as released | stem with the fix |
| --- | --- | --- |
| upstream exitmap | exits in 6, hangs in 11 | exits in 16, hangs in 1 (exitmap's own wait, which mr03 fixes) |
| all 16 patches | exits in 16, hangs in 1 | exits in all 17 |

## What upstream asks for (from 60 MRs and 68 issues on GitLab)

- An issue first. See decision 2; gk did not reply to your announcement and
  later merged !47, !48, !52 and !56 without an issue. Commit messages end
  with `Closes #n.`; gk merges by hand and squashes fixups.
- Small diffs that are easy to check. gk on #68: "making it as easy as possible
  for the reviewer to avoid overlooking mistakes". None of your 17 merged MRs
  added a test (!39 repaired an existing one); the suite still has upstream's
  27.
- Crutches over machinery: "exitmap + stem is not the future as we move to
  arti ... checking for aliveness might be a sufficient crutch" (gk, !33).
- Lazy logging arguments (juga, !28/!33), naming that cannot be misread
  (`require_measured_relays`, !44), `doc/HACKING.md` updated when `probe()`
  changes (!23), flake8 clean on Python 3.10–3.13.
- A clean commit identity is your own practice, not a request from upstream
  (see decision 3).

## What the review changed

| # | Patch | Before | After | What changed |
|---|---|---|---|---|
| 1 | mr01 exit status | +43/−2 | +17/−4 | Same 2-line fix; test rewritten as two real `bin/exitmap` runs |
| 2 | mr03 dead controller | +107/−1 | +64/−3 | One check instead of two; two new guards against a stem deadlock; mock-heavy `main()` test dropped |
| 3 | mr05 queue reader | +102/−4 | +6/−2 | No-op pieces removed; kept daemon thread, bounded join, `cancel_join_thread()` |
| 4 | mr15 fork while logging | — | +11/−1 | New |
| 5 | mr16 bound on the wait | — | +84/−1 | New |
| 6 | mr02 scan completion | +98/−4 | +65/−4 | Same three coupled changes; tests halved and extended; limits disclosed |
| 7 | mr08 empty exit file | +14/−2 | +7/−2 | Only the empty-list fix; case handling moved to mr09 |
| 8 | mr09 fingerprints | +237/−20 | +15/−2 | Validation subsystem replaced by `.upper()` |
| 9 | mr10 config booleans | +33/−1 | +26/−1 | Public argparse API instead of `parser._actions`; invalid values are an error |
| 10 | mr12 failed circuits | +308/−7 | +60/−3 | Registry plus one log line per failure; no lock, no CLOSED accounting |
| 11 | mr11 reliable first hop | +250/−11 | +72/−2 | Flag plus the production filter and a fallback if it matches fewer than two relays; config/CLI conflict is an explicit error |
| 12 | mr06 teardown | +159/−42 | +17 | `run_module()` rewrite replaced by 4 lines |
| 13 | mr13 first hop to probe | +87/−6 | +50/−4 | Commit body added; docs corrected |
| 14 | mr14 stats to teardown | +60/−2 | +41/−2 | Docs corrected; compatibility note |
| 15 | mr04 reap children | +121/−2 | +32 | Deadline/SIGKILL machinery replaced by one `join()` |
| 16 | mr07 controller close | +34/−7 | +7/−7 | Pure block move; test dropped |

Total for the 14 that were yours: 1,653 added lines before, 479 after.

## Findings per patch

In the order of the branch.

### 1. mr01 — Preserve non-zero exit status and exceptions in bin/exitmap
- The fix was right. `or 0` did nothing (`main()` always returns an int).
- The test loaded `bin/exitmap` through importlib and patched three things in a
  loop of five cases. Now it runs the real script twice: once where `main()`
  returns 1 and once where it calls `sys.exit(1)`. It also checks that Tor's
  data directory is gone afterwards. Reverting either half of the fix, or
  cleaning up only when no exception is raised, makes it fail.
- The commit message named "missing Tor consensus" as a case of `main()`
  returning 1; that path is a `sys.exit(1)`. Reworded.

### 2. mr03 — Terminate scan early when Tor controller disconnects
- Removed the second aliveness check inside the `except` branch (the check at
  the top of the loop covers it) and the `main()` test that needed five patches
  for four lines.
- New: `remove_event_listener()` and `controller.close()` are skipped when the
  controller is dead. If Tor dies while an event callback waits for a reply,
  stem deadlocks and both calls block forever. Against the emulator this was
  the difference between hanging and exiting in 11 of 11 runs.
- Still not fixed, and said so in the message: Tor dying while the main thread
  is inside `new_circuit()`. That deadlock is in stem, and the fix for it is
  prepared in `review/stem/` (decision 4).
- On its own this change still ends with exit status 0; the status becomes 1
  with mr01.
- If Tor dies exactly while a circuit is being requested and stem does not
  deadlock, that one circuit is counted as failed (and, with mr12, logged)
  before the scan stops. The original version's second check avoided that.

### 3. mr05 — Bound queue-reader shutdown in EventHandler
- `put(None, timeout=1.0)` was a no-op on an unbounded queue, and the guard
  around the descriptor-missing `put()` had no reachable trigger. Removed.
- My first trim also removed `cancel_join_thread()`. The independent review
  showed that was wrong (Python joins the queue's feeder thread at exit), so
  it is back.
- The commit message lists the three confirmed ways the thread fails to
  terminate. With mr03 plus this, exitmap exited in 25 of 25 Tor-death runs
  where mr03 alone hung in 3 of 13 (the earlier review's runs, a different
  set from the 17 moments under "The order").
- The second of the three (Tor died) is only cured together with mr03: on its
  own this change never reaches the bounded join there. The message says so.
  Without mr01, a `teardown()` that raises ends in exit status 0 and no
  message instead of a hang.
- No test: a real one costs the 5-second timeout, a fast one only asserts mocks.

### 4. mr15 — Do not fork module processes while a log message is written (new)
- Not one of your branches. Local branch `mr15/fork-safe-logging`, one commit
  on upstream `main`, no conflict with any of the 14.
- The bug is in upstream today (see decision 1). There it usually costs one
  exit relay silently, because the blocked process is terminated at the end of
  the scan; with mr02 and without mr16 it would block the scan. Its commit
  message describes the completion rule as it is before mr02, so it has to
  stay ahead of mr02.
- The fix holds the locks of the root logger's handlers around
  `proc.start()`, so no other thread is inside a write at the moment of the
  fork. An independent reviewer could not break it: no deadlock in the parent
  in a stress test with two forking threads, and no hang in 322 emulated
  scans.
- In a loop that logs constantly, upstream's `EventHandler` finished 0 or 1
  of 200 probes with a log file and anything between 0 and 174 of 200 with
  stderr; with the fix 200 of 200 in every run.
- `PYTHONUNBUFFERED=1` hides the problem for stderr (not for `-o`), because
  stderr then has no buffer lock. This container sets it, which misled two
  earlier reviewers into calling stderr safe.
- No test: a real one needs threads and a fork, a fast one would only assert
  mocks. The issue draft has two reproducers instead.

### 5. mr16 — Stop waiting for module processes which never report back (new)
- Not one of your branches; written at your request of 2026-11-27. Local
  branch `mr16/bound-module-wait`, one commit on upstream `main`. Decision 1
  has what it does, what it costs and what is left to decide.
- Three independent design studies arrived at the same mechanism and the
  same place in the series; the patch is their common core. What only one of
  them had is left out: a table that names the abandoned exits, and a helper
  method.
- An adversarial review (two reviewers who tried to break it, one who read
  it as gk and juga would, one who checked every sentence) changed four
  things:
  - On `main`, and before mr02 in the series, the correction now counts
    exactly what `check_finished()` still waits for there. It used mr02's
    arithmetic before, so on `main` a later module of the same run would
    have stopped waiting for some of its own probes too early. That is gone,
    except after a give-up on a circuit that Tor never reported: it counts
    as failed, and `main`'s rule then lets a later module end one probe
    early for it, as for any failed circuit. mr02 now changes that one line
    together with its own rule.
  - The two tests were rewritten. They passed on 16 of 23 altered versions
    of the change, one of which made `wait()` never return. They now patch
    the clock. Of the 25 alterations in the mutation script, among them all
    that the reviewers found, every one that applies fails them, on the
    single branch, in the series and at the tip, except the two that remove
    a `max(0, ...)`; those matter only when more circuits were counted than
    requested.
  - Commit message: the first paragraph says where the exception comes from
    (`check_finished()` stops waiting for one module per failed circuit);
    "what we give Tor to start" instead of "to bootstrap" (the 300 seconds
    are for 75 percent of the bootstrap); and it says that the five minutes
    also pass while exitmap is stopped with Ctrl-Z.
  - mr02's message in the series: "terminated at the end of the scan"
    instead of "right away", and its last paragraph no longer says that
    with `==` the scan "never finishes": with mr16 it ends after five
    minutes. The single branch of mr02 keeps the wording for `main` without
    mr16.
- Written down instead of changed: a probe that reports back in the
  millisecond after the give-up is counted twice (mr18 fixes that
  separately; after a stop with Ctrl-Z it is far more than a millisecond, see
  "Separate: mr18"); circuits given up on are
  counted as failed but not logged by exit relay (mr12); stopped time
  counts; the issue draft has two sentences for `doc/HACKING.md` in case gk
  asks for them.
- The limit is a constant, `IDLE_TIMEOUT = 300`, and the clock is the time
  since the last message from any probe, counted only once all circuits are
  requested. It is not the timeout that #64
  removed: that one was 5 seconds on `queue.get()`, counted during the whole
  scan, and ended the reader thread when it fired. The commit message says
  so.
- On the branch the commit adds its check to the loop that mr03 gave
  `wait()`. On its own branch it has to introduce the loop itself, so the two
  single branches conflict in `wait()`; the commit on `phase1-upstream` is
  the resolution.
- Two tests: `wait()` leaves the counters alone before the limit and
  corrects them after it; a message read from the queue moves the clock.
  Both fail without the change and neither can hang.

### 6. mr02 — Fix scan completion accounting in EventHandler
- This is the real bug of the set. With one failed and one built circuit,
  upstream ends the scan after 0.0 s and kills the running module. Against a
  control-port emulator with 10 exits and 2 failed circuits, upstream probed 6
  or 7 of 8 built circuits, depending on timing, and the fix 8 of 8.
- Your production fork never had this fix: it softened the bug with the grace
  period in `shutdown()`. So this code is new, not 9 months old. Same for most
  of mr01–mr10.
- The three parts have to stay together: with only the first, one circuit
  that Tor builds on its own blocks the scan, on `main` for good and with
  mr16 until `wait()` gives up. exitmap asks Tor not to build such circuits
  (#36), so this is a safeguard; today such a circuit ends the scan one
  circuit early or hangs it, always if no circuit failed.
- Two limits are stated in the commit message. A module process that never
  reports back now delays the end of the scan until `wait()` gives up on it
  (before, it was terminated at the end of the scan if enough circuits had
  failed); that sentence relies on mr16, see decision 1. And a failed
  circuit exitmap did not create can still end a scan one circuit early.
- In the series the commit also changes one line of mr16's `wait()`, so that
  a give-up counts the module processes of all built circuits, as the new
  rule does. The single branch, made for `main` without mr16, has neither
  that line nor the sentences about `wait()`: there such a process "now
  blocks the scan".

### 7. mr08 — Do not scan all exit relays if the exit file is empty
- Split: this MR keeps the empty-list fix (2,290 exits selected for an empty
  list on the test consensus), mr09 gets the case handling. Retitled.
- Not covered, and unchanged from upstream: an empty *argument* (`-E ''`,
  `-e ''`) still means "option not given" and scans everything.

### 8. mr09 — Accept lowercase fingerprints for -e/--exit and -E/--exit-file
- Before: three helpers, `$` prefixes, `#` comments, BOM handling, de-duplication,
  validation before bootstrapping, and a new parameter on `select_exits()` and
  `run_module()`. None of it existed in the production fork.
- After: `.upper()` in two places. Lowercase lines in a mixed-case exit file
  were being skipped silently, which is the stronger argument and is now in the
  commit message. Retitled; the branch name still says "validate".

### 9. mr10 — Parse boolean options from exitmaprc as booleans
- `parser._actions` is private; `parser.get_default()` does the same job.
- An invalid value is now `exitmap: error: bad_exits in <file>: Not a boolean:
  maybe` instead of a warning that drops the option. An empty value used to
  count as false and is now an error too.

### 10. mr12 — Track and log failed circuits by exit relay fingerprint
- Before: a lock, five internal collections, per-module reset, and CLOSED
  events counted as failures (which changed `failed_circuits`, and so scan
  completion).
- After: `pending_circuits` and `failed_circuit_relays`, one INFO line when a
  circuit fails. It replaces the debug message for circuits which could not
  be created, which carried the same data. A lock around `new_circuit()` was
  considered and rejected: it would add a deadlock when Tor dies during that
  call.
- Known limit, in the commit message: a FAILED event handled before
  `new_circuit()` returned cannot be attributed. How often that happens
  depends on how soon the event follows the reply. In the emulator, of 300
  failing circuits, none were lost when the event came 5 ms or more after the
  reply, a few at 0.2–1 ms (0–8; up to 26 on Python 3.10), and anything from 2
  to over 100 when it followed immediately. Against a real Tor (the private
  network on this machine) it happens when the first hop fails at once,
  e.g. a relay on the same host that refuses the connection: Tor's FAILED
  event came 40 to 300 microseconds after the reply, before exitmap stored
  the circuit, and 8 to 20 percent of those failures were not attributed.
  Failures further along the path (0 of 300) and built circuits (0 of 100)
  lost nothing. The circuit then also stays in `pending_circuits`, one small
  entry per lost failure; nothing reads it. The original version matched
  such early events, at the price of the lock and the extra bookkeeping.
- An outside review suggested an `_early_failed` dict without a lock. It is
  not race-free: four of the six orders of its operations still lose the
  failure (83 in 100,000 runs with ordinary thread switching). A small lock
  inside `Statistics`, held only around the two dict operations and never
  around a call to Tor, lost nothing (+23/-2 lines and a test). I kept mr12
  small for upstream; the locked version is ready as a follow-up for your
  fork if dnshealth's `circuit_failures.json` has to be complete. When you
  submit mr12, its sentence about the limit can read: "If Tor reports the
  failure of a circuit before new_circuit() has returned, e.g. because the
  first hop refused the connection, the failure cannot be assigned to an
  exit relay: it is only counted, as before, and the circuit stays in
  pending_circuits."
- The entries are kept for the whole run, like the counters: a later module
  still sees the failures of earlier ones.
- `failed_circuit_relays` keeps the shape dnshealth reads.
- It belongs after mr03: without mr03 exitmap keeps requesting circuits
  after Tor died, and each of the remaining exits would be logged and
  recorded as a failed circuit.

### 11. mr11 — Add --reliable-first-hop option using filtered guard selection
- Removed: fingerprint de-duplication (a consensus has no duplicates), `None`
  bandwidth guards in relayselector (0 of 7,587 relays in the test consensus),
  and 25 lines of config-file handling.
- The filter is exactly the production one, and so is the log line "Using N
  reliable guards for first hop."
- The fallback to all relays from your original MR is kept, with its
  threshold (fewer than two matching relays, since an exit relay is never its
  own first hop). My first trim dropped it; the final cross-check showed why
  it is needed. While fewer than three bandwidth authorities are measuring,
  every relay in the consensus is unmeasured (dir-spec; it happened in
  February 2018). `-r` would then end every scan at the first circuit with an
  `IndexError`. The production code has no fallback and would do the same
  with `RELIABLE_FIRST_HOP=1`. Now a warning is logged and all relays are
  used.
- A first hop from the config file plus `-r` used to be accepted silently with
  a misleading log line; now it is an error. `-i ''` overrides the config file.
- Added `-r` as short option, as every other option has one.
- Wording follows gk's !44 request ("authority-measured", not "measured
  bandwidth"), and the commit message gives the raw numbers from #65 (15 of 318
  against 5 of 318) rather than only percentages.
- Left alone: `reliable_first_hop = true` in the config file cannot be
  switched off on the command line, like the other boolean options.

### 12. mr06 — Call module's teardown() if no exit relays are selected
- Before: `run_module()` re-indented into one try/finally, teardown moved out
  of `EventHandler`, a `can_teardown` flag, swallowed exceptions, and a moved
  `total_circuits` increment that changed nothing. One of its four tests passed
  without the fix; test modules were named `dummy_mr5`.
- After: `teardown()` is called before `ExitSelectionError` is raised, which is
  the one early error exitmap survives. Real but small effect: patchingCheck
  no longer leaves its reference file in `/tmp`.
- If this and mr14 both land, this call must pass `stats=stats`, and the one
  that lands second has to carry it (mr14 in the order above). Git, the tests
  and flake8 all stay quiet if it is forgotten. `phase1-upstream` has the
  change, plus a stricter assertion in mr06's test that fails without it;
  both sit in its mr14 commit, which therefore differs from the mr14 branch
  by those two lines.
- Needs mr01 before it: if `teardown()` raises when no exit was selected, the
  run stops there, and without mr01 it ends with status 0 and no message.

### 13. mr13 — Pass circuit first_hop fingerprint to module probe()
- The commit had no body. The HACKING.md sentence about `destinations` was
  inaccurate and is gone; only `first_hop` is described.
- A `probe()` outside the tree that does not accept `**kwargs` fails with a
  `TypeError` for every exit relay. All modules in the tree accept them, and
  the commit message says that others need to. That is not new for a module
  written to the letter of `doc/HACKING.md`: upstream already passes
  `destinations=`, which the documented signature lacks. What mr13 breaks is
  a module that names `destinations` but has no `**kwargs`.

### 14. mr14 — Pass scan statistics to module teardown()
- A module with `def teardown():` now gets a `TypeError`. On upstream alone
  that is swallowed by `bin/exitmap` and exitmap hangs at exit; with mr01 and
  mr05 merged it is a traceback and exit status 1. Hence the order.
- HACKING.md now says the `Statistics` object is shared by all modules of a run.

### 15. mr04 — Reap terminated module processes during EventHandler shutdown
- 36 lines of shared deadlines, SIGKILL escalation and exception handling for
  children that die on SIGTERM anyway, plus an 86-line test of mock call
  order. Now `proc.join(timeout=1)` after `terminate()`.
- Honest value: tidying. The one real effect is that probes are gone before
  `teardown()` runs.

### 16. mr07 — Close Tor controller when --first-hop is absent from consensus
- Correct, but nothing observable changes: the process exits right after and
  Tor is owned by it. Now a pure move (`git diff -w` shows one line). The
  26-line test with six patches is gone.

## If you submit them as separate merge requests

Of the 120 pairs of single branches, one conflicts in a source file: mr03
and mr16 both turn the single line of `wait()` into a loop. The resolution
is the loop with both checks, as on `phase1-upstream`. Test files conflict
in 20 pairs:

- `test/test_eventhandler.py` is created by mr02, mr03, mr04, mr13, mr14 and
  mr16 with the same fixture. Only one of them can be open at a time without
  a rebase.
- `test/test_exitmap.py`: mr03/mr11/mr12 add a test at the same place, as do
  mr06/mr09 and mr10/mr11.

Rebasing the single branch of mr02 onto a `main` that has mr16 applies
without a conflict in `src/eventhandler.py` but keeps
`- self.stats.failed_circuits` in `wait()`; the mr16 test then fails. Use the
commit from `phase1-upstream`, which removes that line.

`phase1-upstream` has no such problem, because each commit there already
builds on the ones before it. Its commits differ from the single branches
only in these two test files and `tox.ini` (each commit holds exactly its own
tests and imports), in the two lines of the mr14 commit named under mr06,
in `wait()` of the mr16 commit, which there adds its check to mr03's loop,
and in the mr02 commit, which there changes one line of that check and has
the commit message that fits after mr16.

## What changes on your `main`

Compared with the production code. The first two are upstream's behaviour
and were already on `main`:

- The directory that holds Tor's data directory (`-t`) must be sticky, like
  `/tmp`, or owned by you with mode 700. Production accepted any parent.
  Otherwise exitmap prints "Parent directory ... is not owned by the user or
  hasn't mask 700." on stderr, does not start Tor and exits with status 1.
  Your deploy wrapper used `$HOME/exitmap_tor*` when it was last in this
  repository, and Ubuntu creates home directories with mode 750.
- `-d/--build-delay` defaults to 3 seconds again (production: 0). The wrapper
  passed `--build-delay` itself, so only runs without the option change: they
  wait 3 s between circuits, about 1.9 hours for 2,290 exits.
- Exit files must hold bare 40-digit fingerprints, one per line, in any case.
  `$` prefixes, trailing comments and a BOM are not understood. That is the
  same as production and upstream; only the current `main` accepted them.
- Exit status: 1 when Tor dies or exitmap fails (new), 2 for an invalid
  boolean in the config file or `-r` together with a first hop, and still 0
  when no exit matches. Treat status 0 with zero circuits as "nothing
  scanned".
- Failed circuits are logged one per line when they happen: `Circuit with exit
  relay "X" and first hop "Y" failed because: R`. If Tor dies, the message is
  upstream's "Terminating because the controller is not alive."
- `scan_stats.json`: `unresolved_failures` keeps its meaning from
  production, the number of failed circuits that could not be assigned to an
  exit relay. A failure that Tor reports before `new_circuit()` has returned
  is no longer among them: the fork-only lock commit (the mr12 limit above)
  assigns it once the circuit's hops are known, so it is in
  `circuit_failures.json`. Still counted there: circuits that `wait()` gives
  up on, failed circuits that exitmap did not create, and the second count
  of a circuit that Tor rejects with 551 (see "The outside review"). The
  number is exact only if dnshealth is the only module of the run.
- dnshealth still accepts `terminated_relays` and `controller` in
  `teardown()`, but nothing passes them any more.
- A probe that never reports back: production gave the remaining probes 10
  seconds at shutdown, terminated them, logged "Terminated N stalled relays"
  and recorded their exits as timeouts. Now every probe is waited for, and
  exitmap gives up five minutes after the last message from any probe
  (decision 1). The log then has one warning with the number of probes, not
  their exits, and dnshealth writes no result for them. Circuits that never
  got a result are counted as failed and show up in `unresolved_failures`.
- With mr18, nothing that arrives after the end of a module's scan is
  counted, and no probe is started for a circuit built after it. A probe
  that reports back right after `wait()` gave up, which is likely after a
  stop with Ctrl-Z, no longer makes the next module of the run end early.
  dnshealth usually runs alone, so on your scans this mostly keeps the
  final numbers right.

## The snapshot branch and your `main`

`claude/gallant-newton-bdte6o` is the snapshot. Its tree is your new `main`
plus the `review/` folder. Its first parent is the new `main`; the single
branches mr01 to mr18 (mr01 also as it was submitted, `cb56066`) are further
parents, and so is the snapshot before it. Keep this branch: it is the only
GitHub branch that holds the single branches and mr18.

The new `main` is linear. On top of the 16 commits of `phase1-upstream`
(`a212bd7`) it has five more:

| Commit | What | Author and committer |
| --- | --- | --- |
| `c399526` | mr17, the torsocks fix | `1aeo <tor@1aeo.com>` |
| `a8323f7` | mr18 (the same change as `fc40ee8`) | `1aeo <tor@1aeo.com>` |
| `15fa2a0` | fork: dnshealth module and deploy shims | `1aeo <github@1aeo.com>` |
| `d2f36de` | fork: dnshealth error prefixes (PR #21) | `1aeo <github@1aeo.com>` |
| `ffdda25` | fork: the locked mr12 bookkeeping ("attribute early circuit failures") | `1aeo <github@1aeo.com>` |

All of them are unsigned and carry no trailer. The full suite (150 tests)
passes on Python 3.10 to 3.13 and flake8 is clean.

Your current `main` (`dcf8bb6`) is not part of this history: its 16 commits
are the earlier versions of the patches and of the two fork commits. So
moving `main` is a force push, as you decided. No file disappears; the 14
files that differ hold the reviewed versions. The open PRs #19, #20 and the
draft #1 target `main` and are based on those old commits: after the force
push GitHub shows the old commits in their diffs as well, until their
branches are rebased onto the new `main`.

The first fork commit needed three adaptations: the `RELIABLE_FIRST_HOP` shim
moved to the new place in `iter_exit_relays()`, one dnshealth test uses the
new `Statistics` names, and dnshealth computes `unresolved_failures` from the
counters, because the `_early_failed` attribute it used to read is gone.
(`stats=stats` for the second `teardown()` call is in the mr14 commit of
`phase1-upstream`, see mr06 above.) The second one (PR #21, the dnshealth
error prefixes) applies unchanged on top. The lock commit brings
`_early_failed` back, now inside `Statistics` and under a lock; dnshealth
does not read it.

Done already, by you, on 2026-11-28: the 14 old `mrNN` branches are deleted,
and `phase1-upstream` is on GitHub at `a212bd7`.

**The git commands, in order.** In your clone of `1aeo/exitmap` from GitHub.

1. Get the snapshot, which holds every commit below:

```bash
git fetch origin claude/gallant-newton-bdte6o
```

2. Move `main` to the new history. `--force-with-lease` refuses if `main` on
   GitHub is no longer at `dcf8bb6`:

```bash
git push --force-with-lease=main:dcf8bb6a458ce6fd58cd9b6b3d049e58b838af1b origin ffdda25932c52f886d05bc0f7a9fb33ff1f0254e:refs/heads/main
```

3. Update your local `main`, to run it yourselves. The second command drops
   local commits on `main` that are not on GitHub:

```bash
git fetch origin main
```

```bash
git checkout -B main origin/main
```

4. Only if you want the single branches locally, for separate merge
   requests (they are parents of the snapshot, so step 1 fetched them):

```bash
git branch -f mr01/preserve-exit-status cb56066c77d349f1811a794bad69e1925cf48643
git branch -f mr02/fix-check-finished 0b90e9a7c50604b0ab7f74f5a178365c86d14774
git branch -f mr03/detect-dead-controller c9ca94e113e8bde1fc6b0a12d804fb0d231bbec4
git branch -f mr04/reap-terminated-children e8bb3cb5eb3bc97faa0241126a90fb9381f7f59a
git branch -f mr05/bound-queue-shutdown 5164056c94649530fcdaa7d5770d3bfc6438a9e2
git branch -f mr06/teardown-on-early-errors 8cd1f962c304348ba9177f4abcd064a5a9d8a00d
git branch -f mr07/fix-first-hop-controller-leak f5d4f941dcb99a0979b85fa6a7d41448ebce431d
git branch -f mr08/fix-requested-exits-filter bad761af15dd5c2f528fbf7b0d4ca056b1b6e09c
git branch -f mr09/validate-exit-fingerprints 60ccaf90f008fc09756491cff11c2c6d53c86737
git branch -f mr10/parse-config-booleans a825d0e6db5ce558fba40c7449e3d19babfb2dbf
git branch -f mr11/reliable-first-hop 8affc7bb27a0e16ce30a1a7392c05a36843e2030
git branch -f mr12/track-failed-circuits 05e99910b39f554ab409b2806e614c8b5c6c71b8
git branch -f mr13/pass-first-hop-to-probe 3ab0e147248c1384696f357fc16d986d1a0f8fca
git branch -f mr14/pass-stats-to-teardown 229ebeba31cccebaf5ff4b7b98f4c9f2353e8171
git branch -f mr15/fork-safe-logging 6aea7e2b4efda6263ab5ea4c70deba3ad14d0a1c
git branch -f mr16/bound-module-wait d33d69db55f639f158eb210cb4aa5ece2292eb55
git branch -f mr17/send-queue-once 2e4e15a6a55cad83651081117655158d06883995
git branch -f mr18/ignore-late-events fc40ee8c57442ff050f29f3cb956bba0f0c322cb
```

For GitLab nothing here pushes; each push there needs your approval first.

## Separate: the torsocks fix for #46 (`mr17`)

Not part of `phase1-upstream`. It is ready as the branch
`mr17/send-queue-once` (one commit on upstream `main`, 3 lines of code and a
16-line test), with its texts in `review/exitmap/torsocks/`.

**The bug.** `src/torsocks.py` announces the n-th connection of a probe n
times. `_Torsocket.__init__` replaces an entry of PySocks'
`_proxy_negotiators` with a wrapper around the previous entry, and that dict
belongs to the class, so every new socket wraps the wrapper of the one
before. The second message makes exitmap attach stream `None`, and the
stream Tor reports next is never attached; after two minutes the module
gets `0x06: TTL expired`. It came with the port to Python 3 (4d678bc,
2020). It hits every module that opens more than one connection per probe,
`rtt` in the tree among them. It does not hit the DNS modules or dnshealth,
which use `resolve()`.

**Your condition.** You said on 2026-11-27 to fix it only if it resolves an
open upstream issue. #46 (open since 2023, "Support scanning multiple
targets over the full exit list") is the one: both approaches described
there open all their connections in one probe process and hit this bug. gk
had linked #46 to !5, and the notes of !5 from February to May 2021, which
nobody here had read before, show this bug's pattern: `Attempting to attach
stream None to circuit 4.`, attachers that pile up, and `prepare()` called
again and again with the circuit and no stream. gk called it "a hard to
track down bug" and closed !5 in 2022. No other open issue is resolved by
it; #4 (circuit build errors) has one connection per probe.

**Tested against a real Tor.** The Tor 0.4.9.11 installed here ran a
private network of three relays inside a network namespace with only
loopback, so nothing left the machine. With the real `bin/exitmap` and a
module that fetches several URLs per exit, connection 2 failed in 27 of 27
probes on upstream `main`; with the fix none of the 243 connections that
should have worked failed. `rtt` got 1 of its 10 measurements per exit,
with the fix 10 of 10 (one run, three exits). The fake Tor gave the same
picture.

**Why "Relates to #46" and not "Closes".** #46 has no logs, so nobody knows
whether this was all art saw. Tor also closes a circuit that has been in
use for more than 10 minutes (`MaxCircuitDirtiness`) while a probe pauses
between targets; the fix does not change that. The comment for #46 offers
to change the commit to "Closes #46" if gk agrees.

**How to send it.** No new issue: open the merge request with
`review/exitmap/torsocks/mr-description.md`, then post
`review/exitmap/torsocks/issue46-comment.md` in #46 with the number of the
merge request. Any time, independent of the 16; a reviewer found no reason
to put it into the branch, which would renumber patches 12 to 16.

## Separate: mr18, late reports after the give-up

Not part of `phase1-upstream`. It is ready as the branch
`mr18/ignore-late-events` (`fc40ee8`, one commit on `a212bd7`, author and
committer `1aeo <tor@1aeo.com>`, no trailers), with its texts and evidence in
`review/exitmap/mr18/`. You asked for it on 2026-11-28, after the outside
review had found the race and its proposed lock did not close it.

**The bug.** When mr16's `wait()` gives up, it counts the circuits that are
neither built nor failed as failed and the module processes that have not
reported back as finished, because all modules of a run share the
statistics. A module process can still report back, and Tor can still
report one of those circuits, until `shutdown()` has removed the listener and
terminated the processes. Each is then counted twice: after a late report
the next module of the run stops waiting for its module processes one too
early, after a late FAILED for its circuits, and after a late BUILT exitmap
starts a module process that is terminated at once, so the next module waits
for it until `wait()` gives up again.

**How likely.** After a hang the window is a few milliseconds. After a stop
with Ctrl-Z it can be wide open: when exitmap continues, `wait()` gives up at
once unless a message comes first, and the module processes, continued with
it, report back just then. Against the emulator (limit 5 s, two modules of 10
exits, exitmap stopped for 7 s while the first module's probes ran), on
Python 3.11 to 3.13 `wait()` gave up in 17 of 28 runs without the fix, and
the second module then ran only 0 to 3 of its 10 probes. With the fix it ran
all 10 in all 28 runs. On Python 3.10 the emulator's sleeping probes keep
sleeping after SIGCONT and never report back in time, so these runs show
nothing there; a probe that waits in `recv()` shows the same race on 3.10.

**The fix** (+26/-12 in `src/eventhandler.py`, a 32-line test). `wait()`
sets `already_finished` and `finished_event` and corrects the counters while
holding `check_finished_lock`. The queue reader and `new_circuit()` count only
while holding that lock and only if `already_finished` is not set, and
`new_circuit()` then starts no module process either. Since
`already_finished` is also set by a normal end and by the controller's
death, this holds after every end of a module's scan. One consequence, named
in the commit message: when foreign or doubly counted circuits end a scan
early, the exits whose circuits are built after that are no longer probed
(before, they were if their probe ended in time; otherwise the next module
waited for it).

**Review.** Four reviewers and a skeptic for each finding. None found a
problem in the code; they found wording and evidence to correct, and two
gaps in the test. What changed after it:

- The first sentence of the commit message said that `wait()` counts "their
  circuits", the circuits of the silent module processes, as failed. It
  counts the circuits that Tor has not reported yet; corrected.
- Ctrl-Z was told as certain; it is a race, and the text now says so.
- The new paragraph on the early end of a scan, above.
- The test now also checks that the queue reader handled the late report
  and went on to the shutdown signal: before, a reader that hangs on the new
  lock, dies or skips the report passed it. It moved next to mr16's test, so
  that the commit also applies on the series up to mr02, without mr04's
  test.
- The README claimed the race scripts catch the versions without one of the
  locks. They cannot (`wait()` sets the flag before they deliver anything).
  `trace_pause.py` now does: it holds the reader or `new_circuit()` on the
  counting line while `wait()` gives up, and each version without a lock
  counts twice. Two altered versions in the mutation script landed in the
  wrong function; fixed, and the script now refuses an ambiguous anchor.
- The merge request text has a reproducer that needs no Tor (2 module
  processes counted for 1 built circuit without the fix, 1 with it), and
  names the Python versions behind its numbers.

**How to send it.** After the merge requests of mr03, mr16 and mr02 are
merged (mr02 in its `phase1-upstream` form): cherry-pick `fc40ee8` onto
upstream `main`, end the message with `Relates to #<issue of mr16>.`, and
open the merge request with `review/exitmap/mr18/mr-description.md`. No issue
of its own; the merge request of mr16 names this limit and says that the fix
will follow.

The fork-only lock commit for your `main` was reviewed in the same round:
its last line was parsed by git as a trailer (`Fork-only: ...`) and is a
sentence now, the pop of a built circuit takes the lock as well, so that the
message's claim holds, and a test now covers the one line in
`iter_exit_relays()` that makes it work (without it, reverting that line
passed all tests).

## The outside review (Gemini)

An outside review of this snapshot raised six concerns about the code and
added notes on production and on the git commands. Each was tested; the
scripts are in this session's scratch space.

- mr16: a lock around the give-up, to close the race with a late report or
  circuit event. The race is real and documented; the proposed lock changes
  nothing (15 of 15 cases identical), because the threads that increment the
  counters do not take it. No updates are lost on CPython 3.10 to 3.13. A
  real fix is about 7 lines in three methods. At first not adopted, for a
  window of about a millisecond after five silent minutes; at your request
  it is now the separate patch mr18, and a test with Ctrl-Z showed that the
  window is much wider after a stop (see "Separate: mr18").
- mr12: the lost attribution and a stale `pending_circuits` entry. Both
  real, see finding 10; the lock-free fix it proposed is not race-free.
- mr04: shutdown taking N seconds. Only for probes that ignore SIGTERM, and
  then its two-loop version is just as slow; ordinary probes take about
  0.6 ms each. mr04 stays out of the submission.
- mr11: the removed bandwidth guard. Its premise (that stem marks such a
  relay as unmeasured) is wrong, and `-r` would raise a TypeError on a relay
  without a "w" line; but Tor's authorities always write that line, and
  Tor's own code calls a missing one something that "should never happen".
  Left out; it would be one changed line in mr11.
- mr06, mr09, mr11, the production differences and the git notes: accurate
  apart from details (an Onionoo error does call `teardown()`; a bad `-e` or
  `-E` ends with status 0, only `-i` fails). Two of its points corrected
  slips in this report: production logged counts, not fingerprints, and the
  mr13 note on `**kwargs`.
- Found on the way, older than all of this: when Tor rejects an
  EXTENDCIRCUIT outright (reply 551), exitmap counts the circuit as failed,
  and the CIRC FAILED event Tor sends right after is counted again (22
  failures counted for 20). Like a failed circuit exitmap did not create
  (mr02's message), that can end a scan before its last circuits are built.
  Not fixed.

## How this was checked

- Every commit of `phase1-upstream` passes the tests and flake8 on its own
  on Python 3.10 to 3.13 (64 runs on a212bd7, 2026-11-28). Its tip has the same tree as
  the stack that was reviewed before the reorder; the tool that rebuilt it
  reproduces that old stack commit by commit when it is given the old order.
  Each single branch passes on its own. Every commit that adds tests has at
  least one that fails when its change is reverted (19 of the 20 new tests;
  mr11's fallback test fails when the fallback alone is removed).
- The order: the three rankers read every diff and ran the real
  `bin/exitmap` with stem 1.8.2 against the emulator. One of them ran every
  prefix of the series (in an order that differs from the final one only in
  the position of mr13, which it had before mr06) through 24 normal and 17
  Tor-death scenarios: no prefix was worse than upstream, apart from the two
  trade-offs that belong to the patches themselves (mr02: decision 1; mr13
  and mr14: modules outside the tree).
- Before that, three independent reviewers and two rounds of cross-checks
  ran the real `bin/exitmap` and stem 1.8.2 against control-port emulators
  (normal scans, failing circuits, Tor dying at chosen points). Each finding
  was then attacked by a second agent; what survived is in this report.
- mr18 and the fork's lock commit (2026-11-28): the unit tests on Python
  3.10 to 3.13, 26 altered versions of mr18 (22 caught by the tests, the
  three without a lock caught by `trace_pause.py`, one harmless), the race
  scripts, the reproducer without Tor, and the Ctrl-Z runs against the
  emulator on all four versions. Then four reviewers (logic and threads, a
  maintainer's reading, every factual sentence, the fork commit and the new
  `main`) and a skeptic for each finding; what they found is under
  "Separate: mr18". A reviewer's stress test of the lock commit (20,000
  circuits, some failing before `new_circuit()` returned and some at the
  same moment, Python 3.10 to 3.13) lost no attribution; only circuits built
  before `new_circuit()` returned stayed in `pending_circuits`, which is
  harmless. Without the commit, all 4,158 early failures were lost. (That
  run was made with the first version of the commit; the final one also
  takes the lock for a built circuit and adds a test.)
- mr03 and mr05, again before submitting (2026-11-28): the tests on four
  versions, the two snippets of mr05's issue, the emulator's 17 moments at
  which Tor dies (upstream hangs in 11, mr03 in 6, mr03 with mr05 in 1, and
  with the stem fix as well in none), and the first two cases of mr03's
  issue against the private Tor network below.
- There was no access to the Tor network. exitmap ran against the
  emulators and, for the torsocks fix and for mr03, against a private
  network of three Tor relays on this machine. Statements about how the
  public network times its events are from those runs and from Tor's
  documentation.
