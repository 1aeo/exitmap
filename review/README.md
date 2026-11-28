# Review material

This folder exists only in the snapshot on `claude/gallant-newton-bdte6o`.
It is not part of your `main`.

## exitmap

The 16 patches for upstream are the branch `phase1-upstream`: one commit
each on upstream `main`, most important first, optional last. The fifth,
mr16, is the bound on waiting for probes that never report back.

- `exitmap/phase1-review-report.md`: the order and the reasons for it, what
  was found in each patch, what changed, what is left for you to decide, and
  the git commands for GitHub. Start here.
- `exitmap/phase1-upstream-issue-drafts.md`: one draft issue per patch, in
  the same order, with reproducers.
- `exitmap/torsocks/`: the separate fix for upstream issue #46 (mr17), with
  the text for its merge request, the comment for #46 and the scripts behind
  its numbers. It has its own README.
- `exitmap/repro/`: the two reproducers for mr15 and the one for mr16.
- `exitmap/emulator/`: a small stand-in for Tor that can die at a chosen
  moment, with the scenarios behind the table in decision 4 of the report
  and the ones for mr16. It has its own README.

## stem

Filed on 2026-11-28 as tpo/network-health/stem#11 (issue) and
tpo/network-health/stem!11 (merge request).

- `stem/README.md`: the fix, what it costs, the decisions, how it was
  submitted and how it was checked.
- `stem/issue.md`, `stem/merge_request.md`: the texts as written, with `#N`
  where GitLab now has #11.
- `stem/0001-Fix-reader-thread-deadlock-when-tor-disconnects.patch`: the
  commit, for `git am` on stem's `maint`; the one in the merge request ends
  with `Closes: #11.`.
- `stem/reproduce_*.py`: two reproducers of the bug and one of the fix's
  known cost.
- `stem/reserve/`: one reproducer for each of the four related deadlocks the
  fix does not cover, and a spare unit test.
- `stem/scenarios/`: the scripted scenarios and the random-kill test behind
  the numbers in the merge request. It has its own README.

## How the snapshot is built

Its tree is your new `main` plus this folder. Its first parent is the merge
into your `main` (old `main` plus the rebuilt history: upstream exitmap, the
16 patches, the torsocks fix and the two fork-only commits). The other
parents are the single-commit branches mr01 to mr17, each based on upstream
`main`. The stem commit is not in this repository; it is the patch file
above and the merge request on GitLab.
