# mr03, as submitted on 2026-11-28

- Issue: https://gitlab.torproject.org/tpo/network-health/exitmap/-/issues/70
  (`issue_title.txt`, `issue_body_as_filed.md`: `issue_body.md` with the
  placeholder for the other issue replaced by #71)
- Merge request: https://gitlab.torproject.org/tpo/network-health/exitmap/-/merge_requests/62
  (title: the commit's subject; description: `mr_description_as_filed.md`),
  from `1aeo/exitmap` branch `detect-dead-controller`, "allow commits from members who can
  merge" on, no squash, like !61. It names !63, the other one of the pair.
- Commit: `9b3f83f8e251753d3979be9f0a4dbe7fb312473d` (`commit_msg_as_pushed.txt`): the tree of `f64ddd3` (the single
  branch) on `d02f923`, author `1aeo <tor@1aeo.com>` with the original date,
  the same committer, unsigned, its message plus `Closes #70.`
- Fork pipeline 435998: test on Python 3.10, 3.11, 3.12 and 3.13 passed.
