# torsocks: the n-th connection of a probe is announced n times

A fix for upstream issue #46, separate from the 16 patches of
`phase1-upstream`. It shares no file with them and can be sent at any time.

- Branch: `mr17/send-queue-once`, one commit on upstream `main` (`d02f923`),
  author and committer `1aeo <tor@1aeo.com>`, no trailers. 3 lines in
  `src/torsocks.py`, a 16-line test in `test/test_torsocks.py`.
- `0001-Send-each-socket-s-name-to-the-queue-only-once.patch`: the same
  commit, for `git am`.
- `mr-description.md`: the merge request description, with a snippet that
  shows the duplicate messages without Tor.
- `issue46-comment.md`: the comment for #46. Replace `!NN` with the number
  of the merge request.

## How to submit

No new issue: #46 is the issue. Open the merge request first, then post the
comment in #46 with its number. The commit ends with "Relates to #46.", and
the comment offers to change that to "Closes #46" if gk thinks the fix is
enough. Nobody can say for sure that it is: #46 has no logs, and Tor also
closes a circuit that has been in use for more than 10 minutes
(`MaxCircuitDirtiness`) while a probe pauses between two targets.

## What it fixes

`_Torsocket.__init__()` replaces the SOCKS5 entry of PySocks'
`_proxy_negotiators` with a wrapper that announces the connection on the IPC
queue. That dict belongs to the class, so every new socket wraps the wrapper
of the socket before it. The second connection of a probe then sends two
messages, the Attacher tries to attach stream `None`, and the stream Tor
reports next is never attached. After Tor's SocksTimeout (two minutes) the
module gets `0x06: TTL expired`. Since the port to Python 3 (4d678bc, 2020).

Affected: every module that opens more than one connection per probe through
`socket.socket()`, `urllib` or `http.client` (also a redirect), e.g. `rtt` in
the tree and the multi-target modules of #46 and !5. Not affected: the DNS
modules and dnshealth, which use `resolve()`.

The same pattern is in gk's and Corl3ss's logs in !5 (February to May 2021),
once it probed several targets per exit: `Attempting to attach stream None to
circuit 4.`, pending attachers that only go up, and `prepare()` called again
and again with the circuit and no stream. gk took it on as "a hard to track
down bug" and closed !5 in 2022. In #46 they called it "probably the same
issue".

## Numbers, and where they come from

Against a private Tor network on this machine: one directory authority and
two relays, Tor 0.4.9.11, inside a network namespace with only loopback, so
nothing left the machine. The real `bin/exitmap`, with a module that fetches
several URLs over each exit, one `urlopen()` per `run_python_over_tor()`
call (`results/privnet_tally.txt`):

| | runs | probes | connection 2 failed | even connections 4 to 30 failed | odd connections failed |
| --- | --- | --- | --- | --- | --- |
| upstream `main` | 9 | 27 | 27 of 27 | 5 of 105 | 0 of 129 |
| with the fix | 8 | 24 | 0 of 24 | 0 of 99 | 0 of 120 |

The 243 connections with the fix leave out connection 1 of one run, whose
host name was made unresolvable on purpose.

The `rtt` module of the tree, one run with three exits
(`results/privnet_rtt.txt`): upstream recorded 1 of 10 measurements per exit
and then got `0x06: TTL expired`; with the fix 10 of 10.

Without Tor, `scripts/count_msgs.py <exitmap tree>` counts the messages per
connection: 1, 2, 3, 4, 5, 6 on upstream `main`, 1 each with the fix.

## Running the scripts

Linux, `/usr/bin/tor`, and a Python with exitmap's requirements (stem,
PySocks). The private network needs a network namespace:

    unshare -rn -- python3 scripts/lo_up.py \
        python3 scripts/privnet.py /tmp/privnet-out up=<upstream tree> fixed=<fixed tree>
    python3 scripts/privnet_tally.py up /tmp/privnet-out/run-up
    python3 scripts/privnet_tally.py fixed /tmp/privnet-out/run-fixed

Each run writes `run-<label>/results.txt`; the table above sums the runs of
several such output directories.

`lo_up.py` refuses to run outside an isolated namespace. `privnet.py` takes
its settings from the environment (`MULTI_N` connections per exit, default
6; `PRIVNET_MODULE=rtt` for the rtt run; `PRIVNET_SOCKSTIMEOUT` to shorten
Tor's two minutes); its docstring lists them. The runs above were made as
root in a container; `unshare -rn` is the unprivileged equivalent and was
not tried.
