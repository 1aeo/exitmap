Follow-up to #61. The aliveness checks added there only run when exitmap
handles an event from Tor or a message from a module, and once after all
circuits were requested.

* If Tor dies after all circuits were requested, while no module is
  running, nothing sets `finished_event` and `EventHandler.wait()` blocks
  forever.
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
* gk's steps from #61 (note_3330854) show a variant of the last case: the
  callback sends `ATTACHSTREAM` only after Tor died and then waits for the
  socket's send lock, which stem's reader thread holds while it joins the
  event thread. Their test patch no longer applies (`git apply -3` leaves conflicts). Two lines of it are
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
  this change exitmap exited 3 and 1 seconds after Tor died, without running
  the second module.
* A real Tor cannot be made to die at an exact point of the protocol, e.g.
  while a `GETINFO` is pending, so the real `bin/exitmap` and stem 1.8.2 were
  also run against a small control-port emulator which emits CIRC/STREAM
  events and can stall or exit at a chosen request. Of its 17 moments at
  which Tor dies, current `main` hangs in 11. With this change exitmap exits
  in all where only stem's event thread is stuck, in the three where Tor
  exits as soon as the thread reading from the IPC queue sends a request
  (current `main` exits there too), and when Tor dies while circuits are
  created, while exitmap is idle, while modules run, or right at the end of
  a scan: 11 of 17.

What it does not fix:

* the thread reading from the IPC queue being stuck in the controller, which
  makes `shutdown()` wait forever for it (5 of the remaining 6). That is the
  subject of #71; with both changes exitmap exited in 16 of the 17.
* Tor dying while the main thread itself is inside `controller.new_circuit()`
  and an event callback has a request pending. This deadlock is inside stem
  and needs a fix there, see tpo/network-health/stem#11; with that fix as
  well, exitmap exited in all 17.
* the exit status of `bin/exitmap`, which ignores what `main()` returns: it
  stays 0 until !61 is merged.
