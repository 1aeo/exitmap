Since #61 exitmap checks whether the controller is still alive, but only when it handles an event from Tor or a message from a module, and once after all circuits were requested. If Tor dies after that, while no module is running, nothing sets `finished_event` and `wait()` blocks forever. If Tor dies while circuits are still being created, `iter_exit_relays()` fails to create each of the remaining circuits and sleeps for the build delay after every attempt. Afterwards, exitmap goes on with the next module, and `main()` finally returns 0.

Let `wait()` check once a second whether the controller is still alive, stop creating circuits once it is not, and return 1 from `main()` rather than running the remaining modules.

Moreover, neither remove our event listener nor close the controller if the controller is not alive. If Tor died while one of our event callbacks was waiting for a reply, stem's event thread never returns from that callback, and both calls would block forever.

exitmap can still hang if the main thread or the thread reading from the IPC queue is waiting for the controller in that situation.

Closes #ISSUE03.

Related: !MR05 (the thread reading from the IPC queue) and tpo/network-health/stem!11 (the main thread). The exit status of `bin/exitmap` only becomes 1 with !61.
