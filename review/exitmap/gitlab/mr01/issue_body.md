`bin/exitmap` ignores the value `main()` returns and calls `sys.exit(failed)`
inside its `finally` block. A `sys.exit()` in a `finally` block replaces
whatever exception is being propagated, so `SystemExit(1)` from
`bootstrap_tor()` and any unhandled exception (including its traceback) are
lost as well. Scripts and cron jobs running exitmap cannot tell that a scan
did not happen.

```
$ mkdir -p -m 755 /tmp/p; ./bin/exitmap -t /tmp/p/tor checktest; echo $?
Parent directory /tmp/p is not owned by the user or hasn't mask 700.
Removing tmp files...
0
```

Fix: use the return value of `main()` as exit status and move `sys.exit()`
out of the `finally` block (2 lines).
