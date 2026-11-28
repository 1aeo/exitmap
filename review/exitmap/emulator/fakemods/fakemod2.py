"""
Test module for the fake Tor: does not touch the network.

A probe sleeps for $FAKEMOD_SLEEP seconds (0.5 by default) and then appends
the name of the module and the fingerprint of the exit relay to the file
$FAKEMOD_OUT.  A probe for a relay listed in $FAKEMOD_HANG does not end; no
scenario of run.py sets that variable.
"""
import os
import time

destinations = None


def probe(exit_desc, target_host, target_port, run_python_over_tor,
          run_cmd_over_tor, **kwargs):
    if exit_desc.fingerprint in os.environ.get("FAKEMOD_HANG", "").split(","):
        time.sleep(100000)
    time.sleep(float(os.environ.get("FAKEMOD_SLEEP", "0.5")))
    with open(os.environ["FAKEMOD_OUT"], "a") as f:
        f.write("%s %s\n" % (__name__, exit_desc.fingerprint))
