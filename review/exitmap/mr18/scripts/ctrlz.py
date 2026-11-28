#!/usr/bin/env python3
"""
Stop exitmap, its module processes and the fake tor with SIGSTOP 1 s after
the last circuit of the first module was requested (Ctrl-Z stops them the
same way, with SIGTSTP), and continue them once the time limit of wait() has
passed.

Runs the real bin/exitmap of a tree against the emulator's fake tor, with two
modules in one run: boundmod and then fakemod2, 10 exits each; every probe of
both sleeps $FAKEMOD_SLEEP s.  wait() of the first module gives up as soon as
exitmap continues, unless a probe reports back first; the question is whether
the second module still runs all 10 probes.

Run it with a python3 that has stem and PySocks: it runs exitmap with the same
interpreter.  A run in which exitmap ended before it was stopped is reported
as an error and not counted.  With Python 3.10 the probes' time.sleep() does
not count the time they were stopped, so they are terminated before they can
report back and the runs show nothing (see the README).

usage: ctrlz.py EMULATOR_DIR TREE LABEL TRIALS [IDLE] [STOP] [SLEEP]
"""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

EMU, TREE, LABEL, TRIALS = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
IDLE = int(sys.argv[5]) if len(sys.argv) > 5 else 5
STOP = float(sys.argv[6]) if len(sys.argv) > 6 else IDLE + 2
SLEEP = float(sys.argv[7]) if len(sys.argv) > 7 else 4
sys.path.insert(0, EMU)
import run as emu  # noqa: E402

env0 = emu.environment(None)
python = sys.executable


def trial(n):
    work = tempfile.mkdtemp(prefix="ctrlz-")
    os.chmod(work, 0o700)
    try:
        script = emu.copy_exitmap(TREE, work)
        assert emu.set_idle_timeout(script, IDLE)
        probed = os.path.join(work, "probed.txt")
        open(probed, "w").close()
        config = os.path.join(work, "exitmaprc")
        with open(config, "w") as f:
            f.write("[Defaults]\n")
        log = os.path.join(work, "exitmap.log")
        env = dict(env0, FAKETOR_SCENARIO=json.dumps({}),
                   FAKETOR_LOG=os.path.join(work, "faketor.log"),
                   FAKEMOD_OUT=probed, FAKEMOD_SLEEP=str(SLEEP))
        cmd = [python, "-c", emu.WRAPPER, script, "-f", config,
               "-t", os.path.join(work, "tor"), "-v", "debug", "-o", log,
               "-d", "0.3", "-E", emu.E10, "boundmod", "fakemod2"]
        out = open(os.path.join(work, "output.txt"), "w")
        proc = subprocess.Popen(cmd, cwd=work, env=env, stdin=subprocess.DEVNULL,
                                stdout=out, stderr=out)
        stopped = False
        start = time.monotonic()
        status = None
        try:
            while time.monotonic() - start < 120:
                text = emu.read(log)
                if not stopped and "Done triggering circuit creations" in text:
                    # The probes of the first module are sleeping now.
                    time.sleep(1)
                    os.killpg(proc.pid, signal.SIGSTOP)
                    time.sleep(STOP)
                    os.killpg(proc.pid, signal.SIGCONT)
                    stopped = True
                try:
                    status = proc.wait(0.1)
                    break
                except subprocess.TimeoutExpired:
                    pass
        finally:
            emu.kill_group(proc.pid)
            proc.kill()
            proc.wait()
            out.close()
        text = emu.read(log)
        lines = open(probed).read().split("\n")
        mods = [l.split()[0].rpartition(".")[2] for l in lines if l.strip()]
        gave_up = re.findall(r"No longer waiting for (\d+) circuit\(s\) and "
                             r"(\d+) module process\(es\)", text)
        summaries = re.findall(r"Ran (\d+) module\(s\) in [^ ]+ and "
                               r"(\d+)/(\d+) circuits failed", text)
        return dict(trial=n, status=status, stopped=stopped,
                    boundmod=mods.count("boundmod"),
                    fakemod2=mods.count("fakemod2"), gave_up=gave_up,
                    summaries=summaries)
    finally:
        shutil.rmtree(work, ignore_errors=True)


results = [trial(n) for n in range(TRIALS)]
for r in results:
    print(LABEL, json.dumps(r))
bad = [r for r in results if not r["stopped"]]
if bad:
    print("%s: %d run(s) ended before exitmap was stopped; check the "
          "interpreter (stem, PySocks) and the tree" % (LABEL, len(bad)))
results = [r for r in results if r["stopped"]]
full = sum(1 for r in results if r["fakemod2"] == 10)
print("%s: second module ran all 10 probes in %d of %d runs; probes of the "
      "second module per run: %s" % (LABEL, full, len(results),
                                     [r["fakemod2"] for r in results]))
