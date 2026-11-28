#!/usr/bin/env python3
"""
A scan which check_finished() ends while iter_exit_relays() still requests
circuits, e.g. because Tor rejected two of them with 551 (see the README).

Runs the real bin/exitmap of TREE against the emulator's fake tor and
prints, for every circuit the fake tor built, how many probes exitmap
started and finished for its exit relay over the whole run (all modules, so
a later module's probe of the same relay counts too), and whether the
circuit was closed with CLOSECIRCUIT.  Also prints how many processes
shutdown() terminated.

usage: early_end.py EMULATOR_DIR TREE LABEL CASE [TRIALS] [KEEPDIR]
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

EMU, TREE, LABEL, CASE = sys.argv[1:5]
TRIALS = int(sys.argv[5]) if len(sys.argv) > 5 else 1
KEEPDIR = sys.argv[6] if len(sys.argv) > 6 else None
sys.path.insert(0, EMU)
import run as emu  # noqa: E402

OWN = "F" * 40
# name: (fake tor scenario, modules, build delay, probe seconds, exit file)
CASES = {
    # Two of ten EXTENDCIRCUIT answered with 551 plus a CIRC FAILED event.
    "r551": ({"reject551": [2, 5]}, ["fakemod"], "1.0", "0.5", emu.E10),
    # Same, the 551s late in the scan.
    "r551_late": ({"reject551": [7, 8]}, ["fakemod"], "1.0", "0.5", emu.E10),
    # Default build delay, probes of 2 s.
    "r551_d3": ({"reject551": [2, 5]}, ["fakemod"], "3", "2", emu.E10),
    # Probes longer than the build delay: no gap without a running probe.
    "r551_long": ({"reject551": [2, 5]}, ["fakemod"], "1.0", "2.5", emu.E10),
    # Two FAILED events for circuits which the fake tor builds on its own.
    "own": ({"own": [[1, 0.05, "FAILED", OWN], [2, 0.05, "FAILED", OWN]]},
            ["fakemod"], "1.0", "0.5", emu.E10),
    # No extra counts at all: the control case.
    "plain": ({}, ["fakemod"], "1.0", "0.5", emu.E10),
    # Two modules after the 551s.
    "r551_two": ({"reject551": [2, 5]}, ["fakemod", "fakemod2"], "1.0",
                 "0.5", emu.E10),
    # Probes of 0.9 s: a probe started after the end is still running
    # when the last circuit was requested.
    "r551_09": ({"reject551": [2, 5]}, ["fakemod"], "1.0", "0.9", emu.E10),
    "r551_09_two": ({"reject551": [2, 5]}, ["fakemod", "fakemod2"], "1.0",
                    "0.9", emu.E10),
}
scenario, modules, delay, sleep, efile = CASES[CASE]
env0 = emu.environment(None)


def trial(n):
    work = tempfile.mkdtemp(prefix="early-", dir=os.environ.get("WORKDIR"))
    os.chmod(work, 0o700)
    try:
        script = emu.copy_exitmap(TREE, work)
        assert emu.set_idle_timeout(script, 5)
        probed = os.path.join(work, "probed.txt")
        open(probed, "w").close()
        config = os.path.join(work, "exitmaprc")
        with open(config, "w") as f:
            f.write("[Defaults]\n")
        log = os.path.join(work, "exitmap.log")
        ftlog = os.path.join(work, "faketor.log")
        env = dict(env0, FAKETOR_SCENARIO=json.dumps(scenario),
                   FAKETOR_LOG=ftlog, FAKEMOD_OUT=probed,
                   FAKEMOD_SLEEP=sleep)
        cmd = [sys.executable, "-c", emu.WRAPPER, script, "-f", config,
               "-t", os.path.join(work, "tor"), "-v", "debug", "-o", log,
               "-d", delay, "-E", efile] + modules
        out = open(os.path.join(work, "output.txt"), "w")
        proc = subprocess.Popen(cmd, cwd=work, env=env,
                                stdin=subprocess.DEVNULL, stdout=out,
                                stderr=out)
        try:
            status = proc.wait(180)
        except subprocess.TimeoutExpired:
            status = "HANG"
        finally:
            emu.kill_group(proc.pid)
            proc.kill()
            proc.wait()
            out.close()
        text = emu.read(log)
        ft = emu.read(ftlog)
        probed_fprs = [line.split()[1] for line in open(probed)
                       if line.strip()]
        invoked = re.findall(r'Circuit for exit relay "([0-9A-F]{40})" is '
                             r'built\.  Now invoking probing module', text)
        built = re.findall(r"(?m)^ *([\d.]+) event CIRC (\S+) BUILT (\S+)$",
                           ft)
        closed = set(re.findall(r"(?m)< CLOSECIRCUIT (\S+)", ft))
        terminated = re.findall(r"Terminating remaining PID (\d+)", text)
        rows = []
        for t, cid, fpr8 in built:
            if cid.startswith("1") and len(cid) == 4:
                continue  # one of the fake tor's own circuits
            rows.append("circ %s at %s exit %s: invoked=%d probed=%d "
                        "closed=%s" % (
                            cid, t, fpr8,
                            sum(1 for f in invoked if f.startswith(fpr8)),
                            sum(1 for f in probed_fprs if f.startswith(fpr8)),
                            cid in closed))
        counts = re.findall(r"failedCircs=(\d+), builtCircs=(\d+), "
                            r"totalCircs=(\d+), finishedStreams=(\d+)", text)
        gave_up = re.findall(r"No longer waiting for (\d+) circuit\(s\) and "
                             r"(\d+) module process\(es\)", text)
        per_module = {}
        for line in open(probed):
            if line.strip():
                mod = line.split()[0].rpartition(".")[2]
                per_module[mod] = per_module.get(mod, 0) + 1
        summary = dict(trial=n, status=status, probes=len(probed_fprs),
                       per_module=per_module,
                       invoked=len(invoked), built_events=len(rows),
                       closed=len(closed), terminated=len(terminated),
                       gave_up=gave_up, last_counts=counts[-1:])
        if KEEPDIR:
            dest = os.path.join(KEEPDIR, "%s_%s_%d" % (LABEL, CASE, n))
            os.makedirs(dest, exist_ok=True)
            for name in ("exitmap.log", "faketor.log", "probed.txt",
                         "output.txt"):
                src = os.path.join(work, name)
                if os.path.exists(src):
                    shutil.copy(src, dest)
        return summary, rows
    finally:
        shutil.rmtree(work, ignore_errors=True)


for n in range(TRIALS):
    summary, rows = trial(n)
    print(LABEL, CASE, json.dumps(summary), flush=True)
    for row in rows:
        print("   ", row, flush=True)
