"""
Kill the tor of a running exitmap scan at a chosen moment, on the private Tor
network of privnet.py (one directory authority and two relays, all exits,
real /usr/bin/tor, loopback only).  For the first two cases of mr03:

creating  exitmap's tor is killed as soon as the first circuit is built,
          while exitmap is still requesting circuits (-d 3).
waiting   relay1 and relay2 are stopped (SIGSTOP) once exitmap begins to
          request circuits, so that no circuit is built or fails; exitmap's
          tor is killed 2 s after the last circuit was requested.  No module
          process is running then.

Two modules (quickmod, quickmod2) run in one scan; their probes sleep 0.2 s
and write one line each.  exitmap is killed if it has not exited 90 s after
its tor was killed.

Run inside an isolated network namespace:
    unshare -n -- python3 lo_up.py python3 privnet_death.py OUT CASE label=tree ...
"""
import os
import shutil
import signal
import stat
import subprocess
import sys
import time

OUT, CASE = os.path.abspath(sys.argv[1]), sys.argv[2]
TREES = [arg.split("=", 1) for arg in sys.argv[3:]]
sys.argv = [sys.argv[0], OUT]
sys.path.insert(0, os.environ["PRIVNET_SCRIPTS"])
import privnet as pn  # noqa: E402

QUICKMOD = '''"""Sleep 0.2 s and write one line to $QUICK_OUT."""
import os
import time

destinations = None


def probe(exit_desc, run_python_over_tor, **kwargs):
    time.sleep(0.2)
    with open(os.environ["QUICK_OUT"], "a") as f:
        f.write("%s %s\\n" % (__name__, exit_desc.fingerprint))
'''


def tor_pids():
    out = subprocess.run(["pgrep", "-x", "tor"], capture_output=True,
                         text=True).stdout
    return {int(p) for p in out.split()}


def read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def run(label, tree, bindir, relays):
    work = os.path.join(OUT, "%s-%s" % (CASE, label))
    os.makedirs(work, mode=0o700)
    os.chmod(work, stat.S_IRWXU)
    copy = os.path.join(work, "exitmap")
    for name in ("bin", "src"):
        shutil.copytree(os.path.join(tree, name), os.path.join(copy, name),
                        ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("quickmod", "quickmod2"):
        with open(os.path.join(copy, "src", "modules", name + ".py"), "w") as f:
            f.write(QUICKMOD)
    config = os.path.join(work, "exitmaprc")
    with open(config, "w") as f:
        f.write("[Defaults]\n")
    tor_dir = os.path.join(work, "tor")
    os.makedirs(tor_dir, mode=0o700)
    open(os.path.join(tor_dir, "cached-descriptors"), "w").close()
    log = os.path.join(work, "exitmap.log")
    env = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"],
               QUICK_OUT=os.path.join(work, "probes.txt"),
               PYTHONDONTWRITEBYTECODE="1")
    before = tor_pids()
    out = open(os.path.join(work, "output.txt"), "w")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(copy, "bin", "exitmap"), "-f", config,
         "-t", tor_dir, "-d", "3", "-v", "debug", "-o", log,
         "quickmod", "quickmod2"], cwd=work, env=env, stdout=out, stderr=out)
    killed_at = None
    stopped = False
    status = None
    start = time.monotonic()
    try:
        while time.monotonic() - start < 400:
            text = read(log)
            if killed_at is None:
                if (CASE == "waiting" and not stopped and
                        "Beginning to trigger" in text):
                    for relay in relays:
                        relay.send_signal(signal.SIGSTOP)
                    stopped = True
                ready = ("is built.  Now invoking probing module" in text
                         if CASE == "creating" else
                         "Done triggering circuit creations" in text)
                if ready:
                    if CASE == "waiting":
                        time.sleep(2)
                    for pid in tor_pids() - before:
                        os.kill(pid, signal.SIGKILL)
                    killed_at = time.monotonic()
            elif time.monotonic() - killed_at > 90:
                break
            try:
                status = proc.wait(0.2)
                break
            except subprocess.TimeoutExpired:
                pass
    finally:
        if status is None:
            proc.kill()
            proc.wait()
            status = "HANG (killed)"
        out.close()
        if stopped:
            for relay in relays:
                relay.send_signal(signal.SIGCONT)
    text = read(log)
    after = time.monotonic() - killed_at if killed_at else None
    probes = read(os.path.join(work, "probes.txt")).split("\n")
    print("%-8s %-8s exit status %-15s %s after tor was killed | probes: "
          "quickmod %d, quickmod2 %d | 'Running module quickmod2': %s | "
          "'controller is not alive': %d | circuits that could not be "
          "created: %d" % (
              CASE, label, status,
              "%.1f s" % after if after is not None else "(tor not killed)",
              sum(1 for p in probes if p.startswith("modules.quickmod ")),
              sum(1 for p in probes if p.startswith("modules.quickmod2 ")),
              "yes" if "Running module 'quickmod2'" in text else "no",
              text.count("controller is not alive"),
              text.count("could not be created") +
              text.count("CREATION_FAILED")))
    sys.stdout.flush()


def main():
    os.makedirs(OUT)
    os.chmod(OUT, stat.S_IRWXU)
    try:
        auth_line = pn.start_network()
        if not pn.wait_for_consensus(180):
            print("no consensus with all relays after 180 s")
            return 1
        time.sleep(15)
        bindir = pn.tor_wrapper(auth_line)
        relays = pn.PROCS[1:]
        for label, tree in TREES:
            run(label, os.path.abspath(tree), bindir, relays)
    finally:
        for relay in pn.PROCS:
            relay.send_signal(signal.SIGCONT)
            relay.terminate()
        for relay in pn.PROCS:
            try:
                relay.wait(10)
            except subprocess.TimeoutExpired:
                relay.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
