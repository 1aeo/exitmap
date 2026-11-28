#!/usr/bin/env python3
"""
Run exitmap against the fake tor in faketor/ and tell whether it ends.

usage: run.py --exitmap <exitmap checkout> [--stem <stem checkout>]
              [--python <interpreter>] [--jobs N] [--keep <dir>]
              [--idle-timeout N] <scenario> [<scenario> ...]

A scenario is a name from the tables below, or @death (the 17 scenarios in
which tor goes away), @normal (the 14 normal scenarios), @bound (the 10
scenarios for the time limit of EventHandler.wait()) or @all (these three
groups).  --idle-timeout N sets that time limit to N seconds in the copy of
the checkout which is run.

For every scenario one line is printed: "exit <status> after <seconds>s", or
"HANG (killed after <seconds>s)" if exitmap did not end within the timeout
of the scenario, and the number of probes which finished.  For a scenario of
@bound the line also says how often exitmap logged that wait() gave up, and
how often the module's teardown() ran.  If such a scenario runs more than
one module, a line with the probes of each module follows, and then the
text of each warning.  After a hang the innermost frames of every thread of
exitmap follow.  The last line counts the exits and the hangs.  README.md
has the details.
"""
import argparse
import concurrent.futures
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")


def fingerprints(name):
    with open(os.path.join(DATA, name)) as f:
        return f.read().split()


EXITS = fingerprints("exits.txt")
O1 = fingerprints("others.txt")[0]
E2, E5, E10 = (os.path.join(DATA, n) for n in ("e2.txt", "e5.txt", "e10.txt"))
X1, X2 = EXITS[0], EXITS[1]


def hang(match, die_after, nth=1, **more):
    scenario = {"hang": {"match": match, "nth": nth, "die_after": die_after}}
    scenario.update(more)
    return scenario


# name: (timeout, scenario, env, exitmap args)
DEATH = {
    # Request of stem's event thread is pending when Tor dies.
    "H_die_in_getinfo": (25, {"desc_delay": 1.0, "die": {"after_extend": 1, "delay": 0.5}},
                         {}, ["-d", "0.3", "-E", E5, "fakemod"]),
    "H2_die_in_getinfo_wait": (25, {"desc_delay": 1.0, "die": {"after_extend": 1, "delay": 0.8}},
                               {}, ["-d", "0.1", "-E", E2, "fakemod"]),
    "H3_getinfo_prompt_iter": (25, hang("GETINFO desc/id", 0),
                               {}, ["-d", "0.5", "-E", E5, "fakemod"]),
    "AT_evt_prompt_wait": (25, hang("ATTACHSTREAM", 0),
                           {}, ["-d", "0.1", "-E", E2, "sockmod"]),
    "AT_evt_prompt_iter": (25, hang("ATTACHSTREAM", 0),
                           {}, ["-d", "0.5", "-E", E5, "sockmod"]),
    # ... and the queue reader waits for stem's message lock at that time.
    "AT_evt_hang_qr_blocked": (25, hang("ATTACHSTREAM", 1.0),
                               {"SOCKMOD_NOCONNECT": X2, "FAKEMOD_SLEEP": "0.4"},
                               ["-d", "0.1", "-E", E2, "sockmod"]),
    "H4_getinfo_hang_qr_blocked": (25, hang("GETINFO desc/id", 1.0, nth=2),
                                   {"FAKEMOD_SLEEP": "0.3"},
                                   ["-d", "0.1", "-E", E2, "fakemod"]),
    # Request of the queue reader is pending when Tor dies.
    "CC_qr_prompt": (25, hang("CLOSECIRCUIT", 0), {"FAKEMOD_SLEEP": "0.3"},
                     ["-d", "0.1", "-E", E2, "fakemod"]),
    "GC_qr_prompt": (25, hang("GETINFO circuit-status", 0), {"FAKEMOD_SLEEP": "0.3"},
                     ["-d", "0.1", "-E", E2, "fakemod"]),
    "AT_qr_prompt": (25, hang("ATTACHSTREAM", 0, stream_delay=0.0),
                     {}, ["-d", "0.1", "-E", E2, "sockmod_late"]),
    # ... and stem's event thread waits for stem's message lock at that time.
    "CC_qr_hang_evt_blocked": (25, hang("CLOSECIRCUIT", 1.0, own=[[2, 0.6, "BUILT", O1]]),
                               {"FAKEMOD_SLEEP": "0.3"},
                               ["-d", "0.1", "-E", E2, "fakemod"]),
    "GC_qr_hang_evt_blocked": (25, hang("GETINFO circuit-status", 1.0, own=[[2, 0.6, "BUILT", O1]]),
                               {"FAKEMOD_SLEEP": "0.3"},
                               ["-d", "0.1", "-E", E2, "fakemod"]),
    "AT_qr_hang_evt_blocked": (25, hang("ATTACHSTREAM", 1.0, stream_delay=0.0,
                                        own=[[2, 0.8, "BUILT", O1]]),
                               {}, ["-d", "0.1", "-E", E2, "sockmod_late"]),
    # Tor dies while circuits are created, while exitmap waits for circuits
    # which never complete, while the modules run, and at the end of a scan.
    "F_die_creating": (40, {"die": {"after_extend": 4, "delay": 0.1}},
                       {}, ["-d", "0.5", "-E", E10, "fakemod", "fakemod2"]),
    "G_die_idle": (25, {"pending": [4, 5], "die": {"after_extend": 5, "delay": 2.0}},
                   {}, ["-d", "0.3", "-E", E5, "fakemod", "fakemod2"]),
    "J_die_modules_running": (25, {"die": {"after_extend": 5, "delay": 0.3}},
                              {"FAKEMOD_SLEEP": "1.5"},
                              ["-d", "0.3", "-E", E5, "fakemod", "fakemod2"]),
    "Q_die_at_end": (25, {"die_on_unlisten": True},
                     {}, ["-d", "0.3", "-E", E5, "fakemod"]),
}
NORMAL = {
    "N_fakemod": (40, {}, {}, ["-d", "0.3", "-E", E5, "fakemod"]),
    "N_sockmod": (40, {}, {}, ["-d", "0.3", "-E", E5, "sockmod"]),
    "N_sockmod_late": (40, {}, {}, ["-d", "0.3", "-E", E5, "sockmod_late"]),
    "N_failed": (40, {"fail": [3, 6]}, {}, ["-d", "0.3", "-E", E10, "fakemod"]),
    "N_two_modules": (40, {"fail": [3, 6, 13]}, {},
                      ["-d", "0.3", "-E", E10, "fakemod", "fakemod2"]),
    "N_three_modules": (60, {"fail": [2]}, {},
                        ["-d", "0.2", "-E", E5, "fakemod", "sockmod", "fakemod2"]),
    "N_nodesc": (40, {"fail": [3], "no_desc": [EXITS[1], EXITS[6]]}, {},
                 ["-d", "0.3", "-E", E10, "fakemod"]),
    "N_reject": (40, {"reject": [2, 5]}, {}, ["-d", "0.3", "-E", E10, "fakemod"]),
    "N_zero_exits": (40, {}, {}, ["-d", "0.3", "-e", O1, "fakemod", "fakemod2"]),
    "N_one_exit": (40, {}, {}, ["-d", "0.3", "-e", X1, "fakemod", "fakemod2"]),
    "N_firsthop": (40, {}, {}, ["-d", "0.3", "-i", "A" * 40, "-E", E5, "fakemod"]),
    "N_exitfile": (40, {}, {}, ["-d", "0.3", "-E", "/nonexistent", "fakemod"]),
    "N_setupexc": (40, {}, {}, ["-d", "0.3", "-E", E5, "failsetup"]),
    "N_badmodule": (40, {}, {}, ["-d", "0.3", "-E", E5, "nosuchmodule", "fakemod"]),
}
# The scenarios for the time limit of EventHandler.wait().  Their times are
# made for a limit of 5 s (--idle-timeout 5).  The first probes which start
# take the roles in $BOUNDMOD_ROLES; fakemods/boundmod.py describes them.
BOUND = {
    "B_stuck": (25, {}, {"BOUNDMOD_ROLES": "stuck"},
                ["-d", "0.3", "-E", E10, "boundmod"]),
    "B_stuck_failed": (25, {"fail": [3, 6]}, {"BOUNDMOD_ROLES": "stuck"},
                       ["-d", "0.3", "-E", E10, "boundmod"]),
    "B_killed": (25, {}, {"BOUNDMOD_ROLES": "killed"},
                 ["-d", "0.3", "-E", E10, "boundmod"]),
    "B_lost_circuit": (25, {"pending": [4]}, {},
                       ["-d", "0.3", "-E", E10, "boundmod"]),
    "B_chatty": (40, {}, {"BOUNDMOD_ROLES": "chatty"},
                 ["-d", "0.3", "-E", E5, "boundmod"]),
    "B_silent": (40, {}, {"BOUNDMOD_ROLES": "silent"},
                 ["-d", "0.3", "-E", E5, "boundmod"]),
    "B_silent_chatty": (40, {}, {"BOUNDMOD_ROLES": "silent,chatty"},
                        ["-d", "0.3", "-E", E5, "boundmod"]),
    "B_build_delay": (40, {}, {"FAKEMOD_SLEEP": "3"},
                      ["-d", "7", "-E", E2, "boundmod"]),
    "B_two_modules": (40, {}, {"BOUNDMOD_ROLES": "stuck"},
                      ["-d", "0.3", "-E", E10, "boundmod", "fakemod2"]),
    "B_two_modules_failed": (40, {"fail": [3]}, {"BOUNDMOD_ROLES": "stuck,stuck"},
                             ["-d", "0.3", "-E", E10, "boundmod", "fakemod2"]),
}
# B_stuck with a timeout for the limit of 300 s.  It is in no group.
BOUND_300 = {"B_stuck_300": (345,) + BOUND["B_stuck"][1:]}
ALL = dict(DEATH)
ALL.update(NORMAL)
ALL.update(BOUND)
GROUPS = {"@death": list(DEATH), "@normal": list(NORMAL),
          "@bound": list(BOUND), "@all": list(ALL)}
ALL.update(BOUND_300)

# What exitmap logs when wait() gives up; the message is the first group.
GAVE_UP = re.compile(r"(?m) - (No message from a module process for \d+ "
                     r"seconds\..*)$")

# This runs in the interpreter under test.  It makes exitmap the leader of a
# process group of its own, so that it can be killed together with its probe
# processes and the fake tor, and lets SIGUSR1 print the stacks of all
# threads.
WRAPPER = """\
import faulthandler, os, runpy, signal, sys
os.setsid()
faulthandler.register(signal.SIGUSR1, all_threads=True)
del sys.argv[0]
runpy.run_path(sys.argv[0], run_name="__main__")
"""

# Set when run.py is interrupted: stop the scenarios which are running.
STOP = threading.Event()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run exitmap against the fake tor in faketor/ and tell "
                    "whether it ends.")
    parser.add_argument("--exitmap", required=True, metavar="DIR",
                        help="exitmap checkout to test; it is not changed")
    parser.add_argument("--stem", metavar="DIR",
                        help="stem checkout to use; the default is the stem "
                             "which the interpreter has installed")
    parser.add_argument("--python", default=sys.executable, metavar="PATH",
                        help="interpreter which runs exitmap; the default is "
                             "the one which runs run.py")
    parser.add_argument("--jobs", type=int, default=1, metavar="N",
                        help="scenarios to run at the same time (default: 1)")
    parser.add_argument("--keep", metavar="DIR",
                        help="work in this new or empty directory and keep "
                             "it; the default is a temporary directory "
                             "which is removed")
    parser.add_argument("--idle-timeout", type=int, metavar="N",
                        help="set IDLE_TIMEOUT, the time limit of "
                             "EventHandler.wait(), to N seconds in the copy "
                             "of the checkout which is run; the default is "
                             "to leave it as it is")
    parser.add_argument("scenario", nargs="+",
                        help="scenario name, @death, @normal, @bound or @all")
    args = parser.parse_args()

    args.exitmap = os.path.abspath(args.exitmap)
    if not (os.path.isfile(os.path.join(args.exitmap, "bin", "exitmap")) and
            os.path.isdir(os.path.join(args.exitmap, "src", "modules"))):
        parser.error("%s is not an exitmap checkout" % args.exitmap)
    if args.stem:
        args.stem = os.path.abspath(args.stem)
        if not os.path.isfile(os.path.join(args.stem, "stem", "__init__.py")):
            parser.error("%s is not a stem checkout" % args.stem)
    if not os.access(os.path.join(HERE, "faketor", "tor"), os.X_OK):
        parser.error("%s is not executable" %
                     os.path.join(HERE, "faketor", "tor"))
    python = shutil.which(args.python)
    if not python:
        parser.error("cannot run %s" % args.python)
    # Not realpath(): the link of a virtual environment has to stay.
    args.python = os.path.abspath(python)
    if args.jobs < 1:
        parser.error("--jobs needs a positive number")
    if args.idle_timeout is not None and args.idle_timeout < 1:
        parser.error("--idle-timeout needs a positive number")
    args.names = []
    for name in args.scenario:
        if name not in GROUPS and name not in ALL:
            parser.error("unknown scenario %s" % name)
        args.names += GROUPS.get(name, [name])
    return args


def environment(stem):
    """
    Return the environment which all scenarios have in common.
    """

    env = dict(os.environ)
    # The settings of the fake tor and of the fake modules come from the
    # scenario only.
    for key in list(env):
        if key.startswith(("FAKETOR_", "FAKEMOD_", "SOCKMOD_",
                           "BOUNDMOD_")):
            del env[key]
    env["PATH"] = (os.path.join(HERE, "faketor") + os.pathsep +
                   env.get("PATH", os.defpath))
    env["FAKETOR_DATA"] = DATA
    # Do not write byte code into the stem checkout.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if stem:
        env["PYTHONPATH"] = os.pathsep.join(
            [stem] + [p for p in [env.get("PYTHONPATH")] if p])
    return env


def check_interpreter(python, stem, env):
    """
    Return the versions of the interpreter and of stem, and where stem is.
    """

    code = ("import os, socks, stem, sys; print(sys.version.split()[0]); "
            "print(stem.__version__); "
            "print(os.path.dirname(os.path.abspath(stem.__file__)))")
    proc = subprocess.run([python, "-c", code], env=env,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, universal_newlines=True)
    if proc.returncode != 0:
        sys.exit("run.py: %s cannot import stem and socks (PySocks), which "
                 "exitmap needs:\n%s" % (python, proc.stderr.rstrip()))
    python_version, stem_version, stem_dir = proc.stdout.splitlines()[:3]
    if stem and (os.path.realpath(stem_dir) !=
                 os.path.realpath(os.path.join(stem, "stem"))):
        sys.exit("run.py: %s imports stem from %s, not from %s" %
                 (python, stem_dir, stem))
    return python_version, stem_version, stem_dir


def copy_exitmap(checkout, work):
    """
    Copy bin/ and src/ of the checkout and add the fake modules.
    """

    tree = os.path.join(work, "exitmap")
    for name in ("bin", "src"):
        shutil.copytree(os.path.join(checkout, name), os.path.join(tree, name),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    fakemods = os.path.join(HERE, "fakemods")
    for name in sorted(os.listdir(fakemods)):
        if name.endswith(".py"):
            shutil.copy(os.path.join(fakemods, name),
                        os.path.join(tree, "src", "modules", name))
    return os.path.join(tree, "bin", "exitmap")


def set_idle_timeout(script, seconds):
    """
    Set the time limit of EventHandler.wait() in the copy of the checkout.

    Return False if src/eventhandler.py has no line "IDLE_TIMEOUT = 300".
    """

    path = os.path.join(os.path.dirname(os.path.dirname(script)), "src",
                        "eventhandler.py")
    with open(path, encoding="utf-8") as f:
        source = f.read()
    source, count = re.subn(r"(?m)^IDLE_TIMEOUT = 300$",
                            "IDLE_TIMEOUT = %d" % seconds, source)
    if count != 1:
        return False
    with open(path, "w", encoding="utf-8") as f:
        f.write(source)
    return True


def kill_group(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def blocked_threads(output, script):
    """
    Return (thread, innermost frames) for every thread in a faulthandler dump.
    """

    blocked = []
    for block in re.split(r"(?m)^(?:Current thread|Thread) 0x[0-9a-f]+ .*$",
                          output)[1:]:
        frames = re.findall(r'File "([^"]+)", line (\d+) in (\S+)', block)
        funcs = [f[2] for f in frames]
        if "_reader_loop" in funcs:
            who = "stem reader thread"
        elif "_event_loop" in funcs:
            who = "stem event thread"
        elif "queue_reader" in funcs:
            who = "queue reader thread"
        elif "_feed" in funcs:
            who = "queue feeder thread"
        elif any(f[0] == script for f in frames):
            who = "main thread"
        else:
            who = "other"
        chain = []
        for path, lineno, func in frames:
            base = os.path.basename(path)
            if base in ("threading.py", "runpy.py") or path.startswith("<"):
                continue
            chain.append("%s:%s %s" % (base, lineno, func))
        blocked.append((who, " <- ".join(chain[:6])))
    return sorted(blocked)


def read(path):
    """
    Return the content of the file, or "" if there is no such file.
    """

    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def last_exception(output):
    """
    Return the last line of the last traceback in the output, if there is one.
    """

    start = output.rfind("Traceback (most recent call last):")
    if start >= 0:
        for line in output[start:].splitlines()[1:]:
            if line and not line.startswith(" "):
                return line[:200]
    return None


def run(job):
    """
    Run one scenario and return what happened.
    """

    name, work, script, python, env = job
    if STOP.is_set():
        return None
    timeout, scenario, extra_env, exitmap_args = ALL[name]
    # exitmap wants the parent of tor's data directory to be ours alone.
    os.makedirs(work, mode=0o700)
    os.chmod(work, 0o700)
    probed = os.path.join(work, "probed.txt")
    open(probed, "w").close()
    # An empty configuration, so that ~/.exitmaprc is not read.
    config = os.path.join(work, "exitmaprc")
    with open(config, "w") as f:
        f.write("[Defaults]\n")
    faketor_log = os.path.join(work, "faketor.log")

    env = dict(env)
    env.update({
        "FAKETOR_SCENARIO": json.dumps(scenario),
        "FAKETOR_LOG": faketor_log,
        "FAKEMOD_OUT": probed,
    })
    env.update(extra_env)
    cmd = [python, "-c", WRAPPER, script, "-f", config,
           "-t", os.path.join(work, "tor"), "-v", "debug",
           "-o", os.path.join(work, "exitmap.log")] + exitmap_args

    status = None
    start = time.monotonic()
    with open(os.path.join(work, "output.txt"), "w") as out:
        proc = subprocess.Popen(cmd, cwd=work, env=env,
                                stdin=subprocess.DEVNULL, stdout=out,
                                stderr=out)
        try:
            while status is None and not STOP.is_set():
                left = start + timeout - time.monotonic()
                if left <= 0:
                    # Let exitmap print where its threads are.
                    os.kill(proc.pid, signal.SIGUSR1)
                    time.sleep(1)
                    break
                try:
                    status = proc.wait(min(left, 0.5))
                except subprocess.TimeoutExpired:
                    pass
            seconds = time.monotonic() - start
        finally:
            kill_group(proc.pid)
            # In case exitmap had no process group of its own yet.
            proc.kill()
            proc.wait()
    if STOP.is_set():
        return None

    with open(probed) as f:
        # A probe writes "modules.<module> <fingerprint>".
        probed_modules = [line.split()[0].rpartition(".")[2]
                          for line in f.read().splitlines() if line.strip()]
    with open(os.path.join(work, "output.txt"), errors="replace") as f:
        output = f.read()
    gave_up = GAVE_UP.findall(read(os.path.join(work, "exitmap.log")))
    result = {"name": name, "status": status, "seconds": seconds,
              "probes": len(probed_modules), "warnings": len(gave_up),
              "teardown": len(read(probed + ".teardown").splitlines()),
              "details": [("warning", message) for message in gave_up]}
    modules = [arg for arg in exitmap_args if os.path.isfile(
        os.path.join(HERE, "fakemods", arg + ".py"))]
    if name in BOUND and len(modules) > 1:
        result["details"].insert(0, ("probes", ", ".join(
            "%s %d" % (module, probed_modules.count(module))
            for module in modules)))
    if not os.path.exists(faketor_log):
        result["error"] = "exitmap did not start the fake tor"
        result["details"] = [("output", line[:200])
                             for line in output.strip().splitlines()[-1:]]
    elif status is None:
        result["details"] += blocked_threads(output, script)
    elif last_exception(output):
        result["details"] += [("traceback", last_exception(output))]
    return result


def report(result):
    if "error" in result:
        outcome = "ERROR: " + result["error"]
    elif result["status"] is None:
        outcome = "HANG (killed after %.0fs)" % result["seconds"]
    else:
        outcome = "exit %d after %4.1fs" % (result["status"],
                                            result["seconds"])
    counts = "probes=%d" % result["probes"]
    if result["name"] in BOUND or result["name"] in BOUND_300:
        # Only the module of these scenarios has a teardown() function.
        counts += " warnings=%d teardown=%d" % (result["warnings"],
                                                result["teardown"])
    print("%-27s %-26s %s" % (result["name"], outcome, counts))
    for who, where in result["details"]:
        print("      %-20s %s" % (who + ":", where))
    sys.stdout.flush()


def plural(number, noun):
    return "%d %s%s" % (number, noun, "" if number == 1 else "s")


def interrupt(signum, frame):
    raise KeyboardInterrupt


def main():
    args = parse_args()
    env = environment(args.stem)
    python_version, stem_version, stem_dir = check_interpreter(
        args.python, args.stem, env)
    if args.keep:
        work = os.path.realpath(args.keep)
        os.makedirs(work, exist_ok=True)
        if os.listdir(work):
            sys.exit("run.py: %s is not empty" % work)
    else:
        work = os.path.realpath(tempfile.mkdtemp(prefix="exitmap-emulator-"))
    print("exitmap: %s" % args.exitmap)
    print("stem:    %s in %s" % (stem_version, stem_dir))
    print("python:  %s, %s" % (python_version, args.python))
    if args.keep:
        print("files:   %s" % work)
    sys.stdout.flush()

    signal.signal(signal.SIGTERM, interrupt)
    pool = concurrent.futures.ThreadPoolExecutor(args.jobs)
    results = []
    try:
        script = copy_exitmap(args.exitmap, work)
        if args.idle_timeout is not None:
            if set_idle_timeout(script, args.idle_timeout):
                print("limit:   IDLE_TIMEOUT = %d instead of 300 in the copy "
                      "of src/eventhandler.py" % args.idle_timeout)
            else:
                print("limit:   src/eventhandler.py has no line "
                      "\"IDLE_TIMEOUT = 300\"; nothing was changed")
            sys.stdout.flush()
        jobs = []
        for i, name in enumerate(args.names):
            # A scenario which is given several times is run several times.
            nth = args.names[:i].count(name) + 1
            subdir = name if nth == 1 else "%s.%d" % (name, nth)
            jobs.append((name, os.path.join(work, subdir), script,
                         args.python, env))
        for result in pool.map(run, jobs):
            results.append(result)
            report(result)
    except KeyboardInterrupt:
        print("interrupted")
        return 130
    finally:
        STOP.set()
        pool.shutdown()
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)

    errors = sum(1 for r in results if "error" in r)
    hangs = [r["name"] for r in results
             if "error" not in r and r["status"] is None]
    exits = len(results) - errors - len(hangs)
    print("summary: %s, %s, %s%s%s" % (
        plural(len(results), "scenario"), plural(exits, "exit"),
        plural(len(hangs), "hang"),
        ", " + plural(errors, "error") if errors else "",
        " (%s)" % ", ".join(hangs) if hangs else ""))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
