"""
A private Tor network on loopback -- one directory authority and two more
relays, all of them exits, all real tor (/usr/bin/tor) -- and the real
bin/exitmap of one or more trees run against it with a module that fetches
several URLs over each exit (like the module of upstream issue #46).

Run it inside an isolated network namespace (see lo_up.py): nothing can
leave the machine.  The destination is an HTTP server on 127.0.0.1:8080.

usage: privnet.py <out dir> <label>=<exitmap tree> [<label>=<tree> ...]

Environment for the module: MULTI_N (connections per exit, default 6),
MULTI_TIMEOUT (urlopen timeout, default 8), MULTI_FIRST_HOST (if set, the
first URL uses this host name instead of 127.0.0.1, which the exits cannot
resolve).  PRIVNET_SOCKSTIMEOUT sets SocksTimeout of exitmap's tor (default:
tor's default, 120 s).
"""
import http.server
import os
import shutil
import socketserver
import stat
import subprocess
import sys
import threading
import time

OUT = os.path.abspath(sys.argv[1])
TREES = [arg.split("=", 1) for arg in sys.argv[2:]]
TOR = "/usr/bin/tor"
RELAYS = [("auth", 7000, 7100), ("relay1", 7001, 7101),
          ("relay2", 7002, 7102)]
PROCS = []

MODULE = '''"""
Fetch MULTI_N URLs over the exit, one run_python_over_tor() call each,
and append one line per URL to $MULTI_OUT.
"""
import os
import time
import urllib.request

import torsocks

destinations = [("127.0.0.1", 8080)]


def fetch(fpr, n, url, timeout):
    start = time.monotonic()
    wall = time.time()
    ports = []
    orig_send = torsocks.send_queue

    def send_queue(sock_name):
        ports.append(sock_name[1])
        orig_send(sock_name)
    torsocks.send_queue = send_queue
    try:
        urllib.request.urlopen(url, timeout=timeout).read()
        result = "ok"
    except Exception as err:
        result = "FAIL:%s:%s" % (type(err).__name__,
                                 str(err).replace(" ", "_")[:80])
    finally:
        torsocks.send_queue = orig_send
    with open(os.environ["MULTI_OUT"], "a") as f:
        f.write("%s %d %s %.1f %s %.3f\\n" % (
            fpr, n, result, time.monotonic() - start,
            ports[0] if ports else 0, wall))


def probe(exit_desc, run_python_over_tor, **kwargs):
    count = int(os.environ.get("MULTI_N", "6"))
    timeout = float(os.environ.get("MULTI_TIMEOUT", "8"))
    for n in range(1, count + 1):
        if n > 1:
            time.sleep(float(os.environ.get("MULTI_PAUSE", "0")))
        host = "127.0.0.1"
        if n == 1 and os.environ.get("MULTI_FIRST_HOST"):
            host = os.environ["MULTI_FIRST_HOST"]
        run_python_over_tor(fetch, exit_desc.fingerprint, n,
                            "http://%s:8080/%d" % (host, n), timeout)
'''


def run(cmd, **kwargs):
    return subprocess.run(cmd, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=60,
                          universal_newlines=True, **kwargs).stdout


def common(nick, base, auth_line):
    return "\n".join([
        "TestingTorNetwork 1",
        "DataDirectory %s" % base,
        "Nickname %s" % nick,
        "SafeLogging 0",
        "ShutdownWaitLength 0",
        "Log notice file %s/notice.log" % base,
        auth_line,
        "PathsNeededToBuildCircuits 0.67",
        "TestingDirAuthVoteExit *",
        "TestingDirAuthVoteGuard *",
        "TestingDirAuthVoteHSDir *",
        "TestingMinExitFlagThreshold 0",
        "V3AuthNIntervalsValid 2",
        "ServerDNSDetectHijacking 0",
        "ServerDNSResolvConfFile %s/resolv.conf" % OUT,
        ""])


def relay_torrc(nick, orport, dirport, base, auth_line, extra=""):
    return common(nick, base, auth_line) + "\n".join([
        "Address 127.0.0.1",
        "ORPort 127.0.0.1:%d" % orport,
        "DirPort 127.0.0.1:%d" % dirport,
        "SocksPort 0",
        "AssumeReachable 1",
        "ExitRelay 1",
        "ExitPolicy accept *:8080",
        "ExitPolicy accept *:80",
        "ExitPolicy reject *:*",
        "ExitPolicyRejectPrivate 0",
        "ExitPolicyRejectLocalInterfaces 0",
        "ContactInfo test@example.invalid",
        extra, ""])


def start_network():
    with open(os.path.join(OUT, "resolv.conf"), "w") as f:
        f.write("nameserver 127.0.0.1\n")
    auth_dir = os.path.join(OUT, "auth")
    keys = os.path.join(auth_dir, "keys")
    os.makedirs(keys, mode=0o700)
    run(["tor-gencert", "--create-identity-key", "-m", "12",
         "-a", "127.0.0.1:7100",
         "-i", os.path.join(keys, "authority_identity_key"),
         "-s", os.path.join(keys, "authority_signing_key"),
         "-c", os.path.join(keys, "authority_certificate"),
         "--passphrase-fd", "0"], input="passphrase\n")
    with open(os.path.join(keys, "authority_certificate")) as f:
        v3ident = [line.split()[1] for line in f
                   if line.startswith("fingerprint ")][0]
    # The relay identity of the authority, for the DirAuthority line.
    torrc = os.path.join(auth_dir, "torrc-fingerprint")
    with open(torrc, "w") as f:
        f.write("DataDirectory %s\nORPort 127.0.0.1:7000\nNickname auth\n"
                "SocksPort 0\nLog notice stdout\n" % auth_dir)
    print(run([TOR, "-f", torrc, "--list-fingerprint"]).strip()
          .splitlines()[-1])
    with open(os.path.join(auth_dir, "fingerprint")) as f:
        auth_fpr = f.read().split()[1]
    auth_line = ("DirAuthority auth orport=7000 no-v2 v3ident=%s "
                 "127.0.0.1:7100 %s" % (v3ident, auth_fpr))
    with open(os.path.join(OUT, "dirauthority"), "w") as f:
        f.write(auth_line + "\n")
    authority = "\n".join([
        "AuthoritativeDirectory 1", "V3AuthoritativeDirectory 1",
        "TestingV3AuthInitialVotingInterval 10",
        "TestingV3AuthInitialVoteDelay 2",
        "TestingV3AuthInitialDistDelay 2",
        "V3AuthVotingInterval 10", "V3AuthVoteDelay 2", "V3AuthDistDelay 2"])
    for nick, orport, dirport in RELAYS:
        base = os.path.join(OUT, nick)
        os.makedirs(base, mode=0o700, exist_ok=True)
        torrc = os.path.join(base, "torrc")
        with open(torrc, "w") as f:
            f.write(relay_torrc(nick, orport, dirport, base, auth_line,
                                authority if nick == "auth" else ""))
        PROCS.append(subprocess.Popen([TOR, "-f", torrc],
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL))
    return auth_line


def wait_for_consensus(seconds):
    path = os.path.join(OUT, "auth", "cached-consensus")
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if os.path.exists(path):
            with open(path) as f:
                routers = sum(1 for line in f if line.startswith("r "))
            if routers == len(RELAYS):
                return True
        time.sleep(1)
    return False


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def tor_wrapper(auth_line):
    """A "tor" for exitmap's PATH which adds the private network."""
    bindir = os.path.join(OUT, "bin")
    os.makedirs(bindir)
    extra = ["--TestingTorNetwork", "1", "--DirAuthority", auth_line,
             "--SafeLogging", "0"]
    if os.environ.get("PRIVNET_SOCKSTIMEOUT"):
        extra += ["--SocksTimeout", os.environ["PRIVNET_SOCKSTIMEOUT"]]
    if os.environ.get("PRIVNET_DIRTINESS"):
        extra += ["--MaxCircuitDirtiness", os.environ["PRIVNET_DIRTINESS"]]
    if os.environ.get("PRIVNET_NEWCIRCUITPERIOD"):
        extra += ["--NewCircuitPeriod",
                  os.environ["PRIVNET_NEWCIRCUITPERIOD"]]
    path = os.path.join(bindir, "tor")
    with open(path, "w") as f:
        f.write("#!/usr/bin/python3\nimport os, sys\n"
                "args = sys.argv[1:]\n"
                "if '--version' not in args:\n"
                "    args += %r\n"
                "    if os.environ.get('PRIVNET_PORTFILE'):\n"
                "        args += ['--ControlPortWriteToFile',\n"
                "                 os.environ['PRIVNET_PORTFILE']]\n"
                "os.execv(%r, [%r] + args)\n" % (extra, TOR, TOR))
    os.chmod(path, 0o755)
    return bindir


def watch_events(portfile, logfile, done):
    """Record the CIRC and STREAM events of exitmap's tor, as a second
    controller."""
    import stem.connection
    from stem.control import Controller, EventType
    while not done.is_set() and not os.path.exists(portfile):
        time.sleep(0.2)
    if done.is_set():
        return
    time.sleep(0.5)
    with open(portfile) as f:
        port = int(f.read().split(":")[-1])
    with open(logfile, "w", buffering=1) as log:
        def listener(event):
            log.write("%.3f %s\n" % (time.time(), event))
        try:
            controller = Controller.from_port(port=port)
            stem.connection.authenticate(controller)
            controller.add_event_listener(listener, EventType.CIRC,
                                          EventType.STREAM)
        except Exception as err:
            log.write("monitor failed: %r\n" % err)
            return
        done.wait()
        try:
            controller.close()
        except Exception:
            pass


def exits_that_carried(logfile, rows):
    """Map (probe exit, connection number) to the last hop of the circuit
    that carried the connection, from the second controller's events: the
    connection's source port gives the stream (STREAM NEW SOURCE_ADDR, the
    last one before the connection began), the stream the circuit (STREAM
    SUCCEEDED), the circuit its path (CIRC BUILT)."""
    import re
    news, circ_of_stream, exit_of_circ = [], {}, {}
    try:
        with open(logfile) as f:
            lines = f.read().splitlines()
    except OSError:
        return {}
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        when, kind, ident, status = float(parts[0]), parts[1], parts[2], \
            parts[3]
        if kind == "STREAM" and status == "NEW":
            m = re.search(r"SOURCE_ADDR=127\.0\.0\.1:(\d+)", line)
            if m:
                news.append((when, int(m.group(1)), ident))
        elif kind == "STREAM" and status == "SUCCEEDED":
            circ_of_stream[ident] = parts[4]
        elif kind == "CIRC" and status == "BUILT":
            exit_of_circ[ident] = parts[4].split(",")[-1][1:41]
    carried = {}
    for row in rows:
        if len(row) < 6:
            continue
        fpr, n, port, wall = row[0], row[1], int(row[4]), float(row[5])
        cands = [s for s in news if s[1] == port and s[0] >= wall]
        if not cands:
            continue
        sid = min(cands)[2]
        circ = circ_of_stream.get(sid)
        if circ in exit_of_circ:
            carried[(fpr, n)] = exit_of_circ[circ]
    return carried


def run_exitmap(label, tree, bindir):
    work = os.path.join(OUT, "run-" + label)
    os.makedirs(work, mode=0o700)
    os.chmod(work, stat.S_IRWXU)
    copy = os.path.join(work, "exitmap")
    for name in ("bin", "src"):
        shutil.copytree(os.path.join(tree, name), os.path.join(copy, name),
                        ignore=shutil.ignore_patterns("__pycache__"))
    with open(os.path.join(copy, "src", "modules", "multiget.py"), "w") as f:
        f.write(MODULE)
    config = os.path.join(work, "exitmaprc")
    with open(config, "w") as f:
        f.write("[Defaults]\n")
    # A tor that has just bootstrapped in a network of three relays keeps
    # their descriptors in cached-descriptors.new only, and relayselector
    # exits if cached-descriptors does not exist.  An empty one lets it go
    # on to read the .new file.  (bin/exitmap removes the directory when
    # it ends.)
    tor_dir = os.path.join(work, "tor")
    os.makedirs(tor_dir, mode=0o700)
    os.chmod(tor_dir, stat.S_IRWXU)
    open(os.path.join(tor_dir, "cached-descriptors"), "w").close()
    env = dict(os.environ)
    for key in list(env):
        if key.lower() in ("http_proxy", "https_proxy", "all_proxy",
                           "no_proxy"):
            del env[key]
    env["PATH"] = bindir + os.pathsep + env["PATH"]
    env["MULTI_OUT"] = os.path.join(work, "results.txt")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    module = os.environ.get("PRIVNET_MODULE", "multiget")
    extra_args = []
    if module == "rtt":
        with open(os.path.join(work, "rtt-destinations.txt"), "w") as f:
            f.write("127.0.0.1\n")
        extra_args = ["-a", os.path.join(work, "analysis")]
    env["PRIVNET_PORTFILE"] = os.path.join(work, "controlport")
    done = threading.Event()
    monitor = threading.Thread(target=watch_events, args=(
        env["PRIVNET_PORTFILE"], os.path.join(work, "events.log"), done))
    monitor.start()
    start = time.monotonic()
    with open(os.path.join(work, "output.txt"), "w") as out:
        proc = subprocess.Popen(
            [sys.executable, os.path.join(copy, "bin", "exitmap"),
             "-f", config, "-t", os.path.join(work, "tor"), "-d", "0.5",
             "-v", "debug", "-o", os.path.join(work, "exitmap.log")] +
            extra_args + [module], cwd=work, env=env, stdout=out, stderr=out)
        try:
            status = proc.wait(600)
        except subprocess.TimeoutExpired:
            proc.kill()
            status = "killed"
    done.set()
    monitor.join(30)
    print("%s: exitmap exited with %s after %.0fs" % (
        label, status, time.monotonic() - start))
    try:
        with open(env["MULTI_OUT"]) as f:
            rows = [line.split() for line in f]
    except OSError:
        rows = []
    carried = exits_that_carried(os.path.join(work, "events.log"), rows)
    names = {}
    wrong = 0
    for row in rows:
        fpr, n, result, secs = row[:4]
        names.setdefault(fpr, "exit%d" % (len(names) + 1))
        exit_fpr = carried.get((fpr, n))
        note = ""
        if result == "ok" and exit_fpr and exit_fpr != fpr:
            note = "  CARRIED BY ANOTHER EXIT: %s" % exit_fpr[:8]
            wrong += 1
        elif result == "ok" and not exit_fpr:
            note = "  (exit not found in events)"
        print("  %s %s connection %s: %s after %ss (port %s)%s" % (
            names[fpr], fpr[:8], n, result, secs,
            row[4] if len(row) > 4 else "?", note))
    print("  connections carried by another probe's exit: %d" % wrong)
    if module == "rtt":
        for root, _, files in os.walk(os.path.join(work, "analysis")):
            for name in sorted(files):
                with open(os.path.join(root, name)) as f:
                    rows = f.read().splitlines()[1:]
                print("  rtt %s: %d measurements" % (name[:8], len(rows)))
    with open(os.path.join(work, "exitmap.log"), errors="replace") as f:
        log = f.read()
    for line in log.splitlines():
        if "Error in `module_call` closure" in line:
            print("  log: " + line.split(" - ", 1)[-1][:150])
    print("  'Unknown stream \"None\"' warnings: %d, circuits built: %d, "
          "'Unknown circuit' warnings: %d" % (
              log.count('Unknown stream "None"'),
              log.count("is built.  Now invoking probing module"),
              log.count("Unknown circuit")))


def main():
    if os.environ.get("PRIVNET_PORTRANGE"):
        with open("/proc/sys/net/ipv4/ip_local_port_range", "w") as f:
            f.write(os.environ["PRIVNET_PORTRANGE"])
    with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
        print("ephemeral ports: %s" % " ".join(f.read().split()))
    os.makedirs(OUT)
    os.chmod(OUT, stat.S_IRWXU)
    server = Server(("127.0.0.1", 8080), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    server80 = Server(("127.0.0.1", 80), Handler)
    threading.Thread(target=server80.serve_forever, daemon=True).start()
    try:
        auth_line = start_network()
        start = time.monotonic()
        if not wait_for_consensus(180):
            print("no consensus with all relays after 180 s")
            return 1
        print("consensus with %d relays after %.0fs" % (
            len(RELAYS), time.monotonic() - start))
        # Let the relays fetch the consensus and the descriptors.
        time.sleep(15)
        bindir = tor_wrapper(auth_line)
        for label, tree in TREES:
            run_exitmap(label, os.path.abspath(tree), bindir)
    finally:
        for proc in PROCS:
            proc.terminate()
        for proc in PROCS:
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
