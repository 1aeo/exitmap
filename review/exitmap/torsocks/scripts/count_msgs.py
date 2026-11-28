"""
Count the (circ_id, sockname) messages which exitmap's torsocks puts on the
IPC queue for each connection of one probe process.  No Tor: a local server
in a separate process answers SOCKS5 (CONNECT and Tor's RESOLVE) and then
plays HTTP server for the destination.

Every experiment runs in a fresh probe process started like exitmap starts
its probes: multiprocessing.Process(target=eventhandler.module_call, ...).
The parent of this script never creates a _Torsocket (checked below), so a
probe process starts with the class-level negotiator unwrapped, as in
exitmap.

usage: count_msgs.py <exitmap tree>
"""
import http.client
import multiprocessing
import os
import socket
import struct
import sys
import types
import urllib.request

for key in list(os.environ):
    if key.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        del os.environ[key]
os.environ["no_proxy"] = "*"

TREE = os.path.abspath(sys.argv[1])
sys.path.insert(0, os.path.join(TREE, "src"))
import socks         # noqa: E402
import torsocks      # noqa: E402
import eventhandler  # noqa: E402

CIRC = "42"


# ---------------------------------------------------------------- server

def recvall(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data


def handle(client):
    _, nmethods = recvall(client, 2)
    recvall(client, nmethods)
    client.sendall(b"\x05\x00")
    _, cmd, _, atyp = recvall(client, 4)
    if atyp == 1:
        host = socket.inet_ntoa(recvall(client, 4))
    elif atyp == 3:
        host = recvall(client, recvall(client, 1)[0]).decode()
    else:
        recvall(client, 16)
        host = "[::]"
    recvall(client, 2)
    if cmd == 0xF0:  # Tor's RESOLVE extension
        client.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("192.0.2.7") +
                       b"\x00\x00")
        return
    client.sendall(b"\x05\x00\x00\x01" + bytes(4) + b"\x00\x00")
    # From here on we are the destination.  HTTP with keep-alive; the path
    # /hops/N answers with a redirect to /hops/N-1.
    client.settimeout(3)
    buf = b""
    while True:
        while b"\r\n\r\n" not in buf:
            try:
                chunk = client.recv(4096)
            except socket.timeout:
                return
            if not chunk:
                return
            buf += chunk
        head, buf = buf.split(b"\r\n\r\n", 1)
        path = head.split(b" ", 2)[1].decode()
        close = b"connection: close" in head.lower()
        if path.startswith("/hops/") and int(path[6:]) > 0:
            status = "302 Found"
            extra = "Location: http://%s/hops/%d\r\n" % (host,
                                                         int(path[6:]) - 1)
            body = ""
        else:
            status, extra, body = "200 OK", "", "ok"
        client.sendall(("HTTP/1.1 %s\r\n%sContent-Length: %d\r\n"
                        "Connection: %s\r\n\r\n%s" %
                        (status, extra, len(body),
                         "close" if close else "keep-alive", body)).encode())
        if close:
            return


def serve(listener):
    while True:
        client, _ = listener.accept()
        try:
            handle(client)
        except Exception:
            pass
        finally:
            client.close()


# ---------------------------------------------------------------- helpers

def depth():
    """How many ourneg wrappers the class-level SOCKS5 entry has."""
    func = socks.socksocket.__dict__["_proxy_negotiators"][socks.SOCKS5]
    n = 0
    while func.__name__ == "ourneg":
        n += 1
        cell = func.__code__.co_freevars.index("orig_neg")
        func = func.__closure__[cell].cell_contents
    return n


def mark(label):
    """Put a marker on the queue; it separates the connections."""
    torsocks.queue.put(["MARK", label, depth()])


def plain_connect(label):
    mark(label)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect(("192.0.2.1", 80))
    sock.close()


def urlopen(label, path="/"):
    mark(label)
    urllib.request.urlopen("http://example.test" + path, timeout=3).read()


# ---------------------------------------------------------------- probes

def p_socket_6(run_python_over_tor, **kwargs):
    """Six socket.socket() connections in one run_python_over_tor() call."""
    def body():
        for i in range(1, 7):
            plain_connect("connection %d" % i)
    run_python_over_tor(body)


def p_calls_6(run_python_over_tor, **kwargs):
    """Six run_python_over_tor() calls, one connection each (#46, way 1)."""
    for i in range(1, 7):
        run_python_over_tor(urlopen, "call %d: urlopen" % i)


def p_loop_6(run_python_over_tor, **kwargs):
    """One run_python_over_tor() call looping over urlopen() (#46, way 2)."""
    def body():
        for i in range(1, 7):
            urlopen("urlopen %d" % i)
    run_python_over_tor(body)


def p_redirects(run_python_over_tor, **kwargs):
    """urlopen() of a URL that redirects twice: three connections."""
    def body():
        mark("urlopen /hops/2 (two redirects)")
        urllib.request.urlopen("http://example.test/hops/2", timeout=3).read()
        urlopen("urlopen / afterwards")
    run_python_over_tor(body)


def p_httpclient(run_python_over_tor, **kwargs):
    """http.client: three requests on one keep-alive connection, then a
    second HTTPConnection."""
    def body():
        mark("HTTPConnection 1, three requests")
        conn = http.client.HTTPConnection("example.test", 80, timeout=3)
        for _ in range(3):
            conn.request("GET", "/")
            conn.getresponse().read()
        conn.close()
        mark("HTTPConnection 2, one request")
        conn = http.client.HTTPConnection("example.test", 80, timeout=3)
        conn.request("GET", "/")
        conn.getresponse().read()
        conn.close()
    run_python_over_tor(body)


def p_resolve_then_connect(run_python_over_tor, **kwargs):
    """Two resolve() calls (as dnsresolution does), then two connections,
    plus a socket that is created but never connected."""
    def resolve(label):
        mark(label)
        sock = torsocks.torsocket()
        sock.settimeout(3)
        sock.resolve("example.test")
        sock.close()
    run_python_over_tor(resolve, "resolve 1")
    run_python_over_tor(resolve, "resolve 2")
    run_python_over_tor(plain_connect, "connect after 2 resolves")

    def unused_socket():
        mark("socket created, never connected")
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()
    run_python_over_tor(unused_socket)
    run_python_over_tor(plain_connect, "connect after that")


PROBES = [p_socket_6, p_calls_6, p_loop_6, p_redirects, p_httpclient,
          p_resolve_then_connect]


# ---------------------------------------------------------------- driver

def run_probe(probe, socks_port):
    queue = multiprocessing.Queue()
    exit_desc = types.SimpleNamespace(fingerprint="A" * 40)
    proc = multiprocessing.Process(target=eventhandler.module_call, args=(
        queue, probe, CIRC, socks_port, exit_desc, None, set(), None, None))
    proc.start()
    groups = []
    while True:
        item = queue.get(timeout=60)
        if item[0] == "MARK":
            groups.append([item[1], item[2], []])
        elif item[1] is None:
            break
        else:
            groups[-1][2].append(tuple(item[1]))
    proc.join(10)
    print("%s: %s" % (probe.__name__, probe.__doc__.split("\n")[0]))
    for label, wraps, msgs in groups:
        ports = sorted(set(m[1] for m in msgs))
        print("  %-36s wrappers before: %d  messages: %d  source ports: %s" %
              (label, wraps, len(msgs), ports))
    return groups


def main():
    print("exitmap tree: %s" % TREE)
    print("python %s, PySocks %s, start method %s" % (
        sys.version.split()[0], socks.__version__,
        multiprocessing.get_start_method()))
    print("'_proxy_negotiators' in socks.socksocket.__dict__: %s" %
          ("_proxy_negotiators" in socks.socksocket.__dict__))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(50)
    server = multiprocessing.Process(target=serve, args=(listener,),
                                     daemon=True)
    server.start()
    port = listener.getsockname()[1]
    try:
        assert depth() == 0, "parent has wrapped the negotiator"
        for probe in PROBES:
            run_probe(probe, port)
        # The parent still has no wrapper, so each probe started from zero.
        print("wrappers in this (parent) process at the end: %d" % depth())
    finally:
        server.terminate()
        server.join()


if __name__ == "__main__":
    main()
