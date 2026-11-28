Relates to #46.

`_Torsocket.__init__()` wraps PySocks' SOCKS5 negotiation function in `socks.socksocket._proxy_negotiators`, a dict that all sockets share, so the n-th socket of a probe puts its `(circ_id, sockname)` message on the queue n times. exitmap then usually logs `Failed to attach stream because: Unknown stream "None"` for the second connection of a probe, and that connection fails two minutes later with `0x06: TTL expired`, unless the module gives up earlier. The log posted in !5 shows the same once that module fetched several targets per exit relay (`Attempting to attach stream None to circuit 4.`). The commit message has the details.

This gives every socket its own copy of the dict. To see the duplicate messages without Tor, run this in a checkout. On `main` it prints 1, 2, 3 and 4 messages, with this branch 1 each:

```python
import sys
sys.path.insert(0, "src")
import socks
import torsocks

sent = []
torsocks.send_queue = sent.append
# No Tor: leave out PySocks' SOCKS5 handshake.
socks.socksocket._proxy_negotiators[socks.SOCKS5] = lambda *args: None
for n in range(1, 5):
    del sent[:]
    with torsocks._Torsocket() as s:
        # What PySocks' connect() does once it is connected to Tor.
        s._proxy_negotiators[socks.SOCKS5](s, "192.0.2.1", 80)
    print("connection %d: %d message(s)" % (n, len(sent)))
```

The new test fails on `main` with `assert 6 == 3`. The tests and flake8 pass with Python 3.10 to 3.13.
