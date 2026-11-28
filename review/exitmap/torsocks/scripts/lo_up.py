"""
Run inside "unshare -n": bring up the loopback interface of the new network
namespace (which has no other interface, so nothing can leave the machine)
and then exec the given command.

usage: unshare -n -- python3 lo_up.py <command> [args...]
"""
import fcntl
import os
import socket
import struct
import sys

SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
IFF_UP = 0x1

with open("/proc/net/dev") as f:
    ifaces = [line.split(":")[0].strip() for line in f.readlines()[2:]]
if ifaces != ["lo"]:
    sys.exit("lo_up.py: not in an isolated namespace: %s" % ifaces)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ifreq = struct.pack("16sh14x", b"lo", 0)
flags = struct.unpack("16sh14x", fcntl.ioctl(sock, SIOCGIFFLAGS, ifreq))[1]
fcntl.ioctl(sock, SIOCSIFFLAGS, struct.pack("16sh14x", b"lo", flags | IFF_UP))
sock.close()
os.execvp(sys.argv[1], sys.argv[1:])
