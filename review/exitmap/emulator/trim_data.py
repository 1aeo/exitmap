"""
Build the files in data/ from a cached-consensus and cached-descriptors pair.

usage: trim_data.py <source directory> <destination directory> 30 30

The two numbers say how many exit relays and how many other relays to keep.
The relays are taken in the order of the consensus.  An exit relay has the
Exit flag, not the BadExit flag, and "accept *:*" in its descriptor.  Another
relay has no Exit flag and "reject *:*" in its descriptor.

Written are the trimmed cached-consensus and cached-descriptors, exits.txt
and others.txt with the fingerprints of the relays which were kept, and
e2.txt, e5.txt and e10.txt with the first 2, 5 and 10 lines of exits.txt.
The header and the signatures of the consensus are copied as they are, so
the signatures do not fit the trimmed consensus.  The script prints how
many exit relays and how many other relays it kept.
"""
import base64
import binascii
import re
import sys

src, dst, n_exit, n_other = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])

with open(src + "/cached-consensus") as f:
    cons = f.read()
first_r = cons.index("\nr ") + 1
footer = cons.index("\ndirectory-footer") + 1
header, body, tail = cons[:first_r], cons[first_r:footer], cons[footer:]
entries = re.split(r"(?m)^(?=r )", body)
entries = [e for e in entries if e]

with open(src + "/cached-descriptors", errors="replace") as f:
    descs = f.read()
dentries = re.split(r"(?m)^(?=@downloaded-at)", descs)
by_fpr = {}
for d in dentries:
    m = re.search(r"(?m)^fingerprint ((?:[0-9A-F]{4} ?){10})$", d)
    if m:
        by_fpr[m.group(1).replace(" ", "")] = d


def fpr_of(entry):
    b64 = entry.split(" ")[2]
    return binascii.hexlify(base64.b64decode(b64 + "=")).decode().upper()


exits, others = [], []
for e in entries:
    fpr = fpr_of(e)
    if fpr not in by_fpr:
        continue
    flags = re.search(r"(?m)^s (.*)$", e).group(1).split()
    d = by_fpr[fpr]
    if "Exit" in flags and "BadExit" not in flags and "accept *:*" in d:
        if len(exits) < n_exit:
            exits.append((fpr, e))
    elif "Exit" not in flags and "reject *:*" in d:
        if len(others) < n_other:
            others.append((fpr, e))

keep = sorted(exits + others, key=lambda x: x[0])
with open(dst + "/cached-consensus", "w") as f:
    f.write(header + "".join(e for _, e in keep) + tail)
with open(dst + "/cached-descriptors", "w") as f:
    f.write("".join(by_fpr[fpr] for fpr, _ in keep))
with open(dst + "/exits.txt", "w") as f:
    f.write("".join(fpr + "\n" for fpr, _ in exits))
with open(dst + "/others.txt", "w") as f:
    f.write("".join(fpr + "\n" for fpr, _ in others))
for count in (2, 5, 10):
    with open(dst + "/e%d.txt" % count, "w") as f:
        f.write("".join(fpr + "\n" for fpr, _ in exits[:count]))
print(len(exits), len(others))
