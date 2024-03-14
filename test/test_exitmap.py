import sys
import argparse
# hacky, until exitmap is an installable package
sys.path.insert(0, 'src/')  # noqa
import exitmap


def test_get_modules():
    modules = exitmap.get_modules()
    for m in [
        "checktest",
        "cloudflared",
        "dnspoison",
        "dnsresolution",
        "dnssec",
        "patchingCheck",
        "rtt",
        "testfds"
    ]:
        assert m in modules


def test_lookup_destinations():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host')
    parser.add_argument('--port')
    args = parser.parse_args(["--host", "localhost", "--port", "8000"])
    destinations = exitmap.lookup_destinations(args, "checktest.destinations")
    for module in exitmap.get_modules():
        print(module)
        destinations = exitmap.lookup_destinations(args, module)
        assert destinations == {('127.0.0.1', '8000')}
