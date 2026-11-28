"""
Test module for the fake Tor: its setup() function fails.
"""

destinations = None


def setup(**kwargs):
    raise RuntimeError("setup failed")


def probe(exit_desc, target_host, target_port, run_python_over_tor,
          run_cmd_over_tor, **kwargs):
    pass
