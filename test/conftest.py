import argparse
import os.path
import sys
from unittest.mock import Mock

import pytest
from stem import descriptor


@pytest.fixture(scope="session")
def data_path():
    return os.path.join(os.path.abspath(os.path.dirname(__file__)), "data")


@pytest.fixture(scope="session")
def tor_dir(data_path):
    return data_path


@pytest.fixture(scope="session")
def mock_argv():
    sys.argv = ['exitmap.py', 'checktest']
    yield
    sys.argv = []  # Restore original sys.argv


@pytest.fixture(scope="session")
def args_default():
    namespace = argparse.Namespace(
        config_file = None,
        country=None,
        exit=None,
        exit_file=None,
        build_delay=0,
        delay_noise=0,
        tor_dir=None,
        analysis_dir=None,
        verbosity='info',
        first_hop=None,
        logfile=None,
        bad_exits=False,
        all_exits=False,
        host=None,
        port=None,
        module=['checktest'],
    )
    return namespace


@pytest.fixture(scope="session")
def args(args_default, tor_dir):
    namespace = argparse.Namespace(
        config_file = None,
        country=None,
        exit="50485E03CA39D393BD54D315CEBA65E6DD0FDDB9",
        exit_file=None,
        build_delay=0,
        delay_noise=0,
        tor_dir=tor_dir,
        analysis_dir=None,
        verbosity='info',
        first_hop='FAF0A8829E39063669FA609B904E0FB8D5E1F23F',
        logfile=None,
        bad_exits=False,
        all_exits=False,
        host='example.com',
        port=8000,
        module=['checktest'],
    )
    return namespace


@pytest.fixture(scope="session")
def cached_consensus_path(data_path):
    return os.path.join(data_path, "cached-consensus")


@pytest.fixture()
def cached_descriptors_path(data_path):
    return os.path.join(data_path, "cached-descriptors")


@pytest.fixture()
def cached_consensus(cached_consensus_path):
    # if imported on the top, the percent coverage of relayselector.py test
    # will be 0
    import relayselector

    cc = relayselector.get_cached_consensus(cached_consensus_path)
    return cc


@pytest.fixture(scope="session")
def router_statuses(cached_consensus_path):
    network_statuses = descriptor.parse_file(cached_consensus_path)
    return list(network_statuses)


@pytest.fixture(scope="session")
def controller(router_statuses):
    controller = Mock()
    controller.get_info.return_value = "params foo=23"
    controller.get_network_statuses.return_value = router_statuses
    return controller


@pytest.fixture(scope="session")
def modules():
    import exitmap

    return exitmap.get_modules()


@pytest.fixture(scope="function")
def stats_obj():
    import stats

    obj = stats.Statistics()
    return obj


@pytest.fixture(scope="session")
def exit_relays(args):
    import exitmap

    return exitmap.select_exits(args, "checktest")
