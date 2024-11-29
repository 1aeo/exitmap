import os.path
import pytest


@pytest.fixture()
def data_path():
    return os.path.join(os.path.abspath(os.path.dirname(__file__)), "data")


@pytest.fixture()
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
