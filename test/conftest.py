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
