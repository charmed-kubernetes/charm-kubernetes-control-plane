import pytest
from unittest import mock


def patch_fixture(patch_target):
    @pytest.fixture()
    def _fixture():
        with mock.patch(patch_target) as m:
            yield m
    return _fixture


def test_imports():
    # dummy test to just make sure files import properly
    # replace with real tests later
    from charms.layer import kubernetes_master as lib
    from reactive import kubernetes_master as handlers
    assert lib and handlers
