import pytest
from unittest import mock
from reactive import kubernetes_master
from charms.reactive import endpoint_from_flag, remove_state
from charmhelpers.core import hookenv


def patch_fixture(patch_target):
    @pytest.fixture()
    def _fixture():
        with mock.patch(patch_target) as m:
            yield m
    return _fixture


def test_send_default_cni():
    hookenv.config.return_value = 'test-default-cni'
    kubernetes_master.send_default_cni()
    kube_control = endpoint_from_flag('kube-control.connected')
    kube_control.set_default_cni.assert_called_once_with('test-default-cni')


def test_default_cni_changed():
    kubernetes_master.default_cni_changed()
    remove_state.assert_called_once_with(
        'kubernetes-master.components.started'
    )
