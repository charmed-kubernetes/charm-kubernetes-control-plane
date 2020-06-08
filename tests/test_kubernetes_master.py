import json
import pytest
from unittest import mock
from reactive import kubernetes_master
from charms.layer.kubernetes_common import get_version, kubectl
from charms.reactive import endpoint_from_flag, set_flag, is_flag_set
from charmhelpers.core import hookenv, unitdata


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
    set_flag('kubernetes-master.components.started')
    kubernetes_master.default_cni_changed()
    assert not is_flag_set('kubernetes-master.components.started')


@mock.patch('builtins.open', mock.mock_open())
@mock.patch('os.makedirs', mock.Mock(return_value=0))
def configure_apiserver(service_cidr_from_db, service_cidr_from_config):
    set_flag('leadership.is_leader')
    db = unitdata.kv()
    db.get.return_value = service_cidr_from_db
    hookenv.config.return_value = service_cidr_from_config
    get_version.return_value = (1, 18)
    kubernetes_master.configure_apiserver()


def update_for_service_cidr_expansion():
    def _svc(clusterIP):
        return json.dumps({
            "items": [
                {
                    "metadata": {"name": "kubernetes"},
                    "spec": {"clusterIP": clusterIP},
                }
            ]
        }).encode('utf8')

    kubectl.side_effect = [
        _svc('10.152.183.1'),
        None,
        _svc('10.152.0.1'),
        b'{"items":[]}',
    ]
    assert kubectl.call_count == 0
    kubernetes_master.update_for_service_cidr_expansion()


def test_service_cidr_greenfield_deploy():
    configure_apiserver(None, '10.152.183.0/24')
    assert not is_flag_set('kubernetes-master.had-service-cidr-expanded')


def test_service_cidr_no_change():
    configure_apiserver('10.152.183.0/24', '10.152.183.0/24')
    assert not is_flag_set('kubernetes-master.had-service-cidr-expanded')


def test_service_cidr_non_expansion():
    configure_apiserver('10.152.183.0/24', '10.154.183.0/24')
    assert not is_flag_set('kubernetes-master.had-service-cidr-expanded')


def test_service_cidr_expansion():
    configure_apiserver('10.152.183.0/24', '10.152.0.0/16')
    assert is_flag_set('kubernetes-master.had-service-cidr-expanded')
    unitdata.kv().get.return_value = '10.152.0.0/16'
    update_for_service_cidr_expansion()
    assert kubectl.call_count == 4
