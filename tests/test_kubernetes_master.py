import pytest
import tempfile
from pathlib import Path
from unittest import mock
from reactive import kubernetes_master
from charms.layer.kubernetes_common import get_version, kubectl
from charms.layer.kubernetes_master import deprecate_auth_file
from charms.reactive import endpoint_from_flag, remove_state
from charmhelpers.core import hookenv, unitdata


def patch_fixture(patch_target):
    @pytest.fixture()
    def _fixture():
        with mock.patch(patch_target) as m:
            yield m
    return _fixture


@pytest.fixture
def auth_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / 'test_auth.csv'


def test_deprecate_auth_file(auth_file):
    """Verify a comment is written by deprecate_auth_file()"""
    deprecate_auth_file(auth_file)
    assert auth_file.exists()
    assert auth_file.read_text().startswith('#')


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


def test_series_upgrade():
    assert kubernetes_master.service_pause.call_count == 0
    assert kubernetes_master.service_resume.call_count == 0
    kubernetes_master.pre_series_upgrade()
    assert kubernetes_master.service_pause.call_count == 4
    assert kubernetes_master.service_resume.call_count == 0
    kubernetes_master.post_series_upgrade()
    assert kubernetes_master.service_pause.call_count == 4
    assert kubernetes_master.service_resume.call_count == 4


@mock.patch('builtins.open', mock.mock_open())
@mock.patch('os.makedirs', mock.Mock(return_value=0))
def configure_apiserver(service_cidr_from_db, service_cidr_from_config,
                        kubectl_call_count):
    db = unitdata.kv()
    db.get.return_value = service_cidr_from_db
    hookenv.config.return_value = service_cidr_from_config
    get_version.return_value = (1, 18)
    kubectl.return_value = '{"items": []}'.encode('UTF-8')
    kubernetes_master.configure_apiserver()
    assert kubectl.call_count == kubectl_call_count


def test_service_cidr_greenfield_deploy():
    configure_apiserver(None, '10.152.183.0/24', 0)


def test_service_cidr_no_change():
    configure_apiserver('10.152.183.0/24', '10.152.183.0/24', 0)


def test_service_cidr_non_expansion():
    configure_apiserver('10.152.183.0/24', '10.154.183.0/24', 0)


def test_service_cidr_expansion():
    configure_apiserver('10.152.183.0/24', '10.152.0.0/16', 2)
