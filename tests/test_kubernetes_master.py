import json
import pytest
import tempfile
from ipaddress import ip_interface
from pathlib import Path
from unittest import mock
from reactive import kubernetes_master
from charms.layer import kubernetes_common
from charms.layer.kubernetes_common import get_version, kubectl
from charms.layer.kubernetes_master import deprecate_auth_file
from charms.reactive import endpoint_from_flag, set_flag, is_flag_set, clear_flag
from charmhelpers.core import hookenv, unitdata


kubernetes_common.get_networks = lambda cidrs: [ip_interface(cidr.strip()).network
                                                for cidr in cidrs.split(',')]


@pytest.fixture
def auth_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / 'test_auth.csv'


def test_deprecate_auth_file(auth_file):
    """Verify a comment is written by deprecate_auth_file()."""
    deprecate_auth_file(auth_file)
    assert auth_file.exists()
    assert auth_file.read_text().startswith('#')


def test_get_password(auth_file):
    """Verify expected token is returned."""
    password = 'password'
    user = 'admin'

    # Test we handle a missing file
    assert kubernetes_master.get_password('missing', user) is None

    with mock.patch('reactive.kubernetes_master.os.path.join',
                    return_value=str(auth_file)):
        # Test we handle a deprecated file
        deprecate_auth_file(auth_file)
        assert kubernetes_master.get_password(auth_file, user) is None

        # Test we handle a valid file
        auth_file.write_text('{},{},uid,group\n'.format(password, user))
        assert kubernetes_master.get_password(auth_file, user) == password


def test_send_default_cni():
    hookenv.config.return_value = 'test-default-cni'
    kubernetes_master.send_default_cni()
    kube_control = endpoint_from_flag('kube-control.connected')
    kube_control.set_default_cni.assert_called_once_with('test-default-cni')


def test_default_cni_changed():
    set_flag('kubernetes-master.components.started')
    kubernetes_master.default_cni_changed()
    assert not is_flag_set('kubernetes-master.components.started')


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
    configure_apiserver(None, '10.152.183.0/24,fe80::/120')
    assert not is_flag_set('kubernetes-master.had-service-cidr-expanded')


def test_service_cidr_no_change():
    configure_apiserver('10.152.183.0/24', '10.152.183.0/24')
    assert not is_flag_set('kubernetes-master.had-service-cidr-expanded')
    configure_apiserver('10.152.183.0/24,fe80::/120', '10.152.183.0/24,fe80::/120')
    assert not is_flag_set('kubernetes-master.had-service-cidr-expanded')


def test_service_cidr_non_expansion():
    configure_apiserver('10.152.183.0/24', '10.154.183.0/24')
    assert not is_flag_set('kubernetes-master.had-service-cidr-expanded')
    configure_apiserver('10.152.183.0/24,fe80::/120', '10.152.183.0/24,fe81::/120')
    assert not is_flag_set('kubernetes-master.had-service-cidr-expanded')


def test_service_cidr_expansion():
    configure_apiserver('10.152.183.0/24', '10.152.0.0/16')
    assert is_flag_set('kubernetes-master.had-service-cidr-expanded')
    clear_flag('kubernetes-master.had-service-cidr-expanded')
    configure_apiserver('10.152.183.0/24,fe80::/120', '10.152.183.0/24,fe80::/112')
    assert is_flag_set('kubernetes-master.had-service-cidr-expanded')
    unitdata.kv().get.return_value = '10.152.0.0/16'
    update_for_service_cidr_expansion()
    assert kubectl.call_count == 4
