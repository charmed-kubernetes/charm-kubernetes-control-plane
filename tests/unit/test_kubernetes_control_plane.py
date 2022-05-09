import json
from ipaddress import ip_interface
from unittest import mock

import pytest

from reactive import kubernetes_control_plane
from charms.layer import kubernetes_common
from charms.layer.kubernetes_common import get_version, kubectl
from charms.reactive import endpoint_from_flag, endpoint_from_name
from charms.reactive import set_flag, is_flag_set, clear_flag
from charmhelpers.core import hookenv, host, unitdata


kubernetes_common.get_networks = lambda cidrs: [
    ip_interface(cidr.strip()).network for cidr in cidrs.split(",")
]


def test_send_default_cni():
    hookenv.config.return_value = "test-default-cni"
    kubernetes_control_plane.send_default_cni()
    kube_control = endpoint_from_flag("kube-control.connected")
    kube_control.set_default_cni.assert_called_once_with("test-default-cni")


def test_default_cni_changed():
    set_flag("kubernetes-control-plane.components.started")
    kubernetes_control_plane.default_cni_changed()
    assert not is_flag_set("kubernetes-control-plane.components.started")


def test_series_upgrade():
    assert kubernetes_control_plane.service_pause.call_count == 0
    assert kubernetes_control_plane.service_resume.call_count == 0
    kubernetes_control_plane.pre_series_upgrade()
    assert kubernetes_control_plane.service_pause.call_count == 5
    assert kubernetes_control_plane.service_resume.call_count == 0
    kubernetes_control_plane.post_series_upgrade()
    assert kubernetes_control_plane.service_pause.call_count == 5
    assert kubernetes_control_plane.service_resume.call_count == 5


@mock.patch("builtins.open", mock.mock_open())
@mock.patch("os.makedirs", mock.Mock(return_value=0))
def configure_apiserver(service_cidr_from_db, service_cidr_from_config):
    set_flag("leadership.is_leader")
    db = unitdata.kv()
    db.set("kubernetes-master.service-cidr", service_cidr_from_db)
    hookenv.config.return_value = service_cidr_from_config
    get_version.return_value = (1, 18)
    kubernetes_control_plane.configure_apiserver()


def update_for_service_cidr_expansion():
    def _svc(clusterIP):
        return json.dumps(
            {
                "items": [
                    {
                        "metadata": {"name": "kubernetes"},
                        "spec": {"clusterIP": clusterIP},
                    }
                ]
            }
        ).encode("utf8")

    kubectl.side_effect = [
        _svc("10.152.183.1"),
        None,
        _svc("10.152.0.1"),
        b'{"items":[]}',
    ]
    assert kubectl.call_count == 0
    kubernetes_control_plane.update_for_service_cidr_expansion()


def test_service_cidr_greenfield_deploy():
    configure_apiserver(None, "10.152.183.0/24")
    assert not is_flag_set("kubernetes-control-plane.had-service-cidr-expanded")
    configure_apiserver(None, "10.152.183.0/24,fe80::/120")
    assert not is_flag_set("kubernetes-control-plane.had-service-cidr-expanded")


def test_service_cidr_no_change():
    configure_apiserver("10.152.183.0/24", "10.152.183.0/24")
    assert not is_flag_set("kubernetes-control-plane.had-service-cidr-expanded")
    configure_apiserver("10.152.183.0/24,fe80::/120", "10.152.183.0/24,fe80::/120")
    assert not is_flag_set("kubernetes-control-plane.had-service-cidr-expanded")


def test_service_cidr_non_expansion():
    configure_apiserver("10.152.183.0/24", "10.154.183.0/24")
    assert not is_flag_set("kubernetes-control-plane.had-service-cidr-expanded")
    configure_apiserver("10.152.183.0/24,fe80::/120", "10.152.183.0/24,fe81::/120")
    assert not is_flag_set("kubernetes-control-plane.had-service-cidr-expanded")


def test_service_cidr_expansion():
    configure_apiserver("10.152.183.0/24", "10.152.0.0/16")
    assert is_flag_set("kubernetes-control-plane.had-service-cidr-expanded")
    clear_flag("kubernetes-control-plane.had-service-cidr-expanded")
    configure_apiserver("10.152.183.0/24,fe80::/120", "10.152.183.0/24,fe80::/112")
    assert is_flag_set("kubernetes-control-plane.had-service-cidr-expanded")
    db = unitdata.kv()
    db.set("kubernetes-master.service-cidr", "10.152.0.0/16")
    update_for_service_cidr_expansion()
    assert kubectl.call_count == 4


@mock.patch("reactive.kubernetes_control_plane.send_data")
def test_update_certificates_with_missing_relations(mock_send_data):
    # NOTE (rgildein): This test only tests whether the send_data function
    # has been called, if required relations are missing.
    set_flag("test_available")

    kubernetes_control_plane.update_certificates()
    hookenv.log.assert_any_call(
        "Missing relations: 'certificates.available, " "kube-api-endpoint.available'",
        hookenv.ERROR,
    )
    mock_send_data.assert_not_called()


def test_status_set_on_missing_ca():
    """Test that set_final_status() will set blocked state if CA is missing"""
    set_flag("certificates.available")
    set_flag("kubernetes-control-plane.secure-storage.failed")
    kubernetes_control_plane.set_final_status()
    hookenv.status_set.assert_called_with(
        "blocked",
        "Failed to configure encryption; " "secrets are unencrypted or inaccessible",
    )
    clear_flag("certificates.available")
    kubernetes_control_plane.set_final_status()
    hookenv.status_set.assert_called_with(
        "blocked", "Missing relation to certificate " "authority."
    )


def test_status_set_on_incomplete_lb():
    """Test that set_final_status() will set waiting if LB is pending."""
    set_flag("certificates.available")
    clear_flag("kubernetes-control-plane.secure-storage.failed")
    set_flag("kube-control.connected")
    set_flag("etcd.available")
    set_flag("cni.available")
    set_flag("tls_client.certs.saved")
    set_flag("kubernetes-control-plane.auth-webhook-service.started")
    set_flag("kubernetes-control-plane.apiserver.configured")
    set_flag("kubernetes-control-plane.apiserver.running")
    set_flag("authentication.setup")
    set_flag("kubernetes-control-plane.auth-webhook-tokens.setup")
    set_flag("kubernetes-control-plane.components.started")
    set_flag("cdk-addons.configured")
    set_flag("kubernetes.cni-plugins.installed")
    set_flag("kubernetes-control-plane.system-monitoring-rbac-role.applied")
    hookenv.config.return_value = "auto"
    host.service_running.return_value = True
    kubectl.side_effect = None
    kubectl.return_value = b'{"items": []}'

    # test no LB relation
    hookenv.goal_state.return_value = {}
    kubernetes_control_plane.set_final_status()
    hookenv.status_set.assert_called_with("active", mock.ANY)

    # test legacy kube-api-endpoint relation
    hookenv.goal_state.return_value = {"relations": {"kube-api-endpoint": None}}
    kubernetes_control_plane.set_final_status()
    hookenv.status_set.assert_called_with(
        "waiting", "Waiting for kube-api-endpoint relation"
    )
    set_flag("kube-api-endpoint.available")
    kubernetes_control_plane.set_final_status()
    hookenv.status_set.assert_called_with("active", mock.ANY)

    # test loadbalancer-internal relation
    clear_flag("kube-api-endpoint.available")
    hookenv.goal_state.return_value = {"relations": {"loadbalancer-internal": None}}
    endpoint_from_name.return_value.has_response = False
    kubernetes_control_plane.set_final_status()
    hookenv.status_set.assert_called_with(
        "waiting", "Waiting for loadbalancer-internal"
    )
    endpoint_from_name.return_value.has_response = True
    kubernetes_control_plane.set_final_status()
    hookenv.status_set.assert_called_with("active", mock.ANY)

    # test loadbalancer-external relation
    hookenv.goal_state.return_value = {"relations": {"loadbalancer-external": None}}
    endpoint_from_name.return_value.has_response = False
    kubernetes_control_plane.set_final_status()
    hookenv.status_set.assert_called_with(
        "waiting", "Waiting for loadbalancer-external"
    )
    endpoint_from_name.return_value.has_response = True
    kubernetes_control_plane.set_final_status()
    hookenv.status_set.assert_called_with("active", mock.ANY)


@mock.patch("reactive.kubernetes_control_plane.control_plane_services_down")
@mock.patch("reactive.kubernetes_control_plane.HEAL_HANDLER")
@mock.patch("reactive.kubernetes_control_plane.call")
def test_status_set_on_failed_master_services(call, heal_handler, msd):
    """Test that set_final_status() will set node to standby mode if a service fail"""
    set_flag("certificates.available")
    clear_flag("kubernetes-control-plane.secure-storage.failed")
    set_flag("kube-control.connected")
    set_flag("etcd.available")
    set_flag("cni.available")
    set_flag("tls_client.certs.saved")
    set_flag("kubernetes-control-plane.auth-webhook-service.started")
    set_flag("kubernetes-control-plane.apiserver.configured")
    set_flag("kubernetes-control-plane.apiserver.running")
    set_flag("authentication.setup")
    set_flag("kubernetes-control-plane.auth-webhook-tokens.setup")
    set_flag("kubernetes-control-plane.components.started")
    set_flag("ha.connected")

    msd.return_value = ["kube-apiserver"]
    test_heal_handler = {
        "kube-apiserver": {
            "run": lambda: "test_heal",
            "clear_flags": ["kubernetes-control-plane.apiserver.configured"],
        }
    }
    heal_handler.__getitem__.side_effect = test_heal_handler.__getitem__
    kubernetes_control_plane.set_final_status()
    hookenv.status_set.assert_called_with(
        "blocked",
        "Stopped services: kube-apiserver",
    )
    call.assert_called_with("crm -w -F node standby".split())
    clear_flag.assert_called_with("kubernetes-control-plane.apiserver.configured")
    set_flag.assert_called_with("kubernetes-control-plane.components.failed")


@mock.patch("reactive.kubernetes_control_plane.control_plane_services_down")
@mock.patch("reactive.kubernetes_control_plane.HEAL_HANDLER")
@mock.patch("reactive.kubernetes_control_plane.call")
def test_status_set_on_healed_master_services(call, heal_handler, msd):
    """Test that set_final_status() will set node to online mode if service recover"""
    set_flag("certificates.available")
    clear_flag("kubernetes-control-plane.secure-storage.failed")
    set_flag("kube-control.connected")
    set_flag("etcd.available")
    set_flag("cni.available")
    set_flag("tls_client.certs.saved")
    set_flag("kubernetes-control-plane.auth-webhook-service.started")
    set_flag("kubernetes-control-plane.apiserver.configured")
    set_flag("kubernetes-control-plane.apiserver.running")
    set_flag("authentication.setup")
    set_flag("kubernetes-control-plane.auth-webhook-tokens.setup")
    set_flag("kubernetes-control-plane.components.started")
    set_flag("kubernetes-control-plane.components.failed")
    set_flag("ha.connected")

    msd.return_value = []
    kubernetes_control_plane.set_final_status()
    call.assert_called_with("crm -w -F node online".split())
    clear_flag.assert_called_with("kubernetes-control-plane.components.failed")


@mock.patch("reactive.kubernetes_control_plane.setup_tokens")
@mock.patch("reactive.kubernetes_control_plane.get_token")
def test_create_token_sign_auth_requests(get_token, setup_tokens):
    set_flag("kubernetes-control-plane.auth-webhook-tokens.setup")
    kube_control = endpoint_from_flag.return_value
    get_token.return_value = None
    clear_flag("kubernetes-control-plane.auth-webhook-tokens.setup")
    assert not kubernetes_control_plane.create_tokens_and_sign_auth_requests()
    assert kube_control.sign_auth_request.call_count == 0
    assert not is_flag_set("kubernetes-control-plane.auth-webhook-tokens.setup")

    endpoint_from_flag.return_value = None
    get_token.return_value = True
    clear_flag("kubernetes-control-plane.auth-webhook-tokens.setup")
    assert kubernetes_control_plane.create_tokens_and_sign_auth_requests()
    assert kube_control.sign_auth_request.call_count == 0
    assert is_flag_set("kubernetes-control-plane.auth-webhook-tokens.setup")

    endpoint_from_flag.return_value = kube_control
    kube_control.auth_user.return_value = [
        (None, {"user": "foo", "group": "foo"}),
        (None, {"user": None, "group": None}),
    ]
    clear_flag("kubernetes-control-plane.auth-webhook-tokens.setup")
    assert kubernetes_control_plane.create_tokens_and_sign_auth_requests()
    assert kube_control.sign_auth_request.call_count == 1
    assert is_flag_set("kubernetes-control-plane.auth-webhook-tokens.setup")

    kube_control.auth_user.return_value = [
        (None, {"user": "foo", "group": "foo"}),
        (None, {"user": "bar", "group": "bar"}),
    ]
    clear_flag("kubernetes-control-plane.auth-webhook-tokens.setup")
    assert kubernetes_control_plane.create_tokens_and_sign_auth_requests()
    assert kube_control.sign_auth_request.call_count == 3
    assert is_flag_set("kubernetes-control-plane.auth-webhook-tokens.setup")


@mock.patch("reactive.kubernetes_control_plane.create_tokens_and_sign_auth_requests")
@mock.patch("reactive.kubernetes_control_plane.kubectl_success")
def test_setup_auth_webhook_tokens(kcs, ctsar):
    kcs.return_value = False
    ctsar.return_value = True
    set_flag("authentication.setup")
    kubernetes_control_plane.setup_auth_webhook_tokens()
    assert is_flag_set("authentication.setup")

    kcs.return_value = True
    ctsar.return_value = False
    set_flag("authentication.setup")
    kubernetes_control_plane.setup_auth_webhook_tokens()
    assert is_flag_set("authentication.setup")

    kcs.return_value = True
    ctsar.return_value = True
    set_flag("authentication.setup")
    kubernetes_control_plane.setup_auth_webhook_tokens()
    assert not is_flag_set("authentication.setup")


@mock.patch.object(kubernetes_control_plane, "get_ingress_address")
@mock.patch("pathlib.Path.stat", mock.Mock(side_effect=ValueError))
@mock.patch("pathlib.Path.mkdir", mock.Mock(return_value=0))
@mock.patch.object(
    kubernetes_control_plane, "any_file_changed", mock.Mock(return_value=False)
)
def test_ignore_vip(get_ingress_address):
    get_ingress_address.return_value = "5.6.7.8"
    hookenv.config.return_value = "1.2.3.4"
    kubernetes_control_plane.register_auth_webhook()
    get_ingress_address.assert_called_with(
        "kube-api-endpoint", ignore_addresses=["1.2.3.4"]
    )


class TestSendClusterDNSDetail:
    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        self.kube_control = mock.Mock()
        self.config = {"dns_provider": "auto", "dns_domain": "domain"}

        hc = mock.Mock()
        hc.side_effect = lambda k=None: self.config[k] if k else self.config
        monkeypatch.setattr(hookenv, "config", hc)

        gdp = self.get_dns_provider = mock.Mock()
        gdp.side_effect = lambda: hc("dns_provider")
        monkeypatch.setattr(kubernetes_control_plane, "get_dns_provider", gdp)

        gip = self.get_dns_ip = mock.Mock(return_value="ip")
        monkeypatch.setattr(
            kubernetes_control_plane.kubernetes_control_plane, "get_dns_ip", gip
        )

    def test_default_config(self):
        endpoint_from_flag.return_value = None
        hookenv.goal_state.return_value = {}
        kubernetes_control_plane.send_cluster_dns_detail(self.kube_control)
        assert self.kube_control.set_dns.call_args == mock.call(
            53, "domain", "ip", True
        )

    def test_invalid_config(self):
        endpoint_from_flag.return_value = None
        hookenv.goal_state.return_value = {}
        self.get_dns_provider.side_effect = kubernetes_control_plane.InvalidDnsProvider(
            "invalid"
        )
        kubernetes_control_plane.send_cluster_dns_detail(self.kube_control)
        assert self.kube_control.set_dns.call_args is None

    def test_dns_not_ready(self):
        endpoint_from_flag.return_value = None
        hookenv.goal_state.return_value = {}
        self.get_dns_ip.side_effect = kubernetes_control_plane.CalledProcessError(
            1, "cmd"
        )
        kubernetes_control_plane.send_cluster_dns_detail(self.kube_control)
        assert self.kube_control.set_dns.call_args is None

    def test_dns_pending(self):
        self.config["dns_provider"] = "none"
        endpoint_from_flag.return_value = None
        hookenv.goal_state.return_value = {"relations": {"dns-provider": True}}
        kubernetes_control_plane.send_cluster_dns_detail(self.kube_control)
        assert self.kube_control.set_dns.call_args is None

    def test_dns_disabled(self):
        endpoint_from_flag.return_value = None
        self.config["dns_provider"] = "none"
        hookenv.goal_state.return_value = {}
        kubernetes_control_plane.send_cluster_dns_detail(self.kube_control)
        assert self.kube_control.set_dns.call_args == mock.call(None, None, None, False)
