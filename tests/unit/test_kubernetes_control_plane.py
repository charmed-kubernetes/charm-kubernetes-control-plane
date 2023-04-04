import contextlib
import json
from ipaddress import ip_interface
from unittest import mock

import pytest

from reactive import kubernetes_control_plane
from charms.layer import kubernetes_common
from charms.layer.kubernetes_common import (
    get_version,
    kubectl,
    configure_kubernetes_service,
    kubectl_manifest,
)
from charms.reactive import endpoint_from_flag, endpoint_from_name, set_state
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


@contextlib.contextmanager
def endpoint_from_flag_reset():
    restore = endpoint_from_flag.side_effect
    endpoint_from_flag.mock_reset()
    yield endpoint_from_flag
    endpoint_from_flag.side_effect = restore


@mock.patch("builtins.open", mock.mock_open())
@mock.patch("os.makedirs", mock.Mock(return_value=0))
def configure_apiserver(
    service_cidr_from_db, service_cidr_from_config, version=(1, 18)
):
    set_flag("leadership.is_leader")
    db = unitdata.kv()
    db.set("kubernetes-master.service-cidr", service_cidr_from_db)
    hookenv.config.return_value = service_cidr_from_config
    get_version.return_value = version

    with endpoint_from_flag_reset() as mock_endpoints:
        etcd, cni, _ = mock_endpoints.side_effect = [
            mock.MagicMock(),  # etcd relation
            mock.MagicMock(),  # cni relation
            True,  # keystone relation exists
        ]
        kubernetes_control_plane.configure_apiserver()

    etcd.get_connection_string.assert_called_once_with()
    return cni


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
    cni = configure_apiserver(None, "10.152.183.0/24")
    cni.set_service_cidr.assert_called_once_with("10.152.183.0/24")
    assert not is_flag_set("kubernetes-control-plane.had-service-cidr-expanded")
    cni = configure_apiserver(None, "10.152.183.0/24,fe80::/120")
    cni.set_service_cidr.assert_called_once_with("10.152.183.0/24,fe80::/120")
    assert not is_flag_set("kubernetes-control-plane.had-service-cidr-expanded")


def test_service_cidr_no_change():
    cni = configure_apiserver("10.152.183.0/24", "10.152.183.0/24")
    cni.set_service_cidr.assert_called_once_with("10.152.183.0/24")
    assert not is_flag_set("kubernetes-control-plane.had-service-cidr-expanded")
    cni = configure_apiserver(
        "10.152.183.0/24,fe80::/120", "10.152.183.0/24,fe80::/120"
    )
    cni.set_service_cidr.assert_called_once_with("10.152.183.0/24,fe80::/120")
    assert not is_flag_set("kubernetes-control-plane.had-service-cidr-expanded")


def test_service_cidr_non_expansion():
    cni = configure_apiserver("10.152.183.0/24", "10.154.183.0/24")
    cni.set_service_cidr.assert_called_once_with("10.152.183.0/24")
    assert not is_flag_set("kubernetes-control-plane.had-service-cidr-expanded")
    cni = configure_apiserver(
        "10.152.183.0/24,fe80::/120", "10.152.183.0/24,fe81::/120"
    )
    cni.set_service_cidr.assert_called_once_with("10.152.183.0/24,fe80::/120")
    assert not is_flag_set("kubernetes-control-plane.had-service-cidr-expanded")


def test_service_cidr_expansion():
    cni = configure_apiserver("10.152.183.0/24", "10.152.0.0/16")
    cni.set_service_cidr.assert_called_once_with("10.152.0.0/16")
    assert is_flag_set("kubernetes-control-plane.had-service-cidr-expanded")
    clear_flag("kubernetes-control-plane.had-service-cidr-expanded")
    cni = configure_apiserver(
        "10.152.183.0/24,fe80::/120", "10.152.183.0/24,fe80::/112"
    )
    cni.set_service_cidr.assert_called_once_with("10.152.183.0/24,fe80::/112")
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


@mock.patch("reactive.kubernetes_control_plane.get_pods")
def test_get_kube_system_pods_not_running(mock_get_pods):
    """Test that get_kube_system_pods_not_running only takes into account pods
    whose phases are not in the allowed list."""
    pods = json.loads(
        """{
  "items": [
    {
      "metadata": {
        "name": "failed-pod"
      },
      "status": {
        "phase": "Failed"
      }
    },
    {
      "metadata": {
        "name": "succeeded-pod"
      },
      "status": {
        "phase": "Succeeded"
      }
    },
    {
      "metadata": {
        "name": "pending-pod"
      },
      "status": {
        "phase": "Pending"
      }
    }
  ]
}"""
    )
    mock_get_pods.return_value = pods
    not_ready = kubernetes_control_plane.get_kube_system_pods_not_running()
    assert "pending-pod" in [pod["metadata"]["name"] for pod in not_ready]


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


@mock.patch("pathlib.Path.exists", mock.Mock(return_value=False))
@mock.patch("pathlib.Path.glob", mock.Mock(return_value=[]))
@mock.patch("pathlib.Path.mkdir", mock.Mock(return_value=0))
def test_ignore_vip():
    kubernetes_control_plane.any_file_changed.return_value = False
    mock_gia = kubernetes_control_plane.get_ingress_address
    mock_gia.return_value = "5.6.7.8"
    hookenv.config.return_value = "1.2.3.4"
    kubernetes_control_plane.register_auth_webhook()
    mock_gia.assert_called_with("kube-api-endpoint", ignore_addresses=["1.2.3.4"])


def test_image_registry_config_changed_on_cni():
    hookenv.config.return_value = "rocks.canonical.com:443/cdk"
    endpoint_from_flag.reset_mock()
    endpoint_from_flag.return_value = cni = mock.MagicMock()
    kubernetes_control_plane.image_registry_changed()
    endpoint_from_flag.assert_called_once_with("cni.available")
    cni.set_image_registry.assert_called_once_with("rocks.canonical.com:443/cdk")

    # Test when CNI is not up yet
    endpoint_from_flag.reset_mock()
    endpoint_from_flag.return_value = cni = None
    hookenv.log.reset_mock()
    kubernetes_control_plane.image_registry_changed()
    endpoint_from_flag.assert_called_once_with("cni.available")
    hookenv.log.assert_called_once_with(
        "CNI endpoint not available yet, waiting to set image registry data"
    )


def test_image_registry_config_changed_on_container_runtime():
    set_flag.reset_mock()
    hookenv.config.return_value = "rocks.canonical.com:443/cdk"
    endpoint_from_flag.reset_mock()
    endpoint_from_flag.return_value = runtime = mock.MagicMock()
    kubernetes_control_plane.configure_registry_location()
    endpoint_from_flag.assert_called_once_with("endpoint.container-runtime.available")
    kubernetes_common.get_sandbox_image_uri.assert_called_once_with(
        "rocks.canonical.com:443/cdk"
    )
    uri = kubernetes_common.get_sandbox_image_uri.return_value
    runtime.set_config.assert_called_once_with(sandbox_image=uri)
    set_flag.assert_called_once_with("kubernetes-control-plane.sent-registry")


def test_image_registry_config_changed_on_kube_control():
    hookenv.config.return_value = "rocks.canonical.com:443/cdk"
    endpoint_from_flag.reset_mock()
    endpoint_from_flag.return_value = kube_control = mock.MagicMock()
    kubernetes_control_plane.send_registry_location()
    endpoint_from_flag.assert_called_once_with("kube-control.connected")
    kube_control.set_registry_location.assert_called_once_with(
        "rocks.canonical.com:443/cdk"
    )

    # Test when kube-control is not connected yet
    endpoint_from_flag.reset_mock()
    endpoint_from_flag.return_value = kube_control = None
    hookenv.log.reset_mock()
    kubernetes_control_plane.send_registry_location()
    endpoint_from_flag.assert_called_once_with("kube-control.connected")
    hookenv.log.assert_called_once_with(
        "kube-control relation currently unavailable, will be retried"
    )


def test_psp_arg_removed_in_1_25():
    configure_kubernetes_service.reset_mock()
    configure_apiserver("10.152.183.0/24", "10.152.183.0/24", (1, 24, 4))
    args = configure_kubernetes_service.call_args[0][2]
    assert (
        args["enable-admission-plugins"]
        == "PersistentVolumeLabel,PodSecurityPolicy,NodeRestriction"
    )

    configure_kubernetes_service.reset_mock()
    configure_apiserver("10.152.183.0/24", "10.152.183.0/24", (1, 25, 0))
    args = configure_kubernetes_service.call_args[0][2]
    assert args["enable-admission-plugins"] == "PersistentVolumeLabel,NodeRestriction"

    configure_kubernetes_service.reset_mock()
    configure_apiserver("10.152.183.0/24", "10.152.183.0/24", (1, 26, 0))
    args = configure_kubernetes_service.call_args[0][2]
    assert args["enable-admission-plugins"] == "PersistentVolumeLabel,NodeRestriction"


def test_psp_config_1_25():
    # With a non-empty psp config in 1.25+ we should be blocked
    get_version.return_value = (1, 25, 0)
    hookenv.config.return_value = "some-psp"
    kubernetes_control_plane.create_pod_security_policy_resources()
    kubectl_manifest.assert_not_called()
    hookenv.status_set.assert_called_with(
        "blocked",
        "PodSecurityPolicy not available in 1.25+,"
        " please remove pod-security-policy config",
    )

    # Try a 2 length tuple
    get_version.return_value = (1, 25)
    hookenv.config.return_value = "some-psp"
    kubernetes_control_plane.create_pod_security_policy_resources()
    kubectl_manifest.assert_not_called()
    hookenv.status_set.assert_called_with(
        "blocked",
        "PodSecurityPolicy not available in 1.25+,"
        " please remove pod-security-policy config",
    )

    # With an empty psp config we should be ok
    hookenv.config.return_value = ""
    kubernetes_control_plane.create_pod_security_policy_resources()
    kubectl_manifest.assert_not_called()
    set_state.assert_called_with("kubernetes-control-plane.pod-security-policy.applied")

    # Test the 1.24 path
    get_version.return_value = (1, 24, 4)
    kubectl_manifest.return_value = True
    hookenv.config.return_value = ""
    kubernetes_control_plane.create_pod_security_policy_resources()
    hookenv.log.assert_called_with("Creating pod security policy resources.")


def test_has_external_cloud_provider():
    clear_flag("external-cloud-provider.changed")

    # Test no external cloud provider
    hookenv.relations.return_value = {"external-cloud-provider": None}
    assert not kubernetes_control_plane.has_external_cloud_provider()

    # Test best external cloud provider
    hookenv.relations.return_value = {"external-cloud-provider": 42}
    assert kubernetes_control_plane.has_external_cloud_provider()
    assert is_flag_set("external-cloud-provider.changed")


def test_handle_xcp_changes():
    # An external-cloud-provider change should set the stage for service re-config
    set_flag("external-cloud-provider.changed")
    set_flag("kubernetes-control-plane.apiserver.configured")
    set_flag("kubernetes-control-plane.kubelet.configured")
    kubernetes_control_plane.handle_xcp_changes()
    assert not is_flag_set("kubernetes-control-plane.kubelet.configured")
    assert not is_flag_set("kubernetes-control-plane.apiserver.configured")
    assert not is_flag_set("external-cloud-provider.changed")


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

    @mock.patch(
        "reactive.kubernetes_control_plane.hookenv.config",
        side_effect=[False, True, "10.152.183.0/24", False],
    )
    def test_ignore_missing_cni(self, mock_config):
        """Test that set_final_status() will block appropriately according to the value of ignore-missing-cni config option"""
        set_flag("certificates.available")
        clear_flag("kubernetes-control-plane.secure-storage.failed")
        set_flag("kube-control.connected")
        set_flag("etcd.available")
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
        set_flag("kube-api-endpoint.available")
        db = unitdata.kv()
        db.set(
            # wokeignore:rule=master
            "kubernetes-master.service-cidr",
            "10.152.183.0/24",
        )  # Force the service cidr provided by the 3rd hookenv.config call to match
        endpoint_from_name.return_value.has_response = True

        clear_flag("cni.available")

        # Test case when cni is not available but relation is present
        hookenv.goal_state.return_value = {
            "relations": {"loadbalancer-internal": None, "cni": None}
        }
        kubernetes_control_plane.set_final_status()
        hookenv.status_set.assert_called_with(
            "waiting",
            "Waiting for CNI plugins to become available",
        )

        # Test case when cni is not available, relation is not present, cni_config does not exist, and ignore-missing-cni config option is False
        # This uses the first hookenv.config side effect
        kubernetes_common.cni_config_exists.return_value = False
        hookenv.goal_state.return_value = {"relations": {"loadbalancer-internal": None}}
        kubernetes_control_plane.set_final_status()
        hookenv.status_set.assert_called_with(
            "blocked",
            "Missing CNI relation or config",
        )

        # Test case when cni is not available, relation is not present, cni_config does not exist, and ignore-missing-cni config option is True
        # This uses the 2nd hookenv.call side effect, and the 3rd and 4th side effecs allow it to fall through to active status
        # This should get us to active status since we provide values for the other 2 config checks that happen in the set_final_status method
        # hookenv.config("service-cidr") followed by hookenv.config("enable-metrics")
        kubernetes_control_plane.set_final_status()
        hookenv.status_set.assert_called_with(
            "active",
            "Kubernetes control-plane running.",
        )
