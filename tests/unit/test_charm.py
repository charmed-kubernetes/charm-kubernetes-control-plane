# Copyright 2023 Canonical
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import json
from unittest.mock import patch

import ops
import ops.testing
import pytest
from charm import KubernetesControlPlaneCharm
from ops import ActiveStatus


@pytest.fixture
def harness():
    harness = ops.testing.Harness(KubernetesControlPlaneCharm)
    try:
        harness.add_network("10.0.0.10", endpoint="kube-control")
        yield harness
    finally:
        harness.cleanup()


@patch("auth_webhook.configure")
@patch("auth_webhook.get_token")
@patch("cdk_addons.CdkAddons.get_dns_address")
@patch("charms.interface_kubernetes_cni.hash_file")
@patch("charms.kubernetes_snaps.configure_apiserver")
@patch("charms.kubernetes_snaps.configure_controller_manager")
@patch("charms.kubernetes_snaps.configure_kernel_parameters")
@patch("charms.kubernetes_snaps.configure_kube_proxy")
@patch("charms.kubernetes_snaps.configure_kubelet")
@patch("charms.kubernetes_snaps.configure_scheduler")
@patch("charms.kubernetes_snaps.configure_services_restart_always")
@patch("charms.kubernetes_snaps.create_kubeconfig")
@patch("charms.kubernetes_snaps.get_public_address")
@patch("charms.kubernetes_snaps.install_snap")
@patch("charms.kubernetes_snaps.set_default_cni_conf_file")
@patch("charms.kubernetes_snaps.write_certificates")
@patch("charms.kubernetes_snaps.write_etcd_client_credentials")
@patch("charms.kubernetes_snaps.write_service_account_key")
@patch("charm.KubernetesControlPlaneCharm.install_cni_binaries")
def test_active(
    install_cni_binaries,
    write_service_account_key,
    write_etcd_client_credentials,
    write_certificates,
    set_default_cni_conf_file,
    install_snap,
    get_public_address,
    create_kubeconfig,
    configure_services_restart_always,
    configure_scheduler,
    configure_kubelet,
    configure_kube_proxy,
    configure_kernel_parameters,
    configure_controller_manager,
    configure_apiserver,
    hash_file,
    get_dns_address,
    auth_webhook_get_token,
    auth_webhook_configure,
    harness,
):
    get_dns_address.return_value = "10.152.183.10"
    get_public_address.return_value = "10.0.0.10"
    hash_file.return_value = "test-hash"

    certificates_relation_id = harness.add_relation("certificates", "easyrsa")
    cni_relation_id = harness.add_relation("cni", "calico")
    container_runtime_relation_id = harness.add_relation("container-runtime", "containerd")
    etcd_relation_id = harness.add_relation("etcd", "etcd")
    peer_relation_id = harness.add_relation("peer", "kubernetes-control-plane")

    harness.add_relation_unit(certificates_relation_id, "easyrsa/0")
    harness.add_relation_unit(cni_relation_id, "calico/0")
    harness.add_relation_unit(container_runtime_relation_id, "containerd/0")
    harness.add_relation_unit(etcd_relation_id, "etcd/0")

    harness.update_relation_data(
        peer_relation_id,
        "kubernetes-control-plane",
        {"service-account-key": "test-service-account-key", "cluster-name": "test-cluster-name"},
    )
    harness.update_relation_data(
        certificates_relation_id,
        "easyrsa/0",
        {
            "ca": "test-ca",
            "client.cert": "test-client-cert-default",
            "client.key": "test-client-key-default",
            "kubernetes-control-plane_0.server.key": "test-server-key",
            "kubernetes-control-plane_0.server.cert": "test-server-cert",
            "kubernetes-control-plane_0.processed_client_requests": json.dumps(
                {
                    "system:kube-apiserver": {
                        "cert": "test-client-cert-apiserver",
                        "key": "test-client-key-apiserver",
                    }
                }
            ),
        },
    )
    harness.update_relation_data(
        cni_relation_id,
        "calico/0",
        {"cidr": "192.168.0.0/16", "cni-conf-file": "10-calico.conflist"},
    )
    harness.update_relation_data(
        container_runtime_relation_id, "containerd/0", {"socket": "test-container-runtime-socket"}
    )
    harness.update_relation_data(
        etcd_relation_id,
        "etcd/0",
        {
            "client_ca": "test-etcd-ca",
            "client_cert": "test-etcd-client-cert",
            "client_key": "test-etcd-client-key",
            "connection_string": "https://10.0.0.11:2379",
        },
    )

    harness.begin()
    harness.charm.on.config_changed.emit()

    assert harness.model.unit.status == ActiveStatus()

    auth_webhook_configure.assert_called_once_with(
        charm_dir=harness.charm.charm_dir, custom_authn_endpoint=""
    )
    configure_apiserver.assert_called_once_with(
        advertise_address="10.0.0.10",
        audit_policy=harness.charm.model.config["audit-policy"],
        audit_webhook_conf=harness.charm.model.config["audit-webhook-config"],
        auth_webhook_conf="/root/cdk/auth-webhook/auth-webhook-conf.yaml",
        authorization_mode="Node,RBAC",
        cluster_cidr="192.168.0.0/16",
        etcd_connection_string="https://10.0.0.11:2379",
        extra_args_config="",
        privileged="auto",
        service_cidr="10.152.183.0/24",
        external_cloud_provider=harness.charm.external_cloud_provider,
    )
    configure_controller_manager.assert_called_once_with(
        cluster_cidr="192.168.0.0/16",
        cluster_name="test-cluster-name",
        extra_args_config="",
        kubeconfig="/root/cdk/kubecontrollermanagerconfig",
        service_cidr="10.152.183.0/24",
        external_cloud_provider=harness.charm.external_cloud_provider,
    )
    configure_kernel_parameters.assert_called_once_with(
        {
            "net.ipv4.conf.all.forwarding": 1,
            "net.ipv4.conf.all.rp_filter": 1,
            "net.ipv4.neigh.default.gc_thresh1": 128,
            "net.ipv4.neigh.default.gc_thresh2": 28672,
            "net.ipv4.neigh.default.gc_thresh3": 32768,
            "net.ipv6.neigh.default.gc_thresh1": 128,
            "net.ipv6.neigh.default.gc_thresh2": 28672,
            "net.ipv6.neigh.default.gc_thresh3": 32768,
            "fs.inotify.max_user_instances": 8192,
            "fs.inotify.max_user_watches": 1048576,
            "kernel.panic": 10,
            "kernel.panic_on_oops": 1,
            "vm.overcommit_memory": 1,
        }
    )
    configure_kubelet.assert_called_once_with(
        container_runtime_endpoint="test-container-runtime-socket",
        dns_domain="cluster.local",
        dns_ip="10.152.183.10",
        extra_args_config="",
        extra_config={},
        external_cloud_provider=harness.charm.external_cloud_provider,
        kubeconfig="/root/cdk/kubeconfig",
        node_ip="10.0.0.10",
        registry="rocks.canonical.com:443/cdk",
        taints=["node-role.kubernetes.io/control-plane:NoSchedule"],
    )
    configure_kube_proxy.assert_called_once_with(
        cluster_cidr="192.168.0.0/16",
        extra_args_config="",
        extra_config={},
        kubeconfig="/root/cdk/kubeproxyconfig",
        external_cloud_provider=harness.charm.external_cloud_provider,
    )
    configure_scheduler.assert_called_once_with(
        extra_args_config="", kubeconfig="/root/cdk/kubeschedulerconfig"
    )
    configure_services_restart_always.assert_called_once_with(control_plane=True)
    create_kubeconfig.assert_called()
    install_snap.assert_called()
    install_cni_binaries.assert_called()
    set_default_cni_conf_file.assert_called_once_with("10-calico.conflist")
    write_certificates.assert_called_once_with(
        ca="test-ca",
        client_cert="test-client-cert-apiserver",
        client_key="test-client-key-apiserver",
        server_cert="test-server-cert",
        server_key="test-server-key",
    )
    write_etcd_client_credentials.assert_called_once_with(
        ca="test-etcd-ca", cert="test-etcd-client-cert", key="test-etcd-client-key"
    )
    write_service_account_key.assert_called_once_with("test-service-account-key")
