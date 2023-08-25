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
@patch("charms.kubernetes_snaps.configure_apiserver")
@patch("charms.kubernetes_snaps.configure_controller_manager")
@patch("charms.kubernetes_snaps.configure_scheduler")
@patch("charms.kubernetes_snaps.configure_services_restart_always")
@patch("charms.kubernetes_snaps.create_kubeconfig")
@patch("charms.kubernetes_snaps.get_public_address")
@patch("charms.kubernetes_snaps.install_snap")
@patch("charms.kubernetes_snaps.write_certificates")
@patch("charms.kubernetes_snaps.write_etcd_client_credentials")
@patch("charms.kubernetes_snaps.write_service_account_key")
def test_active(
    write_service_account_key,
    write_etcd_client_credentials,
    write_certificates,
    install_snap,
    get_public_address,
    create_kubeconfig,
    configure_services_restart_always,
    configure_scheduler,
    configure_controller_manager,
    configure_apiserver,
    auth_webhook_get_token,
    auth_webhook_configure,
    harness,
):
    get_public_address.return_value = "10.0.0.10"

    certificates_relation_id = harness.add_relation("certificates", "easyrsa")
    etcd_relation_id = harness.add_relation("etcd", "etcd")
    peer_relation_id = harness.add_relation("peer", "kubernetes-control-plane")

    harness.add_relation_unit(certificates_relation_id, "easyrsa/0")
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
        cluster_cidr=None,
        etcd_connection_string="https://10.0.0.11:2379",
        extra_args_config="",
        privileged="auto",
        service_cidr="10.152.183.0/24",
    )
    configure_controller_manager.assert_called_once_with(
        cluster_cidr=None,
        cluster_name="test-cluster-name",
        extra_args_config="",
        kubeconfig="/root/cdk/kubecontrollermanagerconfig",
        service_cidr="10.152.183.0/24",
    )
    configure_scheduler.assert_called_once_with(
        extra_args_config="", kubeconfig="/root/cdk/kubeschedulerconfig"
    )
    configure_services_restart_always.assert_called_once_with(control_plane=True)
    create_kubeconfig.assert_called()
    install_snap.assert_called()
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
