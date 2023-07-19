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
from ops import ActiveStatus, BlockedStatus, WaitingStatus


@pytest.fixture
def harness():
    harness = ops.testing.Harness(KubernetesControlPlaneCharm)
    try:
        harness.add_network("10.0.0.10", endpoint="kube-control")
        yield harness
    finally:
        harness.cleanup()


@patch("charms.kubernetes_snaps.get_public_address")
@patch("charms.kubernetes_snaps.install")
def test_missing_certificate_authority(snaps_install, get_public_address, harness):
    get_public_address.return_value = "10.0.0.10"

    harness.begin_with_initial_hooks()

    assert snaps_install.called
    assert harness.model.unit.status == BlockedStatus("Missing relation to certificate authority")


@patch("charms.kubernetes_snaps.get_public_address")
@patch("charms.kubernetes_snaps.install")
def test_waiting_for_certificates(kubernetes_snaps_install, get_public_address, harness):
    get_public_address.return_value = "10.0.0.10"
    certificates_relation_id = harness.add_relation("certificates", "easyrsa")

    harness.begin()
    harness.add_relation_unit(certificates_relation_id, "easyrsa/0")

    assert harness.model.unit.status == WaitingStatus("Waiting for certificates")


@patch("charms.kubernetes_snaps.write_certificates")
@patch("charms.kubernetes_snaps.get_public_address")
@patch("charms.kubernetes_snaps.install")
def test_active(kubernetes_snaps_install, get_public_address, write_certificates, harness):
    get_public_address.return_value = "10.0.0.10"
    certificates_relation_id = harness.add_relation("certificates", "easyrsa")
    harness.add_relation_unit(certificates_relation_id, "easyrsa/0")

    harness.begin()
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

    assert write_certificates.called_once_with(
        ca="test-ca",
        client_cert="test-client-cert-apiserver",
        client_key="test-client-key-apiserver",
        server_cert="test-server-cert",
        server_key="test-server-key",
    )
    assert harness.model.unit.status == ActiveStatus()
