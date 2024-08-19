import unittest.mock as mock

import ops
import pytest

from charm import KubernetesControlPlaneCharm


@pytest.fixture()
def harness():
    harness = ops.testing.Harness(KubernetesControlPlaneCharm)
    harness.begin()
    with mock.patch.object(harness.charm, "get_cloud_name"):
        with mock.patch.object(harness.charm, "get_cluster_name", return_value="my-cluster"):
            yield harness


@pytest.mark.parametrize(
    "cloud_name, cloud_relation",
    [
        ("aws", "aws"),
        ("gce", "gcp"),
        ("azure", "azure"),
        ("unknown", None),
    ],
)
def test_cloud_detection(harness, cloud_name, cloud_relation):
    # Test that the cloud property returns the correct integration requires object
    harness.charm.get_cloud_name.return_value = cloud_name
    integration = harness.charm.cloud_integration
    assert integration.cloud is None
    if cloud_name != "unknown":
        harness.add_relation(cloud_relation, "cloud-integrator")
        assert integration.cloud


def test_cloud_aws(harness):
    # Test that the cloud property returns the correct integration requires object
    harness.charm.get_cloud_name.return_value = "aws"
    # with mock.patch.object(harness.charm.cloud_integration, "cloud", callable=mock.PropertyMock) as mock_cloud:
    with mock.patch(
        "cloud_integration.CloudIntegration.cloud", callable=mock.PropertyMock
    ) as mock_cloud:
        mock_cloud.evaluate_relation.return_value = None
        event = mock.MagicMock()
        harness.charm.cloud_integration.integrate(event)
        mock_cloud.tag_instance.assert_called_once_with(
            {
                "kubernetes.io/cluster/my-cluster": "owned",
                "k8s.io/role/master": "true",  # wokeignore:rule=master
            }
        )
        mock_cloud.tag_instance_security_group.assert_called_once_with(
            {"kubernetes.io/cluster/my-cluster": "owned"}
        )
        mock_cloud.tag_instance_subnet.assert_called_once_with(
            {"kubernetes.io/cluster/my-cluster": "owned"}
        )
        mock_cloud.enable_object_storage_management.assert_called_once_with(["kubernetes-*"])
        mock_cloud.enable_load_balancer_management.assert_called_once()
        mock_cloud.enable_autoscaling_readonly.assert_called_once()
        mock_cloud.enable_instance_modification.assert_called_once()
        mock_cloud.enable_region_readonly.assert_called_once()
        mock_cloud.enable_instance_inspection.assert_called_once()
        mock_cloud.enable_network_management.assert_called_once()
        mock_cloud.enable_dns_management.assert_called_once()
        mock_cloud.enable_block_storage_management.assert_called_once()
        mock_cloud.evaluate_relation.assert_called_once_with(event)


def test_cloud_gce(harness):
    # Test that the cloud property returns the correct integration requires object
    harness.charm.get_cloud_name.return_value = "gce"
    with mock.patch(
        "cloud_integration.CloudIntegration.cloud", callable=mock.PropertyMock
    ) as mock_cloud:
        mock_cloud.evaluate_relation.return_value = None
        event = mock.MagicMock()
        harness.charm.cloud_integration.integrate(event)
        mock_cloud.tag_instance.assert_called_once_with(
            {
                "k8s-io-cluster-name": "my-cluster",
                "k8s-io-role-master": "master",  # wokeignore:rule=master
            }
        )
        mock_cloud.enable_object_storage_management.assert_called_once()
        mock_cloud.enable_security_management.assert_called_once()
        mock_cloud.enable_instance_inspection.assert_called_once()
        mock_cloud.enable_network_management.assert_called_once()
        mock_cloud.enable_dns_management.assert_called_once()
        mock_cloud.enable_block_storage_management.assert_called_once()
        mock_cloud.evaluate_relation.assert_called_once_with(event)


def test_cloud_azure(harness):
    # Test that the cloud property returns the correct integration requires object
    harness.charm.get_cloud_name.return_value = "azure"
    with mock.patch(
        "cloud_integration.CloudIntegration.cloud", callable=mock.PropertyMock
    ) as mock_cloud:
        mock_cloud.evaluate_relation.return_value = None
        event = mock.MagicMock()
        harness.charm.cloud_integration.integrate(event)
        mock_cloud.tag_instance.assert_called_once_with(
            {
                "k8s-io-cluster-name": "my-cluster",
                "k8s-io-role-master": "master",  # wokeignore:rule=master
            }
        )
        mock_cloud.enable_object_storage_management.assert_called_once()
        mock_cloud.enable_security_management.assert_called_once()
        mock_cloud.enable_loadbalancer_management.assert_called_once()
        mock_cloud.enable_instance_inspection.assert_called_once()
        mock_cloud.enable_network_management.assert_called_once()
        mock_cloud.enable_dns_management.assert_called_once()
        mock_cloud.enable_block_storage_management.assert_called_once()
        mock_cloud.evaluate_relation.assert_called_once_with(event)


def test_cloud_unknown(harness):
    # Test that the cloud property returns the correct integration requires object
    harness.charm.get_cloud_name.return_value = "unknown"
    with mock.patch(
        "cloud_integration.CloudIntegration.cloud", new_callable=mock.PropertyMock
    ) as mock_cloud:
        mock_cloud.return_value = None
        event = mock.MagicMock()
        harness.charm.cloud_integration.integrate(event)
        assert mock_cloud.called
