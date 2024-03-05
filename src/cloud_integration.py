# Copyright 2024 Canonical
# See LICENSE file for licensing details.

"""Cloud Integration for Charmed Kubernetes Control Plane."""

import logging
from typing import Union

import charms.contextual_status as status
import ops
from ops.interface_aws.requires import AWSIntegrationRequires
from ops.interface_gcp.requires import GCPIntegrationRequires

log = logging.getLogger(__name__)


class CloudIntegration:
    """Utility class that handles the integration with clouds for Charmed Kubernetes.

    This class provides methods to configure instance tags and roles for control-plane
    units

    Attributes:
        charm (CharmBase): Reference to the base charm instance.
        aws (AWSIntegrationRequires): Reference to relation integration
        gcp (GCPIntegrationRequires): Reference to relation integration
        azure (AzureIntegrationRequires): Reference to relation integration
    """

    def __init__(self, charm: ops.CharmBase) -> None:
        """Integrate with all possible clouds."""
        self.charm = charm
        self.aws = AWSIntegrationRequires(charm)
        self.gcp = GCPIntegrationRequires(charm)
        self.azure = None  # AzureIntegrationRequires(charm)

    @property
    def cloud(self) -> Union[None, AWSIntegrationRequires, GCPIntegrationRequires]:
        """Determine if we're integrated with a known cloud."""
        cloud_name = self.charm.get_cloud_name()
        cloud_support = {
            "aws": self.aws,
            "gce": self.gcp,
        }
        if not (cloud := cloud_support.get(cloud_name)):
            log.error("Skipping Cloud integration: unsupported cloud %s", cloud_name)
            return

        if not cloud.relation:
            log.info(
                "Skipping Cloud integration: Needs an active %s relation to integrate.", cloud_name
            )
            return
        return cloud

    @status.on_error(ops.WaitingStatus("Waiting for cloud-integration"))
    def integrate(self, event: ops.EventBase):
        """Request tags and permissions for a control-plane node."""
        if not (cloud := self.cloud):
            return None

        cloud_name = self.charm.get_cloud_name()
        cluster_tag = self.charm.get_cluster_name()

        status.add(ops.MaintenanceStatus(f"Integrate with {cloud_name}"))
        if cloud_name == "aws":
            aws_cluster_tag = {f"kubernetes.io/cluster/{cluster_tag}": "owned"}
            # wokeignore:rule=master
            cloud.tag_instance(aws_cluster_tag | {"k8s.io/role/master": "true"})
            cloud.tag_instance_security_group(aws_cluster_tag)
            cloud.tag_instance_subnet(aws_cluster_tag)
            cloud.enable_object_storage_management(["kubernetes-*"])
            cloud.enable_load_balancer_management()

            # Necessary for cloud-provider-aws
            cloud.enable_autoscaling_readonly()
            cloud.enable_instance_modification()
            cloud.enable_region_readonly()
        elif cloud_name == "gce":
            cloud.tag_instance(
                {
                    "k8s-io-cluster-name": cluster_tag,
                    "k8s-io-role-master": "master",  # wokeignore:rule=master
                }
            )
            cloud.enable_object_storage_management()
            cloud.enable_security_management()
        elif cloud_name == "azure":
            cloud.tag_instance(
                {
                    "k8s-io-cluster-name": cluster_tag,
                    "k8s-io-role-master": "master",  # wokeignore:rule=master
                }
            )
            cloud.enable_object_storage_management()
            cloud.enable_security_management()
            cloud.enable_loadbalancer_management()
        cloud.enable_instance_inspection()
        cloud.enable_network_management()
        cloud.enable_dns_management()
        cloud.enable_block_storage_management()
        assert cloud.evaluate_relation(event) is None
