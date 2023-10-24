"""HACluster integration module."""

import logging
import subprocess
from typing import List, Optional

import ops
from cached_property import cached_property
from interface_hacluster.ops_ha_interface import HAServiceRequires
from ops.framework import Object, StoredState
from ops.model import Relation

log = logging.getLogger(__name__)


class HAClusterConfigMismatchError(Exception):
    """A custom exception to represent a HA cluster config conflict."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class HACluster(Object):
    """A class for integrate HA in the charm."""

    state = StoredState()

    def __init__(self, charm: ops.CharmBase, config, endpoint="ha"):
        super().__init__(charm, f"relation-{endpoint}")
        self.charm = charm
        self.endpoint = endpoint
        self.config = config
        self.interface = HAServiceRequires(self.charm, endpoint)

        self.state.set_default(
            current_services={}, desired_services={}, deleted_services={}, vips=set(), dns=set()
        )

    def _configure_dns(self, dns_records: List[str]):
        binding = self.charm.model.get_binding(self.endpoint)
        address = binding.network.ingress_address
        for dns_record in dns_records:
            self.interface.add_dnsha(self._unit_name, address, dns_record, "public")

        self.state.dns = set(dns_records)

    def _configure_vips(self, vips: List[str]):
        for vip in vips:
            self.interface.add_vip(self._unit_name, vip)
        self.state.vips = set(vips)

    @cached_property
    def _unit_name(self):
        """Return the name of the unit."""
        return self.charm.unit.name.split("/")[0]

    def _update_services(self):
        """Update the systemd services."""
        current_services = self.state.current_services
        deleted_services = self.state.deleted_services
        desired_services = self.state.desired_services

        for name, service in deleted_services.items():
            self.interface.remove_systemd_service(name, service)

        for name, service in desired_services.items():
            self.interface.add_systemd_service(name, service)
            current_services[name] = service

        deleted_services.clear()
        desired_services.clear()

    def add_service(self, name, service_name):
        """Add a service to the desired services in the HA cluster.

        Args:
            name (str): The key name of the service.
            service_name (str): The name of the service to be added.
        """
        current_services = self.state.current_services
        if name not in current_services:
            self.state.desired_services[name] = service_name

    def configure_hacluster(self):
        """Configure the HACluster relation with VIPs of DNS records."""
        vips = self.config.get("ha-cluster-vip").split()
        dns_records = self.config.get("ha-cluster-dns").split()
        if vips and dns_records:
            msg = "Unsupported config. ha-cluster-vip and ha-cluster-dns cannot both be set."
            log.warning(msg)
            raise HAClusterConfigMismatchError(msg)
        if vips:
            self._configure_vips(vips)
        elif dns_records:
            self._configure_dns(dns_records)

        self._update_services()

        self.interface.bind_resources()

    @property
    def is_ready(self):
        """Check if the HACluster integration is ready.

        Returns:
            bool: True if the HACluster relation is ready, False otherwise.
        """
        if self.relation and self.relation.units:
            return True
        return False

    @property
    def relation(self) -> Optional[Relation]:
        """Get the HACluster relation."""
        return self.model.get_relation(self.endpoint)

    def remove_service(self, name, service_name):
        """Remove a service from the desired services in the HA cluster.

        Args:
            name (str): The key name of the service.
            service_name (str): The name of the service to be removed.
        """
        current_services = self.state.current_services
        deleted_services = self.state.deleted_services
        desired_services = self.state.desired_services

        if name in current_services:
            deleted_services[name] = service_name

        if name in desired_services:
            del desired_services[name]

    def set_node_online(self):
        """Set pacemaker node to online."""
        log.info("Setting pacemaker node status to online")
        subprocess.check_call(["crm", "-w", "-F", "node", "online"])

    def set_node_standby(self):
        """Set pacemaker node to standby, forcing VIPs to failover to other nodes."""
        log.warning("Setting pacemaker node status to standby")
        subprocess.check_call(["crm", "-w", "-F", "node", "standby"])

    def update_vips(self):
        """Update the Virtual IP addresses for the HACluster relation."""
        original_vips = self.state.vips
        new_vips = set(self.config.get("ha-cluster-vip").split())
        old_vips = original_vips - new_vips

        for vip in old_vips:
            self.interface.remove_vip(self._unit_name, vip)
