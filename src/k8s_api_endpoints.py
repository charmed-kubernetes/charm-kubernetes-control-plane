from ipaddress import ip_address
from typing import Optional

from charms import kubernetes_snaps


class K8sApiEndpoints:
    """Kubernetes API endpoints for this charm."""

    def __init__(self, charm):
        self.charm = charm

    def from_config(self) -> Optional[str]:
        """Endpoint URL from charm configuration.

        Usually an IP address. Could be a domain name.

        If the loadbalancer-ips config option is set, use that first.

        Otherwise, if we are integrated with hacluster, then build an endpoint
        from the ha-cluster-vip or ha-cluster-dns configs.
        """
        addresses = self.charm.config["loadbalancer-ips"].split()
        if addresses:
            return build_url(addresses[0], 6443)

        if self.charm.hacluster.is_ready:
            for key in ["ha-cluster-vip", "ha-cluster-dns"]:
                addresses = self.charm.config[key].split()
                if addresses:
                    return build_url(addresses[0], 6443)

    def get_external_api_endpoint(self) -> Optional[str]:
        response = self.charm.lb_external.get_response("api-server-external")
        if not response or response.error:
            return None
        return response.address

    def get_internal_api_endpoint(self) -> Optional[str]:
        response = self.charm.lb_external.get_response("api-server-internal")
        if not response or response.error:
            return None
        return response.address

    def from_lb_external(self) -> Optional[str]:
        """Endpoint URL from the loadbalancer-external relation."""
        ep = self.get_external_api_endpoint()
        return ep and build_url(ep, 443)

    def from_lb_internal(self) -> Optional[str]:
        """Endpoint URL from the loadbalancer-internal relation."""
        ep = self.get_internal_api_endpoint()
        return ep and build_url(ep, 6443)

    def from_public_address(self) -> str:
        """Endpoint URL from unit-get public-address."""
        return build_url(kubernetes_snaps.get_public_address(), 6443)

    def from_ingress_address(self) -> str:
        """Endpoint URL from kube-control ingress addresses."""
        return build_url(self.charm.kube_control.ingress_addresses[0], 6443)

    def external(self) -> str:
        """External or public endpoint URL.

        Should be reachable by users outside of the cluster.
        """
        return (
            self.from_config()
            or self.from_lb_external()
            or self.from_lb_internal()
            or self.from_public_address()
        )

    def internal(self) -> str:
        """Return internal endpoint URL.

        Should be reachable by other machines in the cluster. Usually IP
        addresses, but could sometimes be domain names.
        """
        return (
            self.from_config()
            or self.from_lb_internal()
            or self.from_lb_external()
            or self.from_ingress_address()
        )

    def local(self) -> str:
        """Local endpoint URL. Only reachable from the local machine."""
        return build_url("127.0.0.1", 6443)


def build_url(address, port):
    if is_ipv6_address(address):
        return f"https://[{address}]:{port}"
    else:
        return f"https://{address}:{port}"


def is_ipv6_address(address):
    try:
        address = ip_address(address)
        return address.version == 6
    except ValueError:
        return False
