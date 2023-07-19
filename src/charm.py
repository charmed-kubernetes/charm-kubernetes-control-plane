#!/usr/bin/env python3
# Copyright 2023 Canonical
# See LICENSE file for licensing details.

"""Charm."""

import logging
import socket

import charms.contextual_status as status
import ops
from charms import kubernetes_snaps
from charms.reconciler import Reconciler
from ops import BlockedStatus, WaitingStatus
from ops.interface_tls_certificates import CertificatesRequires

log = logging.getLogger(__name__)


class KubernetesControlPlaneCharm(ops.CharmBase):
    """Charm."""

    def __init__(self, *args):
        super().__init__(*args)
        self.certificates = CertificatesRequires(self, endpoint="certificates")
        self.reconciler = Reconciler(self, self.reconcile)

    def reconcile(self, event):
        """Reconcile state change events."""
        kubernetes_snaps.install(channel=self.model.config["channel"], control_plane=True)
        self.request_certificates()
        self.write_certificates()

    def request_certificates(self):
        """Request client and server certificates."""
        if not self.certificates.relation:
            status.add(BlockedStatus("Missing relation to certificate authority"))
            return

        bind_addrs = kubernetes_snaps.get_bind_addresses()
        common_name = kubernetes_snaps.get_public_address()
        domain = self.config["dns_domain"]
        extra_sans = self.config["extra_sans"].split()
        k8s_service_addrs = kubernetes_snaps.get_kubernetes_service_addresses(
            self.config["service-cidr"].split(",")
        )
        ingress_addrs = [
            # RFC 5280 section 4.2.1.6: "For IP version 6 ... the octet string
            # MUST contain exactly sixteen octets." We'll use .exploded to be
            # safe.
            addr.exploded
            for addr in self.model.get_binding("kube-control").network.ingress_addresses
        ]

        sans = [
            # The CN field is checked as a hostname, so if it's an IP, it
            # won't match unless also included in the SANs as an IP field.
            common_name,
            "127.0.0.1",
            socket.gethostname(),
            socket.getfqdn(),
            "kubernetes",
            f"kubernetes.{domain}",
            "kubernetes.default",
            "kubernetes.default.svc",
            f"kubernetes.default.svc.{domain}",
        ]
        sans += bind_addrs
        sans += ingress_addrs
        sans += k8s_service_addrs
        sans += extra_sans
        sans = list(set(sans))

        self.certificates.request_client_cert("system:kube-apiserver")
        self.certificates.request_server_cert(cn=common_name, sans=sans)

    def write_certificates(self):
        """Write certificates from the certificates relation."""
        common_name = kubernetes_snaps.get_public_address()
        ca = self.certificates.ca
        client_cert = self.certificates.client_certs_map.get("system:kube-apiserver")
        server_cert = self.certificates.server_certs_map.get(common_name)

        if not ca or not client_cert or not server_cert:
            status.add(WaitingStatus("Waiting for certificates"))
            return

        kubernetes_snaps.write_certificates(
            ca=ca,
            client_cert=client_cert.cert,
            client_key=client_cert.key,
            server_cert=server_cert.cert,
            server_key=server_cert.key,
        )


if __name__ == "__main__":  # pragma: nocover
    ops.main(KubernetesControlPlaneCharm)
