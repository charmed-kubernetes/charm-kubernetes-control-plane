#!/usr/bin/env python3
# Copyright 2023 Canonical
# See LICENSE file for licensing details.

"""Charmed Machine Operator for Kubernetes Control Plane."""

import logging
import os
import re
import shlex
import socket
import subprocess
from pathlib import Path
from subprocess import CalledProcessError

import auth_webhook
import charms.contextual_status as status
import leader_data
import ops
import tenacity
import yaml
from cdk_addons import CdkAddons
from charms import kubernetes_snaps
from charms.grafana_agent.v0.cos_agent import COSAgentProvider
from charms.interface_container_runtime import ContainerRuntimeProvides
from charms.interface_external_cloud_provider import ExternalCloudProvider
from charms.interface_kube_dns import KubeDnsRequires
from charms.interface_kubernetes_cni import KubernetesCniProvides
from charms.interface_tokens import TokensProvider
from charms.kubernetes_libs.v0.etcd import EtcdReactiveRequires
from charms.node_base import LabelMaker
from charms.reconciler import Reconciler
from cos_integration import COSIntegration
from hacluster import HACluster
from k8s_api_endpoints import K8sApiEndpoints
from k8s_kube_system import get_kube_system_pods_not_running
from kubectl import kubectl
from loadbalancer_interface import LBProvider
from ops.interface_kube_control import KubeControlProvides
from ops.interface_tls_certificates import CertificatesRequires

log = logging.getLogger(__name__)

OBSERVABILITY_ROLE = "system:cos"


class KubernetesControlPlaneCharm(ops.CharmBase):
    """Charmed Operator for Kubernetes Control Plane."""

    def __init__(self, *args):
        super().__init__(*args)
        self.cdk_addons = CdkAddons(self)
        self.certificates = CertificatesRequires(self, endpoint="certificates")
        self.cni = KubernetesCniProvides(
            self, endpoint="cni", default_cni=self.model.config["default-cni"]
        )
        self.container_runtime = ContainerRuntimeProvides(self, endpoint="container-runtime")
        self.cos_integration = COSIntegration(self)
        self.cos_agent = COSAgentProvider(
            self,
            relation_name="cos-agent",
            scrape_configs=self.cos_integration.get_metrics_endpoints,
            refresh_events=[
                self.on.peer_relation_changed,
                self.on.upgrade_charm,
            ],
        )
        self.etcd = EtcdReactiveRequires(self)
        self.node_base = LabelMaker(self, kubeconfig_path="/root/.kube/config")
        self.hacluster = HACluster(self, self.config)
        self.k8s_api_endpoints = K8sApiEndpoints(self)
        self.kube_control = KubeControlProvides(self, endpoint="kube-control")
        self.kube_dns = KubeDnsRequires(self, endpoint="dns-provider")
        self.lb_external = LBProvider(self, "loadbalancer-external")
        self.lb_internal = LBProvider(self, "loadbalancer-internal")
        self.external_cloud_provider = ExternalCloudProvider(self, "external-cloud-provider")
        self.reconciler = Reconciler(self, self.reconcile)
        self.tokens = TokensProvider(self, endpoint="tokens")
        self.framework.observe(self.on.update_status, self.update_status)

        self.framework.observe(self.on.upgrade_action, self.on_upgrade_action)

    @status.on_error(ops.WaitingStatus("Waiting on valid ceritifcate data"))
    def api_dependencies_ready(self):
        common_name = kubernetes_snaps.get_public_address()
        ca = self.certificates.ca
        client_cert = self.certificates.client_certs_map.get("system:kube-apiserver")
        server_cert = self.certificates.server_certs_map.get(common_name)
        assert ca, "CA Certificate not ready"
        assert client_cert, "Client Cert not ready"
        assert server_cert, "Server Cert not ready"

        return True

    def configure_apiserver(self):
        status.add(ops.MaintenanceStatus("Configuring API Server"))
        kubernetes_snaps.configure_apiserver(
            advertise_address=self.kube_control.ingress_addresses[0],
            audit_policy=self.model.config["audit-policy"],
            audit_webhook_conf=self.model.config["audit-webhook-config"],
            auth_webhook_conf=auth_webhook.auth_webhook_conf,
            authorization_mode=self.model.config["authorization-mode"],
            cluster_cidr=self.cni.cidr,
            etcd_connection_string=self.etcd.get_connection_string(),
            extra_args_config=self.model.config["api-extra-args"],
            privileged=self.model.config["allow-privileged"],
            service_cidr=self.model.config["service-cidr"],
            external_cloud_provider=self.external_cloud_provider,
        )

    def configure_apiserver_kubelet_api_admin(self):
        status.add(ops.MaintenanceStatus("Configuring API Server kubelet admin"))
        kubectl("apply", "-f", "templates/apiserver-kubelet-api-admin.yaml")

    def configure_auth_webhook(self):
        auth_webhook.configure(
            charm_dir=self.charm_dir,
            custom_authn_endpoint=self.model.config["authn-webhook-endpoint"],
            # TODO: aws iam, keystone
            # aws_iam_endpoint=???,
            # keystone_endpoint=???
        )

    @status.on_error(ops.WaitingStatus("Waiting for container runtime"))
    def configure_container_runtime(self):
        assert self.container_runtime.relations, "Missing container-runtime integration"
        status.add(ops.MaintenanceStatus("Configuring CRI"))
        registry = self.model.config["image-registry"]
        sandbox_image = kubernetes_snaps.get_sandbox_image(registry)
        self.container_runtime.set_sandbox_image(sandbox_image)

    def configure_cni(self):
        status.add(ops.MaintenanceStatus("Configuring CNI"))
        self.cni.set_image_registry(self.model.config["image-registry"])
        self.cni.set_kubeconfig_hash_from_file("/root/.kube/config")
        self.cni.set_service_cidr(self.model.config["service-cidr"])
        kubernetes_snaps.set_default_cni_conf_file(self.cni.cni_conf_file)

    def configure_controller_manager(self):
        cluster_name = self.get_cluster_name()
        if not cluster_name:
            status.add(ops.WaitingStatus("Waiting for cluster name"))
            return

        status.add(ops.MaintenanceStatus("Configuring Controller Manager"))
        kubernetes_snaps.configure_controller_manager(
            cluster_cidr=self.cni.cidr,
            cluster_name=cluster_name,
            extra_args_config=self.model.config["controller-manager-extra-args"],
            kubeconfig="/root/cdk/kubecontrollermanagerconfig",
            service_cidr=self.model.config["service-cidr"],
            external_cloud_provider=self.external_cloud_provider,
        )

    def configure_hacluster(self):
        if self.hacluster.is_ready:
            status.add(ops.MaintenanceStatus("Configuring HACluster"))
            self.hacluster.update_vips()
            self.hacluster.configure_hacluster()
            # Note that we do not register any systemd services with HACluster.
            # We used to register the Kubernetes control plane services, but
            # that meant Pacemaker would take over managing the services, and
            # often would not start them when it should. Long history of bugs
            # there.

    def configure_kernel_parameters(self):
        status.add(ops.MaintenanceStatus("Configuring Kernel Params"))
        sysctl = yaml.safe_load(self.model.config["sysctl"])
        kubernetes_snaps.configure_kernel_parameters(sysctl)

    def configure_kube_control(self):
        status.add(ops.MaintenanceStatus("Configuring Kube Control"))
        dns_address = self.get_dns_address()
        dns_domain = self.get_dns_domain()
        dns_enabled = bool(dns_address)
        dns_port = self.get_dns_port()

        self.kube_control.set_api_endpoints([self.k8s_api_endpoints.internal()])
        self.kube_control.set_cluster_name(self.get_cluster_name())
        self.kube_control.set_default_cni(self.model.config["default-cni"])
        self.kube_control.set_dns_address(dns_address)
        self.kube_control.set_dns_domain(dns_domain)
        self.kube_control.set_dns_enabled(dns_enabled)
        self.kube_control.set_dns_port(dns_port)
        self.kube_control.set_has_external_cloud_provider(self.external_cloud_provider.has_xcp)
        self.kube_control.set_image_registry(self.model.config["image-registry"])
        self.kube_control.set_labels(self.model.config["labels"].split())
        self.kube_control.set_taints(self.model.config["register-with-taints"].split())

        if self.unit.is_leader():
            client_token = auth_webhook.get_token("admin")
            proxy_token = auth_webhook.get_token("system:kube-proxy")

            for request in self.kube_control.auth_requests:
                kubelet_token = auth_webhook.create_token(
                    uid=request.unit, username=request.user, groups=[request.group]
                )
                self.kube_control.sign_auth_request(
                    request,
                    client_token=client_token,
                    kubelet_token=kubelet_token,
                    proxy_token=proxy_token,
                )
        else:
            self.kube_control.clear_creds()

    def configure_kube_proxy(self):
        status.add(ops.MaintenanceStatus("Configuring Kube Proxy"))
        kubernetes_snaps.configure_kube_proxy(
            cluster_cidr=self.cni.cidr,
            extra_args_config=self.model.config["proxy-extra-args"],
            extra_config=yaml.safe_load(self.model.config["proxy-extra-config"]),
            kubeconfig="/root/cdk/kubeproxyconfig",
            external_cloud_provider=self.external_cloud_provider,
        )

    def configure_kubelet(self):
        status.add(ops.MaintenanceStatus("Configuring Kubelet"))
        kubernetes_snaps.configure_kubelet(
            container_runtime_endpoint=self.container_runtime.socket,
            dns_domain=self.get_dns_domain(),
            dns_ip=self.get_dns_address(),
            extra_args_config=self.model.config["kubelet-extra-args"],
            extra_config=yaml.safe_load(self.model.config["kubelet-extra-config"]),
            external_cloud_provider=self.external_cloud_provider,
            kubeconfig="/root/cdk/kubeconfig",
            node_ip=self.kube_control.ingress_addresses[0],
            registry=self.model.config["image-registry"],
            taints=self.model.config["register-with-taints"].split(),
        )

    def configure_loadbalancers(self):
        if not self.unit.is_leader():
            return

        def check_status(endpoint, ep_name):
            if not endpoint.has_response:
                status.add(ops.WaitingStatus(f"Waiting for {ep_name}"))
            elif resp := endpoint.get_response("api-server-external"):
                if resp and resp.error:
                    status.add(ops.BlockedStatus(f"Blocked by {ep_name}"))

        status.add(ops.MaintenanceStatus("Configuring LoadBalancers"))
        if self.lb_external.is_available:
            req = self.lb_external.get_request("api-server-external")
            req.protocol = req.protocols.tcp
            req.port_mapping = {443: 6443}
            req.public = True
            if not req.health_checks:
                req.add_health_check(protocol=req.protocols.http, port=6443, path="/livez")
            self.lb_external.send_request(req)
            check_status(self.lb_external, "loadbalancer-external")

        if self.lb_internal.is_available:
            req = self.lb_internal.get_request("api-server-internal")
            req.protocol = req.protocols.tcp
            req.port_mapping = {6443: 6443}
            req.public = False
            if not req.health_checks:
                req.add_health_check(protocol=req.protocols.http, port=6443, path="/livez")
            self.lb_internal.send_request(req)

            check_status(self.lb_internal, "loadbalancer-internal")

    def configure_scheduler(self):
        status.add(ops.MaintenanceStatus("Configuring Scheduler"))
        kubernetes_snaps.configure_scheduler(
            extra_args_config=self.model.config["scheduler-extra-args"],
            kubeconfig="/root/cdk/kubeschedulerconfig",
        )

    @status.on_error(ops.WaitingStatus("Waiting for Auth Tokens"), tenacity.RetryError)
    def create_kubeconfigs(self):
        status.add(ops.MaintenanceStatus("Creating kubeconfigs"))
        ca = self.certificates.ca
        local_server = self.k8s_api_endpoints.local()
        node_name = self.get_node_name()
        public_server = self.k8s_api_endpoints.external()

        if not os.path.exists("/root/.kube/config"):
            # Create a bootstrap client config. This initial config will allow
            # us to get and create auth webhook tokens via the Kubernetes API,
            # but will not have the final admin token just yet.
            kubernetes_snaps.create_kubeconfig(
                "/root/.kube/config",
                ca=ca,
                server=local_server,
                user="admin",
                token=auth_webhook.token_generator(),
            )

        admin_token = auth_webhook.create_token(
            uid="admin",
            username="admin",
            # wokeignore:rule=master
            groups=["system:masters"],
        )

        for dest in ["/root/.kube/config", "/home/ubuntu/.kube/config"]:
            kubernetes_snaps.create_kubeconfig(
                dest,
                ca=ca,
                server=local_server,
                token=admin_token,
                user="admin",
            )

        kubernetes_snaps.create_kubeconfig(
            "/home/ubuntu/config",
            ca=ca,
            server=public_server,
            token=admin_token,
            user="admin",
        )

        kubernetes_snaps.create_kubeconfig(
            "/root/cdk/kubecontrollermanagerconfig",
            ca=ca,
            server=local_server,
            token=auth_webhook.create_token(
                uid="kube-controller-manager", username="system:kube-controller-manager", groups=[]
            ),
            user="kube-controller-manager",
        )

        kubernetes_snaps.create_kubeconfig(
            "/root/cdk/kubeschedulerconfig",
            ca=ca,
            server=local_server,
            token=auth_webhook.create_token(
                uid="system:kube-scheduler", username="system:kube-scheduler", groups=[]
            ),
            user="kube-scheduler",
        )

        kubernetes_snaps.create_kubeconfig(
            "/root/cdk/kubeconfig",
            ca=ca,
            server=local_server,
            token=auth_webhook.create_token(
                uid=self.unit.name,
                username=f"system:node:{node_name.lower()}",
                groups=["system:nodes"],
            ),
            user="kubelet",
        )

        kubernetes_snaps.create_kubeconfig(
            "/root/cdk/kubeproxyconfig",
            ca=ca,
            server=local_server,
            token=auth_webhook.create_token(
                uid="kube-proxy", username="system:kube-proxy", groups=[]
            ),
            user="kube-proxy",
        )

    def configure_observability(self):
        """Apply observability configurations to the cluster."""
        # Apply Clusterrole and Clusterrole binding for COS observability
        status.add(ops.MaintenanceStatus("Configuring Observability"))
        if self.unit.is_leader():
            kubectl("apply", "-f", "templates/observability.yaml")
        # Issue a token for metrics scraping
        node_name = self.get_node_name()
        cos_user = f"system:cos:{node_name}"
        auth_webhook.create_token(
            uid=self.model.unit.name, username=cos_user, groups=[OBSERVABILITY_ROLE]
        )

    def generate_tokens(self):
        """Generate and send tokens for units that request them."""
        if not self.unit.is_leader():
            return

        status.add(ops.MaintenanceStatus("Generating Tokens"))
        self.tokens.remove_stale_tokens()

        for request in self.tokens.token_requests:
            tokens = {
                user: auth_webhook.create_token(uid=request.unit, username=user, groups=[group])
                for user, group in request.requests.items()
            }
            self.tokens.send_token(request, tokens)

    def get_cluster_name(self):
        peer_relation = self.model.get_relation("peer")
        cluster_name = peer_relation.data[self.app].get("cluster-name")

        if cluster_name:
            return cluster_name

        if not self.unit.is_leader():
            status.add(ops.WaitingStatus("Waiting for cluster name from leader"))
            return None

        # Check for old cluster name in leader data
        cluster_name = leader_data.get("cluster_tag")
        if cluster_name:
            peer_relation.data[self.app]["cluster-name"] = cluster_name
            leader_data.set("cluster_tag", "")
            return cluster_name

        cluster_name = f"kubernetes-{auth_webhook.token_generator().lower()}"
        peer_relation.data[self.app]["cluster-name"] = cluster_name
        return cluster_name

    def get_dns_address(self):
        return self.kube_dns.address or self.cdk_addons.get_dns_address()

    def get_dns_domain(self):
        return self.kube_dns.domain or self.model.config["dns_domain"]

    def get_dns_port(self):
        return self.kube_dns.port or 53

    def get_cloud_name(self) -> str:
        return self.external_cloud_provider.name

    def get_node_name(self) -> str:
        fqdn = self.external_cloud_provider.name == "aws" and self.external_cloud_provider.has_xcp
        return kubernetes_snaps.get_node_name(fqdn=fqdn)

    @status.on_error(ops.BlockedStatus("cni-plugins resource missing or invalid"))
    def install_cni_binaries(self):
        try:
            resource_path = self.model.resources.fetch("cni-plugins")
        except (ops.ModelError, NameError):
            log.error("Something went wrong when claiming 'cni-plugins' resource.")
            raise

        unpack_path = Path("/opt/cni/bin")
        unpack_path.mkdir(parents=True, exist_ok=True)

        command = f"tar -xzvf {resource_path} -C {unpack_path} --no-same-owner"
        try:
            subprocess.check_call(shlex.split(command))
        except CalledProcessError:
            log.error("Failed to extract 'cni-plugins:'")
            raise

        log.info(f"Extracted 'cni-plugins' to {unpack_path}")

    def on_upgrade_action(self, event):
        """Handle the upgrade action."""
        with status.context(self.unit):
            channel = self.model.config.get("channel")
            kubernetes_snaps.upgrade_snaps(channel=channel, event=event, control_plane=True)

    def reconcile(self, event):
        """Reconcile state change events."""
        self.install_cni_binaries()
        kubernetes_snaps.install(channel=self.model.config["channel"], control_plane=True)
        kubernetes_snaps.configure_services_restart_always(control_plane=True)
        self.request_certificates()
        self.write_certificates()
        self.write_etcd_client_credentials()
        self.write_service_account_key()
        self.configure_auth_webhook()
        self.configure_loadbalancers()
        if self.api_dependencies_ready():
            self.configure_apiserver()
            self.create_kubeconfigs()
            self.configure_controller_manager()
            self.configure_scheduler()
            self.configure_apiserver_kubelet_api_admin()
            self.cdk_addons.configure()
            self.configure_container_runtime()
            self.configure_cni()
            self.configure_kernel_parameters()
            self.configure_kubelet()
            self.configure_kube_proxy()
            self.configure_kube_control()
            self.configure_hacluster()
            self.generate_tokens()
            self.configure_observability()
            self.apply_node_labels()

    def apply_node_labels(self):
        """Request client and server certificates."""
        status.add(ops.MaintenanceStatus("Apply Node Labels"))
        node = self.get_node_name()
        if self.node_base.active_labels() is not None:
            self.node_base.apply_node_labels()
            log.info("Node %s labelled successfully", node)
        else:
            log.info("Node %s not yet labelled", node)

    @status.on_error(ops.WaitingStatus("Waiting for certificate authority"))
    def request_certificates(self):
        """Request client and server certificates."""
        assert self.certificates.relation, "Certificates relation doesn't yet exist"

        bind_addrs = kubernetes_snaps.get_bind_addresses()
        common_name = kubernetes_snaps.get_public_address()
        config_addrs = [
            address
            for option in ["loadbalancer-ips", "ha-cluster-vip", "ha-cluster-dns"]
            for address in self.config[option].split()
            if address
        ]
        domain = self.get_dns_domain()
        extra_sans = self.config["extra_sans"].split()
        k8s_service_addrs = kubernetes_snaps.get_kubernetes_service_addresses(
            self.config["service-cidr"].split(",")
        )
        ingress_addrs = self.kube_control.ingress_addresses

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
        sans += config_addrs
        sans += ingress_addrs
        sans += k8s_service_addrs
        sans += filter(None, [self.k8s_api_endpoints.get_external_api_endpoint()])
        sans += filter(None, [self.k8s_api_endpoints.get_internal_api_endpoint()])
        sans += extra_sans
        sans = sorted(set(sans))

        self.certificates.request_client_cert("system:kube-apiserver")
        self.certificates.request_server_cert(cn=common_name, sans=sans)

    def update_status(self, event):
        if self.hacluster.is_ready:
            apiserver_running = (
                subprocess.call(["systemctl", "is-active", "snap.kube-apiserver.daemon"]) == 0
            )
            if apiserver_running:
                self.hacluster.set_node_online()
            else:
                self.hacluster.set_node_standby()
        self._set_workload_version()
        self._check_kube_system()

    def write_service_account_key(self):
        peer_relation = self.model.get_relation("peer")
        key = peer_relation.data[self.app].get("service-account-key")

        if key:
            kubernetes_snaps.write_service_account_key(key)
            return

        if not self.unit.is_leader():
            status.add(ops.WaitingStatus("Waiting for key from leader"))
            return

        # Check for old key in leader data
        key = leader_data.get("/root/cdk/serviceaccount.key")
        if key:
            peer_relation.data[self.app]["service-account-key"] = key
            leader_data.set("/root/cdk/serviceaccount.key", "")
            return

        key = kubernetes_snaps.create_service_account_key()
        peer_relation.data[self.app]["service-account-key"] = key

    def write_certificates(self):
        """Write certificates from the certificates relation."""
        common_name = kubernetes_snaps.get_public_address()
        ca = self.certificates.ca
        client_cert = self.certificates.client_certs_map.get("system:kube-apiserver")
        server_cert = self.certificates.server_certs_map.get(common_name)

        if not ca or not client_cert or not server_cert:
            status.add(ops.WaitingStatus("Waiting for certificates"))
            return

        kubernetes_snaps.write_certificates(
            ca=ca,
            client_cert=client_cert.cert,
            client_key=client_cert.key,
            server_cert=server_cert.cert,
            server_key=server_cert.key,
        )

    @status.on_error(ops.WaitingStatus("Waiting for etcd"))
    def write_etcd_client_credentials(self):
        """Write etcd client credentials from the etcd relation."""
        assert self.etcd.relation, "Relation to etcd is missing"
        assert self.etcd.is_ready, "Relation to etcd is not yet ready"
        creds = self.etcd.get_client_credentials()

        kubernetes_snaps.write_etcd_client_credentials(
            ca=creds["client_ca"], cert=creds["client_cert"], key=creds["client_key"]
        )

    def _set_workload_version(self):
        cmd = ["kubelet", "--version"]
        try:
            version = subprocess.run(cmd, stdout=subprocess.PIPE)
        except FileNotFoundError:
            log.warning("kubelet not yet found, skip setting workload version")
            return
        if not version.returncode:
            val = version.stdout.split(b" v")[-1].rstrip().decode()
            log.info("Setting workload version to %s.", val)
            self.unit.set_workload_version(val)
        else:
            stderr = version.stderr.decode()
            log.warning("Unable to get kubectl version. %s", stderr)
            self.unit.set_workload_version("")

    def _check_kube_system(self):
        if not self.reconciler.stored.reconciled:
            # Bail, the unit isn't reconciled
            log.info("Wait to check kube-system until reconciled")
            return

        # only update the kube-system status under these conditions
        # 1) currently active status
        # 2) matches a waiting on kube-system message

        kube_system_re = re.compile(r"Waiting for (?:\d+ )?kube-system pods? to start")
        pre_status = self.unit.status
        if isinstance(pre_status, ops.ActiveStatus) or kube_system_re.match(pre_status.message):
            with status.context(self.unit):
                unready = get_kube_system_pods_not_running(self)
                if unready is None:
                    status.add(ops.WaitingStatus("Waiting for kube-system pods to start"))
                elif unready:
                    plural = "s" if len(unready) > 1 else ""
                    msg = "Waiting for {} kube-system pod{} to start"
                    msg = msg.format(len(unready), plural)
                    status.add(ops.WaitingStatus(msg))


if __name__ == "__main__":  # pragma: nocover
    ops.main(KubernetesControlPlaneCharm)
