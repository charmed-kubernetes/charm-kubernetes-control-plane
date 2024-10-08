import json
import logging
import os
import shutil
from subprocess import CalledProcessError, check_call, check_output

import charms.contextual_status as status
import tenacity
from ops import BlockedStatus

from kubectl import ROOT_KUBECONFIG, get_service_ip, kubectl, kubectl_get

kubeconfig_dir = "/root/snap/cdk-addons/common"
kubeconfig_path = f"{kubeconfig_dir}/kubeconfig"
log = logging.getLogger(__name__)


class CdkAddons:
    """Class for handling configuration of cdk-addons."""

    def __init__(self, charm):
        self.charm = charm

    @tenacity.retry(
        reraise=True,
        stop=tenacity.stop_after_delay(60),
        wait=tenacity.wait_exponential(),
        before=tenacity.before_log(log, logging.WARNING),
    )
    def apply(self):
        """Apply addons."""
        check_call(["cdk-addons.apply"])

    def configure(self):
        """Configure cdk-addons and apply."""
        if not self.charm.unit.is_leader():
            return

        # TODO: gpu plugin
        # load_gpu_plugin = self.charm.model.config["enable-nvidia-plugin"].lower()
        # gpuEnable = (
        #     and load_gpu_plugin == "auto"
        #     and is_state("kubernetes-control-plane.gpu.enabled")
        # )
        registry = self.charm.model.config["image-registry"]
        db_enabled = str(self.charm.model.config["enable-dashboard-addons"]).lower()
        metrics_enabled = str(self.charm.model.config["enable-metrics"]).lower()
        default_storage = self.get_default_storage_class()

        args = [
            "arch=" + arch(),
            "cluster-tag=" + self.charm.get_cluster_name(),
            "dashboard-auth=token",
            "default-storage=" + default_storage,
            "dns-domain=" + self.charm.model.config["dns_domain"],
            "dns-provider=" + self.get_dns_provider(),
            "enable-dashboard=" + db_enabled,
            "enable-metrics=" + metrics_enabled,
            "kubeconfig=" + kubeconfig_path,
            "registry=" + registry,
        ]
        check_call(["snap", "set", "cdk-addons"] + args)
        self.copy_kubeconfig()
        self.apply()
        self.set_default_storage_class()

    def copy_kubeconfig(self):
        """Copy the admin kubeconfig to a location where cdk-addons can read it."""
        os.makedirs(kubeconfig_dir, exist_ok=True)
        shutil.copy(ROOT_KUBECONFIG, kubeconfig_path)

    def get_default_storage_class(self):
        """Get the name of the default StorageClass."""
        def_storage_class = self.charm.model.config["default-storage"]
        if def_storage_class == "auto":
            def_storage_class = "ceph-xfs"
        return def_storage_class

    def get_dns_address(self):
        if self.get_dns_provider() == "core-dns":
            return get_service_ip(namespace="kube-system", name="kube-dns")
        else:
            return ""

    def get_dns_provider(self):
        """Get the DNS provider.

        Can return "core-dns" or "none".
        """
        valid_dns_providers = ["auto", "core-dns", "none"]

        dns_provider = self.charm.model.config["dns-provider"].lower()
        if dns_provider not in valid_dns_providers:
            status.add(BlockedStatus(f"dns-provider={dns_provider} is invalid"))
            raise InvalidDnsProviderError(dns_provider)

        if dns_provider == "auto":
            dns_provider = "core-dns"

        return dns_provider

    def get_storage_classes(self):
        """Get StorageClasses from Kubernetes."""
        try:
            storage_classes = kubectl_get("storageclass")
        except (CalledProcessError, FileNotFoundError):
            log.exception("Failed to get the current storage classes.")
            storage_classes = {"items": []}
        for storage_class in storage_classes["items"]:
            yield storage_class

    def set_default_storage_class(self):
        """Set the default storage class.

        This applies the storageclass.kubernetes.io/is-default-class annotation
        to the StorageClass named by the charm's default-storage config option.
        The annotation is removed from all other StorageClasses.
        """
        default_storage_class = self.get_default_storage_class()
        for storage_class in self.get_storage_classes():
            name = storage_class["metadata"]["name"]
            is_default = name == default_storage_class
            cur_annotations = storage_class["metadata"].get("annotations") or {}
            new_annotations = cur_annotations.copy()
            storage_class_annotation = "storageclass.kubernetes.io/is-default-class"
            if is_default:
                new_annotations.update(**{storage_class_annotation: "true"})
            elif not is_default and storage_class_annotation in new_annotations:
                new_annotations.pop(storage_class_annotation)

            if new_annotations != cur_annotations:
                log.info(f"{'S' if is_default else 'Uns'}etting default storage-class {name}.")
                patch_set = json.dumps({"metadata": new_annotations})
                kubectl("patch", "storageclass", name, "-p", patch_set)


class InvalidDnsProviderError(Exception):
    """Raised when the dns-provider config option is invalid."""

    pass


def arch():
    """Return the package architecture as a string.

    Raise an exception if the architecture is not supported by kubernetes.
    """
    architecture = check_output(["dpkg", "--print-architecture"]).rstrip()
    return architecture.decode("utf-8")
