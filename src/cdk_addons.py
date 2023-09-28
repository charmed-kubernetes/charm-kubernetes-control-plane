import json
import logging
import os
import shutil
from subprocess import CalledProcessError, check_call, check_output

from kubectl import kubectl
from tenacity import retry, stop_after_delay, wait_exponential

kubeconfig_dir = "/root/snap/cdk-addons/common"
kubeconfig_path = f"{kubeconfig_dir}/kubeconfig"
log = logging.getLogger(__name__)


class CdkAddons:
    """Class for handling configuration of cdk-addons."""

    def __init__(self, charm):
        self.charm = charm

    @retry(stop=stop_after_delay(60), wait=wait_exponential())
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
            # "ceph-admin-key=" + (ceph.get("admin_key", "")),
            # "ceph-fsid=" + (ceph.get("fsid", "")),
            # "ceph-fsname=" + (ceph.get("fsname", "")),
            # "ceph-kubernetes-key=" + (ceph.get("admin_key", "")),
            # 'ceph-mon-hosts="' + (ceph.get("mon_hosts", "")) + '"',
            # "ceph-user=" + hookenv.application_name(),
            # "cephfs-mounter=" + cephfs_mounter,
            # "cinder-availability-zone=" + hookenv.config("cinder-availability-zone"),
            "cluster-tag=" + self.charm.get_cluster_name(),
            "dashboard-auth=token",
            "default-storage=" + default_storage,
            "dns-domain=" + self.charm.model.config["dns_domain"],
            "dns-provider=" + self.get_dns_provider(),
            # "enable-aws=" + enable_aws,
            # "enable-azure=" + enable_azure,
            # "enable-ceph=" + cephEnabled,
            # "enable-cephfs=" + cephFsEnabled,
            "enable-dashboard=" + db_enabled,
            # "enable-gcp=" + enable_gcp,
            # "enable-gpu=" + str(gpuEnable).lower(),
            # "enable-keystone=" + keystoneEnabled,
            "enable-metrics=" + metrics_enabled,
            # "enable-openstack=" + enable_openstack,
            # "keystone-cert-file=" + keystone.get("cert", ""),
            # "keystone-key-file=" + keystone.get("key", ""),
            # "keystone-server-ca=" + keystone.get("keystone-ca", ""),
            # "keystone-server-url=" + keystone.get("url", ""),
            "kubeconfig=" + kubeconfig_path,
            # "openstack-cloud-conf=",
            # "openstack-endpoint-ca=",
            "registry=" + registry,
        ]
        check_call(["snap", "set", "cdk-addons"] + args)
        self.copy_kubeconfig()
        self.apply()
        self.set_default_storage_class()

    def copy_kubeconfig(self):
        """Copy the admin kubeconfig to a location where cdk-addons can read it."""
        os.makedirs(kubeconfig_dir, exist_ok=True)
        shutil.copy("/root/.kube/config", kubeconfig_path)

    def get_default_storage_class(self):
        """Get the name of the default StorageClass."""
        def_storage_class = self.charm.model.config["default-storage"]
        if def_storage_class == "auto":
            def_storage_class = "ceph-xfs"
        return def_storage_class

    def get_dns_provider(self):
        """Get the DNS provider.

        Can return "core-dns" or "none".
        """
        valid_dns_providers = ["auto", "core-dns", "none"]

        dns_provider = self.charm.model.config["dns-provider"].lower()
        if dns_provider not in valid_dns_providers:
            raise InvalidDnsProviderError(dns_provider)

        if dns_provider == "auto":
            dns_provider = "core-dns"

        return dns_provider

    def get_storage_classes(self):
        """Get StorageClasses from Kubernetes."""
        try:
            storage_classes = json.loads(kubectl("get", "storageclass", "-o=json"))
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
    architecture = architecture.decode("utf-8")
    return architecture
