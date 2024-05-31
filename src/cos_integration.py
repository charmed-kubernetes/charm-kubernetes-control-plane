import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Union

import os
import ops
import hashlib
from pathlib import Path

log = logging.getLogger(__name__)

OBSERVABILITY_ROLE = "system:cos"


@dataclass
class JobConfig:
    """Data class representing the configuration for a Prometheus scrape job.

    Attributes:
        name (str): The name of the scrape job. Corresponds to the name of the Kubernetes
                    component being monitored (e.g., 'kube-apiserver').
        metrics_path (str): The endpoint path where the metrics are exposed by the
                            component (e.g., '/metrics').
        scheme (str): The scheme used for the endpoint. (e.g.'http' or 'https').
        target (str): The network address of the target component along with the port.
                      Format is 'hostname:port' (e.g., 'localhost:6443').
        relabel_configs (List[Dict[str, str]]): Additional configurations for relabeling.
        static_config (Optional[List[Any]]): Static configs to override the default ones.
    """

    name: str
    metrics_path: str
    scheme: str
    target: str
    relabel_configs: List[Dict[str, Union[str, Sequence[str]]]]
    static_configs: Optional[List[Any]] = None


class AlertManagerDefinitionsReadyEvent(ops.EventBase):
    """Event emitted when alert manager definitions are ready."""

class COSIntegrationEvents(ops.ObjectEvents):
    definitions_ready = ops.EventSource(AlertManagerDefinitionsReadyEvent)


class COSIntegration(ops.Object):
    """Utility class that handles the integration with COS for Charmed Kubernetes.

    This class provides methods to retrieve and configure Prometheus metrics scraping endpoints
    based on the Kubernetes components running within the cluster.

    Attributes:
        charm (CharmBase): Reference to the base charm instance.
    """
    on = COSIntegrationEvents()
    stored = ops.StoredState()

    def __init__(self, charm: ops.CharmBase) -> None:
        """Initialize a COSIntegration instance.

        Args:
            charm (ops.CharmBase): A charm object representing the current charm.
        """
        super().__init__(charm)
        self.charm = charm
        self.stored.set_default(metrics_rules_hash=None)

    def _hash_file(self, filename: str):
        """Hash a file using sha256."""
        hash_sha256 = hashlib.sha256()
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def _hash_metrics_rules_files(self):
        """Hash the metrics rules files to determine if they have changed."""
        directory = "./src/prometheus_alert_rules_parsed"

        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]

        concat_hashes = "".join([self._hash_file(os.path.join(directory, file)) for file in files])
        log.info("Hash of metrics (%s) rules files: %s", str(len(files)), concat_hashes)

        return concat_hashes

    def _hash_metrics_rules_files_changed(self):
        """Check if the metrics rules files have changed."""
        new_hash = self._hash_metrics_rules_files()
        if new_hash != self.metrics_rules_hash:
            log.info("Metrics rules files have changed")
            self.metrics_rules_hash = new_hash
            return True
        return False

    def _parse_metrics_rules_files(self):
        """Parse the metrics rules files."""
        input_directory = Path("./src/prometheus_alert_rules")
        output_directory = Path("./src/prometheus_alert_rules_parsed")

        os.makedirs(output_directory, exist_ok=True)

        replace_rules = {
            "kubernetesControlPlane-prometheusRule.yaml": {
                "[[- namespace -]]": 'namespace=~' + f'"{self.charm.config["namespace"]}"',
            },
        }

        input_files = [
            f
            for f in os.listdir(input_directory)
            if os.path.isfile(os.path.join(input_directory, f))
        ]

        for filename in input_files:
            input_file_path = input_directory / filename
            output_file_path = output_directory / filename

            with open(input_file_path) as input_file:
                content = input_file.read()

            log.info("Writing parsed file to %s", output_directory / filename)

            with open(output_file_path, "w+") as output_file:
                try:
                    rules = replace_rules[filename]
                    for k, v in rules.items():
                        content = content.replace(k, v)
                except KeyError:
                    continue
                finally:
                    output_file.write(content)

    def ensure_metrics_rules(self):
        self._parse_metrics_rules_files()

        if self._hash_metrics_rules_files_changed():
            self.on.definitions_ready.emit()

    def _create_scrape_job(
        self, config: JobConfig, node_name: str, token: str, cluster_name: str
    ) -> Dict:
        """Create a scrape job configuration.

        Args:
            config (JobConfig): The configuration for the scrape job.
            node_name (str): The name of the node.
            token (str): The token for authorization.
            cluster_name (str): The name of the cluster.

        Returns:
            Dict: The scrape job configuration.
        """
        return {
            "tls_config": {"insecure_skip_verify": True},
            "authorization": {"credentials": token},
            "job_name": config.name,
            "metrics_path": config.metrics_path,
            "scheme": config.scheme,
            "static_configs": config.static_configs
            or [
                {
                    "targets": [config.target],
                    "labels": {"node": node_name, "cluster": cluster_name},
                }
            ],
            "relabel_configs": config.relabel_configs,
        }

    def get_metrics_endpoints(self, node_name: str, token: str, cluster_name: str) -> List[Dict]:
        """Retrieve Prometheus scrape job configurations for Kubernetes components.

        Args:
            node_name (str): The name of the node.
            token (str): The authentication token.
            cluster_name (str): The name of the cluster.

        Returns:
            List[Dict]: A list of Prometheus scrape job configurations.
        """
        log.info("Building Prometheus scraping jobs.")

        instance_relabel = {
            "source_labels": ["instance"],
            "target_label": "instance",
            "replacement": node_name,
        }

        kubernetes_jobs = [
            JobConfig(
                "kube-proxy",
                "/metrics",
                "http",
                "localhost:10249",
                [{"target_label": "job", "replacement": "kube-proxy"}],
            ),
            JobConfig(
                "apiserver",
                "/metrics",
                "https",
                "localhost:6443",
                [
                    {
                        "source_labels": ["job"],
                        "target_label": "job",
                        "replacement": "apiserver",
                    },
                    instance_relabel,
                ],
            ),
            JobConfig(
                "kube-scheduler",
                "/metrics",
                "https",
                "localhost:10259",
                [{"target_label": "job", "replacement": "kube-scheduler"}, instance_relabel],
            ),
            JobConfig(
                "kube-controller-manager",
                "/metrics",
                "https",
                "localhost:10257",
                [
                    {"target_label": "job", "replacement": "kube-controller-manager"},
                    instance_relabel,
                ],
            ),
        ]
        kubelet_metrics_paths = [
            "/metrics",
            "/metrics/resource",
            "/metrics/cadvisor",
            "/metrics/probes",
        ]

        kubelet_jobs = [
            JobConfig(
                f"kubelet-{metric}" if metric else "kubelet",
                path,
                "https",
                "localhost:10250",
                [
                    {"target_label": "metrics_path", "replacement": path},
                    {"target_label": "job", "replacement": "kubelet"},
                    instance_relabel,
                ],
            )
            for path in kubelet_metrics_paths
            if (metric := path.strip("/metrics")) is not None
        ]

        kube_state_metrics = [
            JobConfig(
                "kube-state-metrics",
                "/api/v1/namespaces/kube-system/services/kube-state-metrics:8080/proxy/metrics",
                "https",
                "localhost:6443",
                [
                    {"target_label": "job", "replacement": "kube-state-metrics"},
                ],
                [
                    {
                        "targets": ["localhost:6443"],
                        "labels": {"cluster": cluster_name},
                    }
                ],
            )
        ]

        return [
            self._create_scrape_job(job, node_name, token, cluster_name)
            for job in kubernetes_jobs + kubelet_jobs + kube_state_metrics
        ]
