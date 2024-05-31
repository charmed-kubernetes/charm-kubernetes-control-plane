from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

import ops

log = logging.getLogger(__name__)

OBSERVABILITY_ROLE = "system:cos"
METRICS_SOURCE_DIR = Path("src/prometheus_alert_rules")
METRICS_PARSED_DIR = Path("src/prometheus_alert_rules_parsed")


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
    """Manages COSIntegration events."""

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
        super().__init__(charm, key=None)
        self.charm = charm
        self.stored.set_default(metrics_rules_hash=None)

    def _hash_files(self, path: Path, glob: str) -> list[hashlib._Hash]:
        """Hash the metrics rules files to determine if they have changed."""

        def hash_file(path: Path):
            return hashlib.sha256(path.read_bytes())

        return [hash_file(f) for f in path.glob(glob)]

    def _do_hashes_match(self, a: list[hashlib._Hash], b: list[hashlib._Hash]) -> bool:
        """Check if the metrics rules files have changed."""
        return all([one.digest() == two.digest() for one, two in zip(a, b)])

    def _parse_metrics_rules_files(self):
        input_directory = Path("./src/prometheus_alert_rules")
        output_directory = Path("./src/prometheus_alert_rules_parsed")

        output_directory.mkdir(exist_ok=True)

        replace_rules = {
            "kubernetesControlPlane-prometheusRule.yaml": {
                "[[- namespace -]]": "namespace=~" + f'"{self.charm.config["namespace"]}"',
            },
        }

        for f in input_directory.glob("*.yaml"):
            output_file_path = output_directory / f.name

            content = f.read_text()

            for k, v in replace_rules.get(f.name, {}).items():
                content = content.replace(k, v)

            output_file_path.write_text(content)

    def ensure_metrics_rules(self):
        old_hashes = self._hash_files(METRICS_PARSED_DIR, "*.yaml")

        self._parse_metrics_rules_files()

        new_hashes = self._hash_files(METRICS_PARSED_DIR, "*.yaml")

        if not self._do_hashes_match(old_hashes, new_hashes):
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
