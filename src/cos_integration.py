import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Union

from ops import CharmBase

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


class COSIntegration:
    """Utility class that handles the integration with COS for Charmed Kubernetes.

    This class provides methods to retrieve and configure Prometheus metrics scraping endpoints
    based on the Kubernetes components running within the cluster.

    Attributes:
        charm (CharmBase): Reference to the base charm instance.
    """

    def __init__(self, charm: CharmBase) -> None:
        """Initialize a COSIntegration instance.

        Args:
            charm (CharmBase): A charm object representing the current charm.
        """
        self.charm = charm

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
                name="apiserver",
                metrics_path="/metrics",
                scheme="https",
                target="localhost:6443",
                relabel_configs=[{"target_label": "job", "replacement": "apiserver"}, instance_relabel],
            ),
            JobConfig(
                name="kube-proxy",
                metrics_path="/metrics",
                scheme="http",
                target="localhost:10249",
                relabel_configs=[{"target_label": "job", "replacement": "kube-proxy"}],
            ),
            JobConfig(
                name="kube-scheduler",
                metrics_path="/metrics",
                scheme="https",
                target="localhost:10259",
                relabel_configs=[{"target_label": "job", "replacement": "kube-scheduler"}, instance_relabel],
            ),
            JobConfig(
                name="kube-controller-manager",
                metrics_path="/metrics",
                scheme="https",
                target="localhost:10257",
                relabel_configs=[{"target_label": "job", "replacement": "kube-controller-manager"}, instance_relabel],
            )
        ]
        kubelet_metrics_paths = [
            "/metrics",
            "/metrics/resource",
            "/metrics/cadvisor",
            "/metrics/probes",
        ]

        kubelet_jobs = [
            JobConfig(
                name=f"kubelet{metric.replace('/', '-')}",
                metrics_path=metric,
                scheme="https",
                target="localhost:10250",
                relabel_configs=[
                    {"target_label": "metrics_path", "replacement": metric},
                    {"target_label": "job", "replacement": "kubelet"},
                    instance_relabel,
                ],
            )
            for metric in kubelet_metrics_paths
        ]

        jobs = [
            self._create_scrape_job(job, node_name, token, cluster_name)
            for job in kubernetes_jobs + kubelet_jobs
        ]

        if self.charm.unit.is_leader():
            # NOTE: Leader should be the only one gathering KSM data.
            kube_state_metrics_job = JobConfig(
                name="kube-state-metrics",
                metrics_path="/api/v1/namespaces/kube-system/services/kube-state-metrics:8080/proxy/metrics",
                scheme="https",
                target="localhost:6443",
                relabel_configs=[
                    {"target_label": "job", "replacement": "kube-state-metrics"},
                ],
                static_configs=[
                    {
                        "targets": ["localhost:6443"],
                        "labels": {"cluster": cluster_name},
                    }
                ],
            )
            jobs.append(
                self._create_scrape_job(kube_state_metrics_job, node_name, token, cluster_name)
            )

        return jobs
