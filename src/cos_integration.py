import logging
from dataclasses import dataclass
from subprocess import CalledProcessError

import auth_webhook
from ops import CharmBase
from tenacity import RetryError

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
    """

    name: str
    metrics_path: str
    scheme: str
    target: str


class COSIntegration:
    """Utility class that handles the integration with COS for Charmed Kubernetes.

    This class provides methods to retrieve and configure Prometheus metrics scraping endpoints
    based on the Kubernetes components running within the cluster.

    Attributes:
        charm (CharmBase): Reference to the base charm instance.
    """

    def __init__(self, charm: CharmBase) -> None:
        self.charm = charm

    def _create_scrape_jobs(self, config: JobConfig, node_name: str, token: str) -> dict:
        return {
            "tls_config": {"insecure_skip_verify": True},
            "authorization": {"credentials": token},
            "job_name": config.name,
            "metrics_path": config.metrics_path,
            "scheme": config.scheme,
            "static_configs": [
                {
                    "targets": [config.target],
                    "labels": {"node": node_name},
                }
            ],
            "relabel_configs": [
                {"target_label": "metrics_path", "replacement": config.metrics_path},
                {"target_label": "job", "replacement": config.name},
            ],
        }

    def get_metrics_endpoints(self) -> list:
        """Return the metrics endpoints for K8s components."""
        log.info("Building Prometheus scraping jobs.")

        try:
            node_name = self.charm.get_node_name()
            cos_user = f"system:cos:{node_name}"
            token = auth_webhook.get_token(cos_user)
        except (CalledProcessError, RetryError):
            log.error("Failed to retrieve observability token.")
            return []

        if not token:
            log.info("COS Token not yet available")
            return []

        kubernetes_jobs = [
            JobConfig("kube-proxy", "/metrics", "http", "localhost:10249"),
            JobConfig("kube-apiserver", "/metrics", "https", "localhost:6443"),
            JobConfig("kube-controller-manager", "/metrics", "https", "localhost:10257"),
        ]
        kubelet_paths = [
            "/metrics",
            "/metrics/resource",
            "/metrics/cadvisor",
            "/metrics/probes",
        ]

        kubelet_jobs = [
            JobConfig(f"kubelet-{path.split('/')[-1]}", path, "https", "localhost:10250")
            for path in kubelet_paths
        ]

        return [self.create_scrape_job(job) for job in kubernetes_jobs + kubelet_jobs]
