import logging
from dataclasses import dataclass
from subprocess import CalledProcessError
from typing import Dict, List

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
        relabel_configs (List[Dict[str, str]]): Additional configurations for relabeling.
    """

    name: str
    metrics_path: str
    scheme: str
    target: str
    relabel_configs: List[Dict[str, str]]


class COSIntegration:
    """Utility class that handles the integration with COS for Charmed Kubernetes.

    This class provides methods to retrieve and configure Prometheus metrics scraping endpoints
    based on the Kubernetes components running within the cluster.

    Attributes:
        charm (CharmBase): Reference to the base charm instance.
    """

    def __init__(self, charm: CharmBase) -> None:
        self.charm = charm

    def _create_scrape_job(self, config: JobConfig, node_name: str, token: str) -> dict:
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
            "relabel_configs": config.relabel_configs,
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
                [{"target_label": "job", "replacement": "apiserver"}],
            ),
            JobConfig(
                "kube-scheduler",
                "/metrics",
                "https",
                "localhost:6443",
                [{"target_label": "job", "replacement": "kube-scheduler"}],
            ),
            JobConfig(
                "kube-controller-manager",
                "/metrics",
                "https",
                "localhost:10257",
                [{"target_label": "job", "replacement": "kube-controller-manager"}],
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
            )
        ]

        return [
            self._create_scrape_job(job, node_name, token)
            for job in kubernetes_jobs + kubelet_jobs + kube_state_metrics
        ]
