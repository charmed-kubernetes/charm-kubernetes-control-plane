import logging
from subprocess import CalledProcessError
from typing import List, Optional

from kubectl import kubectl_get

log = logging.getLogger(__name__)


def get_pods(namespace="default"):
    try:
        result = kubectl_get("po", "-n", namespace, "--request-timeout", "10s")
    except CalledProcessError:
        log.error("failed to get {} pod status".format(namespace))
        return None
    return result


def get_kube_system_pods_not_running(charm) -> Optional[List]:
    """Check pod status in the kube-system namespace.

    returns None if unable to determine pod status. This can
    occur when the api server is not currently running. On success,
    returns a list of pods that are not currently running
    or an empty list if all are running, ignoring pods whose names
    start with those provided in the ignore-kube-system-pods config option.
    """
    result = get_pods("kube-system")
    if result is None or result.get("items") is None:
        return None

    # Remove pods whose names start with ones provided in the ignore list
    pod_names_space_separated = charm.config.get("ignore-kube-system-pods") or ""
    ignore_list = pod_names_space_separated.strip().split()
    result["items"] = [
        pod
        for pod in result["items"]
        if not any(pod["metadata"]["name"].startswith(name) for name in ignore_list)
    ]

    log.info(
        "Checking system pods status: {}".format(
            ", ".join(
                "=".join([pod["metadata"]["name"], pod["status"]["phase"]])
                for pod in result["items"]
            )
        )
    )

    def is_not_running(pod) -> bool:
        status = pod["status"]
        pod_phase, pod_reason = status["phase"], status.get("reason", "")
        if pod_phase == "Failed":
            # Failed pods are not running -- full stop
            not_running = True
        elif pod_phase == "Succeeded":
            # Exclude Succeeded pods since they have run and done their work
            not_running = False
        elif pod_phase == "Running":
            # Any Running phase pod with not ready containers, should be considered not running
            container_statuses = pod["status"].get("initContainerStatuses", [])
            container_statuses += pod["status"].get("containerStatuses", [])
            not_running = any(not status.get("ready", True) for status in container_statuses)
        else:
            # Any other phase (Pending or Unknown) are not running if they aren't evicted
            not_running = pod_reason != "Evicted"
        
        if not_running:
            pod_name, pod_ns = pod["metadata"]["namespace"], pod["metadata"]["name"]
            log.warning("Pod/%s/%s in phase=%s is not running because of reason=%s", pod_ns, pod_name, pod_phase, pod_reason)
        
        return not_running

    not_running = [pod for pod in result["items"] if is_not_running(pod)]

    return not_running
