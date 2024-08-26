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

    # Pods in phases such as ['Running', 'Succeeded', 'Failed']
    # should not be considered as pending Pods.
    valid_phases = ["Running", "Succeeded", "Failed"]

    # Pods that are Running or Evicted (which should re-spawn) are
    # considered running
    def is_ready(pod):
        container_statuses = pod["status"].get("initContainerStatuses", [])
        container_statuses += pod["status"].get("containerStatuses", [])
        return all(status.get("ready", True) for status in container_statuses)

    def is_invalid(pod):
        status = pod["status"]
        return status["phase"] not in valid_phases and status.get("reason", "") != "Evicted"

    not_running = [pod for pod in result["items"] if is_invalid(pod) or not is_ready(pod)]

    return not_running
