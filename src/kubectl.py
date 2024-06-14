import json
import logging
from pathlib import Path
from subprocess import CalledProcessError, check_output

import tenacity

log = logging.getLogger(__name__)


def get_service_ip(name, namespace):
    service = kubectl_get("svc", "-n", namespace, name)
    return service.get("spec", {}).get("clusterIP")


def kubectl_get(*args: str, **kwargs) -> dict:
    """Run a kubectl get command with json.

    By default, this function uses the root kubeconfig that points to the local apiserver.
    Setting the 'external' keyword-argument to 'True' will use the ubuntu config which points to
    the external cluster endpoint.

    Args:
        args (str): arguments to pass to kubectl get.
        kwargs    : flags passed to kubectl().

    Returns:
        dict: A mapping of the get response.

    Raises:
        json.JSONDecodeError: If the output is not valid json.
    """
    output = kubectl("get", "-o", "json", *args, **kwargs)
    return json.loads(output) if output else {}


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(CalledProcessError),
    reraise=True,
    stop=tenacity.stop_after_delay(60),
    wait=tenacity.wait_exponential(),
    before=tenacity.before_log(log, logging.WARNING),
)
def kubectl(*args: str, external=False):
    """Run a kubectl cli command with a config file.

    By default, this function uses the root kubeconfig that points to the local apiserver.
    Setting the 'external' parameter to 'True' will use the ubuntu config which points to
    the external cluster endpoint.

    Args:
        args (str): arguments to pass to kubectl.
        external (bool): Use the external cluster kubeconfig.

    Returns:
        str: The output of the command.

    Raises:
        FileNotFoundError: If the kubeconfig file is not found.
        CalledProcessError: If the command fails.
    """
    cfg = Path("/home/ubuntu/config" if external else "/root/.kube/config")
    if not cfg.exists():
        raise FileNotFoundError(f"kubeconfig not found at {cfg}")
    command = ["kubectl", f"--kubeconfig={cfg}", *args]
    log.info("Executing {}".format(command))
    try:
        return check_output(command).decode("utf-8")
    except CalledProcessError as e:
        log.error(
            f"Command failed: {command}\nreturncode: {e.returncode}\nstdout: {e.output.decode()}"
        )
        raise
