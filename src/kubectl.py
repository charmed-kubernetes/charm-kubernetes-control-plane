import json
import logging
from subprocess import CalledProcessError, check_output

from tenacity import retry, stop_after_delay, wait_exponential

log = logging.getLogger(__name__)


def get_service_ip(name, namespace):
    service = kubectl_get("svc", "-n", namespace, name)
    return service.get("spec", {}).get("clusterIP")


@retry(stop=stop_after_delay(60), wait=wait_exponential())
def kubectl(*args, external=False):
    """Run a kubectl cli command with a config file.

    By default, this function uses the root kubeconfig that points to the local apiserver.
    Setting the 'external' parameter to 'True' will use the ubuntu config which points to
    the external cluster endpoint.

    Returns stdout and throws an error if the command fails.
    """
    cfg = "/home/ubuntu/config" if external else "/root/.kube/config"
    command = ["kubectl", f"--kubeconfig={cfg}"] + list(args)
    log.info("Executing {}".format(command))
    try:
        return check_output(command).decode("utf-8")
    except CalledProcessError as e:
        log.error(
            f"Command failed: {command}\nreturncode: {e.returncode}\nstdout: {e.output.decode()}"
        )
        raise


def kubectl_get(*args):
    output = kubectl("get", "-o", "json", *args)
    return json.loads(output)
