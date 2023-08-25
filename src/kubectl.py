import logging
from subprocess import check_output

from tenacity import retry, stop_after_delay, wait_exponential

log = logging.getLogger(__name__)


@retry(stop=stop_after_delay(60), wait=wait_exponential())
def kubectl(*args):
    """Run a kubectl cli command with a config file.

    Returns stdout and throws an error if the command fails.
    """
    command = ["kubectl", "--kubeconfig=/root/.kube/config"] + list(args)
    log.info("Executing {}".format(command))
    return check_output(command).decode("utf-8")
