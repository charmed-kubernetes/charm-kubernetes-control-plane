from kubernetes_wrapper import Kubernetes
import logging
import pytest
import random
import string

log = logging.getLogger(__name__)


@pytest.fixture(scope="module")
@pytest.mark.asyncio
async def kubernetes(ops_test):
    kubeconfig_path = ops_test.tmp_path / "kubeconfig"
    retcode, stdout, stderr = await ops_test.run(
        "juju",
        "scp",
        "-m",
        ops_test.model_full_name,
        "kubernetes-master/leader:config",
        kubeconfig_path,
    )
    if retcode != 0:
        log.error(f"retcode: {retcode}")
        log.error(f"stdout:\n{stdout.strip()}")
        log.error(f"stderr:\n{stderr.strip()}")
        pytest.fail("Failed to copy kubeconfig from kubernetes-master")
    namespace = "test-kubernetes-master-integration-" + "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(5)
    )
    kubernetes = Kubernetes(namespace, kubeconfig=str(kubeconfig_path))
    namespace_object = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": namespace},
    }
    kubernetes.apply_object(namespace_object)
    yield kubernetes
    kubernetes.delete_object(namespace_object)
