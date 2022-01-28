import logging
import pytest
import random
import string

from lightkube import KubeConfig, Client
from lightkube.resources.core_v1 import Namespace
from lightkube.models.meta_v1 import ObjectMeta


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
        "kubernetes-control-plane/leader:config",
        kubeconfig_path,
    )
    if retcode != 0:
        log.error(f"retcode: {retcode}")
        log.error(f"stdout:\n{stdout.strip()}")
        log.error(f"stderr:\n{stderr.strip()}")
        pytest.fail("Failed to copy kubeconfig from kubernetes-control-plane")

    namespace = (
        "test-kubernetes-control-plane-integration-"
        + random.choice(string.ascii_lowercase + string.digits) * 5
    )
    config = KubeConfig.from_file(kubeconfig_path)
    kubernetes = Client(
        config=config.get(context_name="juju-context"),
        namespace=namespace,
        trust_env=False,
    )
    namespace_obj = Namespace(metadata=ObjectMeta(name=namespace))
    kubernetes.create(namespace_obj)
    yield kubernetes
    kubernetes.delete(Namespace, namespace)
