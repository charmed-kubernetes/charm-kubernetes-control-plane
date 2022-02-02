import logging
import pytest
import random
import string

from lightkube import KubeConfig, Client
from lightkube.resources.core_v1 import Namespace
from lightkube.models.meta_v1 import ObjectMeta


log = logging.getLogger(__name__)


def pytest_addoption(parser):
    parser.addoption(
        "--enable-hacluster",
        action="store_true",
        default=False,
        help="run hacluster tests",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "hacluster: mark test as hacluster to run")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--enable-hacluster"):
        # --enable-hacluster given in cli: do not skip hacluster tests
        return
    skip_hacluster = pytest.mark.skip(reason="need --enable-hacluster option to run")
    for item in items:
        if "hacluster" in item.keywords:
            item.add_marker(skip_hacluster)


@pytest.fixture
def hacluster(request):
    return request.config.getoption("--enable-hacluster")


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
