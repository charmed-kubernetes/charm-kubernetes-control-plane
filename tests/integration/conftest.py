import logging
import pytest
import random
import string
import yaml

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

    parser.addoption(
        "--enable-keystone",
        action="store_true",
        default=False,
        help="run keystone tests",
    )

    parser.addoption(
        "--series",
        type=str,
        default="",
        help="Set series for the machine units",
    )

    parser.addoption(
        "--snap-channel",
        type=str,
        default="",
        help="Set snap channel for the control-plane & worker units",
    )


@pytest.fixture(scope="module")
def k8s_core_bundle(ops_test):
    return ops_test.Bundle("kubernetes-core", channel="1.26/stable")


@pytest.fixture(scope="module")
@pytest.mark.asyncio
async def k8s_core_yaml(ops_test, k8s_core_bundle):
    """Download and render the kubernetes-core bundle, return it's full yaml"""
    (bundle_path,) = await ops_test.async_render_bundles(k8s_core_bundle)
    return yaml.safe_load(bundle_path.read_text())


@pytest.fixture(scope="module")
def series(k8s_core_yaml, request):
    series = request.config.getoption("--series")
    return series if series else k8s_core_yaml["series"]


@pytest.fixture(scope="module")
def snap_channel(k8s_core_yaml, request):
    channel = request.config.getoption("--snap-channel")
    kcp = k8s_core_yaml["applications"]["kubernetes-control-plane"]
    return channel if channel else kcp["options"]["channel"]


def pytest_configure(config):
    config.addinivalue_line("markers", "hacluster: mark test as hacluster to run")
    config.addinivalue_line("markers", "keystone: mark test as keystone to run")


def pytest_collection_modifyitems(config, items):
    skip_if_marked = {"hacluster", "keystone"}
    for mark in skip_if_marked:
        if not config.getoption(f"--enable-{mark}"):
            to_skip = pytest.mark.skip(reason=f"need --enable-{mark} option to run")
            for item in items:
                if mark in item.keywords:
                    item.add_marker(to_skip)


@pytest.fixture
def hacluster(request):
    return request.config.getoption("--enable-hacluster")


@pytest.fixture
def keystone(request):
    return request.config.getoption("--enable-keystone")


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
