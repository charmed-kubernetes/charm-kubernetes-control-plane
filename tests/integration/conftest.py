import dataclasses
import logging
from pathlib import Path
from typing import List, Union
import pytest
import random
import string
import zipfile

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


###################################
#  vvv Move to pytest-operator vvv
###################################
@dataclasses.dataclass
class Bundle:
    name: str
    channel: str = "stable"
    arch: str = "all"
    series: str = "all"

    @property
    def juju_download_args(self):
        return [
            f"--{field.name}={getattr(self, field.name)}"
            for field in dataclasses.fields(Bundle)
            if field.default is not dataclasses.MISSING
        ]


async def render_overlays(
    self, *overlays: Union[Bundle, Path], **context: str
) -> List[Path]:
    """Render a set of templated bundles using Jinja2.
    This can be used to populate built charm paths or config values.
    :param overlays:  Bundle or Path to overlay file.
    :param **context: Additional optional context as keyword args.
    Returns the Path for the rendered bundle.
    """
    bundles_dst_dir = self.tmp_path / "bundles"
    bundles_dst_dir.mkdir(exist_ok=True)
    bundles = []
    for overlay in overlays:
        if isinstance(overlay, Path):
            content = overlay.read_text()
        elif isinstance(overlay, Bundle):
            filepath = f"{bundles_dst_dir}/{overlay.name}.bundle"
            await self.juju(
                "download",
                overlay.name,
                *overlay.juju_download_args,
                f"--filepath={filepath}",
                check=True,
                fail_msg=f"Couldn't download {overlay.name} bundle",
            )
            bundle_zip = zipfile.Path(filepath, "bundle.yaml")
            content = bundle_zip.read_text()
        bundles.append(self.render_bundle(content, context=context))
    return bundles


#################################################################################
# ^^^  stop here
# vvv remove once in pytest-operator
#################################################################################
@pytest.fixture(autouse=True)
def overwrite_opstest_render_bundle(ops_test):
    klass = type(ops_test)
    setattr(klass, "render_overlays", render_overlays)
    klass.Bundle = Bundle


#################################################################################


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
