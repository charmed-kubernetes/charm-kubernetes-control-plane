import logging

import pytest


log = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test):
    bundle = ops_test.render_bundle(
        "tests/data/bundle_pod_security_policy.yaml",
        master_charm=await ops_test.build_charm("."),
    )
    await ops_test.model.deploy(bundle)
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)


async def test_status_messages(ops_test):
    """ Validate that the status messages are correct. """
    expected_messages = {
        "kubernetes-master": "Kubernetes master running.",
        "kubernetes-worker": "Kubernetes worker running.",
    }
    for app, message in expected_messages.items():
        for unit in ops_test.model.applications[app].units:
            assert unit.workload_status_message == message
