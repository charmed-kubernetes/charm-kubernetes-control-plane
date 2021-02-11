import logging

from pytest_operator import OperatorTest


log = logging.getLogger(__name__)


class KubernetesMasterIntegrationTest(OperatorTest):
    async def test_build_and_deploy(self):
        bundle = self.render_bundle(
            "tests/data/bundle.yaml", master_charm=await self.build_charm(".")
        )
        await self.model.deploy(bundle)
        await self.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)

    async def test_status_messages(self):
        """ Validate that the status messages are correct. """
        expected_messages = {
            "kubernetes-master": "Kubernetes master running.",
            "kubernetes-worker": "Kubernetes worker running.",
        }
        for app, message in expected_messages.items():
            for unit in self.model.applications[app].units:
                assert unit.workload_status_message == message
