import logging

from pytest_operator import OperatorTest


log = logging.getLogger(__name__)


class KubernetesMasterIntegrationTest(OperatorTest):
    async def test_build_and_deploy(self):
        bundle = self.render_bundle(
            "tests/data/bundle.yaml", master_charm=await self.build_charm(".")
        )
        await self.model.deploy(bundle)
        await self.model.wait_for_idle(timeout=30 * 60)

        def _check_statuses():
            busy_units = []
            for unit in self.model.units.values():
                if unit.workload_status != "active":
                    busy_units.append(f"{unit.name}: {unit.workload_status}")
            if busy_units:
                s = "s" if len(busy_units) > 1 else ""
                busy_units = ", ".join(busy_units)
                log.info(f"Waiting for unit{s}: {busy_units}")
                return False

        log.info("Model is idle, waiting for cluster to be ready")
        await self.model.block_until(
            _check_statuses,
            timeout=10 * 60,
            wait_period=60,
        )

    async def test_status_messages(self):
        """ Validate that the status messages are correct. """
        expected_messages = {
            "kubernetes-master": "Kubernetes master running.",
            "kubernetes-worker": "Kubernetes worker running.",
        }
        for app, message in expected_messages.items():
            for unit in self.model.applications[app].units:
                assert unit.workload_status_message == message
