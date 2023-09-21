#!/usr/bin/env python3
# Copyright 2023 Canonical
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

log = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest):
    """Build kubernetes-control-plane and deploy with kubernetes-core bundle."""
    log.info("Building charm")
    charm = await ops_test.build_charm(".")

    bundle, *overlays = await ops_test.async_render_bundles(
        ops_test.Bundle("charmed-kubernetes", channel="edge"), "tests/data/overlay.yaml", charm=charm
    )

    log.info("Deploying bundle")
    cmd = ["juju", "deploy", "-m", ops_test.model_full_name, bundle]
    for overlay in overlays:
        cmd += ["--overlay", overlay]
    rc, stdout, stderr = await ops_test.run(*cmd)
    assert rc == 0, f"Bundle deploy failed: {(stderr or stdout).strip()}"

    await ops_test.model.wait_for_idle(status="active", timeout=60 * 60)
