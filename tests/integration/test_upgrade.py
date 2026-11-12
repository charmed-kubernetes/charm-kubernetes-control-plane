#!/usr/bin/env python3
# Copyright 2025 Canonical
# See LICENSE file for licensing details.
"""CUJ 3: `juju refresh` to the new build restarts no Kubernetes service.

Own module, so the first-deploy fixture of the other integration tests does not run.

Environment:
    WORKER_CHARM: a prebuilt worker `.charm` from the worker branch of the same name.
    UPGRADE_FROM_CHANNEL: Charmhub channel of the starting revision of both charms
        (the branch's own `1.3x/stable` track on release branches). Default: `stable`.
"""

import os
import re
from pathlib import Path

import pytest
from helpers import (
    CP_APP,
    WORKER_APP,
    invocation_ids,
    restarted_services,
    settle,
    snap_revisions,
)
from pytest_operator.plugin import OpsTest

# The auth-webhook is expected not to restart on upgrade (Stage 0 results). The value
# becomes True only if the marker in the unit file is added.
AUTH_WEBHOOK_RESTARTS_ON_UPGRADE = False
# wokeignore:rule=master
AUTH_WEBHOOK = (CP_APP, "cdk.master.auth-webhook")
TRACK_RISK = re.compile(r"^\d+\.\d+/\w+$")


@pytest.fixture(scope="module")
def charms():
    worker = os.environ.get("WORKER_CHARM")
    assert worker, "set WORKER_CHARM to a prebuilt worker .charm"
    control_plane = next(Path().glob("kubernetes-control-plane*.charm"), None)
    assert control_plane, "pack the control-plane charm first (charmcraft pack)"
    return {CP_APP: control_plane.resolve(), WORKER_APP: Path(worker).resolve()}


@pytest.mark.abort_on_fail
async def test_deploy_starting_revision(ops_test: OpsTest):
    channel = os.environ.get("UPGRADE_FROM_CHANNEL", "stable")
    rc, stdout, stderr = await ops_test.run(
        "juju", "deploy", "-m", ops_test.model_full_name, "kubernetes-core", "--channel", channel
    )  # fmt: skip
    assert rc == 0, f"Bundle deploy failed: {(stderr or stdout).strip()}"
    await settle(ops_test)

    # The `channel` config must be `track/risk`: a value such as `latest/edge` makes the
    # charm's channel check fail on a non-numeric track.
    for name in (CP_APP, WORKER_APP):
        app = ops_test.model.applications[name]
        if not TRACK_RISK.match((await app.get_config())["channel"]["value"]):
            minor = ".".join(app.data["workload-version"].split(".")[:2])
            await app.set_config({"channel": f"{minor}/stable"})
    await settle(ops_test)


async def refresh(ops_test, charms):
    """Refresh the worker first, then the control plane, like a release does."""
    for app in (WORKER_APP, CP_APP):
        rc, stdout, stderr = await ops_test.run(
            "juju", "refresh", "-m", ops_test.model_full_name, app, "--path", str(charms[app])
        )  # fmt: skip
        assert rc == 0, f"refresh {app} failed: {(stderr or stdout).strip()}"
    await settle(ops_test)


async def test_refresh_restarts_no_kubernetes_service(ops_test: OpsTest, charms):
    before = await invocation_ids(ops_test)
    revisions = await snap_revisions(ops_test)

    await refresh(ops_test, charms)

    expected = {AUTH_WEBHOOK} if AUTH_WEBHOOK_RESTARTS_ON_UPGRADE else set()
    assert restarted_services(before, await invocation_ids(ops_test)) == expected
    assert await snap_revisions(ops_test) == revisions  # no snap revision was pulled in


async def test_second_refresh_with_no_changes_restarts_nothing(ops_test: OpsTest, charms):
    before = await invocation_ids(ops_test)
    revisions = await snap_revisions(ops_test)

    await refresh(ops_test, charms)

    assert restarted_services(before, await invocation_ids(ops_test)) == set()
    assert await snap_revisions(ops_test) == revisions
