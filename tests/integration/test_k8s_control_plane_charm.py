#!/usr/bin/env python3
# Copyright 2023 Canonical
# See LICENSE file for licensing details.

import asyncio
import logging
from pathlib import Path

import pytest
from helpers import (
    CP_APP,
    CP_SERVICES,
    ETCD_APP,
    WORKER_APP,
    invocation_ids,
    no_change_counts,
    restarted_services,
    run_on_unit,
    settle,
    units_of,
    utc_now,
)
from pytest_operator.plugin import OpsTest

log = logging.getLogger(__name__)


SERIES = "noble"


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest):
    """Build kubernetes-control-plane and deploy with kubernetes-core bundle."""
    charm = next(Path().glob("kubernetes-control-plane*.charm"), None)
    if not charm:
        log.info("Building charm")
        charm = await ops_test.build_charm(".")

    resource_path = ops_test.tmp_path / "charm-resources"
    resource_path.mkdir()
    resource_build_script = Path("./build-cni-resources.sh").resolve()
    log.info("Building charm resources")
    rc, stdout, stderr = await ops_test.run(
        "env", "ARCH=amd64", str(resource_build_script), cwd=resource_path
    )
    if rc != 0:
        log.error(f"rc: {rc}\nstdout: {stdout}\nstderr: {stderr}")
        pytest.fail("Failed to build charm resources")

    log.info("Building bundle")
    bundle, *overlays = await ops_test.async_render_bundles(
        ops_test.Bundle("kubernetes-core", channel="edge", series=SERIES),
        Path("tests/data/charm.yaml"),
        arch="amd64",
        series=SERIES,
        charm=charm.resolve(),
        resource_path=resource_path,
    )

    log.info("Deploying bundle")
    cmd = ["juju", "deploy", "-m", ops_test.model_full_name, bundle]
    for overlay in overlays:
        cmd += ["--overlay", overlay]
    rc, stdout, stderr = await ops_test.run(*cmd)
    assert rc == 0, f"Bundle deploy failed: {(stderr or stdout).strip()}"

    core_apps = set(ops_test.model.applications) - {"opentelemetry-collector"}
    async with ops_test.fast_forward(fast_interval="30s"):
        await ops_test.model.wait_for_idle(apps=core_apps, status="active", timeout=60 * 60)


async def test_status(ops_test):
    cp = ops_test.model.applications["kubernetes-control-plane"]
    k8s_version_str = cp.data["workload-version"]
    assert k8s_version_str, "Workload version is unset"
    assert tuple(int(i) for i in k8s_version_str.split(".")[:2]) >= (1, 26)


async def test_getkubeconfig(ops_test: OpsTest):
    cp = ops_test.model.applications["kubernetes-control-plane"]
    actions = await cp.get_actions()
    assert "get-kubeconfig" in actions
    action = await cp.units[0].run_action("get-kubeconfig")
    result = await action.wait()
    assert result.results["kubeconfig"]


async def test_user_create(ops_test: OpsTest):
    cp = ops_test.model.applications["kubernetes-control-plane"]
    actions = await cp.get_actions()
    assert "user-create" in actions
    action = await cp.units[0].run_action("user-create", name="testuser", groups="system:masters")
    result = await action.wait()
    assert result.results["kubeconfig"].startswith("juju scp")


APISERVER = "snap.kube-apiserver.daemon"


async def test_hook_with_nothing_changed_restarts_nothing(ops_test: OpsTest):
    """CUJ 2: hooks that change no argument and no input file restart no service."""
    app = ops_test.model.applications[CP_APP]
    before = await invocation_ids(ops_test)
    since = utc_now()

    # `ignore-kube-system-pods` only affects status messages; setting and resetting it
    # fires two config-changed hooks on every control-plane unit.
    await app.set_config({"ignore-kube-system-pods": "test-0"})
    await settle(ops_test)
    await app.set_config({"ignore-kube-system-pods": ""})
    await settle(ops_test)

    assert restarted_services(before, await invocation_ids(ops_test)) == set()
    counts = await no_change_counts(ops_test, since)
    for unit in units_of(ops_test, CP_APP):
        for service in CP_SERVICES:
            assert counts.get((unit, service), 0) >= 2, f"{unit} {service}: {counts}"


async def test_worker_add_and_remove_restart_nothing(ops_test: OpsTest):
    """CUJ 1: adding or removing a worker restarts no control-plane service."""
    workers = ops_test.model.applications[WORKER_APP]
    initial_workers = set(units_of(ops_test, WORKER_APP))
    before = await invocation_ids(ops_test)

    await workers.add_unit()
    await settle(ops_test)
    added = set(units_of(ops_test, WORKER_APP)) - initial_workers
    assert len(added) == 1
    assert restarted_services(before, await invocation_ids(ops_test)) == set()

    await workers.destroy_units(*added)
    await ops_test.model.block_until(
        lambda: not added & set(units_of(ops_test, WORKER_APP)), timeout=15 * 60
    )
    await settle(ops_test)
    assert restarted_services(before, await invocation_ids(ops_test)) == set()


async def test_argument_change_restarts_only_the_api_server(ops_test: OpsTest):
    app = ops_test.model.applications[CP_APP]
    before = await invocation_ids(ops_test)

    await app.set_config({"api-extra-args": "min-request-timeout=301"})
    await settle(ops_test)
    after = await invocation_ids(ops_test)

    assert restarted_services(before, after) == {APISERVER}
    changed = [
        u
        for u in units_of(ops_test, CP_APP)
        if before[u][APISERVER] != after[u][APISERVER]
    ]
    assert changed == units_of(ops_test, CP_APP)


async def test_certificate_reissue_restarts_the_services_that_read_it(ops_test: OpsTest):
    """A new server certificate restarts what loads `server.crt`, and nothing else."""
    app = ops_test.model.applications[CP_APP]
    unit = units_of(ops_test, CP_APP)[0]
    show_crt = "sha256sum /root/cdk/server.crt"
    old_crt = await run_on_unit(ops_test, unit, show_crt)
    before = await invocation_ids(ops_test)

    await app.set_config({"extra_sans": "restart-test.example.com"})
    for _ in range(120):
        if await run_on_unit(ops_test, unit, show_crt) != old_crt:
            break
        await asyncio.sleep(5)
    else:
        pytest.fail("server.crt was not reissued")
    await settle(ops_test)
    after = await invocation_ids(ops_test)

    # kube-scheduler and kube-proxy do not read server.crt.
    assert restarted_services(before, after) == {
        "snap.kube-apiserver.daemon",
        "snap.kube-controller-manager.daemon",
        "snap.kubelet.daemon",
        # wokeignore:rule=master
        "cdk.master.auth-webhook",
    }


async def test_etcd_unit_added_restarts_only_the_api_server(ops_test: OpsTest):
    before = await invocation_ids(ops_test)
    await ops_test.model.applications[ETCD_APP].add_unit()
    await settle(ops_test)
    assert restarted_services(before, await invocation_ids(ops_test)) == {APISERVER}
