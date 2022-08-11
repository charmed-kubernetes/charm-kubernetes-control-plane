import asyncio
import logging
from juju.unit import Unit
from pathlib import Path
import shlex

import aiohttp
import json
import os
import pytest
import time
import yaml

from lightkube.resources.policy_v1beta1 import PodSecurityPolicy
from lightkube.resources.core_v1 import Node

log = logging.getLogger(__name__)


def _check_status_messages(ops_test):
    """Validate that the status messages are correct."""
    expected_messages = {
        "kubernetes-control-plane": "Kubernetes control-plane running.",
        "kubernetes-worker": "Kubernetes worker running.",
    }
    for app, message in expected_messages.items():
        for unit in ops_test.model.applications[app].units:
            assert unit.workload_status_message == message


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test, hacluster, keystone):
    log.info("Build Charm...")
    charm = await ops_test.build_charm(".")

    build_script = Path.cwd() / "build-cni-resources.sh"
    resources = await ops_test.build_resources(build_script)
    expected_resources = {"cni-amd64", "cni-arm64", "cni-s390x"}

    if resources and all(rsc.stem in expected_resources for rsc in resources):
        resources = {rsc.stem.replace("-", "_"): rsc for rsc in resources}
    else:
        log.info("Failed to build resources, downloading from latest/edge")
        arch_resources = ops_test.arch_specific_resources(charm)
        resources = await ops_test.download_resources(charm, resources=arch_resources)
        resources = {name.replace("-", "_"): rsc for name, rsc in resources.items()}

    assert resources, "Failed to build or download charm resources."

    context = dict(charm=charm, **resources)
    overlays = [
        ops_test.Bundle("kubernetes-core", channel="edge"),
        Path("tests/data/charm.yaml"),
    ]

    if hacluster:
        log.info("Using hacluster overlay")
        vips = os.getenv("OS_VIP00", "10.5.2.204 10.5.2.205")
        log.info("OS_VIP00: {}".format(vips))
        context.update(dict(OS_VIP00=vips))
        overlays.append(Path("tests/data/bundle-hacluster.yaml"))

    if keystone:
        log.info("Using keystone overlay")
        overlays.append(Path("tests/data/bundle-keystone.yaml"))

    bundle, *overlays = await ops_test.async_render_bundles(*overlays, **context)

    log.info("Deploy Charm...")
    model = ops_test.model_full_name
    cmd = f"juju deploy -m {model} {bundle} " + " ".join(
        f"--overlay={f}" for f in overlays
    )
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Bundle deploy failed: {(stderr or stdout).strip()}"

    log.info(stdout)
    await ops_test.model.block_until(
        lambda: "kubernetes-control-plane" in ops_test.model.applications, timeout=60
    )

    try:
        await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)
    except asyncio.TimeoutError:
        if "kubernetes-control-plane" not in ops_test.model.applications:
            raise
        app = ops_test.model.applications["kubernetes-control-plane"]
        if not app.units:
            raise
        unit = app.units[0]
        if "kube-system pod" in unit.workload_status_message:
            log.debug(
                await juju_run(
                    unit, "kubectl --kubeconfig /root/.kube/config get all -A"
                )
            )
        raise
    _check_status_messages(ops_test)


async def test_kube_api_endpoint(ops_test):
    """Validate that adding the kube-api-endpoint relation works"""
    await ops_test.model.add_relation(
        "kubernetes-control-plane:kube-api-endpoint",
        "kubernetes-worker:kube-api-endpoint",
    )
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=10 * 60)
    _check_status_messages(ops_test)


async def juju_run(unit: Unit, cmd):
    action = await unit.run(cmd)
    result = await action.wait()
    code = result.results["Code"]
    stdout = result.results.get("Stdout")
    stderr = result.results.get("Stderr")
    assert code == "0", f"{cmd} failed ({code}): {stderr or stdout}"
    return stdout


async def test_auth_load(ops_test):
    """Verify that the auth server can handle heavy load and / or dead endpoints."""
    app = ops_test.model.applications["kubernetes-control-plane"]
    unit = app.units[0]

    log.info("Opening auth-webhook port")
    await juju_run(unit, "open-port 5000")

    log.info("Getting internal auth address")
    auth_addr = await juju_run(unit, "network-get --ingress-address kube-api-endpoint")

    log.info("Getting admin token")
    kubeconfig = yaml.safe_load(await juju_run(unit, "cat /home/ubuntu/config"))
    valid_token = kubeconfig["users"][0]["user"]["token"]
    invalid_token = "invalid"

    log.info("Configuring custom endpoint")
    url = f"https://{auth_addr.strip()}:5000/slow-test"
    await app.set_config({"authn-webhook-endpoint": url})

    log.info("Waiting for model to settle")
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=10 * 60)

    async def _auth_req(token, timeout=30):
        url = f"https://{unit.public_address}:5000/v1beta1"
        req = {"kind": "TokenReview", "spec": {"token": token}}
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url, json=req, timeout=timeout, verify_ssl=False
            ) as resp:
                resp_json = await resp.json()
                return resp_json["status"]["authenticated"]

    log.info("Starting 20 background slow auth requests")
    tasks = [asyncio.create_task(_auth_req(invalid_token)) for _ in range(20)]

    log.info("Waiting for slow auth requests to block")
    await asyncio.sleep(1)

    log.info("Verifying one concurrent good auth request")
    assert await _auth_req(valid_token, timeout=5)

    log.info("Waiting for slow auth requests to complete")
    assert not any(await asyncio.gather(*tasks))


async def test_pod_security_policy(ops_test, kubernetes):
    """Test the pod-security-policy config option"""
    test_psp = {
        "apiVersion": "policy/v1beta1",
        "kind": "PodSecurityPolicy",
        "metadata": {"name": "privileged"},
        "spec": {
            "privileged": False,
            "fsGroup": {"rule": "RunAsAny"},
            "runAsUser": {"rule": "RunAsAny"},
            "seLinux": {"rule": "RunAsAny"},
            "supplementalGroups": {"rule": "RunAsAny"},
            "volumes": ["*"],
        },
    }

    async def wait_for_psp(privileged):
        deadline = time.time() + 60 * 10
        while time.time() < deadline:
            psp = kubernetes.get(PodSecurityPolicy, name="privileged")
            if bool(psp.spec.privileged) == privileged:
                break
            await asyncio.sleep(10)
        else:
            pytest.fail("Timed out waiting for PodSecurityPolicy update")

    app = ops_test.model.applications["kubernetes-control-plane"]

    await app.set_config({"pod-security-policy": yaml.dump(test_psp)})
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=120)
    await wait_for_psp(privileged=False)

    await app.set_config({"pod-security-policy": ""})
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=120)
    await wait_for_psp(privileged=True)


@pytest.mark.hacluster
async def test_service_down(ops_test):
    """Test VIP change node when control_plane services fail"""
    ha_unit = ops_test.model.applications["hacluster-kubernetes-control-plane"].units[0]
    action = await ha_unit.run_action("status")
    action = await action.wait()
    result = json.loads(action.results["result"])
    vip_main = result["resources"]["groups"]["grp_kubernetes-control-plane_vips"]
    node_before = vip_main[0]["nodes"][0]["name"]

    # simulate a failover on one control_plane resource (scheduler)
    main_machine = node_before.split("-")[-1]
    for unit in ops_test.model.applications["kubernetes-control-plane"].units:
        if unit.entity_id.split("/")[-1] == main_machine:
            await unit.run("systemctl stop snap.kube-scheduler.daemon")
            # run a hook to update status of the unit
            await unit.run("./hooks/update-status")

    # check that the resource changed node
    action = await ha_unit.run_action("status")
    action = await action.wait()
    result = json.loads(action.results["result"])
    vip_main = result["resources"]["groups"]["grp_kubernetes-control-plane_vips"]
    node_after = vip_main[0]["nodes"][0]["name"]
    assert node_after != node_before


async def test_node_label(ops_test, kubernetes):
    nodes = kubernetes.list(Node)
    for node in nodes:
        assert "juju-application" in node.metadata.labels
        assert node.metadata.labels["juju-application"] in [
            "kubernetes-worker",
            "kubernetes-control-plane",
        ]
