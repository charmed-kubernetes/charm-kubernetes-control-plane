import asyncio
import logging

import aiohttp
import pytest
import yaml


log = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test):
    bundle = ops_test.render_bundle(
        "tests/data/bundle.yaml", master_charm=await ops_test.build_charm(".")
    )
    await ops_test.model.deploy(bundle)
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)


async def test_status_messages(ops_test):
    """Validate that the status messages are correct."""
    expected_messages = {
        "kubernetes-master": "Kubernetes master running.",
        "kubernetes-worker": "Kubernetes worker running.",
    }
    for app, message in expected_messages.items():
        for unit in ops_test.model.applications[app].units:
            assert unit.workload_status_message == message


async def juju_run(unit, cmd):
    result = await unit.run(cmd)
    assert result.results["Code"] == "0"
    return result.results.get("Stdout")


async def test_auth_load(ops_test):
    """Verify that the auth server can handle heavy load and / or dead endpoints."""
    app = ops_test.model.applications["kubernetes-master"]
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
